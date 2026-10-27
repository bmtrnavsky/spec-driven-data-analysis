"""Kernel bootstrap: runs inside the `dda run` child process (spec §10.1, §10.1b).

Launched only by `dda run` (`python -m ddalib.kernel_bootstrap <script>
[args...]`), bound to the session's workdir via DDA_* env vars. Before any
user code runs it:

1. re-validates the lock (refuses to run user code when invalid);
2. installs a `sys.addaudithook` that logs every `open` on a data-root path
   and every `socket.connect` to the audit log, refuses write-mode opens on
   raw roots and snapshots, refuses non-allowlisted hosts, and logs spawns;
3. applies the native lockdown + reader wrappers for duckdb, polars and
   pyarrow (each recorded as enforced / not-installed / wrap-failed);
4. seeds randomness and installs the row-cap / PII-masking display formatter.

`--self-test` exercises the audit hook and the wrappers against synthetic
roots and stub modules (no workdir needed) and prints JSON — the red-team
harness and unit tests use it where the baseline stack is absent.

Stdlib only in this file: the child must start even to report that a
baseline package is missing.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import runpy
import sys
import threading
import time
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS_DIR))

from ddalib import chain, lockstate  # noqa: E402
from ddalib.layout import Workdir  # noqa: E402
from ddalib.matching import canon, under  # noqa: E402

STATUS_ENV = "DDA_KERNEL_STATUS"


class KernelRefusal(Exception):
    """The audit hook or a wrapper refused an operation (fail closed)."""


class Ctx:
    """Resolved kernel policy for one run."""

    def __init__(self, wd: Workdir, lock: dict, variant: str, run_id: str, session: str,
                 log_fn=None):
        from ddalib.layout import load_config
        cfg = load_config(wd)
        self.wd = wd
        self.lock = lock
        self.variant = variant
        self.run_id = run_id
        self.session = session
        self.aliases = sorted(lock.get("aliases") or [])
        self.roots: dict[str, list[str]] = {}
        self.hosts: set[str] = set()
        for alias in self.aliases:
            loc = cfg["data_roots"].get(alias) or {}
            paths = []
            for p in loc.get("paths") or []:
                c = canon(p, str(wd.root))
                if c:
                    paths.append(c)
            self.roots[alias] = paths
            self.hosts |= {h.lower() for h in loc.get("hosts") or []}
        snaps = canon(str(wd.root / "derived" / "snapshots"))
        self.snapshots = snaps or ""
        allowed = [p for ps in self.roots.values() for p in ps]
        self.allowed_dirs = sorted(set(allowed + [canon(str(wd.root / "derived")),
                                                  canon(str(wd.root / "outputs"))]))
        self._log_fn = log_fn or self._chain_log
        self._local = threading.local()
        self._valid_at = 0.0
        self._valid = True
        self.recheck()

    # ---------- logging ----------

    def _chain_log(self, rec: dict) -> None:
        from ddalib import ledger
        chain.append(ledger.audit_log(self.wd), rec, spill_on_busy=True)

    def log(self, event: str, aliases: list[str], **extra) -> None:
        if getattr(self._local, "in_log", False):
            return
        self._local.in_log = True
        try:
            self._log_fn({"type": "audit", "kind": "audit", "event": event,
                          "aliases": sorted(set(aliases)), "variant": self.variant,
                          "run_id": self.run_id, "session": self.session, **extra})
        finally:
            self._local.in_log = False

    # ---------- classification ----------

    def alias_of(self, path: str) -> str | None:
        c = canon(path, os.getcwd())
        if not c:
            return None
        for alias, paths in self.roots.items():
            if any(under(c, p) for p in paths):
                return alias
        return None

    def is_snapshot(self, path: str) -> bool:
        c = canon(path, os.getcwd())
        return bool(c and self.snapshots and (c == self.snapshots or under(c, self.snapshots)))

    def recheck(self) -> bool:
        now = time.monotonic()
        if now - self._valid_at > 5.0:
            try:
                state, _, _ = lockstate.quick_status(self.wd)
                self._valid = state == "valid"
            except Exception:
                self._valid = False
            self._valid_at = now
        return self._valid


def _is_write_mode(mode, flags) -> bool:
    if isinstance(mode, str):
        m = mode.lower()
        return any(c in m for c in ("w", "a", "+")) or "x" in m
    if isinstance(flags, int):
        return bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
    return False


def install_audit_hook(ctx: Ctx):
    """sys.addaudithook: log data-root opens and connects; refuse writes and strangers."""
    def hook(event, args):
        if event == "open":
            path, mode = (list(args) + [None, None])[:2] if args else (None, None)
            flags = args[2] if len(args) > 2 else None
            if not isinstance(path, (str, bytes, os.PathLike)):
                return
            p = os.fspath(path)
            if isinstance(p, bytes):
                try:
                    p = p.decode("utf-8")
                except UnicodeDecodeError:
                    return
            alias = ctx.alias_of(p)
            snap = ctx.is_snapshot(p)
            if alias is None and not snap:
                return
            write = _is_write_mode(mode, flags)
            ctx.log("open", [a for a in (alias,) if a],
                    path=p[:300], mode=str(mode)[:20], write=write,
                    snapshot=snap, refused=False)
            if not ctx.recheck():
                raise KernelRefusal(f"dda kernel: lock is not valid; data reads are refused ({alias or 'snapshot'})")
            if write and (snap or alias is not None and _is_raw_write(ctx, p)):
                ctx.log("open-refused", [a for a in (alias,) if a],
                        path=p[:300], mode=str(mode)[:20], reason="write to raw root or snapshot")
                raise KernelRefusal(f"dda kernel: write access to raw data is refused ({alias or 'snapshot'}); "
                                    "write derived data to derived/ or outputs/")
        elif event == "socket.connect":
            addr = args[1] if len(args) > 1 else None
            host = (addr[0] if isinstance(addr, (tuple, list)) and addr else str(addr)).lower()
            if host in ("127.0.0.1", "::1", "localhost"):
                return
            allowed = host in ctx.hosts
            ctx.log("socket-connect", [], host=host, refused=not allowed)
            if not allowed:
                raise KernelRefusal(f"dda kernel: network connect to {host!r} refused "
                                    f"(allowlist: {sorted(ctx.hosts) or 'none'})")
        elif event in ("subprocess.Popen", "os.exec", "os.spawn", "os.system"):
            try:
                detail = str(args[0])[:200] if args else event
            except Exception:
                detail = event
            ctx.log("spawn", [], detail=detail)
    sys.addaudithook(hook)
    return {"audit_hook": "installed"}


def _is_raw_write(ctx: Ctx, path: str) -> bool:
    """Raw roots are immutable: any write-mode open under one is refused (snapshots handled by caller)."""
    return ctx.alias_of(path) is not None


# ---------- native lockdown + reader wrappers (§10.1b) ----------

_REMOTE_RE = re.compile(r"^(s3|gs|az|abfs|hdfs|https?)://([^/]+)", re.IGNORECASE)


def _refuse_remote(ctx: Ctx, target) -> str | None:
    s = str(target)
    m = _REMOTE_RE.match(s)
    if not m:
        return None
    host = m.group(2).lower()
    if host in ctx.hosts:
        return None
    raise KernelRefusal(f"dda kernel: remote {s[:120]!r} refused (host {host!r} not on the allowlist)")


def _check_local(ctx: Ctx, target, *, write: bool, what: str):
    _refuse_remote(ctx, target)
    alias = ctx.alias_of(str(target))
    snap = ctx.is_snapshot(str(target))
    if alias is None and not snap:
        return
    ctx.log(f"{what}-{'write' if write else 'read'}", [a for a in (alias,) if a],
            path=str(target)[:300], snapshot=snap)
    if not ctx.recheck():
        raise KernelRefusal(f"dda kernel: lock is not valid; data reads are refused ({alias or 'snapshot'})")
    if write and (snap or alias is not None):
        raise KernelRefusal(f"dda kernel: write to raw data refused ({alias or 'snapshot'}); "
                            "write derived data to derived/ or outputs/")


def wrap_duckdb(mod, ctx: Ctx) -> str:
    """Harden duckdb: allowed_directories + no extensions/external access, locked; log + refuse writes."""
    raw_paths = [p for ps in ctx.roots.values() for p in ps]
    orig_connect = mod.connect

    def configured(con):
        dirs = list(ctx.allowed_dirs)
        if not ctx.recheck():
            dirs = [d for d in dirs if d not in raw_paths]
        con.execute("SET autoinstall_known_extensions = false")
        con.execute("SET autoload_known_extensions = false")
        con.execute("SET enable_external_access = false")
        quoted = ", ".join("'" + d.replace("'", "''") + "'" for d in sorted(set(dirs)) if d)
        if quoted:
            con.execute(f"SET allowed_directories = [{quoted}]")
        con.execute("SET lock_configuration = true")
        return con

    def scan_sql(sql: str) -> None:
        for m in re.finditer(r"'((?:[^'\\]|\\.|'')+)'", sql):
            cand = m.group(1)
            if "/" in cand or "\\" in cand or cand.lower().endswith((".csv", ".parquet", ".json", ".db", ".duckdb")):
                alias = ctx.alias_of(cand)
                if alias is not None or ctx.is_snapshot(cand):
                    ctx.log("duckdb-read", [a for a in (alias,) if a], statement=sql[:300])
        up = sql.upper()
        if re.search(r"\b(COPY\s+.*\s+TO|EXPORT\s+DATABASE|ATTACH)\b", up):
            for m in re.finditer(r"TO\s+'((?:[^'\\]|\\.|'')+)'", sql, re.IGNORECASE):
                tgt = m.group(1)
                if ctx.alias_of(tgt) is not None or ctx.is_snapshot(tgt):
                    raise KernelRefusal("dda kernel: COPY TO / EXPORT / ATTACH onto a raw root or snapshot "
                                        "is refused (duckdb cannot make one directory read-only)")
            if re.search(r"\bATTACH\s+'", up):
                for m in re.finditer(r"ATTACH\s+'((?:[^'\\]|\\.|'')+)'", sql, re.IGNORECASE):
                    tgt = m.group(1)
                    if ctx.alias_of(tgt) is not None or ctx.is_snapshot(tgt):
                        raise KernelRefusal("dda kernel: ATTACH of a raw-root or snapshot file is refused")

    class GuardedCon:
        def __init__(self, inner):
            self._inner = inner

        def execute(self, sql, *a, **k):
            if isinstance(sql, str):
                scan_sql(sql)
            return self._inner.execute(sql, *a, **k)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    def connect(*a, **k):
        return GuardedCon(configured(orig_connect(*a, **k)))

    default_box: dict = {}

    def default_connection():
        if "con" not in default_box:
            default_box["con"] = GuardedCon(configured(orig_connect()))
        return default_box["con"]

    def sql(sql, *a, **k):
        return default_connection().execute(sql, *a, **k)

    mod.connect = connect
    mod.default_connection = default_connection
    for name in ("sql", "query"):
        if hasattr(mod, name):
            setattr(mod, name, sql)
    for name in ("read_csv", "read_parquet", "read_json", "read_csv_auto", "from_csv_auto", "from_parquet"):
        if hasattr(mod, name):
            orig = getattr(mod, name)
            def _mk_reader(o):
                def reader(*a, **k):
                    src = k.get("path") or k.get("file") or (a[0] if a else None)
                    if src is not None:
                        _check_local(ctx, src, write=False, what="duckdb")
                    return o(*a, **k)
                return reader
            setattr(mod, name, _mk_reader(orig))
    return "enforced"


def _wrap_first_arg(mod, names: tuple, ctx: Ctx, what: str):
    wrapped = 0
    for name in names:
        objname, _, attr = name.rpartition(".")
        target = mod
        if objname:
            target = getattr(mod, objname, None)
            if target is None:
                continue
        orig = getattr(target, attr, None)
        if not callable(orig):
            continue

        def _mk(o):
            def fn(*a, **k):
                src = k.get("source") or k.get("file") or k.get("path") or k.get("uri") or (a[0] if a else None)
                if src is not None:
                    _check_local(ctx, src, write=False, what=what)
                return o(*a, **k)
            return fn

        setattr(target, attr, _mk(orig))
        wrapped += 1
    return wrapped


def _wrap_writer(mod, names: tuple, ctx: Ctx, what: str):
    wrapped = 0
    for name in names:
        objname, _, attr = name.rpartition(".")
        target = mod
        if objname:
            target = getattr(mod, objname, None)
            if target is None:
                continue
        orig = getattr(target, attr, None)
        if not callable(orig):
            continue

        def _mk(o):
            def fn(*a, **k):
                dst = k.get("where") or k.get("file") or k.get("path") or k.get("uri") or (a[0] if a else None)
                if dst is not None:
                    _check_local(ctx, dst, write=True, what=what)
                return o(*a, **k)
            return fn

        setattr(target, attr, _mk(orig))
        wrapped += 1
    return wrapped


def wrap_polars(mod, ctx: Ctx) -> str:
    n = _wrap_first_arg(mod, ("read_csv", "read_parquet", "read_ipc", "read_json", "read_ndjson",
                              "read_avro", "read_excel", "read_ods", "scan_csv", "scan_parquet",
                              "scan_ipc", "scan_ndjson"), ctx, "polars")
    n += _wrap_writer(mod, ("DataFrame.write_csv", "DataFrame.write_parquet", "DataFrame.write_ipc",
                            "DataFrame.write_json", "DataFrame.write_avro", "DataFrame.write_excel",
                            "LazyFrame.sink_csv", "LazyFrame.sink_parquet", "LazyFrame.sink_ipc",
                            "LazyFrame.sink_ndjson"), ctx, "polars")
    return f"enforced ({n} entry points)"


def wrap_pyarrow(mod, ctx: Ctx) -> str:
    n = 0
    try:
        from pyarrow import parquet as _pq  # noqa: F401
        n += _wrap_first_arg(mod, ("parquet.read_table", "parquet.ParquetFile", "parquet.read_metadata"), ctx, "pyarrow")
        n += _wrap_writer(mod, ("parquet.write_table", "parquet.write_to_dataset"), ctx, "pyarrow")
    except Exception:
        pass
    n += _wrap_first_arg(mod, ("dataset.dataset", "csv.read_csv", "csv.open_csv", "feather.read_table",
                               "feather.read_feather", "ipc.new_file"), ctx, "pyarrow")
    n += _wrap_writer(mod, ("dataset.write_dataset", "csv.write_csv", "feather.write_feather"), ctx, "pyarrow")
    return f"enforced ({n} entry points)"


def apply_wrappers(ctx: Ctx) -> dict[str, str]:
    """Wrap every installed native data library; absent ones are detect-only (§10.1b)."""
    out: dict[str, str] = {}
    try:
        import duckdb as _dd
        try:
            out["duckdb"] = wrap_duckdb(_dd, ctx)
        except Exception as exc:
            out["duckdb"] = f"wrap-failed: {exc}"
    except ImportError:
        out["duckdb"] = "not-installed (detect-only: native duckdb I/O unenforced)"
    try:
        import polars as _pl
        try:
            out["polars"] = wrap_polars(_pl, ctx)
        except Exception as exc:
            out["polars"] = f"wrap-failed: {exc}"
    except ImportError:
        out["polars"] = "not-installed (detect-only: native polars I/O unenforced)"
    try:
        import pyarrow as _pa
        try:
            out["pyarrow"] = wrap_pyarrow(_pa, ctx)
        except Exception as exc:
            out["pyarrow"] = f"wrap-failed: {exc}"
    except ImportError:
        out["pyarrow"] = "not-installed (detect-only: native pyarrow I/O unenforced)"
    try:
        import pandas  # noqa: F401
        out["pandas"] = "via-audit-hook + pyarrow wrappers (pandas readers route through python open or pyarrow)"
    except ImportError:
        out["pandas"] = "not-installed (detect-only)"
    return out


# ---------- display formatter (§10.2) ----------

def install_display_limit(ctx: Ctx, max_rows: int = 20) -> str:
    try:
        from IPython import get_ipython
        ip = get_ipython()
        if ip is None:
            return "no active IPython shell (plain script run)"
    except ImportError:
        return "IPython not installed (plain script run)"
    try:
        from ddalib.layout import load_config as _lc
        pii = set()
        for loc in (_lc(ctx.wd)["data_roots"] or {}).values():
            pii |= set(loc.get("pii_columns") or [])
    except Exception:
        pii = set()

    def masker(obj, _p, _b):
        try:
            import pandas as _pd
            if isinstance(obj, _pd.DataFrame):
                cols = [c for c in obj.columns if str(c) in pii]
                view = obj.head(max_rows)
                if cols:
                    view = view.copy()
                    for c in cols:
                        view[c] = "<masked>"
                return f"<dda: first {min(len(obj), max_rows)} of {len(obj)} rows>\n" + view.to_string()
        except ImportError:
            pass
        return None

    try:
        ip.display_formatter.formatters["text/plain"].for_type_by_name("pandas.core.frame", "DataFrame", masker)
        return f"row cap {max_rows}, {len(pii)} PII column(s) masked"
    except Exception as exc:
        return f"formatter install failed: {exc}"


# ---------- startup ----------

def write_status(payload: dict) -> None:
    path = os.environ.get(STATUS_ENV)
    if not path:
        return
    tmp = path + f".{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def boot() -> tuple[Ctx, dict]:
    """Validate the lock, install the audit hook, wrap natives, seed. Returns (ctx, status)."""
    from ddalib import kernel as _k
    from ddalib.layout import load_config as _lc
    root = os.environ.get("DDA_WORKDIR") or os.getcwd()
    wd = Workdir.at(root, os.environ.get("DDA_MILESTONE") or None)
    wd.require_initialized()
    lock = lockstate.read_lock(wd)
    if not lock:
        raise SystemExit("dda kernel: no lock; run `dda lock` first")
    if lock.get("lock_hash") != os.environ.get("DDA_LOCK_HASH"):
        raise SystemExit("dda kernel: lock changed since launch; refusing to run")
    ctx = Ctx(wd, lock, os.environ.get("DDA_VARIANT", ""), os.environ.get("DDA_RUN_ID", ""),
              os.environ.get("DDA_SESSION", ""))
    status: dict = {"python": sys.version.split()[0], "ok": True}
    status.update(install_audit_hook(ctx))
    versions, missing = _k.baseline_versions()
    status["baseline"] = versions
    if missing:
        status["ok"] = False
        status["missing_baseline"] = missing
    status["wrappers"] = apply_wrappers(ctx)
    unenforced = [lib for lib, st in status["wrappers"].items()
                  if st.startswith(("not-installed", "wrap-failed"))]
    status["network_policy"] = ("detect-only (unenforced native path: " + ", ".join(unenforced) + ")"
                                if unenforced else "audit+wrapper-enforced")
    seed = int(os.environ.get("DDA_SEED") or 0)
    try:
        import random as _r
        _r.seed(seed)
    except Exception:
        pass
    try:
        import numpy as _np
        _np.random.seed(seed % 4294967296)
    except Exception:
        pass
    status["seed"] = seed
    status["display"] = install_display_limit(ctx)
    try:
        ky = (wd.analysis / "kernel.yaml").read_bytes()
    except OSError:
        ky = None
    status["environment_hash"] = _k.environment_hash(versions, ky)
    write_status(status)
    return ctx, status


def main(argv: list[str]) -> int:
    if argv[:1] == ["--self-test"]:
        return self_test()
    if not argv:
        print("usage: python -m ddalib.kernel_bootstrap <script> [args...]", file=sys.stderr)
        return 2
    ctx, status = boot()
    if not status.get("ok"):
        print(f"dda kernel does not start: missing baseline packages: "
              f"{', '.join(status.get('missing_baseline') or [])} (§10.1a)", file=sys.stderr)
        return 7
    script = os.path.abspath(argv[0])
    sys.argv = [script, *argv[1:]]
    sys.path.insert(0, os.path.dirname(script))
    ctx.log("kernel-start", ctx.aliases, script=script)
    try:
        runpy.run_path(script, run_name="__main__")
    finally:
        ctx.log("kernel-stop", ctx.aliases, script=script)
    return 0


# ---------- self-test (no workdir needed) ----------

def self_test() -> int:
    """Exercise the audit hook + wrappers against synthetic roots and stub modules."""
    import tempfile
    checks: dict[str, object] = {}
    tmp = Path(tempfile.mkdtemp(prefix="dda-kernel-test-"))
    raw = tmp / "raw"
    raw.mkdir()
    (raw / "orders.csv").write_text("id,amount\n1,10\n", encoding="utf-8")
    events: list[dict] = []

    class FakeCtx:
        variant, run_id, session = "v1", "r1", "test"
        roots = {"sales": [canon(str(raw))]}
        hosts = {"db.example.internal"}
        snapshots = canon(str(tmp / "snaps"))
        allowed_dirs = [canon(str(raw))]

        def __init__(self):
            self._valid = True

        def alias_of(self, path):
            c = canon(path, os.getcwd())
            if c and under(c, canon(str(raw))):
                return "sales"
            return None

        def is_snapshot(self, path):
            c = canon(path, os.getcwd())
            return bool(c and self.snapshots and (c == self.snapshots or under(c, self.snapshots)))

        def recheck(self):
            return self._valid

        def log(self, event, aliases, **extra):
            events.append({"event": event, "aliases": aliases, **extra})

    ctx = FakeCtx()
    install_audit_hook(ctx)

    def tried(fn) -> tuple[bool, str]:
        try:
            fn()
            return True, ""
        except KernelRefusal as exc:
            return False, str(exc)[:100]
        except Exception as exc:
            return True, f"OTHER-ERROR {type(exc).__name__}: {exc}"[:100]

    ok, _ = tried(lambda: open(raw / "orders.csv", newline=""))
    checks["read-logged"] = ok and any(e["event"] == "open" and not e.get("write") for e in events)
    ok, _ = tried(lambda: open(raw / "orders.csv", "a"))
    checks["write-refused"] = (not ok) and any(e["event"] == "open-refused" for e in events)
    # Runtime-built path (string concatenation, the §0.1 limit for string-match hooks).
    p = str(raw) + "/" + "orders" + ".csv"
    ok, _ = tried(lambda: open(p, "a"))
    checks["constructed-path-refused"] = not ok
    outside = tmp / "elsewhere.txt"
    ok, _ = tried(lambda: open(outside, "w"))
    checks["outside-raw-allowed"] = ok
    import socket as _sock
    ok, _ = tried(lambda: _sock.socket().connect(("169.254.169.254", 80)))
    checks["strange-host-refused"] = not ok
    logged_hosts = [e for e in events if e["event"] == "socket-connect"]
    checks["connect-logged"] = bool(logged_hosts)

    # Wrapper unit checks against stub modules (no real duckdb/polars needed).
    class StubCon:
        def __init__(self):
            self.sets = []

        def execute(self, sql, *a, **k):
            self.sets.append(sql)
            return self

    made = {}

    class StubDuck:
        def connect(self, *a, **k):
            made["con"] = StubCon()
            return made["con"]

    stub = StubDuck()
    wrap_duckdb(stub, ctx)
    gcon = stub.connect()
    gcon.execute("SELECT * FROM 'x.csv'")
    sets = " ".join(made["con"].sets).lower()
    checks["duckdb-lockdown-sets"] = all(s in sets for s in (
        "allowed_directories", "autoinstall_known_extensions", "autoload_known_extensions",
        "enable_external_access", "lock_configuration"))
    ok, _ = tried(lambda: gcon.execute("COPY (SELECT 1) TO '" + str(raw / "out.csv") + "'"))
    checks["duckdb-copy-to-raw-refused"] = not ok

    class StubPl:
        def read_csv(self, src, **k):
            return ("read", str(src))

    stubpl = StubPl()
    wrap_polars(stubpl, ctx)
    ok, _ = tried(lambda: stubpl.read_csv(raw / "orders.csv"))
    checks["polars-read-logged"] = ok and any(e["event"] == "polars-read" for e in events)

    results = {"checks": checks, "events": len(events)}
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
