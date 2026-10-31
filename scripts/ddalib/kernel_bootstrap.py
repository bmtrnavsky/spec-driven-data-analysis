"""Kernel bootstrap: runs inside the `dda run` child process (spec §10.1, §10.1b).

The child is a separate locked subprocess: it never reads the workdir's
`.analysis` (no spec.lock, no ledger, no chains) and never appends to one.
The parent (`dda run`) freezes policy into a JSON file in a directory
outside the workdir and passes it via DDA_POLICY_FILE; the child's only
outputs are derived files, stdio tails, an IPC status file and an IPC
audit-event file (DDA_IPC_STATUS / DDA_IPC_EVENTS, same outside dir).
The parent imports the event file into `audit.log` through the locked
appender after the subprocess exits. The audit hook therefore refuses
every `open` under `.analysis` except a read-only open of the entry
script itself.

Launched only by `dda run` (`python -I -P <scripts>/ddalib/kernel_bootstrap.py
<script> [args...]`). Before any user code it:

1. loads the frozen policy (refuses to run user code when absent);
2. installs a `sys.addaudithook` that queues every `open` on a data-root
   path and every `socket.connect` to the IPC event file, refuses all
   opens under `.analysis` (except reading the entry script), refuses
   write-mode opens on raw roots and snapshots, refuses non-allowlisted
   hosts, refuses every `os`-level mutation or link on raw roots,
   snapshots and `.analysis` (`remove`/`unlink`, `rmdir`, `mkdir`,
   `rename`/`replace`, `link`, `symlink`, `truncate`), logs
   `listdir`/`scandir` enumeration of raw roots and snapshots (refusing
   it under `.analysis` and when the lock is invalid), and refuses every
   subprocess spawn (`subprocess.Popen`, `os.spawn`/`posix_spawn`/`exec`,
   `os.fork`, `os.system`, `os.startfile`) — the kernel is contained, it
   has no child processes whose I/O the hook cannot see. The spawn,
   `os`-mutation and enumeration refusals engage when DDA_KERNEL_ACTIVE=1
   is present at hook-install time (`dda run` sets it for every kernel);
   plain `open`/`socket` refusals are unconditional;
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
# Baseline stubs for tests/harness reach the child ONLY through the frozen
# policy (`baseline_dir`, written by the parent from its own environment).
# The child environment is stripped of DDA_BASELINE_DIR (and PYTHONPATH /
# PYTHONHOME), so user code cannot inject a stub directory that shadows the
# real stack; `ddalib` itself is pinned to SCRIPTS_DIR below (a swapped
# copy anywhere else is refused).
sys.path.insert(0, str(SCRIPTS_DIR))

from ddalib import chain, lockstate  # noqa: E402
from ddalib.layout import Workdir  # noqa: E402
from ddalib.matching import canon, under  # noqa: E402

if not Path(getattr(chain, "__file__", "") or "").resolve().is_relative_to(SCRIPTS_DIR):
    raise SystemExit("dda kernel: refusing to run with a swapped ddalib "
                     f"(loaded from {getattr(chain, '__file__', '?')}, "
                     f"expected under {SCRIPTS_DIR})")

STATUS_ENV = "DDA_KERNEL_STATUS"
POLICY_ENV = "DDA_POLICY_FILE"
EVENTS_ENV = "DDA_IPC_EVENTS"
IPC_STATUS_ENV = "DDA_IPC_STATUS"


class KernelRefusal(Exception):
    """The audit hook or a wrapper refused an operation (fail closed)."""


class PolicyCtx:
    """Resolved kernel policy for one run, from the parent's frozen snapshot.

    Used inside the locked subprocess: no Workdir, no lockstate, no
    ledger — policy arrives via DDA_POLICY_FILE and events leave via the
    IPC event file. `recheck()` is frozen-true: the lock was valid when
    the parent spawned this process, and a re-lock mid-run does not
    change the running kernel (the parent binds the spawn-time lock hash
    to the run entry; G6 compares it).
    """

    def __init__(self, policy: dict, log_fn=None):
        self.variant = policy.get("variant") or ""
        self.run_id = policy.get("run_id") or ""
        self.session = policy.get("session") or ""
        self.aliases = sorted(policy.get("aliases") or [])
        self.roots: dict[str, list[str]] = {a: list(ps) for a, ps in (policy.get("roots") or {}).items()}
        self.hosts: set[str] = {str(h).lower() for h in policy.get("hosts") or []}
        self.snapshots = policy.get("snapshots") or ""
        self.analysis_dir = policy.get("analysis_dir") or ""
        self.script = policy.get("script") or ""
        self.allowed_dirs = sorted(policy.get("allowed_dirs") or [])
        # Verify-replay snapshot overlay (SPEC §10.3): {live canon path:
        # snapshot canon path}, parent-owned via the frozen policy. Empty
        # on every normal run — redirection installs only when non-empty.
        ov = policy.get("overlay") or {}
        self.overlay = {str(k): str(v) for k, v in ov.items()
                        if isinstance(k, str) and isinstance(v, str) and k and v}
        self._log_fn = log_fn or self._ipc_log
        self._events_path = os.environ.get(EVENTS_ENV) or ""
        self._local = threading.local()

    # ---------- logging ----------

    def _ipc_log(self, rec: dict) -> None:
        line = json.dumps(rec, sort_keys=True) + "\n"
        if self._events_path:
            with open(self._events_path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(line)
        # No event file (unit tests): keep events in memory.
        if not hasattr(self, "_mem"):
            self._mem = []
        if not self._events_path:
            self._mem.append(rec)

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

    def aliases_of(self, path: str) -> list[str]:
        """Every alias whose roots contain the path (a path can sit under
        several aliases; logging only the first would blind exposure scans
        for the others)."""
        c = canon(path, os.getcwd())
        if not c:
            return []
        return sorted(a for a, paths in self.roots.items() if any(under(c, p) for p in paths))

    def alias_of(self, path: str) -> str | None:
        found = self.aliases_of(path)
        return found[0] if found else None

    def is_analysis(self, path: str) -> bool:
        c = canon(path, os.getcwd())
        return bool(c and self.analysis_dir and (c == self.analysis_dir or under(c, self.analysis_dir)))

    def is_script(self, path: str) -> bool:
        c = canon(path, os.getcwd())
        return bool(c and self.script and c == self.script)

    def is_evidence_exempt(self, path: str) -> bool:
        """No `.analysis` writes leave the locked subprocess — the status
        and event files live in the parent-owned IPC directory outside the
        workdir, so there is nothing to exempt."""
        return False

    def is_snapshot(self, path: str) -> bool:
        c = canon(path, os.getcwd())
        return bool(c and self.snapshots and (c == self.snapshots or under(c, self.snapshots)))

    def recheck(self) -> bool:
        return True


class Ctx:
    """Resolved kernel policy for one run."""

    def __init__(self, wd: Workdir, lock: dict, variant: str, run_id: str, session: str,
                 log_fn=None, script: str = ""):
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
        self.analysis_dir = canon(str(wd.analysis))
        self.audit_path = canon(str(wd.analysis / "audit.log"))
        status_env = os.environ.get(STATUS_ENV)
        self.status_path = canon(status_env) if status_env else ""
        allowed = [p for ps in self.roots.values() for p in ps]
        self.allowed_dirs = sorted(set(allowed + [canon(str(wd.root / "derived")),
                                                  canon(str(wd.root / "outputs"))]))
        # Live-kernel boots never carry a snapshot overlay: redirection is
        # a verify-replay instrument, installed only via the IPC policy.
        self.overlay = {}
        self.script = canon(script, os.getcwd()) if script else ""
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

    def aliases_of(self, path: str) -> list[str]:
        """Every alias whose roots contain the path (a path can sit under
        several aliases; logging only the first would blind exposure scans
        for the others)."""
        c = canon(path, os.getcwd())
        if not c:
            return []
        return sorted(a for a, paths in self.roots.items() if any(under(c, p) for p in paths))

    def alias_of(self, path: str) -> str | None:
        found = self.aliases_of(path)
        return found[0] if found else None

    def is_analysis(self, path: str) -> bool:
        c = canon(path, os.getcwd())
        return bool(c and self.analysis_dir and (c == self.analysis_dir or under(c, self.analysis_dir)))

    def is_evidence_exempt(self, path: str) -> bool:
        """Nothing under `.analysis` is writable from inside the kernel:
        the status and event files live in the parent-owned IPC directory
        outside the workdir, so there is nothing to exempt."""
        return False

    def is_script(self, path: str) -> bool:
        """The entry script is the single `.analysis` path the kernel may
        open — read-only (the parent launches it by path)."""
        c = canon(path, os.getcwd())
        return bool(c and self.script and c == self.script)

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


def _iter_path_args(args) -> object:
    """Yield every argument that could be a path (str/bytes/PathLike).

    `os.*` audit events carry trailing dir-fd/mode ints after the path
    arguments; those are skipped here.
    """
    for a in args or ():
        if isinstance(a, (str, bytes, os.PathLike)):
            yield a


def _decode_path(p) -> str | None:
    if isinstance(p, os.PathLike):
        try:
            p = os.fspath(p)
        except Exception:
            return None
    if isinstance(p, bytes):
        try:
            p = p.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return p if isinstance(p, str) else None


# ---------- snapshot overlay (verify replays, SPEC §10.3) ----------

def overlay_target(ctx, target) -> str | None:
    """Snapshot path for a live path under the verify overlay, else None.

    The overlay maps live canon paths (files or directory prefixes) to
    their snapshot copies. Matching is longest-prefix-first so a file
    entry wins over its parent directory entry.
    """
    ov = getattr(ctx, "overlay", None)
    if not ov:
        return None
    s = target if isinstance(target, str) else _decode_path(target)
    if not s:
        return None
    c = canon(s, os.getcwd())
    if not c:
        return None
    for live in sorted(ov, key=len, reverse=True):
        if c == live or under(c, live):
            return ov[live] + c[len(live):]
    return None


def _redirect_value(ctx, value):
    """Rewrite one path-like argument through the overlay, preserving type."""
    redir = overlay_target(ctx, value) if isinstance(value, (str, bytes, os.PathLike)) else None
    if redir is None:
        return value, None
    if isinstance(value, os.PathLike):
        return type(value)(redir), str(value)
    if isinstance(value, bytes):
        return redir.encode("utf-8"), value.decode("utf-8", "replace")
    return redir, value


def _rewrite_paths(ctx, a, k) -> tuple[tuple, dict, list]:
    """Rewrite path-like call arguments through the overlay.

    Returns (new_args, new_kwargs, redirected) where redirected is a list
    of (original, snapshot) pairs for the audit trail.
    """
    redirected: list = []
    new_a = []
    for v in a:
        nv, orig = _redirect_value(ctx, v)
        if orig is not None:
            redirected.append((orig, nv if isinstance(nv, str) else str(nv)))
        new_a.append(nv)
    new_k = {}
    for key, v in k.items():
        if isinstance(v, (list, tuple)):
            nv_list = []
            for item in v:
                nv, orig = _redirect_value(ctx, item)
                if orig is not None:
                    redirected.append((orig, nv if isinstance(nv, str) else str(nv)))
                nv_list.append(nv)
            new_k[key] = type(v)(nv_list) if isinstance(v, tuple) else nv_list
        else:
            nv, orig = _redirect_value(ctx, v)
            if orig is not None:
                redirected.append((orig, nv if isinstance(nv, str) else str(nv)))
            new_k[key] = nv
    return tuple(new_a), new_k, redirected


def install_open_redirect(ctx) -> str:
    """Redirect read-mode stdlib opens/listings from live roots to the snapshot.

    Installed ONLY for verify replays (non-empty parent-owned overlay).
    Write-mode opens pass through untouched — the audit hook still refuses
    raw-root and snapshot writes exactly as on a live run.
    """
    if not getattr(ctx, "overlay", None):
        return "no overlay (live run)"
    import builtins as _bi
    import io as _io
    orig_open = _bi.open
    orig_io_open = _io.open
    orig_os_open = os.open
    orig_listdir = os.listdir
    orig_scandir = os.scandir

    def _resolve(path, write: bool):
        if write:
            return None
        redir = overlay_target(ctx, path)
        if redir is None:
            return None
        if not os.path.exists(redir):
            raise KernelRefusal(f"dda kernel: snapshot copy is missing for {str(path)[:200]!r}; "
                                f"re-run `dda profile` (§10.3)")
        ctx.log("open-overlay", ctx.aliases_of(path) if hasattr(ctx, "aliases_of") else [],
                path=str(path)[:300], redirected=redir[:300])
        return redir

    def guarded_open(path, *a, **k):
        mode = a[0] if a else k.get("mode", "r")
        redir = _resolve(path, _is_write_mode(mode, None))
        return orig_open(redir if redir is not None else path, *a, **k)

    def guarded_io_open(path, *a, **k):
        mode = a[0] if a else k.get("mode", "r")
        redir = _resolve(path, _is_write_mode(mode, None))
        return orig_io_open(redir if redir is not None else path, *a, **k)

    def guarded_os_open(path, flags, *a, **k):
        redir = _resolve(path, _is_write_mode(None, flags))
        return orig_os_open(redir if redir is not None else path, flags, *a, **k)

    def guarded_listdir(path=".", *a, **k):
        redir = overlay_target(ctx, path)
        if redir is not None and os.path.isdir(redir):
            ctx.log("os-list-overlay", ctx.aliases_of(path) if hasattr(ctx, "aliases_of") else [],
                    path=str(path)[:300], redirected=redir[:300])
            return orig_listdir(redir, *a, **k)
        return orig_listdir(path, *a, **k)

    def guarded_scandir(path=".", *a, **k):
        redir = overlay_target(ctx, path)
        if redir is not None and os.path.isdir(redir):
            ctx.log("os-list-overlay", ctx.aliases_of(path) if hasattr(ctx, "aliases_of") else [],
                    path=str(path)[:300], redirected=redir[:300])
            return orig_scandir(redir, *a, **k)
        return orig_scandir(path, *a, **k)

    _bi.open = guarded_open
    _io.open = guarded_io_open
    os.open = guarded_os_open
    os.listdir = guarded_listdir
    os.scandir = guarded_scandir
    return f"enforced ({len(ctx.overlay)} overlay entr{'y' if len(ctx.overlay) == 1 else 'ies'})"


# `os.*` audit events that mutate the filesystem or create links: every
# path argument is checked, because a raw root can sit on either side
# (`rename`/`replace` move a raw file away; a raw destination is a write).
_OS_MUTATE_EVENTS = frozenset({
    "os.remove", "os.unlink", "os.rmdir", "os.mkdir",
    "os.rename", "os.link", "os.symlink", "os.truncate",
})

# `os.*` audit events that only enumerate: logged on raw roots and
# snapshots (lock-gated like reads), refused under `.analysis`. `shutil`
# copies/moves/trees route through these `os.*` primitives and `open`,
# so they are covered transitively — there is no `shutil` audit event.
_OS_LIST_EVENTS = frozenset({"os.listdir", "os.scandir"})

# Spawning a subprocess would leave the containment boundary: the child
# would run without the audit hook, the wrappers, or the policy. The
# kernel is contained — spawns are refused, not merely logged — whenever
# containment is engaged (DDA_KERNEL_ACTIVE=1 in the install environment,
# which `dda run` sets for every real kernel). Gating matters because the
# hook is process-global and cannot be uninstalled: library/harness use
# of install_audit_hook in-process must not permanently contain the host.
_SPAWN_EVENTS = frozenset({
    "subprocess.Popen", "os.exec", "os.spawn", "os.posix_spawn",
    "os.fork", "os.system", "os.startfile",
})

# Set at install time from the environment (before any user code runs).
# Read dynamically by the hook so in-process test installs can disengage
# afterwards; user code cannot reach this module's globals (the bootstrap
# runs as __main__, and runpy replaces sys.modules['__main__'] with the
# user script before it executes — only gc/ctypes-level introspection
# could, which is outside the hook's bar like all native I/O).
_HOOK_STATE: dict = {"ctx": None, "installed": False, "contained": False}


def install_audit_hook(ctx: Ctx):
    """sys.addaudithook: log data-root opens and connects; refuse writes and strangers.

    Containment (no subprocesses, no `os`-level raw mutation, no
    `.analysis` enumeration) engages when DDA_KERNEL_ACTIVE=1 is present
    at install time — `dda run` sets it for every real kernel. The flag
    is captured here, before any user code runs, so user code cannot
    switch containment off by editing its own environment.

    Idempotent: a second call in one process re-points the single hook at
    the new Ctx instead of stacking a stale hook that would refuse — and
    shadow — the live one.
    """
    _HOOK_STATE["ctx"] = ctx
    if os.environ.get("DDA_KERNEL_ACTIVE") == "1":
        _HOOK_STATE["contained"] = True
    if _HOOK_STATE["installed"]:
        return {"audit_hook": "installed"}
    def hook(event, args):
        ctx = _HOOK_STATE["ctx"]
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
            write = _is_write_mode(mode, flags)
            if ctx.is_analysis(p):
                # Locked subprocess: user code may read only the entry
                # script (the parent launches it by path); every other
                # open under .analysis — reads and writes alike — is
                # refused. Evidence leaves the kernel through the IPC
                # event file, never through a direct chain append.
                if not write and hasattr(ctx, "is_script") and ctx.is_script(p):
                    return
                ctx.log("open-refused", [], path=p[:300], mode=str(mode)[:20],
                        reason="no .analysis access from inside the kernel (only the entry script, read-only)")
                raise KernelRefusal("dda kernel: .analysis is not accessible from inside the kernel "
                                    "(only the entry script, read-only)")
            aliases = ctx.aliases_of(p)
            snap = ctx.is_snapshot(p)
            if not aliases and not snap:
                return
            ctx.log("open", aliases,
                    path=p[:300], mode=str(mode)[:20], write=write,
                    snapshot=snap, refused=False)
            if not ctx.recheck():
                raise KernelRefusal(f"dda kernel: lock is not valid; data reads are refused ({aliases[0] if aliases else 'snapshot'})")
            if write and (snap or aliases and _is_raw_write(ctx, p)):
                ctx.log("open-refused", aliases,
                        path=p[:300], mode=str(mode)[:20], reason="write to raw root or snapshot")
                raise KernelRefusal(f"dda kernel: write access to raw data is refused ({aliases[0] if aliases else 'snapshot'}); "
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
        elif event in _SPAWN_EVENTS and _HOOK_STATE["contained"]:
            try:
                detail = str(args[0])[:200] if args else event
            except Exception:
                detail = event
            ctx.log("spawn", [], detail=detail, refused=True)
            raise KernelRefusal(f"dda kernel: subprocess spawn ({event}) is refused "
                                f"(contained kernel: no child processes)")
        elif event in _OS_MUTATE_EVENTS and _HOOK_STATE["contained"]:
            # `os.remove/unlink/rmdir/mkdir/rename/replace/link/symlink/
            # truncate` bypass `open` entirely (as does everything built on
            # them: `pathlib` mutation, `shutil` move/copytree). Every path
            # argument is checked — a raw root on either side of a rename
            # is a mutation of raw data.
            for raw_p in _iter_path_args(args):
                p = _decode_path(raw_p)
                if p is None:
                    continue
                if ctx.is_analysis(p):
                    ctx.log("os-refused", [], path=p[:300], op=event,
                            reason="no .analysis mutation from inside the kernel")
                    raise KernelRefusal(f"dda kernel: {event} on .analysis is refused "
                                        f"(only the entry script, read-only)")
                aliases = ctx.aliases_of(p)
                snap = ctx.is_snapshot(p)
                if not aliases and not snap:
                    continue
                ctx.log("os-refused", aliases, path=p[:300], op=event,
                        snapshot=snap, reason="mutation of raw data or snapshot")
                raise KernelRefusal(f"dda kernel: {event} on a raw root or snapshot is refused "
                                    f"({aliases[0] if aliases else 'snapshot'}); "
                                    f"write derived data to derived/ or outputs/")
        elif event in _OS_LIST_EVENTS and _HOOK_STATE["contained"]:
            # `os.listdir`/`os.scandir` (and everything built on them)
            # enumerate without `open`: logged on raw roots like reads,
            # refused under `.analysis`.
            for raw_p in _iter_path_args(args):
                p = _decode_path(raw_p)
                if p is None:
                    continue
                if ctx.is_analysis(p):
                    ctx.log("os-refused", [], path=p[:300], op=event,
                            reason="no .analysis enumeration from inside the kernel")
                    raise KernelRefusal(f"dda kernel: {event} on .analysis is refused")
                aliases = ctx.aliases_of(p)
                snap = ctx.is_snapshot(p)
                if not aliases and not snap:
                    continue
                ctx.log("os-list", aliases, path=p[:300], snapshot=snap, refused=False)
                if not ctx.recheck():
                    raise KernelRefusal(f"dda kernel: lock is not valid; data reads are refused "
                                        f"({aliases[0] if aliases else 'snapshot'})")
    sys.addaudithook(hook)
    _HOOK_STATE["installed"] = True
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
    if ctx.is_analysis(str(target)):
        if not write and hasattr(ctx, "is_script") and ctx.is_script(str(target)):
            return
        ctx.log(f"{what}-refused", [], path=str(target)[:300],
                reason="no .analysis access from inside the kernel")
        raise KernelRefusal(f"dda kernel: {what} access to .analysis refused; "
                            "only the entry script (read-only), derived data to derived/ or outputs/")
    aliases = ctx.aliases_of(str(target))
    snap = ctx.is_snapshot(str(target))
    if not aliases and not snap:
        return
    ctx.log(f"{what}-{'write' if write else 'read'}", aliases,
            path=str(target)[:300], snapshot=snap)
    if not ctx.recheck():
        raise KernelRefusal(f"dda kernel: lock is not valid; data reads are refused ({aliases[0] if aliases else 'snapshot'})")
    if write and (snap or aliases):
        raise KernelRefusal(f"dda kernel: write to raw data refused ({aliases[0] if aliases else 'snapshot'}); "
                            "write derived data to derived/ or outputs/")


def wrap_duckdb(mod, ctx: Ctx) -> str:
    """Harden duckdb: allowed_directories + no extensions/external access, locked; log + refuse writes."""
    raw_paths = [p for ps in ctx.roots.values() for p in ps]
    orig_connect = mod.connect

    def configured(con):
        dirs = list(ctx.allowed_dirs)
        if not ctx.recheck():
            dirs = [d for d in dirs if d not in raw_paths]
        # Order matters (§10.1b): allowed_directories FIRST — duckdb refuses
        # to change it once enable_external_access is false — then no
        # extensions, then no external access, then freeze everything.
        quoted = ", ".join("'" + d.replace("'", "''") + "'" for d in sorted(set(dirs)) if d)
        if quoted:
            con.execute(f"SET allowed_directories = [{quoted}]")
        con.execute("SET autoinstall_known_extensions = false")
        con.execute("SET autoload_known_extensions = false")
        con.execute("SET enable_external_access = false")
        con.execute("SET lock_configuration = true")
        return con

    def _guard_result(res):
        # execute/executemany/cursor always hand back a live connection, so
        # the result is always re-wrapped (an unguarded handle would let the
        # very next call bypass the scan). Data results (sql/query relations)
        # never pass through here.
        if isinstance(res, GuardedCon):
            return res
        return GuardedCon(res)

    def scan_sql(sql: str) -> str:
        out = sql
        for m in reversed(list(re.finditer(r"'((?:[^'\\]|\\.|'')+)'", sql))):
            cand = m.group(1)
            if "/" in cand or "\\" in cand or cand.lower().endswith((".csv", ".parquet", ".json", ".db", ".duckdb")):
                aliases = ctx.aliases_of(cand)
                if aliases or ctx.is_snapshot(cand):
                    ctx.log("duckdb-read", aliases, statement=sql[:300])
                redir = overlay_target(ctx, cand)
                if redir is not None:
                    ctx.log("duckdb-overlay", ctx.aliases_of(cand), statement=cand[:300],
                            redirected=redir[:300])
                    out = out[:m.start(1)] + redir.replace("'", "''") + out[m.end(1):]
        up = sql.upper()
        if re.search(r"\b(COPY\s+.*\s+TO|EXPORT\s+DATABASE|ATTACH)\b", up):
            for m in re.finditer(r"TO\s+'((?:[^'\\]|\\.|'')+)'", sql, re.IGNORECASE):
                tgt = m.group(1)
                if ctx.aliases_of(tgt) or ctx.is_snapshot(tgt):
                    raise KernelRefusal("dda kernel: COPY TO / EXPORT / ATTACH onto a raw root or snapshot "
                                        "is refused (duckdb cannot make one directory read-only)")
            if re.search(r"\bATTACH\s+'", up):
                for m in re.finditer(r"ATTACH\s+'((?:[^'\\]|\\.|'')+)'", sql, re.IGNORECASE):
                    tgt = m.group(1)
                    if ctx.aliases_of(tgt) or ctx.is_snapshot(tgt):
                        raise KernelRefusal("dda kernel: ATTACH of a raw-root or snapshot file is refused")
        return out

    class GuardedCon:
        """A duckdb connection whose every query entry point is scanned.

        `execute` returns the live connection, so the result is re-wrapped:
        an unguarded handle would let the very next `.execute` bypass the
        scan. Same for `cursor`; `sql`/`query` results are data, but their
        SQL argument is still scanned.
        """
        def __init__(self, inner):
            self._inner = inner

        def execute(self, sql, *a, **k):
            if isinstance(sql, str):
                sql = scan_sql(sql)
            return _guard_result(self._inner.execute(sql, *a, **k))

        def executemany(self, sql, *a, **k):
            if isinstance(sql, str):
                sql = scan_sql(sql)
            return _guard_result(self._inner.executemany(sql, *a, **k))

        def sql(self, sql, *a, **k):
            if isinstance(sql, str):
                sql = scan_sql(sql)
            return self._inner.sql(sql, *a, **k)

        def query(self, sql, *a, **k):
            if isinstance(sql, str):
                sql = scan_sql(sql)
            return self._inner.query(sql, *a, **k)

        def cursor(self, *a, **k):
            # The cursor inherits the parent connection's locked-down
            # settings; only the query surface needs guarding.
            return _guard_result(self._inner.cursor(*a, **k))

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
                    na, nk, redirected = _rewrite_paths(ctx, a, k)
                    for orig, snap in redirected:
                        ctx.log("duckdb-overlay", ctx.aliases_of(orig), statement=str(orig)[:300],
                                redirected=str(snap)[:300])
                    src = nk.get("path") or nk.get("file") or (na[0] if na else None)
                    if src is not None:
                        _check_local(ctx, src, write=False, what="duckdb")
                    return o(*na, **nk)
                return reader
            setattr(mod, name, _mk_reader(orig))
    return "enforced"


def _path_candidates(a, k) -> list:
    """Every argument that could be a path: all positionals, the known
    path keywords, and any other str/PathLike keyword (one list level
    flattened). Writers often take the destination SECOND
    (e.g. `pyarrow.parquet.write_table(table, where)`), so checking only
    the first argument would let a raw-root write sail through."""
    cands: list = list(a)
    for key in ("source", "file", "path", "uri", "where", "base_dir", "output",
                "output_file", "sink"):
        if key in k and k[key] is not None:
            cands.append(k[key])
    for key, val in k.items():
        if val is not None and val not in cands:
            cands.append(val)
    flat: list = []
    for c in cands:
        if isinstance(c, (list, tuple)):
            flat.extend(c)
        else:
            flat.append(c)
    return [c for c in flat if isinstance(c, (str, os.PathLike))]


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
                na, nk, redirected = _rewrite_paths(ctx, a, k)
                for orig, snap in redirected:
                    ctx.log(f"{what}-overlay", ctx.aliases_of(orig), path=str(orig)[:300],
                            redirected=str(snap)[:300])
                for src in _path_candidates(na, nk):
                    _check_local(ctx, src, write=False, what=what)
                return o(*na, **nk)
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
                for dst in _path_candidates(a, k):
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
        n += _wrap_writer(mod, ("parquet.write_table", "parquet.write_to_dataset",
                                 "parquet.ParquetWriter"), ctx, "pyarrow")
    except Exception:
        pass
    n += _wrap_first_arg(mod, ("dataset.dataset", "csv.read_csv", "csv.open_csv", "feather.read_table",
                              "feather.read_feather"), ctx, "pyarrow")
    n += _wrap_writer(mod, ("dataset.write_dataset", "csv.write_csv", "feather.write_feather",
                           "ipc.new_file"), ctx, "pyarrow")
    n += _wrap_pyarrow_fs(mod, ctx)
    return f"enforced ({n} entry points)"


def _wrap_pyarrow_fs(mod, ctx: Ctx) -> int:
    """Wrap the `pyarrow.fs` remote filesystem constructors (§10.1b).

    `FileSystem.from_uri` carries the full URI, so its host is checked
    exactly like any other remote target. The bare remote constructors
    (`S3FileSystem()`, `GcsFileSystem()`, ...) take no uniform host
    argument, so they are logged as detect-only: the kernel audit hook
    cannot see native sockets, and reads through them appear only here.
    """
    try:
        fs = mod.fs
    except AttributeError:
        try:
            from pyarrow import fs as fs  # noqa: F401
        except Exception:
            return 0
    wrapped = 0
    from_uri = getattr(fs, "FileSystem", None)
    from_uri = getattr(from_uri, "from_uri", None) if from_uri is not None else None
    if callable(from_uri):
        orig = from_uri

        def guarded_from_uri(uri, *a, **k):
            _refuse_remote(ctx, uri)
            ctx.log("pyarrow-read", [], path=str(uri)[:300])
            return orig(uri, *a, **k)

        fs.FileSystem.from_uri = staticmethod(guarded_from_uri)
        wrapped += 1
    for cls_name in ("S3FileSystem", "GcsFileSystem", "HadoopFileSystem", "HdfsFileSystem",
                     "HttpFileSystem", "AzureBlobFileSystem"):
        cls = getattr(fs, cls_name, None)
        if cls is None:
            continue
        orig_init = cls.__init__

        def _mk_init(o, name=cls_name):
            def __init__(self, *a, **k):
                ctx.log("pyarrow-fs", [], filesystem=name,
                        note="remote filesystem constructor (detect-only: native I/O)")
                o(self, *a, **k)
            return __init__

        try:
            cls.__init__ = _mk_init(orig_init)
            wrapped += 1
        except (TypeError, AttributeError):
            continue
    return wrapped


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
    path = os.environ.get(IPC_STATUS_ENV) or os.environ.get(STATUS_ENV)
    if not path:
        return
    tmp = path + f".{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def boot_ipc() -> tuple[PolicyCtx, dict]:
    """Boot the locked subprocess from the parent's frozen policy file.

    No Workdir, no lock, no ledger reads: everything the kernel needs is
    in the policy snapshot. Refuses to run user code when the policy
    file is absent or unreadable."""
    from ddalib import kernel as _k
    ppath = os.environ.get(POLICY_ENV) or ""
    try:
        with open(ppath, encoding="utf-8") as fh:
            policy = json.load(fh)
    except (OSError, ValueError, TypeError):
        raise SystemExit("dda kernel: no policy snapshot from the parent; refusing to run")
    if not isinstance(policy, dict) or not policy.get("run_id"):
        raise SystemExit("dda kernel: policy snapshot is invalid; refusing to run")
    # Baseline stubs (tests/harness) arrive ONLY here, in the
    # parent-written policy — never from the child environment, which the
    # parent strips (a user-controlled stub dir must not shadow the stack).
    baseline_dir = policy.get("baseline_dir") or ""
    if baseline_dir:
        if not isinstance(baseline_dir, str) or not os.path.isdir(baseline_dir):
            raise SystemExit("dda kernel: policy baseline_dir is invalid; refusing to run")
        sys.path.insert(0, baseline_dir)
    ctx = PolicyCtx(policy)
    status: dict = {"python": sys.version.split()[0], "ok": True, "ipc": True,
                    "run_id": policy.get("run_id")}
    status.update(install_audit_hook(ctx))
    versions, missing = _k.baseline_versions()
    status["baseline"] = versions
    if missing:
        status["ok"] = False
        status["missing_baseline"] = missing
    status["wrappers"] = apply_wrappers(ctx)
    status["snapshot_overlay"] = install_open_redirect(ctx)
    unenforced = [lib for lib, st in status["wrappers"].items()
                  if st.startswith(("not-installed", "wrap-failed"))]
    status["network_policy"] = ("detect-only (unenforced native path: " + ", ".join(unenforced) + ")"
                                if unenforced else "audit+wrapper-enforced")
    seed = int(policy.get("seed") or 0)
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
    ky = policy.get("kernel_yaml")
    status["environment_hash"] = _k.environment_hash(
        versions, ky.encode("utf-8") if isinstance(ky, str) else None)
    write_status(status)
    return ctx, status


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
    status["snapshot_overlay"] = install_open_redirect(ctx)
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
    # `-I` ignores PYTHONUTF8, so pin stdio to UTF-8 here: the parent reads
    # the tails as UTF-8 and the status JSON must be exact bytes.
    for fh in (sys.stdout, sys.stderr):
        try:
            fh.reconfigure(encoding="utf-8", errors="backslashreplace")
        except Exception:
            pass
    if argv[:1] == ["--self-test"]:
        return self_test()
    if argv[:1] == ["--check-baseline"]:
        # Parent-owned baseline preflight: `dda run` executes this in an
        # isolated interpreter with the exact child env BEFORE spawning the
        # real kernel, so the parent — not the child's status file — owns
        # the baseline verdict in the kernel record. Optional argv[1] is a
        # parent-supplied stub dir ("-" or absent = none); unlike the old
        # DDA_BASELINE_DIR channel this arrives on argv, which user code
        # cannot control.
        stub_dir = argv[1] if len(argv) > 1 else ""
        if stub_dir and stub_dir != "-":
            if not os.path.isdir(stub_dir):
                print(json.dumps({"ok": False, "error": f"stub dir is missing: {stub_dir}"}))
                return 7
            sys.path.insert(0, stub_dir)
        from ddalib import kernel as _k
        versions, missing = _k.baseline_versions()
        print(json.dumps({"ok": not missing, "versions": versions, "missing": missing}))
        return 0 if not missing else 7
    if not argv:
        print("usage: python -I -P <scripts>/ddalib/kernel_bootstrap.py <script> [args...]", file=sys.stderr)
        return 2
    if os.environ.get(POLICY_ENV):
        ctx, status = boot_ipc()
    else:
        ctx, status = boot()
    if not status.get("ok"):
        print(f"dda kernel does not start: missing baseline packages: "
              f"{', '.join(status.get('missing_baseline') or [])} (§10.1a)", file=sys.stderr)
        return 7
    script = os.path.abspath(argv[0])
    sys.argv = [script, *argv[1:]]
    # NOTE: the script's directory is deliberately NOT added to sys.path.
    # The locked subprocess is a single entry script: any other file under
    # .analysis is unreadable through the open hook, so a sibling import
    # could never succeed — and inserting the dir would make the import
    # system's own sys.path scans (os.listdir per path entry) trip the
    # .analysis enumeration refusal for every script that imports anything.
    ctx.log("kernel-start", ctx.aliases, script=script, via_ipc=True)
    try:
        runpy.run_path(script, run_name="__main__")
    finally:
        ctx.log("kernel-stop", ctx.aliases, script=script, via_ipc=True)
    return 0


# ---------- self-test (no workdir needed) ----------

def self_test() -> int:
    """Exercise the audit hook + wrappers against synthetic roots and stub modules."""
    import tempfile
    # Self-test runs in its own process: engage containment exactly like a
    # real kernel (`dda run` sets this for every child).
    os.environ["DDA_KERNEL_ACTIVE"] = "1"
    checks: dict[str, object] = {}
    tmp = Path(tempfile.mkdtemp(prefix="dda-kernel-test-"))
    raw = tmp / "raw"
    raw.mkdir()
    (raw / "orders.csv").write_text("id,amount\n1,10\n", encoding="utf-8")
    analysis = tmp / ".analysis"
    analysis.mkdir()
    (analysis / "ledger.md").write_text("# ledger\n", encoding="utf-8")
    audit_p = analysis / "audit.log"
    audit_p.write_text("", encoding="utf-8")
    (analysis / "variants").mkdir(exist_ok=True)
    (analysis / "variants" / "v1.py").write_text("x = 1\n", encoding="utf-8")
    status_p = analysis / ".kernel-test.json"
    events: list[dict] = []

    class FakeCtx:
        variant, run_id, session = "v1", "r1", "test"
        roots = {"sales": [canon(str(raw))], "sales2": [canon(str(raw))]}
        hosts = {"db.example.internal"}
        snapshots = canon(str(tmp / "snaps"))
        allowed_dirs = [canon(str(raw))]
        analysis_dir = canon(str(analysis))
        script = canon(str(analysis / "variants" / "v1.py"))

        def __init__(self):
            self._valid = True

        def aliases_of(self, path):
            c = canon(path, os.getcwd())
            if c and under(c, canon(str(raw))):
                return ["sales", "sales2"]
            return []

        def alias_of(self, path):
            found = self.aliases_of(path)
            return found[0] if found else None

        def is_analysis(self, path):
            c = canon(path, os.getcwd())
            return bool(c and (c == self.analysis_dir or under(c, self.analysis_dir)))

        def is_script(self, path):
            c = canon(path, os.getcwd())
            return bool(c and self.script and c == self.script)

        def is_evidence_exempt(self, path):
            return False

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
    # Every alias covering a path is logged, not just the first.
    logged = [e for e in events if e["event"] == "open" and not e.get("write")]
    checks["all-aliases-logged"] = bool(logged) and logged[-1]["aliases"] == ["sales", "sales2"]
    # Runtime-built path (string concatenation, the §0.1 limit for string-match hooks).
    p = str(raw) + "/" + "orders" + ".csv"
    ok, _ = tried(lambda: open(p, "a"))
    checks["constructed-path-refused"] = not ok
    outside = tmp / "elsewhere.txt"
    ok, _ = tried(lambda: open(outside, "w"))
    checks["outside-raw-allowed"] = ok
    # Locked subprocess: user code may read only the entry script;
    # every other open under .analysis — reads and writes alike — is
    # refused (status and audit traffic leave via the IPC directory
    # outside the workdir).
    ok, _ = tried(lambda: open(analysis / "ledger.md").read())
    checks["evidence-read-refused"] = (not ok) and any(
        e["event"] == "open-refused" and "analysis" in str(e.get("reason", "")) for e in events)
    script_p = analysis / "variants" / "v1.py"
    ok, _ = tried(lambda: open(script_p).read())
    checks["script-read-allowed"] = ok
    ok, _ = tried(lambda: open(script_p, "w"))
    checks["script-write-refused"] = (not ok) and any(
        e["event"] == "open-refused" and "analysis" in str(e.get("reason", "")) for e in events)
    ok, _ = tried(lambda: open(analysis / "ledger.md", "a"))
    checks["evidence-write-refused"] = (not ok) and any(
        e["event"] == "open-refused" and "analysis" in str(e.get("reason", "")) for e in events)
    ok, _ = tried(lambda: open(audit_p, "a"))
    checks["audit-append-refused"] = (not ok) and any(
        e["event"] == "open-refused" and "analysis" in str(e.get("reason", "")) for e in events)
    ok, _ = tried(lambda: open(status_p, "w"))
    checks["status-write-refused"] = (not ok) and any(
        e["event"] == "open-refused" and "analysis" in str(e.get("reason", "")) for e in events)
    import socket as _sock
    ok, _ = tried(lambda: _sock.socket().connect(("169.254.169.254", 80)))
    checks["strange-host-refused"] = not ok
    logged_hosts = [e for e in events if e["event"] == "socket-connect"]
    checks["connect-logged"] = bool(logged_hosts)
    # `os`-level mutation bypasses `open` entirely and must be refused on
    # raw roots, snapshots and .analysis — on EITHER side of a rename
    # (moving a raw file away mutates raw data; a raw destination is a
    # write). `shutil`/`pathlib` mutation routes through these same
    # primitives, so it is covered transitively.
    import shutil as _shutil
    Victim = raw / "orders.csv"
    ok, _ = tried(lambda: os.remove(Victim))
    checks["os-remove-raw-refused"] = (not ok) and any(
        e["event"] == "os-refused" for e in events)
    ok, _ = tried(lambda: os.rename(Victim, tmp / "moved.csv"))
    checks["os-rename-away-raw-refused"] = not ok
    ok, _ = tried(lambda: os.rename(tmp / "elsewhere.txt", raw / "planted.csv"))
    checks["os-rename-into-raw-refused"] = not ok
    ok, _ = tried(lambda: os.replace(Victim, tmp / "moved2.csv"))
    checks["os-replace-raw-refused"] = not ok
    ok, _ = tried(lambda: os.mkdir(raw / "newdir"))
    checks["os-mkdir-raw-refused"] = not ok
    ok, _ = tried(lambda: os.rmdir(raw))
    checks["os-rmdir-raw-refused"] = not ok
    ok, _ = tried(lambda: os.truncate(str(Victim), 1))
    checks["os-truncate-raw-refused"] = not ok
    ok, _ = tried(lambda: os.link(str(Victim), str(tmp / "hardlink.csv")))
    checks["os-link-raw-refused"] = not ok
    ok, _ = tried(lambda: os.symlink(str(Victim), str(tmp / "link.csv")))
    checks["os-symlink-raw-refused"] = not ok
    ok, _ = tried(lambda: _shutil.copy(str(Victim), str(raw / "copy.csv")))
    checks["shutil-copy-onto-raw-refused"] = not ok
    ok, _ = tried(lambda: os.remove(analysis / "ledger.md"))
    checks["os-remove-analysis-refused"] = not ok
    ok, _ = tried(lambda: os.rename(str(outside), str(analysis / "planted.txt")))
    checks["os-rename-into-analysis-refused"] = not ok
    # Enumeration without `open`: logged on raw roots (lock-gated like
    # reads), refused under .analysis, silent elsewhere.
    ok, _ = tried(lambda: os.listdir(raw))
    checks["os-listdir-raw-logged"] = ok and any(
        e["event"] == "os-list" and "sales" in e.get("aliases", []) for e in events)
    ok, _ = tried(lambda: os.scandir(raw))
    checks["os-scandir-raw-logged"] = ok and any(e["event"] == "os-list" for e in events)
    ok, _ = tried(lambda: os.listdir(analysis))
    checks["os-listdir-analysis-refused"] = not ok
    ctx._valid = False
    ok, _ = tried(lambda: os.listdir(raw))
    checks["os-listdir-raw-invalid-lock-refused"] = not ok
    ctx._valid = True
    n_ev = len(events)
    ok, _ = tried(lambda: os.listdir(tmp))
    checks["os-listdir-outside-allowed"] = ok and not any(
        e["event"] in ("os-list", "os-refused") for e in events[n_ev:])
    # Spawn containment: the kernel has no child processes — a subprocess
    # would run without the hook, the wrappers, or the policy. Refused,
    # not merely logged.
    import subprocess as _sp
    ok, _ = tried(lambda: _sp.Popen([sys.executable, "-c", "pass"]))
    checks["spawn-popen-refused"] = (not ok) and any(
        e["event"] == "spawn" and e.get("refused") for e in events)
    ok, _ = tried(lambda: os.system("exit 0"))
    checks["spawn-system-refused"] = not ok

    # Wrapper unit checks against stub modules (no real duckdb/polars needed).
    class StubCon:
        def __init__(self):
            self.sets = []

        def execute(self, sql, *a, **k):
            self.sets.append(sql)
            return self

        def executemany(self, sql, *a, **k):
            self.sets.append(sql)
            return self

        def cursor(self, *a, **k):
            return StubCon()

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
    needed = ("allowed_directories", "autoinstall_known_extensions", "autoload_known_extensions",
              "enable_external_access", "lock_configuration")
    checks["duckdb-lockdown-sets"] = all(s in sets for s in needed)
    # Spec order: allowed_directories first (duckdb rejects changing it
    # after enable_external_access=false), lock last so it freezes all.
    checks["duckdb-set-order"] = (
        sets.index("allowed_directories") < sets.index("enable_external_access")
        < sets.index("lock_configuration"))
    ok, _ = tried(lambda: gcon.execute("COPY (SELECT 1) TO '" + str(raw / "out.csv") + "'"))
    checks["duckdb-copy-to-raw-refused"] = not ok
    # Every query surface is scanned: the connection execute() returns, the
    # cursor, executemany, and the module-level sql/query shims.
    ok, _ = tried(lambda: gcon.execute("SELECT 1").execute(
        "COPY (SELECT 1) TO '" + str(raw / "out2.csv") + "'"))
    checks["duckdb-chained-execute-scanned"] = not ok
    ok, _ = tried(lambda: gcon.cursor().execute(
        "COPY (SELECT 1) TO '" + str(raw / "out3.csv") + "'"))
    checks["duckdb-cursor-scanned"] = not ok
    ok, _ = tried(lambda: gcon.executemany("COPY (SELECT 1) TO '" + str(raw / "out4.csv") + "'", []))
    checks["duckdb-executemany-scanned"] = not ok

    class StubPl:
        def read_csv(self, src, **k):
            return ("read", str(src))

    stubpl = StubPl()
    wrap_polars(stubpl, ctx)
    ok, _ = tried(lambda: stubpl.read_csv(raw / "orders.csv"))
    checks["polars-read-logged"] = ok and any(e["event"] == "polars-read" for e in events)

    class StubPa:
        class parquet:
            @staticmethod
            def write_table(table, where, **k):
                return ("wrote", str(where))

            @staticmethod
            def read_table(source, **k):
                return ("read", str(source))

    stubpa = StubPa()
    n_pa = 0
    n_pa += _wrap_first_arg(stubpa, ("parquet.read_table",), ctx, "pyarrow")
    n_pa += _wrap_writer(stubpa, ("parquet.write_table",), ctx, "pyarrow")
    # The destination is the SECOND positional (table, where): a
    # first-arg-only check would miss it and let a raw write through.
    ok, _ = tried(lambda: stubpa.parquet.write_table("TABLE", raw / "out.parquet"))
    checks["writer-second-arg-refused"] = (not ok) and any(
        e["event"] == "pyarrow-write" for e in events)
    ok, _ = tried(lambda: stubpa.parquet.read_table(raw / "orders.csv"))
    checks["reader-second-arg-logged"] = ok and any(
        e["event"] == "pyarrow-read" for e in events)
    # pyarrow.fs remote constructors: from_uri is host-checked, the bare
    # remote constructors are logged detect-only.
    class FakeFS:
        class FileSystem:
            @staticmethod
            def from_uri(uri, *a, **k):
                return ("fs", uri)

        class S3FileSystem:
            def __init__(self, *a, **k):
                pass

    class StubPaFs:
        fs = FakeFS()

    n_fs = _wrap_pyarrow_fs(StubPaFs(), ctx)
    ok, _ = tried(lambda: FakeFS.FileSystem.from_uri("s3://evil.example/x"))
    checks["pyarrow-from-uri-refused"] = not ok
    n_ev = len(events)
    FakeFS.S3FileSystem()
    checks["pyarrow-fs-logged"] = any(e["event"] == "pyarrow-fs" for e in events[n_ev:]) and n_fs >= 2

    results = {"checks": checks, "events": len(events)}
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
