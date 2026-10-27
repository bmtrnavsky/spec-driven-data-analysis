"""Sanctioned data path (spec §3.3, §4.3, §10, §14 item 3).

After lock, data flows only through `dda run` (the kernel) and declared
connector tools (§6.1); before lock, `dda meta <alias>` is the only allowed
data-root access (§3.3). Variants are registered with `dda variant`, frozen
on first run, and the G6 gate fails orphan runs (data reads with no
registered variant id).

specs-tried.jsonl entry types used here (all hash-chained via ddalib.chain):
  {"type": "variant", ...}        registration: id, parent, variant key, header, why, label
  {"type": "freeze", ...}         first run: variant id + script body hash (evidenceguard reads this)
  {"type": "run", ...}            every kernel execution: variant, run id, body hash, kernel record
  {"type": "variant-locked", ...} the reported (locked) variant id

Stdlib only. Everything fails closed: unknown alias, missing lock, invalid
lock, unregistered variant, or a changed script body is an error, never a
silent pass.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path

from . import chain, ledger, lockstate
from .layout import ALIAS_RE, DdaError, Workdir, load_config, read_text_lf

# Required baseline data stack, always installed and pinned (§10.1a).
# `sklearn` is the import name for scikit-learn; everything else imports
# under its distribution name.
BASELINE = ("pandas", "numpy", "pyarrow", "polars", "duckdb", "scipy", "statsmodels", "sklearn",
            "matplotlib", "seaborn", "openpyxl", "xlrd", "ipykernel", "IPython", "jupyter_client")

# Structured variant header fields (§4.3). A change to any field is a new variant.
HEADER_FIELDS = ("population", "window", "filters", "cuts", "model", "outlier_rule", "definitions")

VARIANT_LABELS = ("exploratory", "post-data-locked", "locked")

# Closed local port for the proxy belt (§10.1b): refused, never routed.
DEAD_PROXY = "http://127.0.0.1:9"

RUN_SCRIPT_SUFFIXES = (".py", ".sql")


def variant_key(header: dict) -> str:
    """Mechanical variant identity: SHA-256 over sorted `field=value` lines (§4.3)."""
    lines = [f"{k}={header[k]}" for k in sorted(header)]
    return hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()


def tried_records(wd: Workdir) -> list[dict]:
    return chain.read_records(ledger.specs_tried(wd))


def registrations(wd: Workdir) -> dict[str, dict]:
    regs: dict[str, dict] = {}
    for rec in tried_records(wd):
        if rec.get("type") == "variant" and isinstance(rec.get("variant"), str):
            regs.setdefault(rec["variant"], rec)
    return regs


def find_registration(wd: Workdir, vid: str) -> dict | None:
    return registrations(wd).get(vid)


def frozen_hash(wd: Workdir, vid: str) -> str | None:
    for rec in tried_records(wd):
        if rec.get("type") == "freeze" and rec.get("variant") == vid and rec.get("frozen_hash"):
            return rec["frozen_hash"]
    return None


def run_entries(wd: Workdir, vid: str | None = None) -> list[dict]:
    out = [r for r in tried_records(wd) if r.get("type") == "run"]
    return [r for r in out if vid is None or r.get("variant") == vid] if vid else out


def locked_variant_id(wd: Workdir) -> str | None:
    locked = None
    for rec in tried_records(wd):
        if rec.get("type") == "variant-locked" and isinstance(rec.get("variant"), str):
            locked = rec["variant"]
    return locked


def _require_lock(wd: Workdir) -> dict:
    lock = lockstate.read_lock(wd)
    if not lock:
        raise DdaError("no lock yet: lock the spec (`dda lock`) before registering a variant")
    return lock


def _check_vid(vid: str) -> None:
    if not vid or not ALIAS_RE.match(vid):
        raise DdaError(f"invalid variant id {vid!r} (lowercase, digits, - and _)")


def register_variant(wd: Workdir, vid: str, *, parent: str | None = None, why: str,
                     label: str | None, header: dict) -> dict:
    """Register a variant (writes specs-tried + ledger). A changed header is a new id."""
    _check_vid(vid)
    if parent:
        _check_vid(parent)
    if not (why or "").strip():
        raise DdaError("a variant needs a reason (`--why`; G6 requires a ledger entry with a reason, §4.3)")
    unknown = sorted(set(header) - set(HEADER_FIELDS))
    if unknown:
        raise DdaError(f"unknown header field(s): {', '.join(unknown)} (allowed: {', '.join(HEADER_FIELDS)})")
    if not header:
        raise DdaError(f"empty header: set at least one of {', '.join(HEADER_FIELDS)} (`--set field=value`)")
    if label is None:
        lock = _require_lock(wd)
        label = "post-data-locked" if str(lock.get("label", "")).startswith("post-data") else "exploratory"
    if label not in VARIANT_LABELS:
        raise DdaError(f"invalid label {label!r} (one of: {', '.join(VARIANT_LABELS)})")
    _require_lock(wd)
    if parent and not find_registration(wd, parent):
        raise DdaError(f"unknown parent variant {parent!r} (register it first, or omit --parent)")
    key = variant_key(header)
    existing = find_registration(wd, vid)
    if existing:
        if existing.get("variant_key") != key:
            raise DdaError(f"variant {vid!r} is already registered with a different header "
                           f"(key {existing.get('variant_key', '')[:12]}); a changed header is a new variant id")
        return existing
    if frozen_hash(wd, vid):
        raise DdaError(f"variant {vid!r} already ran and is frozen")
    parent_header = (find_registration(wd, parent) or {}).get("header") or {} if parent else {}
    diff = sorted(k for k in set(header) | set(parent_header) if header.get(k) != parent_header.get(k))
    rec = {"type": "variant", "variant": vid, "parent": parent, "variant_key": key, "header": header,
           "header_diff": diff, "why": why.strip(), "label": label, "output": None}
    stored = chain.append(ledger.specs_tried(wd), rec)
    chain.append(ledger.ledger_path(wd), {"type": "variant-registered", "variant": vid, "why": why.strip(),
                                         "label": label, "variant_key": key[:16]})
    return stored


def mark_locked(wd: Workdir, vid: str) -> dict:
    """Mark the reported (locked) variant. Verify replays this one (G7)."""
    _check_vid(vid)
    if not find_registration(wd, vid):
        raise DdaError(f"unknown variant {vid!r} (register it with `dda variant` first)")
    _require_lock(wd)
    stored = chain.append(ledger.specs_tried(wd), {"type": "variant-locked", "variant": vid})
    chain.append(ledger.ledger_path(wd), {"type": "variant-locked", "variant": vid})
    return stored


# ---------- dda meta (§3.3) ----------

_CSV_SUFFIXES = {".csv", ".tsv", ".txt"}
_META_READ_CAP = 1 << 20  # 1 MiB: enough for header + type sniffing, never dumped


def _infer_types(rows: list[list[str]], ncols: int) -> list[str]:
    kinds = []
    for c in range(ncols):
        vals = [r[c].strip() for r in rows if c < len(r) and r[c].strip() not in ("", "NA", "NaN", "NULL", "null")]
        if not vals:
            kinds.append("unknown")
            continue
        try:
            for v in vals:
                int(v)
            kinds.append("integer")
            continue
        except ValueError:
            pass
        try:
            for v in vals:
                float(v)
            kinds.append("number")
            continue
        except ValueError:
            pass
        kinds.append("string")
    return kinds


def _csv_meta(path: Path) -> list[str]:
    """Header names, row count, inferred column types. Values are read but never returned."""
    import csv
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as fh:
            sample = fh.read(_META_READ_CAP)
    except (OSError, UnicodeDecodeError):
        return ["unreadable as text (size and mtime only)"]
    lines = sample.splitlines()
    if not lines:
        return ["empty file: 0 columns, 0 rows"]
    try:
        dialect = csv.Sniffer().sniff(lines[0] + ("\n" + lines[1] if len(lines) > 1 else ""))
    except Exception:
        dialect = csv.excel
    try:
        rows = list(csv.reader(lines, dialect))
    except Exception:
        return ["unparseable header (size and mtime only)"]
    if not rows:
        return ["empty file: 0 columns, 0 rows"]
    header, data = rows[0], rows[1:1001]
    ncols = len(header)
    try:
        with open(path, "rb") as fh:
            total_nl = sum(chunk.count(b"\n") for chunk in iter(lambda: fh.read(65536), b""))
    except OSError:
        total_nl = len(lines)
    types = _infer_types(data, ncols)
    out = [f"table {path.name}: {ncols} columns, ~{max(total_nl - 1, 0)} rows"]
    for name, typ in zip(header, types):
        out.append(f"  column {(name or '?')[:80]}: {typ}")
    if len(header) != len(set(header)):
        out.append("  (duplicate column names present)")
    return out


def _file_meta(path: Path) -> list[str]:
    try:
        st = path.stat()
    except OSError as exc:
        return [f"{path.name}: unreadable ({exc.strerror or exc})"]
    head = [f"{path.name}: {st.st_size} bytes, mtime {time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(st.st_mtime))}"]
    if path.suffix.lower() in _CSV_SUFFIXES:
        head += _csv_meta(path)
    elif path.suffix.lower() in (".parquet", ".pq", ".feather", ".arrow", ".ipc"):
        head += ["column listing needs pyarrow (not run by `dda meta`; see `dda run`)"]
    elif path.suffix.lower() in (".xls", ".xlsx", ".ods"):
        head += ["sheet listing needs openpyxl (not run by `dda meta`; see `dda run`)"]
    return head


def do_meta(wd: Workdir, alias: str, *, session: str = "") -> tuple[str, dict]:
    """Metadata only: names, sizes, mtimes, column names/types, row counts. No values, ever."""
    wd.require_initialized()
    cfg = load_config(wd)
    if alias not in cfg["data_roots"]:
        raise DdaError(f"unknown alias {alias!r} (declared: {', '.join(sorted(cfg['data_roots'])) or 'none'})")
    loc = cfg["data_roots"][alias]
    lines = [f"metadata for alias '{alias}' (names, types, counts — no values, §3.3):"]
    for p in loc.get("paths") or []:
        base = Path(p if os.path.isabs(p) else str(wd.root / p))
        if base.is_dir():
            entries = sorted(base.iterdir())
            lines.append(f"path {p}: directory, {len(entries)} entr(ies)")
            for e in entries[:200]:
                if e.is_file():
                    lines += ["  " + l for l in _file_meta(e)]
                else:
                    lines.append(f"  {e.name}/: subdirectory")
            if len(entries) > 200:
                lines.append(f"  ... and {len(entries) - 200} more (listing truncated)")
        elif base.is_file():
            lines.append(f"path {p}: file")
            lines += ["  " + l for l in _file_meta(base)]
        else:
            lines.append(f"path {p}: not found from here (declared locator only)")
    for h in loc.get("hosts") or []:
        lines.append(f"host {h}: declared locator (no fetch; use `dda run` with a connector)")
    for u in loc.get("url_prefixes") or []:
        lines.append(f"url {u}: declared locator (no fetch; use `dda run` with a connector)")
    for t in loc.get("tool_patterns") or []:
        lines.append(f"connector {t}: declared tool pattern (queries run through `dda run` or the tool)")
    text = "\n".join(lines) + "\n"
    rec = {"type": "done", "session": session, "tool": "dda", "subcommand": "meta",
           "call": None, "aliases": [alias], "kind": "meta", "variant": None}
    stored = chain.append(ledger.runs_log(wd), rec)
    return text, stored


# ---------- dda run (§10) ----------

def baseline_versions() -> tuple[dict[str, str | None], list[str]]:
    """Import every baseline package; a missing or unimportable one fails the start (§10.1a).

    The check is importability, exactly as the spec words it. The recorded
    version comes from the installed distribution metadata, or "unknown"
    when a package imports but ships none.
    """
    import importlib
    versions: dict[str, str | None] = {}
    for pkg in BASELINE:
        try:
            importlib.import_module(pkg)
        except Exception:
            versions[pkg] = None
            continue
        try:
            versions[pkg] = importlib.metadata.version(pkg if pkg != "sklearn" else "scikit-learn")
        except importlib.metadata.PackageNotFoundError:
            versions[pkg] = "unknown"
    missing = sorted(p for p, v in versions.items() if v is None)
    return versions, missing


def environment_hash(versions: dict[str, str | None], kernel_yaml: bytes | None) -> str:
    lines = [f"{p}=={versions.get(p) or 'missing'}" for p in sorted(versions)]
    lines.append(f"python={sys.version.split()[0]}")
    lines.append(f"kernel.yaml={'sha256:' + hashlib.sha256(kernel_yaml).hexdigest() if kernel_yaml is not None else 'absent'}")
    return hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()


def _default_seed(lock_hash: str, vid: str) -> int:
    return int(hashlib.sha256(f"{lock_hash}:{vid}".encode()).hexdigest()[:8], 16)


def _variant_script(wd: Workdir, vid: str, script: str) -> tuple[Path, str]:
    if not script:
        raise DdaError("no script given: `dda run --variant <id> variants/<id>.py`")
    sp = Path(os.path.abspath(script))
    allowed = {str((wd.analysis / "variants" / f"{vid}{s}").resolve()) for s in RUN_SCRIPT_SUFFIXES}
    try:
        resolved = str(sp.resolve())
    except OSError:
        raise DdaError(f"script not found: {script}") from None
    if resolved not in allowed:
        raise DdaError(f"variant {vid!r} must run its frozen script "
                       f"(.analysis/variants/{vid}.py|sql), not {script} (§4.3)")
    if sp.suffix not in RUN_SCRIPT_SUFFIXES or not sp.is_file():
        raise DdaError(f"script not found: {sp} (write it under .analysis/variants/ first)")
    if sp.suffix == ".sql":
        raise DdaError("SQL variants are not runnable in this build (no duckdb baseline query path yet); "
                       "use a .py variant")
    return sp, read_text_lf(sp)


def do_run(wd: Workdir, vid: str, script: str, script_args: list[str], *, session: str = "",
           seed: int | None = None) -> dict:
    """Run a variant script in the locked-down kernel. Returns the kernel record."""
    from . import hooks as _hooks  # local import: hooks never imports kernel
    _check_vid(vid)
    wd.require_initialized()
    reg = find_registration(wd, vid)
    if not reg:
        raise DdaError(f"unknown variant {vid!r}: register it first (`dda variant {vid} --why \"...\"`); "
                       "runs without a registered variant id are orphan runs and fail G6 (§4.3)")
    state, detail, lock = lockstate.quick_status(wd)
    if state != "valid":
        raise DdaError(f"lock is not valid ({state}: {detail}); re-lock before reading data (§3.1)")
    sp, body_text = _variant_script(wd, vid, script)
    body_hash = hashlib.sha256(body_text.encode("utf-8")).hexdigest()
    frozen = frozen_hash(wd, vid)
    if frozen and frozen != body_hash:
        raise DdaError(f"variant {vid!r} is frozen with body {frozen[:12]} but the script now hashes "
                       f"{body_hash[:12]}; a changed script is a new variant id (§4.3)")
    lock_hash = lock["lock_hash"]
    run_seed = int(seed) if seed is not None else _default_seed(lock_hash, vid)
    run_id = hashlib.sha256(f"{lock_hash}:{vid}:{body_hash}:{time.time_ns()}".encode()).hexdigest()[:12]
    code_hash, blob_ptr = _hooks.write_blob(wd, body_text)
    audit = ledger.audit_log(wd)
    chain.append(audit, {"type": "audit", "kind": "audit", "event": "kernel-launch", "aliases": sorted(lock["aliases"]),
                        "variant": vid, "run_id": run_id, "session": session})

    env = dict(os.environ)
    status_file = wd.analysis / "runs" / f".kernel-{run_id}.json"
    env.update({
        "PYTHONPATH": str(Path(__file__).resolve().parent.parent) + os.pathsep + env.get("PYTHONPATH", ""),
        "DDA_WORKDIR": str(wd.root),
        "DDA_MILESTONE": wd.milestone or "",
        "DDA_VARIANT": vid,
        "DDA_RUN_ID": run_id,
        "DDA_SESSION": session,
        "DDA_LOCK_HASH": lock_hash,
        "DDA_SEED": str(run_seed),
        "DDA_KERNEL_STATUS": str(status_file),
        "PYTHONHASHSEED": str(run_seed % 4294967296),
        "HTTP_PROXY": env.get("HTTP_PROXY") or DEAD_PROXY,
        "HTTPS_PROXY": env.get("HTTPS_PROXY") or DEAD_PROXY,
    })
    t0 = time.time()
    proc = subprocess.run([sys.executable, "-m", "ddalib.kernel_bootstrap", str(sp), *script_args],
                          cwd=str(wd.root), env=env, capture_output=True, text=True)
    dt = round(time.time() - t0, 3)
    try:
        status = json.loads(status_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        status = {"ok": False, "error": "kernel did not write its status file"}
    try:
        status_file.unlink()
    except OSError:
        pass
    versions = status.get("baseline") or {}
    ky = wd.analysis / "kernel.yaml"
    env_hash = environment_hash(versions, ky.read_bytes() if ky.is_file() else None)
    net = status.get("network_policy") or "detect-only (kernel status missing)"
    record = {"run_id": run_id, "variant": vid, "variant_key": reg.get("variant_key"),
              "lock_hash": lock_hash, "seed": run_seed, "python": status.get("python") or sys.version.split()[0],
              "baseline": versions, "environment_hash": env_hash, "network_policy": net,
              "audit_hook": status.get("audit_hook"), "wrappers": status.get("wrappers"),
              "display": status.get("display"), "returncode": proc.returncode,
              "elapsed_s": dt, "stdout_tail": proc.stdout[-2000:], "stderr_tail": proc.stderr[-2000:]}
    kdir = wd.analysis / "runs" / "kernels"
    kdir.mkdir(parents=True, exist_ok=True)
    kpath = kdir / f"{run_id}.json"
    with open(kpath, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
        fh.write("\n")
    if not frozen:
        chain.append(ledger.specs_tried(wd), {"type": "freeze", "variant": vid, "frozen_hash": body_hash,
                                             "run_id": run_id, "code_hash": code_hash})
    chain.append(ledger.specs_tried(wd), {"type": "run", "variant": vid, "run_id": run_id,
                                         "body_hash": body_hash, "code_hash": code_hash, "seed": run_seed,
                                         "lock_hash": lock_hash, "label": reg.get("label"),
                                         "kernel": f"runs/kernels/{run_id}.json", "returncode": proc.returncode})
    chain.append(ledger.runs_log(wd), {"type": "done", "session": session, "tool": "dda", "subcommand": "run",
                                      "call": run_id, "aliases": sorted(lock["aliases"]), "kind": "data",
                                      "variant": vid, "code_hash": code_hash, "blob": blob_ptr,
                                      "kernel": f"runs/kernels/{run_id}.json"})
    chain.append(audit, {"type": "audit", "kind": "audit", "event": "kernel-stop", "aliases": sorted(lock["aliases"]),
                        "variant": vid, "run_id": run_id, "session": session, "returncode": proc.returncode,
                        "elapsed_s": dt})
    record["kernel_file"] = str(kpath)
    record["blob"] = blob_ptr
    if proc.returncode != 0:
        raise DdaError(f"kernel exited {proc.returncode} (record: runs/kernels/{run_id}.json):\n"
                       f"{(proc.stderr or proc.stdout).strip()[-1500:]}", code=proc.returncode or 1)
    return record


__all__ = ["BASELINE", "HEADER_FIELDS", "VARIANT_LABELS", "variant_key", "registrations", "find_registration",
           "frozen_hash", "run_entries", "locked_variant_id", "register_variant", "mark_locked", "do_meta",
           "do_run", "baseline_versions", "environment_hash"]
