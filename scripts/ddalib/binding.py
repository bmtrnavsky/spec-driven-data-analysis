"""Session binding and the active-workdir registry (spec §6.0).

State lives under dda_home():
  sessions/<session-id>.json   {"session_id", "workdir", "workdir_id", "milestone", "bound_at"}
  active.json                  {"workdirs": {<workdir-id>: {"path", "aliases", "roots", "registered_at"}}}

Both are written atomically (temp file + os.replace). A rebind is logged
to both workdirs' ledgers through the chain appender (phase 2).
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
from pathlib import Path

from .layout import DdaError, Workdir, dda_home, load_config

SESSION_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def write_json_atomic(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_json(path: Path, default):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default


def sessions_dir() -> Path:
    return dda_home() / "sessions"


def session_file(session_id: str) -> Path:
    if not SESSION_RE.match(session_id or ""):
        raise DdaError(f"invalid session id {session_id!r}")
    return sessions_dir() / f"{session_id}.json"


def registry_path() -> Path:
    return dda_home() / "active.json"


def read_registry() -> dict:
    reg = _read_json(registry_path(), {"workdirs": {}})
    if not isinstance(reg, dict) or not isinstance(reg.get("workdirs"), dict):
        raise DdaError(f"{registry_path()} is corrupt")
    return reg


def get_binding(session_id: str) -> dict | None:
    return _read_json(session_file(session_id), None)


def _roots_from_config(cfg: dict) -> dict:
    roots = {}
    for alias, spec in cfg["data_roots"].items():
        roots[alias] = {k: list(spec.get(k) or []) for k in ("paths", "hosts", "url_prefixes", "tool_patterns")}
    return roots


def start(wd: Workdir, session_id: str, rebind: bool = False) -> dict:
    wd.require_initialized()
    cfg = load_config(wd)
    sf = session_file(session_id)
    existing = _read_json(sf, None)
    if existing and existing.get("workdir_id") != wd.id and not rebind:
        raise DdaError(
            f"session {session_id} is already bound to {existing.get('workdir')}; "
            "use `dda start --rebind` (logged) or `dda release` that workdir first"
        )
    if existing and existing.get("workdir_id") == wd.id and existing.get("milestone") != wd.milestone and not rebind:
        raise DdaError(f"session {session_id} is bound to milestone {existing.get('milestone')!r}; use --rebind")
    binding = {
        "session_id": session_id,
        "workdir": str(wd.root),
        "workdir_id": wd.id,
        "milestone": wd.milestone,
        "bound_at": _now(),
    }
    if existing and rebind:
        binding["rebound_from"] = {k: existing.get(k) for k in ("workdir", "milestone", "bound_at")}
    if existing and rebind and (existing.get("workdir_id") != wd.id or existing.get("milestone") != wd.milestone):
        from . import chain, ledger
        rec = {"type": "rebind", "session": session_id,
               "from": {"workdir": existing.get("workdir"), "milestone": existing.get("milestone")},
               "to": {"workdir": str(wd.root), "milestone": wd.milestone}}
        old = Workdir.at(existing["workdir"], existing.get("milestone")) if existing.get("workdir") else None
        if old is not None and old.analysis.is_dir():
            chain.append(ledger.ledger_path(old), rec)
        chain.append(ledger.ledger_path(wd), rec)
    reg = read_registry()
    reg["workdirs"][wd.id] = {
        "path": str(wd.root),
        "aliases": sorted(cfg["data_roots"]),
        "roots": _roots_from_config(cfg),
        "registered_at": reg["workdirs"].get(wd.id, {}).get("registered_at") or _now(),
    }
    write_json_atomic(registry_path(), reg)
    write_json_atomic(sf, binding)
    return binding


def refresh_registry(wd: Workdir) -> None:
    """Re-read config roots into the registry entry if the workdir is active (after a lock or amendment)."""
    reg = read_registry()
    entry = reg["workdirs"].get(wd.id)
    if entry is None:
        return
    cfg = load_config(wd)
    entry["aliases"] = sorted(cfg["data_roots"])
    entry["roots"] = _roots_from_config(cfg)
    write_json_atomic(registry_path(), reg)


def release(wd: Workdir, cause: str = "release", reason: str | None = None) -> list[str]:
    """Unbind every session bound to `wd`, drop it from the active registry,
    and ledger the release (spec §6.0).

    Without the ledger line a release launders later reads: the roots leave
    the active set, so a re-lock afterwards looks clean. `cause` is
    "release" (G9) or "abandon" (dropped work). Only a human runs these;
    every blocking hook refuses them from agent tool calls.
    """
    released = []
    sdir = sessions_dir()
    if sdir.is_dir():
        for f in sorted(sdir.glob("*.json")):
            b = _read_json(f, None)
            if isinstance(b, dict) and b.get("workdir_id") == wd.id:
                f.unlink()
                released.append(b.get("session_id", f.stem))
    reg = read_registry()
    if reg["workdirs"].pop(wd.id, None) is not None or released:
        write_json_atomic(registry_path(), reg)
    if cause not in ("release", "abandon"):
        raise DdaError(f"unknown release cause {cause!r}")
    from . import chain, ledger
    chain.append(ledger.ledger_path(wd), {"type": cause, "sessions": sorted(released),
                                          **({"reason": reason} if reason else {})})
    return released


def status() -> dict:
    reg = read_registry()
    sessions = []
    sdir = sessions_dir()
    if sdir.is_dir():
        for f in sorted(sdir.glob("*.json")):
            b = _read_json(f, None)
            if isinstance(b, dict):
                sessions.append(b)
    return {"dda_home": str(dda_home()), "active": reg["workdirs"], "sessions": sessions}
