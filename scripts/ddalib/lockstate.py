"""Lock state: spec.lock, the per-workdir lock-state cache, and fast validity checks
(spec §4.2, §6.1, §6.9).

The hot path (`quick_status`) never hashes a file whose mtime and size match
the cache. `dda lock` writes the cache; hooks refresh entries whose stat
changed. The cache lives in dda home (guarded by evidenceguard).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from . import lockhash
from .layout import DdaError, Workdir, dda_home, read_text_lf

LOCK_FILE_FORMAT = "dda-spec-lock-v1"

# Label ranking: higher is worse. Effective label = worst of spec.lock and later relabels.
LABELS = ("pre-data", "pre-data (prior exposure)", "post-data", "post-data (unbound access)")


def worst_label(*labels: str | None) -> str | None:
    known = [l for l in labels if l in LABELS]
    return max(known, key=LABELS.index) if known else None


def cache_path(wd: Workdir) -> Path:
    suffix = f"--{wd.milestone}" if wd.milestone else ""
    return dda_home() / "state" / f"{wd.id}{suffix}.json"


def read_lock(wd: Workdir) -> dict | None:
    try:
        raw = wd.lock_path.read_bytes()
    except FileNotFoundError:
        return None
    try:
        lock = json.loads(raw)
    except ValueError:
        raise DdaError(f"{wd.lock_path} is not valid JSON (edited?); run `dda verify-chain`") from None
    if not isinstance(lock, dict) or lock.get("format") != LOCK_FILE_FORMAT:
        raise DdaError(f"{wd.lock_path} has an unknown format")
    lock["_file_sha"] = hashlib.sha256(raw).hexdigest()
    return lock


def _stat(p: Path):
    try:
        st = p.stat()
        return [st.st_mtime_ns, st.st_size]
    except FileNotFoundError:
        return None


def _spec_hash(p: Path) -> str:
    return lockhash.sha256_hex(lockhash.normalized_spec(read_text_lf(p)))


def _config_hash(p: Path) -> str:
    return lockhash.sha256_hex(read_text_lf(p))


def tracked_files(wd: Workdir, lock: dict) -> dict[str, tuple[Path, str, object]]:
    """{key: (path, expected_hash, hash_fn)} for every file the lock depends on."""
    files = {
        "spec": (wd.spec_path, lock["spec_hash"], _spec_hash),
        "config": (wd.config_path, lock["config_hash"], _config_hash),
    }
    for pin in lock.get("pins", []):
        name, rest = pin.split("@", 1)
        expected = rest.split("#", 1)[1]
        files[f"def:{name}"] = (wd.definitions / f"{name}.md",
                                expected, lambda p, n=name: lockhash.load_definition(wd, n).content_hash)
    return files


def write_cache(wd: Workdir, lock: dict) -> None:
    from .chain import _write_json_atomic
    entries = {}
    for key, (path, _exp, fn) in tracked_files(wd, lock).items():
        st = _stat(path)
        entries[key] = {"stat": st, "hash": fn(path) if st else None}
    _write_json_atomic(cache_path(wd), {"lock_hash": lock["lock_hash"], "lock_file_sha": lock["_file_sha"],
                                        "version": lock["version"], "files": entries})


def quick_status(wd: Workdir) -> tuple[str, str, dict | None]:
    """(state, detail, lock). state: none | valid | spec-changed | config-changed |
    definitions-changed | tampered."""
    try:
        lock = read_lock(wd)
    except DdaError as exc:
        return "tampered", str(exc), None
    try:
        with open(cache_path(wd), "r", encoding="utf-8") as fh:
            cache = json.load(fh)
    except (FileNotFoundError, ValueError):
        cache = None
    if lock is None:
        if cache:
            return "tampered", "spec.lock is missing but dda recorded a lock for this workdir", None
        return "none", "no lock yet", None
    if cache is None:
        # Rebuild the cache only from a lock the ledger agrees with.
        from .ledger import last_lock_record
        rec = last_lock_record(wd)
        if not rec or rec.get("lock_hash") != lock.get("lock_hash"):
            return "tampered", "spec.lock does not match the last ledger lock entry", lock
        write_cache(wd, lock)
        with open(cache_path(wd), "r", encoding="utf-8") as fh:
            cache = json.load(fh)
    if cache.get("lock_file_sha") != lock["_file_sha"] or cache.get("lock_hash") != lock.get("lock_hash"):
        return "tampered", "spec.lock changed outside `dda lock`", lock
    changed = False
    state = "valid"
    detail = f"lock v{lock['version']} valid"
    order = {"spec": "spec-changed", "config": "config-changed"}
    for key, (path, expected, fn) in tracked_files(wd, lock).items():
        entry = cache["files"].get(key) or {}
        st = _stat(path)
        if st is None:
            cur = None
        elif entry.get("stat") == st:
            cur = entry.get("hash")
        else:
            try:
                cur = fn(path)
            except DdaError:
                cur = "unparseable"
            cache["files"][key] = {"stat": st, "hash": cur}
            changed = True
        if cur != expected and state == "valid":
            state = order.get(key, "definitions-changed")
            detail = f"{path.name} differs from lock v{lock['version']}"
    if changed:
        try:
            from .chain import _write_json_atomic
            _write_json_atomic(cache_path(wd), cache)
        except Exception:
            pass
    return state, detail, lock


__all__ = ["read_lock", "quick_status", "write_cache", "cache_path", "LABELS", "worst_label", "LOCK_FILE_FORMAT"]
