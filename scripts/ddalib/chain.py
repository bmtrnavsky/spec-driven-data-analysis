"""Hash-chained, append-only evidence logs (spec §4.4).

Every writer — hooks, `dda`, later the kernel — appends through `append()`:

  1. exclusive OS lock on `<file>.lock` (msvcrt.locking / fcntl.flock),
     waiting at most LOCK_TIMEOUT_S;
  2. read the last line; `seq = last.seq + 1`, `prev = sha256(last line)`;
  3. one `write` of the new line, flush, fsync;
  4. update the heads mirror (`<dda_home>/heads/<key>.<name>.json`) while
     still holding the lock, then release.

On lock timeout a caller may ask for a spill instead: the record goes to
`<file>.spill/<pid>-<n>.json` and `merge_spills()` folds it into the chain
under the lock later (logged with a `spill-merge` line). An unmerged spill
file at a gate is a hook fault (§6.8).

Lines are canonical JSON (sorted keys, ASCII, no spaces) so the hash of a
line is reproducible from its bytes alone. Stdlib only.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import tempfile
import time
from pathlib import Path

from .layout import DdaError, canonical_path, dda_home, workdir_id

LOCK_TIMEOUT_S = 2.0
GENESIS = "0" * 64

if os.name == "nt":  # pragma: no cover - platform branch
    import msvcrt
else:  # pragma: no cover
    import fcntl


class ChainBusy(Exception):
    """The chain lock could not be taken within the timeout."""


class FileLock:
    """Exclusive lock on a side file. Re-entrant use is not supported."""

    def __init__(self, path: Path, timeout: float = LOCK_TIMEOUT_S):
        self.path = Path(path)
        self.timeout = timeout
        self.fh = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.path, "a+b")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                if os.name == "nt":
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.fh = fh
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    fh.close()
                    raise ChainBusy(f"evidence log busy: {self.path}") from None
                time.sleep(0.002 + random.random() * 0.008)

    def __exit__(self, *exc):
        fh, self.fh = self.fh, None
        if fh is None:
            return False
        try:
            if os.name == "nt":
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()
        return False


def line_hash(line: bytes) -> str:
    return hashlib.sha256(line.rstrip(b"\n")).hexdigest()


def canonical_line(record: dict) -> bytes:
    return (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def now_iso() -> str:
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t)) + f".{int(t % 1 * 1000):03d}" + time.strftime("%z")


# ---------- heads mirror ----------

def heads_ref(path: Path) -> tuple[str, str]:
    """(key, name) for a chain file: workdir chains are keyed by workdir id and their
    path relative to the workdir; dda-home chains are keyed `global`."""
    cp = canonical_path(path)
    home = canonical_path(dda_home())
    if cp.startswith(home + "/"):
        return "global", cp[len(home) + 1:]
    marker = "/.analysis/"
    i = cp.rfind(marker)
    if i < 0:
        raise DdaError(f"{path}: not an evidence chain location (.analysis/ or dda home)")
    root = cp[:i]
    return workdir_id(root), cp[i + 1:]


def heads_path(path: Path) -> Path:
    key, name = heads_ref(path)
    return dda_home() / "heads" / f"{key}.{name.replace('/', '__')}.json"


def _write_json_atomic(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    for attempt in range(50):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:  # Windows: a reader has the target open
            time.sleep(0.005)
    os.unlink(tmp)
    raise DdaError(f"could not update {path}")


def _read_heads(path: Path) -> dict | None:
    try:
        with open(heads_path(path), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None


# ---------- reading ----------

def _last_line(path: Path) -> bytes | None:
    try:
        fh = open(path, "rb")
    except FileNotFoundError:
        return None
    with fh:
        fh.seek(0, os.SEEK_END)
        end = fh.tell()
        if end == 0:
            return None
        buf = b""
        pos = end
        while pos > 0:
            step = min(65536, pos)
            pos -= step
            fh.seek(pos)
            buf = fh.read(step) + buf
            body = buf[:-1] if buf.endswith(b"\n") else buf
            nl = body.rfind(b"\n")
            if nl >= 0:
                return buf[nl + 1:]
        return buf


def read_records(path: Path) -> list[dict]:
    """Parse every line (no verification). Missing file -> []."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except FileNotFoundError:
        return []
    out = []
    for raw in data.split(b"\n"):
        if raw.strip():
            try:
                out.append(json.loads(raw))
            except ValueError:
                out.append({"__corrupt__": True})
    return out


# ---------- appending ----------

def _append_locked(path: Path, record: dict) -> dict:
    last = _last_line(path)
    if last is None:
        seq, prev = 1, GENESIS
    else:
        if not last.endswith(b"\n"):
            raise DdaError(f"{path}: last line is incomplete (torn write); run `dda verify-chain`")
        try:
            seq = int(json.loads(last)["seq"]) + 1
        except Exception:
            raise DdaError(f"{path}: last line is not a chain record; run `dda verify-chain`") from None
        prev = line_hash(last)
    rec = dict(record)
    rec.pop("seq", None)
    rec.pop("prev", None)
    rec.setdefault("t", now_iso())
    rec.setdefault("ts", round(time.time(), 3))
    rec["seq"], rec["prev"] = seq, prev
    line = canonical_line(rec)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "ab") as fh:
        fh.write(line)
        fh.flush()
        os.fsync(fh.fileno())
    _write_json_atomic(heads_path(path), {"seq": seq, "hash": line_hash(line), "file": canonical_path(path)})
    return rec


def append(path, record: dict, *, spill_on_busy: bool = False, timeout: float = LOCK_TIMEOUT_S) -> dict:
    """Append `record` to the chain at `path`. Returns the stored record (with seq/prev),
    or {"spilled": <file>} when the lock was busy and `spill_on_busy` is set."""
    path = Path(path)
    try:
        with FileLock(Path(str(path) + ".lock"), timeout):
            return _append_locked(path, record)
    except ChainBusy:
        if not spill_on_busy:
            raise
        return {"spilled": str(spill(path, record))}


def spill(path: Path, record: dict) -> Path:
    d = Path(str(path) + ".spill")
    d.mkdir(parents=True, exist_ok=True)
    rec = dict(record)
    rec.setdefault("t", now_iso())
    rec.setdefault("ts", round(time.time(), 3))
    name = f"{os.getpid()}-{time.time_ns()}-{random.randrange(1 << 30):08x}.json"
    tmp = d / (name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, d / name)
    return d / name


def pending_spills(path: Path) -> list[Path]:
    d = Path(str(path) + ".spill")
    return sorted(d.glob("*.json")) if d.is_dir() else []


def merge_spills(path, timeout: float = 10.0) -> int:
    """Fold spill files into the chain under the lock. Returns the number merged."""
    path = Path(path)
    if not pending_spills(path):
        return 0
    n = 0
    with FileLock(Path(str(path) + ".lock"), timeout):
        files = pending_spills(path)
        for f in files:
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
            except ValueError:
                rec = {"type": "spill-corrupt", "file": f.name}
            rec["spilled_from"] = f.name
            _append_locked(path, rec)
            f.unlink()
            n += 1
        if n:
            _append_locked(path, {"type": "spill-merge", "count": n})
    return n


# ---------- verification ----------

def verify(path) -> list[str]:
    """Return a list of problems (empty = chain intact and matches its heads mirror)."""
    path = Path(path)
    problems: list[str] = []
    heads = _read_heads(path)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except FileNotFoundError:
        if heads and heads.get("seq", 0) > 0:
            problems.append(f"{path.name}: file missing but heads mirror records seq {heads['seq']}")
        return problems
    if not data:
        if heads and heads.get("seq", 0) > 0:
            problems.append(f"{path.name}: file empty but heads mirror records seq {heads['seq']} (truncated)")
        return problems
    if not data.endswith(b"\n"):
        problems.append(f"{path.name}: last line incomplete (torn write or edit)")
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    prev = GENESIS
    hashes = []
    for i, raw in enumerate(lines, 1):
        try:
            rec = json.loads(raw)
        except ValueError:
            problems.append(f"{path.name}: line {i} is not JSON")
            break
        if not isinstance(rec, dict) or rec.get("seq") != i:
            problems.append(f"{path.name}: line {i} has seq {rec.get('seq') if isinstance(rec, dict) else '?'} (expected {i})")
            break
        if rec.get("prev") != prev:
            problems.append(f"{path.name}: line {i} prev hash does not match line {i - 1} (edited or forked)")
            break
        if raw + b"\n" != canonical_line(rec):
            problems.append(f"{path.name}: line {i} is not in canonical form (hand-edited)")
            break
        prev = line_hash(raw)
        hashes.append(prev)
    if problems:
        return problems
    if heads is None:
        problems.append(f"{path.name}: no heads mirror ({heads_path(path).name}); file was not written by the appender")
    else:
        hs, hh = heads.get("seq"), heads.get("hash")
        if not isinstance(hs, int) or hs < 1:
            problems.append(f"{path.name}: heads mirror malformed")
        elif hs > len(hashes):
            problems.append(f"{path.name}: {len(hashes)} lines but heads mirror records seq {hs} (truncated)")
        elif hashes[hs - 1] != hh:
            problems.append(f"{path.name}: line {hs} does not match the heads mirror (rewritten)")
        elif hs < len(hashes):
            problems.append(f"{path.name}: {len(hashes) - hs} line(s) after the mirrored head (appended outside the appender)")
    return problems


__all__ = ["append", "spill", "merge_spills", "pending_spills", "verify", "read_records", "ChainBusy",
           "FileLock", "heads_path", "now_iso", "canonical_line", "line_hash"]
