"""Evidence files, `dda lock`, exposure scanning, and gate G4 (spec §3, §4.2, §4.4, §6.0).

Ledger records (JSON lines, hash-chained through chain.append):
  lock / amendment  version, lock_hash, label, post_data, reason, watermarks, exposure summary
  relabel           version, label, reason       (G4 found exposure the lock missed)
  rebind / abandon  session bookkeeping (§6.0)
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path

from . import chain, lockhash, lockstate
from .layout import DdaError, Workdir, canonical_path, dda_home, load_config, read_text_lf

EXIT_CHAIN = 4


# ---------- evidence locations ----------

def runs_log(wd: Workdir) -> Path:
    return wd.analysis / "runs.log"


def audit_log(wd: Workdir) -> Path:
    return wd.analysis / "audit.log"


def ledger_path(wd: Workdir) -> Path:
    return wd.scope / "ledger.md"


def specs_tried(wd: Workdir) -> Path:
    return wd.analysis / "specs-tried.jsonl"


def approvals_index(wd: Workdir) -> Path:
    return wd.analysis / "approvals.index.jsonl"


def blobs_dir(wd: Workdir) -> Path:
    return wd.analysis / "runs" / "blobs"


def unbound_log() -> Path:
    return dda_home() / "unbound-access.log"


def heartbeat_log(session_id: str) -> Path:
    return dda_home() / "heartbeat" / f"{session_id}.log"


def workdir_chains(wd: Workdir) -> list[Path]:
    out = [runs_log(wd), audit_log(wd), wd.analysis / "ledger.md", specs_tried(wd), approvals_index(wd)]
    ms = wd.analysis / "milestones"
    if ms.is_dir():
        out += sorted(p / "ledger.md" for p in ms.iterdir() if p.is_dir())
    return out


def verify_all(wd: Workdir, merge: bool = True, include_global: bool = True) -> tuple[list[str], int]:
    """Merge spills (optional) and verify every chain. Returns (problems, merged)."""
    paths = workdir_chains(wd)
    if include_global:
        paths.append(unbound_log())
    merged = 0
    if merge:
        for p in paths:
            merged += chain.merge_spills(p)
    problems = []
    for p in paths:
        problems += chain.verify(p)
        if not merge and chain.pending_spills(p):
            problems.append(f"{p.name}: {len(chain.pending_spills(p))} unmerged spill file(s) (hook fault)")
    return problems, merged


def last_lock_record(wd: Workdir) -> dict | None:
    for rec in reversed(chain.read_records(ledger_path(wd))):
        if rec.get("type") in ("lock", "amendment"):
            return rec
    return None


def ledger_summary(wd: Workdir) -> dict:
    recs = chain.read_records(ledger_path(wd))
    locks = [r for r in recs if r.get("type") in ("lock", "amendment")]
    cur = locks[-1] if locks else None
    label = cur.get("label") if cur else None
    if cur:
        for r in recs:
            if r.get("type") == "relabel" and r.get("version") == cur.get("version"):
                label = lockstate.worst_label(label, r.get("label"))
    amends = [r for r in locks if r.get("type") == "amendment"]
    return {
        "versions": len(locks),
        "amendments": len(amends),
        "post_data_amendments": sum(1 for r in amends if r.get("post_data")),
        "current": cur,
        "effective_label": label,
    }


# ---------- exposure (what makes a lock post-data) ----------

def _locator_set(loc: dict) -> set[str]:
    from .matching import norm_root, norm_text
    out = set()
    for p in loc.get("paths") or []:
        out.add("path:" + norm_root(p))
    for h in loc.get("hosts") or []:
        out.add("host:" + h.lower())
    for u in loc.get("url_prefixes") or []:
        out.add("url:" + norm_text(u))
    for t in loc.get("tool_patterns") or []:
        out.add("tool:" + t)
    return out


def _release_line_sessions(workdir_path) -> set[str]:
    """Sessions named by `release` / `abandon` records in a workdir's ledger.

    A release unbinds sessions that may have no `done` line of their own
    (seen-only reads, suppressed post hooks); the release line keeps the
    laundering step attributable (spec §6.0). Reads the top-level ledger
    and any milestone ledgers (releases land in the bound scope's ledger).
    """
    out: set[str] = set()
    base = Path(workdir_path) / ".analysis"
    cands = [base / "ledger.md"]
    try:
        ms = base / "milestones"
        if ms.is_dir():
            cands += sorted(p / "ledger.md" for p in ms.iterdir() if p.is_dir())
    except OSError:
        pass
    for cand in cands:
        try:
            recs = chain.read_records(cand)
        except OSError:
            continue
        for rec in recs:
            if rec.get("type") in ("release", "abandon"):
                for s in rec.get("sessions") or []:
                    if isinstance(s, str):
                        out.add(s)
    return out


def _scan_workdirs() -> dict:
    """Active workdirs plus released ones (released keep their runs.log
    visible to exposure even though hooks no longer match their roots)."""
    from .binding import read_registry
    try:
        reg = read_registry()
    except DdaError:
        return {}
    workdirs = dict(reg.get("workdirs") or {})
    for wid, w in (reg.get("released") or {}).items():
        workdirs.setdefault(wid, w)
    return workdirs


def exposure(wd: Workdir, aliases: list[str], watermarks: dict | None, locked_ts: float | None) -> dict:
    """Reads of `aliases` attributable to this workdir, plus hopping signals.

    watermarks None = scan everything (a lock being made now). With the lock's
    watermarks (G4): runs/audit scan only lines up to the lock; the unbound
    log skips lines the lock already judged (only newer lines count); the
    session-history and rebind scans have no upper bound, because a hop after
    the lock is the laundering case."""
    al = set(aliases)
    wm = watermarks or {}
    found = {"runs": [], "audit": [], "unbound": [], "other_workdirs": [],
             "session_history": [], "rebind": []}
    data_sessions: set = set()
    mine_sessions: set = set()
    for rec in chain.read_records(runs_log(wd)):
        if wm.get("runs") is not None and rec.get("seq", 0) > wm["runs"]:
            break
        if rec.get("type") == "done" and rec.get("kind") == "data" and al & set(rec.get("aliases") or []):
            found["runs"].append({"seq": rec.get("seq"), "session": rec.get("session"), "aliases": rec.get("aliases")})
        if rec.get("type") == "done" and rec.get("session"):
            mine_sessions.add(rec.get("session"))
            if rec.get("kind") == "data":
                data_sessions.add(rec.get("session"))
    for rec in chain.read_records(audit_log(wd)):
        if wm.get("audit") is not None and rec.get("seq", 0) > wm["audit"]:
            break
        if rec.get("kind") in ("audit", "open", "data") and al & set(rec.get("aliases") or []):
            found["audit"].append({"seq": rec.get("seq"), "aliases": rec.get("aliases")})
    for rec in chain.read_records(unbound_log()):
        if wm.get("unbound") is not None and rec.get("seq", 0) <= wm["unbound"]:
            continue  # judged at the lock whose watermark G4 carries; only newer lines count
        hits = [m for m in rec.get("matches") or [] if m.get("workdir_id") == wd.id and m.get("alias") in al]
        if hits:
            found["unbound"].append({"seq": rec.get("seq"), "session": rec.get("session"), "tool": rec.get("tool"),
                                     "aliases": sorted({m["alias"] for m in hits})})
    mine_sessions |= _release_line_sessions(wd.root)  # ever bound here, even if since released
    # Workdir hopping: other workdirs declaring the same locators (§6.0).
    # Released workdirs stay in the scan (registry `released` section): a
    # finished analysis still counts as prior exposure for later workdirs,
    # otherwise a release launders the reads out of the active set.
    reg = _scan_workdirs()
    mine = {}
    try:
        cfg = load_config(wd)
        mine = {a: _locator_set(cfg["data_roots"].get(a) or {}) for a in al}
    except DdaError:
        pass
    for wid, w in reg.items():
        if wid == wd.id:
            continue
        overlap = {oa for oa, loc in (w.get("roots") or {}).items()
                   if any(_locator_set(loc) & s for s in mine.values())}
        if not overlap:
            continue
        for rec in chain.read_records(Path(w["path"]) / ".analysis" / "runs.log"):
            if locked_ts is not None and rec.get("ts", 0) > locked_ts:
                break
            if rec.get("type") == "done" and rec.get("kind") == "data" and overlap & set(rec.get("aliases") or []):
                found["other_workdirs"].append({"workdir": w["path"], "seq": rec.get("seq"),
                                                "session": rec.get("session"), "aliases": rec.get("aliases")})
    # Rootless workdir hopping (§6.0): a session seen in this workdir's log that
    # also has data reads in ANY other workdir's log — even one declaring no
    # shared locator — hopped between workdirs. No upper time bound: a hop
    # after the lock counts, because that is the laundering case.
    other_data: set = set()
    other_sessions: set = set()
    other_done: list = []
    if mine_sessions:
        for wid, w in reg.items():
            if wid == wd.id:
                continue
            other = Path(w["path"]) / ".analysis" / "runs.log"
            if other.is_file():
                for rec in chain.read_records(other):
                    if rec.get("type") != "done" or not rec.get("session"):
                        continue
                    other_sessions.add(rec.get("session"))
                    if rec.get("kind") == "data":
                        other_data.add(rec.get("session"))
                    if rec.get("kind") in ("data", "other"):
                        other_done.append({"workdir": w["path"], "seq": rec.get("seq"),
                                           "session": rec.get("session"), "kind": rec.get("kind"),
                                           "aliases": rec.get("aliases")})
            # Release/abandon lines attribute sessions to the workdir even
            # when its runs.log has no `done` line for them (seen-only reads,
            # suppressed post hooks) — read the release lines (§6.0).
            other_sessions |= _release_line_sessions(w["path"])
    # The session must have read data somewhere (here or another workdir's
    # log): mere `dda status` cross-talk without any data read is not hopping.
    carried = data_sessions | other_data
    for f in other_done:
        if f["session"] in mine_sessions and f["session"] in carried:
            found["session_history"].append(f)
    # Release-attributed sessions with no `done` line of their own: bound to
    # another workdir (named in its release line) and data-reads elsewhere.
    seen_done = {f["session"] for f in other_done}
    for s in sorted(other_sessions - seen_done):
        if s in mine_sessions and s in carried:
            for wid, w in reg.items():
                if wid != wd.id and s in _release_line_sessions(w["path"]):
                    found["session_history"].append({"workdir": w["path"], "seq": None, "session": s,
                                                      "kind": "release", "aliases": []})
                    break
    for rec in chain.read_records(ledger_path(wd)):
        if rec.get("type") == "rebind" and rec.get("session") in carried:
            found["rebind"].append({"seq": rec.get("seq"), "session": rec.get("session"),
                                    "from": rec.get("from"), "to": rec.get("to")})
    return found


def label_for(found: dict, prior_exposure: str) -> str:
    if found.get("unbound") or found.get("other_workdirs") or found.get("session_history") or found.get("rebind"):
        return "post-data (unbound access)"
    if found.get("runs") or found.get("audit"):
        return "post-data"
    pe = lockhash.normalize_ws(prior_exposure).lower().strip(" .")
    if pe and pe not in ("none known", "none"):
        return "pre-data (prior exposure)"
    return "pre-data"


def _last_seq(path: Path) -> int:
    recs = chain.read_records(path)
    return recs[-1].get("seq", 0) if recs else 0


# ---------- git ----------

def _git(root: Path, *args, check=True) -> subprocess.CompletedProcess:
    git = shutil.which("git")
    if not git:
        raise DdaError("git not found on PATH; locks are git commits (§4.2)")
    r = subprocess.run([git, "-C", str(root), *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise DdaError(f"git {' '.join(args[:3])} failed: {(r.stderr or r.stdout).strip()[:400]}")
    return r


def in_git_repo(root: Path) -> bool:
    return shutil.which("git") is not None and _git(root, "rev-parse", "--show-toplevel", check=False).returncode == 0


def git_commit(root: Path, paths: list[Path], message: str) -> str:
    if not in_git_repo(root):
        raise DdaError(f"{root} is not inside a git repository; locks are git commits (§4.2). Run `git init` there.")
    rels = [str(p.relative_to(root)).replace("\\", "/") for p in paths if p.exists()]
    ident = []
    if not _git(root, "config", "user.email", check=False).stdout.strip():
        ident = ["-c", "user.name=dda", "-c", "user.email=dda@localhost"]
    nosign = ["-c", "commit.gpgsign=false", "-c", "tag.gpgSign=false"]
    _git(root, "add", "-f", "--", *rels)
    _git(root, *nosign, *ident, "commit", "--no-verify", "-q", "-m", message, "--", *rels)
    return _git(root, "rev-parse", "HEAD").stdout.strip()


# ---------- git safety scan (shared by `dda gitcheck` and gate G9) ----------

import re as _re

GIT_SAFETY_EXTS = frozenset({
    ".csv", ".tsv", ".tab",
    ".parquet", ".pq", ".feather", ".arrow", ".ipc",
    ".avro", ".orc",
    ".xlsx", ".xls", ".xlsm", ".xlsb", ".ods",
    ".json", ".jsonl", ".ndjson", ".geojson",
    ".db", ".sqlite", ".sqlite3", ".db3", ".duckdb",
    ".pkl", ".pickle", ".pck", ".npy", ".npz",
    ".h5", ".hdf5", ".h5ad",
    ".sav", ".dta", ".sas7bdat", ".xpt", ".rdata", ".rds",
    ".zip", ".tar", ".tgz", ".7z", ".gz", ".bz2", ".xz", ".zst",
    ".key", ".pem", ".p12", ".pfx", ".jks", ".kdbx", ".env",
})

_GIT_SAFETY_NAME_RES = tuple(_re.compile(rx) for rx in (
    r"^id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$",
    r"secret|passwd|password|credential|private[_-]?key|seed[_-]?phrase|\.key$|\.pem$",
))

_GIT_SAFETY_SECRET_RES = (
    (_re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), "private key material"),
    (_re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"), "possible AWS access key"),
    (_re.compile(r"(?<![A-Za-z0-9])ASIA[0-9A-Z]{16}(?![A-Za-z0-9])"), "possible AWS temporary key"),
    (_re.compile(r"(?<![A-Za-z0-9])(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}(?![A-Za-z0-9])"),
     "possible GitHub token"),
    (_re.compile(r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9\-_]{16,}(?![A-Za-z0-9])"),
     "possible Anthropic API key"),
    (_re.compile(r"(?<![A-Za-z0-9])sk-(?:live|test|proj)-[A-Za-z0-9-]{16,}(?![A-Za-z0-9])"),
     "possible Stripe secret key"),
    (_re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9]{20,}(?![A-Za-z0-9])"),
     "possible OpenAI API key"),
    (_re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9])"), "possible GCP API key"),
    (_re.compile(r"(?<![A-Za-z0-9])ya29\.[0-9A-Za-z\-_]{20,}(?![A-Za-z0-9])"),
     "possible GCP OAuth token"),
    (_re.compile(r"(?<![A-Za-z0-9])xox[bap]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9])"), "possible Slack token"),
    (_re.compile(r"(?<![A-Za-z0-9])bearer\s+[A-Za-z0-9\-._~+/=]{20,}(?![A-Za-z0-9])", _re.IGNORECASE),
     "possible bearer token"),
    (_re.compile(r"(?<![A-Za-z0-9])(?:api[_-]?key|client[_-]?secret|secret|passwd|password)(?![A-Za-z0-9])"
                 r"(?:[\"']?\s*[:=]\s*[\"']?\S{2,}|[\"']?\s+\bis\b\s+[\"']?\S{2,}|[\"']?\s+[\"']?\S{4,})",
                 _re.IGNORECASE),
     "possible embedded credential"),
)

_GIT_SAFETY_SAMPLE_HEAD = 65_536
_GIT_SAFETY_SAMPLE_MID = 65_536
_GIT_SAFETY_SAMPLE_TAIL = 65_536
# Blobs larger than this are sampled in windows rather than read whole
# (streamed straight from the git object store).
_GIT_SAFETY_STREAM_CAP = 8 * 1024 * 1024


def _git_safety_sample(data: bytes) -> bytes:
    """Bound a blob for regex scanning: small blobs scan whole; large blobs
    keep head+middle+tail windows so a secret anywhere can still be caught."""
    cap = _GIT_SAFETY_SAMPLE_HEAD + _GIT_SAFETY_SAMPLE_MID + _GIT_SAFETY_SAMPLE_TAIL
    if len(data) <= max(cap, _GIT_SAFETY_STREAM_CAP):
        return data
    mid = len(data) // 2
    half = _GIT_SAFETY_SAMPLE_MID // 2
    return (data[:_GIT_SAFETY_SAMPLE_HEAD] + b"\n"
            + data[mid - half:mid + half] + b"\n"
            + data[-_GIT_SAFETY_SAMPLE_TAIL:])


def _git_safety_known(wd: Workdir) -> tuple:
    """Known dda governance files under evidence dirs: exempt from extension
    and filename checks, but still content-scanned for secrets (SPEC §11:
    dda's own committed records, not analysis data)."""
    specs_rel = wd.specs_dir.relative_to(wd.root).as_posix()
    runs_rel = (wd.analysis / "runs").relative_to(wd.root).as_posix()
    appr_rel = (wd.analysis / "approvals").relative_to(wd.root).as_posix()
    return (
        _re.compile(_re.escape(specs_rel) + r"/v\d+\.md\Z"),
        _re.compile(_re.escape(runs_rel) + r"/kernels/[^/]+\.json\Z"),
        _re.compile(_re.escape(runs_rel) + r"/blobs/[0-9a-f]{64}\Z"),
        _re.compile(_re.escape(appr_rel) + r"/[^/]+\.json\Z"),
    )


def _git_safety_evidence(wd: Workdir, lock: dict | None) -> set[str]:
    """Lock/governance evidence paths exempt from the safety scan (SPEC §11:
    these are dda's own committed records, not analysis data). Sub-directories
    that hold evidence (specs/, runs/, approvals/) are NOT blanket-exempt:
    only known governance filenames under them skip the extension/name
    checks, and everything there is still content-scanned for secrets."""
    exact: set[str] = set()

    def add(p: Path) -> None:
        try:
            exact.add(p.relative_to(wd.root).as_posix())
        except ValueError:
            pass

    add(wd.spec_path)
    add(wd.lock_path)
    add(ledger_path(wd))
    add(wd.config_path)
    add(wd.wayfinder_path)
    add(wd.root / ".gitignore")
    add(runs_log(wd))
    add(audit_log(wd))
    add(specs_tried(wd))
    add(approvals_index(wd))
    for chained in workdir_chains(wd):
        add(chained)
    for pin in (lock.get("pins") if lock else []) or []:
        add(wd.definitions / f"{pin.split('@', 1)[0]}.md")
    return exact


def _git_safety_stream_git_blob(wd: Workdir, rel: str) -> bytes | None:
    """Stream a git object with bounded memory, keeping head+middle+tail."""
    git = shutil.which("git")
    if not git:
        return None
    try:
        proc = subprocess.Popen([git, "-C", str(wd.root), "show", ":" + rel],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return None
    chunks: list[bytes] = []
    total = 0
    try:
        assert proc.stdout is not None
        while True:
            chunk = proc.stdout.read(65_536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _GIT_SAFETY_STREAM_CAP:
                break
        data = b"".join(chunks)
    except OSError:
        return None
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        proc.wait()
    if proc.returncode != 0 or not data:
        return None
    return _git_safety_sample(data)


def _git_safety_blob(wd: Workdir, rel: str) -> bytes | None:
    """Best-effort content for a git-listed path: the whole workdir file up
    to a cap (else head+middle+tail windows), else the index blob streamed
    with bounded memory."""
    p = wd.root / rel
    try:
        if p.is_file():
            size = p.stat().st_size
            if size <= _GIT_SAFETY_STREAM_CAP:
                return p.read_bytes()
            with open(p, "rb") as fh:
                head = fh.read(_GIT_SAFETY_SAMPLE_HEAD)
                fh.seek(size // 2 - _GIT_SAFETY_SAMPLE_MID // 2)
                middle = fh.read(_GIT_SAFETY_SAMPLE_MID)
                fh.seek(-_GIT_SAFETY_SAMPLE_TAIL, 2)
                tail = fh.read(_GIT_SAFETY_SAMPLE_TAIL)
            return head + b"\n" + middle + b"\n" + tail
    except OSError:
        pass
    streamed = _git_safety_stream_git_blob(wd, rel)
    if streamed is not None:
        return streamed
    try:
        r = _git(wd.root, "show", ":" + rel, check=False)
        if r.returncode == 0:
            return _git_safety_sample(r.stdout.encode("utf-8", "ignore"))
    except Exception:
        pass
    return None


def git_safety_scan(wd: Workdir) -> list[str]:
    """Paths that must not go to git: data formats, key material, secret names.

    Scans everything git sees (tracked files = committed + staged, plus
    untracked-but-not-ignored files from `git status`), including inside
    `.spill` directories. Dda's own lock/governance evidence skips the
    extension/name checks but is still content-scanned for key material.
    Content-scans textish files for key material so
    secrets in `.txt` or extensionless files are caught too.
    """
    wd.require_initialized()
    lock = None
    try:
        lock = lockstate.read_lock(wd)
    except DdaError:
        lock = None
    exact = _git_safety_evidence(wd, lock)
    known_res = _git_safety_known(wd)
    tracked = [t for t in _git(wd.root, "ls-files", "-z").stdout.split("\0") if t]
    st = _git(wd.root, "status", "--porcelain=v1", "--untracked-files=all", "-z").stdout
    toks = st.split("\0")
    i = 0
    status_paths: list[str] = []
    while i < len(toks):
        tok = toks[i]
        i += 1
        if len(tok) < 4:
            continue
        xy, path = tok[:2], tok[3:]
        if xy[0] in ("R", "C"):
            if i < len(toks) and toks[i]:
                i += 1  # skip the rename/copy source; scan the destination
            if not path:
                continue
        if path:
            status_paths.append(path)
    problems: list[str] = []
    for rel in sorted(set(tracked) | set(status_paths)):
        norm = rel.strip()
        if not norm or norm.startswith(".git/") or norm == ".git":
            continue
        in_exact = norm in exact
        if in_exact:
            # Exact governance paths skip the extension/name checks, but
            # are still content-scanned for secrets (a bypass must not be
            # able to hide key material behind an exempt filename).
            pass
        known = any(rx.match(norm) for rx in known_res)
        low = norm.lower()
        base = low.rsplit("/", 1)[-1]
        reason = ""
        if not known and not in_exact:
            if base == ".env" or base.startswith(".env."):
                reason = "secret file"
            elif any(s in GIT_SAFETY_EXTS for s in Path(low).suffixes):
                reason = "data/secret format"
            elif any(rx.search(base) for rx in _GIT_SAFETY_NAME_RES):
                reason = "suspicious secret-like name"
        if not reason:
            blob = _git_safety_blob(wd, norm)
            if blob and b"\0" not in blob[:8192]:
                try:
                    sample = blob.decode("utf-8", "ignore")
                except Exception:
                    sample = ""
                for rx, label in _GIT_SAFETY_SECRET_RES:
                    if rx.search(sample):
                        reason = label
                        break
        if reason:
            problems.append(f"{norm} ({reason})")
    return problems


# ---------- dda lock ----------

def do_lock(wd: Workdir, amend: str | None = None) -> dict:
    wd.require_initialized()
    problems, merged = verify_all(wd)
    if problems:
        raise DdaError("evidence chain failed to verify — stop and ask (§3.2 case 8):\n  - " + "\n  - ".join(problems),
                       EXIT_CHAIN)
    spec_text = read_text_lf(wd.spec_path)
    comp = lockhash.compute(wd, spec_text)
    sections = lockhash.parse_sections(spec_text)
    prior = sections.get("Prior exposure", "")
    if not lockhash.normalize_ws(prior):
        raise DdaError("spec: '## Prior exposure' is required (§4.1); write 'none known' or list each exposure")

    existing = lockstate.read_lock(wd)
    last = last_lock_record(wd)
    if existing:
        state, detail, _ = lockstate.quick_status(wd)
        if state == "tampered":
            raise DdaError(f"lock state tampered: {detail} — stop and ask (§3.2 case 8)", EXIT_CHAIN)
        if existing["lock_hash"] == comp.lock_hash:
            return {"noop": True, **{k: v for k, v in existing.items() if not k.startswith("_")}}
        if not amend:
            raise DdaError(f"spec, config, or definitions changed since lock v{existing['version']}; "
                           "re-lock as an amendment: `dda lock --amend \"<reason>\"` (§3.1)")
    elif last:
        raise DdaError("ledger records a lock but spec.lock is missing — stop and ask (§3.2 case 8)", EXIT_CHAIN)
    elif amend:
        raise DdaError("nothing to amend: no lock yet; run `dda lock`")

    version = (last.get("version", 0) if last else 0) + 1
    found = exposure(wd, comp.aliases, None, None)
    label = label_for(found, prior)
    locked_ts = time.time()
    watermarks = {"runs": _last_seq(runs_log(wd)), "audit": _last_seq(audit_log(wd)), "unbound": _last_seq(unbound_log())}

    vpath = wd.specs_dir / f"v{version}.md"
    if vpath.exists():
        raise DdaError(f"{vpath} already exists but the ledger has no v{version} lock — stop and ask (§3.2 case 8)",
                       EXIT_CHAIN)
    wd.specs_dir.mkdir(parents=True, exist_ok=True)
    with open(vpath, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(spec_text)

    lock = {
        "format": lockstate.LOCK_FILE_FORMAT,
        "version": version,
        "lock_hash": comp.lock_hash,
        "spec_hash": comp.spec_hash,
        "config_hash": comp.config_hash,
        "pins": comp.pins,
        "aliases": comp.aliases,
        "tier": comp.tier,
        "rung": comp.rung,
        "label": label,
        "locked_at": chain.now_iso(),
        "locked_ts": round(locked_ts, 3),
        "watermarks": watermarks,
        "amend_reason": amend,
        "prev_lock_hash": existing["lock_hash"] if existing else None,
        "milestone": wd.milestone,
    }
    summary = {k: len(v) for k, v in found.items() if v}
    chain.append(ledger_path(wd), {
        "type": "amendment" if existing else "lock", "version": version, "lock_hash": comp.lock_hash,
        "label": label, "post_data": label.startswith("post-data"), "reason": amend, "watermarks": watermarks,
        "exposure": summary, "spec_file": f"specs/v{version}.md", "tier": comp.tier, "rung": comp.rung,
    })
    with open(wd.lock_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(lock, fh, indent=2, sort_keys=True)
        fh.write("\n")
    lockstate.write_cache(wd, lockstate.read_lock(wd))

    from . import binding
    binding.refresh_registry(wd)

    files = [wd.spec_path, vpath, wd.lock_path, ledger_path(wd), wd.config_path, wd.root / ".gitignore",
             runs_log(wd), audit_log(wd), specs_tried(wd)]
    files += [wd.definitions / f"{p.split('@', 1)[0]}.md" for p in comp.pins]
    if blobs_dir(wd).is_dir() and any(blobs_dir(wd).iterdir()):
        files.append(blobs_dir(wd))
    sha = git_commit(wd.root, files, f"dda lock v{version} {comp.lock_hash[:12]} ({label})"
                     + (f"\n\nAmendment: {amend}" if amend else ""))
    lock["commit"] = sha
    lock["exposure"] = found
    lock["merged_spills"] = merged
    return lock


# ---------- gate G4 ----------

def write_wayfinder(wd: Workdir, gate: str, passed: bool, reason: str) -> None:
    line = f"{gate}: {'pass' if passed else 'fail'} — {reason}"
    with open(wd.wayfinder_path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(line + "\n")


def gate_g6(wd: Workdir) -> tuple[bool, str, dict]:
    """Analyze gate (§3 stage 6): no orphan runs, frozen bodies, ledger reasons, heartbeat complete."""
    from . import kernel as _kernel
    problems: list[str] = []
    lock = lockstate.read_lock(wd)
    if not lock:
        return False, "G6 fail: no spec.lock (run `dda lock` first)", {}
    state, detail, live = lockstate.quick_status(wd)
    if state != "valid":
        return False, f"G6 fail: lock is not valid ({state}: {detail}); re-lock before Analyze", {}
    comp = lockhash.compute(wd)
    if comp.lock_hash != lock["lock_hash"]:
        return False, "G6 fail: lock does not match the live spec/config (run `dda lock --amend \"<reason>\"`)", {}
    last = last_lock_record(wd)
    if not last or last.get("lock_hash") != lock["lock_hash"]:
        return False, "G6 fail: no ledger lock entry for this lock hash", {}
    chain_problems, _ = verify_all(wd)
    if chain_problems:
        problems.append(f"chains broken: {'; '.join(chain_problems[:3])}")
    regs = _kernel.registrations(wd)
    freezes = {r.get("variant"): r.get("frozen_hash")
               for r in chain.read_records(specs_tried(wd)) if r.get("type") == "freeze"}
    runs = [r for r in chain.read_records(specs_tried(wd)) if r.get("type") == "run"]
    locked = _kernel.locked_variant_id(wd)
    dones = [r for r in chain.read_records(runs_log(wd)) if r.get("type") == "done" and r.get("kind") == "data"]

    orphans = sorted({str(r.get("variant") or "<none>") for r in dones if r.get("variant") not in regs})
    if orphans:
        problems.append(f"orphan runs: data reads with no registered variant ({', '.join(orphans)})")
    for r in runs:
        vid = r.get("variant")
        if vid not in regs:
            problems.append(f"orphan kernel run {r.get('run_id')} under unknown variant {vid!r}")
        elif freezes.get(vid) and r.get("body_hash") != freezes.get(vid):
            problems.append(f"variant {vid!r} ran body {str(r.get('body_hash'))[:12]} after freezing "
                            f"{str(freezes.get(vid))[:12]}")
        kp = wd.analysis / str(r.get("kernel") or "")
        if not kp.is_file():
            problems.append(f"run {r.get('run_id')} of variant {vid!r} has no kernel record")
            continue
        # The `run` entry hash-binds its kernel record: a hand-edited
        # record file no longer matches and fails here.
        if not r.get("kernel_hash"):
            problems.append(f"run {r.get('run_id')} of variant {vid!r} kernel record is not hash-bound "
                            "(no kernel_hash on the run entry; re-run with this build)")
            continue
        try:
            actual = hashlib.sha256(kp.read_bytes()).hexdigest()
        except OSError as e:
            problems.append(f"run {r.get('run_id')} of variant {vid!r} kernel record unreadable ({e})")
            continue
        if actual != r.get("kernel_hash"):
            problems.append(f"run {r.get('run_id')} of variant {vid!r} kernel record hash mismatch "
                            "(edited or forked?)")
            continue
        # IPC binding (§10.1): the record must come from the locked-subprocess
        # path (`ipc: true`, policy hash matching this run entry) and be
        # bound to the same lock hash. A hand-written record that merely
        # carries a kernel_hash fails here.
        try:
            rec = json.loads(kp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            rec = {}
        if not rec.get("ipc"):
            problems.append(f"run {r.get('run_id')} of variant {vid!r} kernel record predates the "
                            "locked-subprocess IPC path (no ipc marker; re-run with this build)")
        elif rec.get("lock_hash") != r.get("lock_hash"):
            problems.append(f"run {r.get('run_id')} of variant {vid!r} kernel record lock hash "
                             "does not match the run entry")
        elif not r.get("policy_hash") or rec.get("policy_hash") != r.get("policy_hash"):
            problems.append(f"run {r.get('run_id')} of variant {vid!r} kernel record policy hash "
                            "does not match the run entry (policy snapshot mismatch?)")
    # Every successful run must pair with a kernel-start in the audit log:
    # a `run` entry plus a kernel JSON with no booted kernel behind them
    # is a fabricated run. kernel-start reaches the log only through the
    # parent's IPC import (§10.1), so the pairing also proves the import
    # ran. (Failed starts never ran user code, so they are exempt from
    # the pairing.)
    started = set()
    for r in chain.read_records(audit_log(wd)):
        if r.get("type") == "audit" and r.get("event") in ("kernel-start", "kernel-launch"):
            rid = r.get("run_id")
            if rid:
                started.add(str(rid))
    for r in runs:
        if r.get("returncode", 0) == 0 and str(r.get("run_id")) not in started:
            problems.append(f"run {r.get('run_id')} of variant {r.get('variant')!r} has no kernel-start "
                            "in the audit log (kernel never started?)")
    reg_ledger = {(l.get("variant"), (l.get("why") or "").strip()) for l in chain.read_records(ledger_path(wd))
                  if l.get("type") == "variant-registered"}
    for vid in sorted(regs):
        if not any(v == vid and w for v, w in reg_ledger):
            problems.append(f"variant {vid!r} has no ledger entry with a reason")
    # The kernel audit log is the independent second source (§6.8): every
    # kernel data-open must map to a data `done` with the same run id.
    run_ids = {str(r.get("call")) for r in dones if r.get("call")}
    stray = set()
    for r in chain.read_records(audit_log(wd)):
        if r.get("type") == "audit" and r.get("event") in ("open", "duckdb-read", "polars-read", "pyarrow-read"):
            if r.get("aliases") and str(r.get("run_id") or "") not in run_ids:
                stray.add(str(r.get("run_id") or "<none>"))
    if stray:
        problems.append(f"audit log shows data opens with no matching run ({', '.join(sorted(stray))}): "
                        "hook fault or evasion (§6.8)")
    # Heartbeat complete: every session with runs.log lines has a verifiable
    # heartbeat log, and every seen call id has a matching done.
    sessions = {str(r.get("session") or "") for r in chain.read_records(runs_log(wd))} - {""}
    for s in sorted(sessions):
        hp = heartbeat_log(s)
        if not hp.is_file():
            problems.append(f"session {s}: runs.log lines but no heartbeat log (hook fault, §6.8)")
        else:
            problems += [f"heartbeat {s}: {p}" for p in chain.verify(hp)[:2]]
    seen = {(str(r.get("session")), str(r.get("call"))) for r in chain.read_records(runs_log(wd))
            if r.get("type") == "seen" and r.get("call")}
    donekeys = {(str(r.get("session")), str(r.get("call"))) for r in chain.read_records(runs_log(wd))
                if r.get("type") == "done" and r.get("call")}
    missing = sorted(f"{s}/{c}" for s, c in seen - donekeys)
    if missing:
        problems.append(f"runs.log seen without done (hook fault): {', '.join(missing[:5])}")
    info = {"variants": len(regs), "runs": len(runs), "locked": locked, "orphans": sorted(orphans)}
    if problems:
        return False, "G6 fail: " + "; ".join(problems[:6]), info
    tried = len(regs) + ledger_summary(wd)["versions"]
    return True, (f"G6 pass: {len(dones)} data run(s) under {len(regs)} registered variant(s) "
                  f"({tried} tried incl. spec versions), locked variant {locked or 'none marked'}, "
                  "heartbeat complete"), info


def gate_g4(wd: Workdir) -> tuple[bool, str, dict]:
    wd.require_initialized()
    lock = lockstate.read_lock(wd)
    if not lock:
        return False, "no lock; run `dda lock`", {}
    state, detail, _ = lockstate.quick_status(wd)
    if state != "valid":
        return False, f"lock not valid ({state}: {detail})", {}
    comp = lockhash.compute(wd)
    if comp.lock_hash != lock["lock_hash"]:
        return False, "lock hash does not recompute", {}
    last = last_lock_record(wd)
    if not last or last.get("lock_hash") != lock["lock_hash"] or last.get("version") != lock["version"]:
        return False, "spec.lock does not match the last ledger lock entry", {}
    problems, merged = verify_all(wd)
    if problems:
        return False, "evidence chain: " + "; ".join(problems), {}
    found = exposure(wd, lock["aliases"], lock.get("watermarks"), lock.get("locked_ts"))
    prior = lockhash.parse_sections(read_text_lf(wd.spec_path)).get("Prior exposure", "")
    recomputed = label_for(found, prior)
    eff = lockstate.worst_label(ledger_summary(wd)["effective_label"], recomputed)
    if eff != ledger_summary(wd)["effective_label"]:
        sessions = sorted({f.get("session") for k in ("unbound", "other_workdirs", "session_history", "rebind")
                           for f in found[k] if f.get("session")})
        chain.append(ledger_path(wd), {"type": "relabel", "version": lock["version"], "label": eff,
                                       "reason": "G4 exposure scan", "sessions": sessions,
                                       "exposure": {k: len(v) for k, v in found.items() if v}})
    tier = lock.get("tier")
    notes = [f"lock v{lock['version']} {lock['lock_hash'][:12]} ({eff})"]
    if merged:
        notes.append(f"merged {merged} spill file(s)")
    if found["unbound"]:
        notes.append("unbound sessions: " + ", ".join(sorted({f['session'] for f in found['unbound'] if f.get('session')})))
    if found["session_history"] or found["rebind"]:
        notes.append("workdir hopping: " + ", ".join(sorted({f['session'] for f in found['session_history'] + found['rebind']
                                                             if f.get('session')})))
    # Config approval (§4.5): a `config` approval for the exact config hash.
    from . import approvals as _approvals
    comp_hash = lockhash.config_hash(wd)
    status = _approvals.config_status(wd)
    st = status.get("state")
    if st == "verified":
        notes.append(f"config approval verified ({status.get('detail')})")
    elif st == "downgraded":
        notes.append(f"config approval DOWNGRADED to unverified: {status.get('detail')}")
        st = "unverified"
    elif st == "unverified":
        notes.append(f"config approval unverified (agent could have produced it): {status.get('detail')}")
    elif st == "missing":
        notes.append(f"no config approval for config {comp_hash[:12]}")
    else:
        notes.append(f"config approval unknown: {status.get('detail')}")
        st = "missing"
    if tier == "EXPLORE":
        if st == "missing":
            notes.append("unapproved config disclosed at EXPLORE")
        passed = True
    elif st == "verified":
        passed = True
    elif st == "unverified":
        notes.append("human approval unverified (agent could have produced it)")
        if tier == "PUBLISH":
            notes.append("PUBLISH needs a verified config approval: parked (§3.2 case 9)")
            passed = False
        else:
            passed = True
    else:
        notes.append(f"data reads block at {tier or 'undeclared tier'} until a human approves the new config "
                     f"(`dda approve config` in their own terminal, then `dda approved config`)")
        passed = False
    return passed, "; ".join(notes), {"label": eff, "exposure": found, "config_approval": st}


__all__ = ["do_lock", "gate_g4", "verify_all", "ledger_summary", "last_lock_record", "exposure", "label_for",
           "runs_log", "audit_log", "ledger_path", "specs_tried", "approvals_index", "unbound_log", "heartbeat_log",
           "blobs_dir", "workdir_chains", "write_wayfinder", "in_git_repo", "_git",
           "git_safety_scan", "GIT_SAFETY_EXTS"]
