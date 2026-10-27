"""Evidence files, `dda lock`, exposure scanning, and gate G4 (spec §3, §4.2, §4.4, §6.0).

Ledger records (JSON lines, hash-chained through chain.append):
  lock / amendment  version, lock_hash, label, post_data, reason, watermarks, exposure summary
  relabel           version, label, reason       (G4 found exposure the lock missed)
  rebind / abandon  session bookkeeping (§6.0)
"""
from __future__ import annotations

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


def exposure(wd: Workdir, aliases: list[str], watermarks: dict | None, locked_ts: float | None) -> dict:
    """Data-root reads of `aliases` that precede the lock.

    watermarks None = scan everything (a lock being made now)."""
    al = set(aliases)
    wm = watermarks or {}
    found = {"runs": [], "audit": [], "unbound": [], "other_workdirs": []}
    for rec in chain.read_records(runs_log(wd)):
        if wm.get("runs") is not None and rec.get("seq", 0) > wm["runs"]:
            break
        if rec.get("type") == "done" and rec.get("kind") == "data" and al & set(rec.get("aliases") or []):
            found["runs"].append({"seq": rec.get("seq"), "session": rec.get("session"), "aliases": rec.get("aliases")})
    for rec in chain.read_records(audit_log(wd)):
        if wm.get("audit") is not None and rec.get("seq", 0) > wm["audit"]:
            break
        if rec.get("kind") in ("audit", "open", "data") and al & set(rec.get("aliases") or []):
            found["audit"].append({"seq": rec.get("seq"), "aliases": rec.get("aliases")})
    for rec in chain.read_records(unbound_log()):
        hits = [m for m in rec.get("matches") or [] if m.get("workdir_id") == wd.id and m.get("alias") in al]
        if hits:
            found["unbound"].append({"seq": rec.get("seq"), "session": rec.get("session"), "tool": rec.get("tool"),
                                     "aliases": sorted({m["alias"] for m in hits})})
    # Workdir hopping: other active workdirs declaring the same locators (§6.0).
    from .binding import read_registry
    try:
        reg = read_registry()["workdirs"]
    except DdaError:
        reg = {}
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
    return found


def label_for(found: dict, prior_exposure: str) -> str:
    if found["unbound"] or found["other_workdirs"]:
        return "post-data (unbound access)"
    if found["runs"] or found["audit"]:
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
        sessions = sorted({f.get("session") for k in ("unbound", "other_workdirs") for f in found[k] if f.get("session")})
        chain.append(ledger_path(wd), {"type": "relabel", "version": lock["version"], "label": eff,
                                       "reason": "G4 exposure scan", "sessions": sessions,
                                       "exposure": {k: len(v) for k, v in found.items() if v}})
    tier = lock.get("tier")
    notes = [f"lock v{lock['version']} {lock['lock_hash'][:12]} ({eff})"]
    if merged:
        notes.append(f"merged {merged} spill file(s)")
    if found["unbound"]:
        notes.append("unbound sessions: " + ", ".join(sorted({f['session'] for f in found['unbound'] if f.get('session')})))
    # Config approval (§4.5) arrives in build phase 4.
    if tier == "EXPLORE":
        notes.append("config approval not built (phase 4): unapproved config disclosed")
        passed = True
    else:
        notes.append(f"config approval required at {tier or 'undeclared tier'} and not built until phase 4")
        passed = False
    return passed, "; ".join(notes), {"label": eff, "exposure": found}


__all__ = ["do_lock", "gate_g4", "verify_all", "ledger_summary", "last_lock_record", "exposure", "label_for",
           "runs_log", "audit_log", "ledger_path", "specs_tried", "approvals_index", "unbound_log", "heartbeat_log",
           "blobs_dir", "workdir_chains", "write_wayfinder", "in_git_repo", "_git"]
