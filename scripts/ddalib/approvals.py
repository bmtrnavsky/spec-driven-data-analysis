"""Human approval artifacts (spec §4.5).

An approval is a git commit, made by an approver in their own terminal with
`dda approve <kind> <artifact>`, that adds exactly one file
`.analysis/approvals/<kind>-<artifact-hash>.json` and is signed. Kinds:
tier, spec, amendment, signoff, definition, correction, config.

`dda approved <kind> <artifact>` verifies the commit (signature via
`git verify-commit`, signer against the approver chain, exactly-one-file,
reachability, artifact match, and `dda doctor`'s key checks passing now)
and appends the result to the chained `approvals.index.jsonl`, so a later
deletion is visible. Anything that fails verification is recorded as
**unverified** — disclosed at DECIDE, parking at PUBLISH (§3.2 case 9).
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path

from . import chain, lockhash
from .layout import DdaError, Workdir, load_config, read_text_lf

KINDS = ("tier", "spec", "amendment", "signoff", "definition", "correction", "config")
FORMAT = "dda-approval-v1"
_ARTIFACT_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._\-]{1,127}$")


def approvals_dir(wd: Workdir) -> Path:
    return wd.analysis / "approvals"


def approval_rel(kind: str, artifact: str) -> str:
    return f".analysis/approvals/{kind}-{artifact}.json"


def approval_path(wd: Workdir, kind: str, artifact: str) -> Path:
    return approvals_dir(wd) / f"{kind}-{artifact}.json"


def check_kind_artifact(kind: str, artifact: str) -> None:
    if kind not in KINDS:
        raise DdaError(f"unknown approval kind {kind!r} (kinds: {', '.join(KINDS)})")
    if not _ARTIFACT_RE.match(artifact or ""):
        raise DdaError(f"bad artifact {artifact!r}: must be a filename-safe hash/token")


def current_artifact(wd: Workdir, kind: str) -> str | None:
    """The artifact hash the current workdir state requires, if computable."""
    if kind == "config":
        return lockhash.config_hash(wd)
    if kind in ("spec", "amendment"):
        if not wd.spec_path.is_file():
            return None
        return lockhash.sha256_hex(lockhash.normalized_spec(read_text_lf(wd.spec_path)))
    return None


def _git(wd: Workdir, *args, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(wd.root), *args],
                          capture_output=True, text=True, check=False)


def _git_ok(wd: Workdir, *args) -> bool:
    return _git(wd, *args, check=False).returncode == 0


def _norm_fp(s: str) -> str:
    return re.sub(r"[^0-9A-Za-z]", "", s or "").upper()


def approver_matches(approvers: list, *candidates: str) -> str | None:
    """Return the approver name whose key matches a candidate, else None.

    Exact-only (§4.5): a candidate matches when its normalized form EQUALS
    the approver's normalized ``fingerprint``/``key_id`` (case/punctuation
    differences ignored), or its whitespace-normalized form EQUALS the
    approver's full ``key``. Substrings never match, and names never match:
    ``%GS``/``%GK`` signer text is self-asserted and forgeable without the
    key, so only ``%GF``/``%GP``-style key material counts.
    """
    normed: set[str] = set()
    raws: set[str] = set()
    for c in candidates:
        if c is None:
            continue
        s = str(c)
        if not s.strip():
            continue
        raws.add(" ".join(s.split()))
        for tok in [s, *s.split()]:
            n = _norm_fp(tok)
            if n:
                normed.add(n)
    for a in approvers:
        if not isinstance(a, dict):
            continue
        for key in ("fingerprint", "key_id"):
            v = a.get(key)
            if isinstance(v, str) and v.strip():
                nv = _norm_fp(v)
                if nv and nv in normed:
                    return a.get("name")
        k = a.get("key")
        if isinstance(k, str) and k.strip():
            if " ".join(k.split()) in raws:
                return a.get("name")
    return None


def fingerprints_of(approvers: list) -> list[str]:
    out = []
    for a in approvers:
        if isinstance(a, dict):
            for key in ("fingerprint", "key_id", "key"):
                v = a.get(key)
                if isinstance(v, str) and v.strip():
                    out.append(f"{a.get('name')}:{v.strip()[:64]}")
                    break
    return out


# ---------- dda approve ----------

def do_approve(wd: Workdir, kind: str, artifact: str | None = None,
               key: str | None = None, sign: bool = True, message: str | None = None) -> dict:
    """Write the approval file and commit it (signed unless --no-sign)."""
    wd.require_initialized()
    if artifact is None:
        artifact = current_artifact(wd, kind)
        if artifact is None:
            raise DdaError(f"`dda approve {kind}` needs an explicit artifact "
                           f"(only config/spec/amendment default from the current workdir state)")
    check_kind_artifact(kind, artifact)
    try:
        cfg = load_config(wd)
    except DdaError as exc:
        raise DdaError(f"cannot approve with an invalid config.yaml: {exc}") from None
    rel = approval_rel(kind, artifact)
    path = approval_path(wd, kind, artifact)
    record = {
        "format": FORMAT,
        "kind": kind,
        "artifact": artifact,
        "workdir_id": wd.id,
        "config_hash": lockhash.config_hash(wd),
        "spec_hash": current_artifact(wd, "spec"),
        "approvers": cfg.get("approvers") or [],
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "note": message or "",
    }
    if path.is_file():
        try:
            if json.loads(path.read_text(encoding="utf-8")).get("artifact") == artifact:
                tracked = _git(wd, "ls-files", "--", rel).stdout.strip()
                if tracked:
                    log = _git(wd, "log", "--diff-filter=A", "--format=%H", "--", rel).stdout.strip()
                    if log:
                        raise DdaError(f"{rel} is already approved (commit {log.split()[0][:12]}); "
                                       f"verify it with `dda approved {kind} {artifact}`")
        except (ValueError, OSError):
            pass
    approvals_dir(wd).mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    if _git(wd, "rev-parse", "--show-toplevel").returncode != 0:
        raise DdaError(f"{wd.root} is not a git repo; approvals must be committable")
    msg = message or f"dda approve {kind} {artifact[:16]}"
    _git(wd, "add", "--", rel)
    pre: list[str] = []
    cmd = ["commit"]
    if sign:
        cmd.append("-S")
        if key:
            cmd.append(f"--gpg-sign={key}")
    else:
        pre += ["-c", "commit.gpgsign=false", "-c", "tag.gpgSign=false"]
    if not _git(wd, "config", "--get", "user.email").stdout.strip():
        pre += ["-c", "user.name=dda", "-c", "user.email=dda@localhost"]
    cmd += ["--no-verify", "-q", "-m", msg, "--", rel]
    r = _git(wd, *pre, *cmd)
    if r.returncode != 0:
        err = (r.stderr or r.stdout).strip()[-400:]
        if sign:
            raise DdaError(f"signing the approval commit failed ({err}); configure the approver key "
                           f"or re-run with --no-sign to record an unverified approval")
        raise DdaError(f"committing the approval failed ({err})")
    sha = _git(wd, "rev-parse", "HEAD").stdout.strip()
    # The commit must add exactly this one file.
    if _only_added_file(wd, sha) != rel:
        raise DdaError(f"approval commit {sha[:12]} touches more than {rel}; "
                       "an approval commit must add exactly one file (§4.5)")
    return {"kind": kind, "artifact": artifact, "file": rel, "commit": sha, "signed": sign}


def _only_added_file(wd: Workdir, sha: str) -> str | None:
    r = _git(wd, "show", "--pretty=format:", "--name-status", sha)
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    if len(lines) != 1:
        return None
    m = re.match(r"^A\t(.*)$", lines[0])
    return m.group(1).replace("\\", "/") if m else None


# ---------- dda approved ----------

def _adding_commits(wd: Workdir, rel: str) -> list[str]:
    r = _git(wd, "log", "--diff-filter=A", "--format=%H", "--", rel)
    if r.returncode != 0:
        return []
    return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]


def _signer_fields(wd: Workdir, sha: str) -> tuple[bool, list[str]]:
    v = _git(wd, "verify-commit", sha)
    sig_ok = v.returncode == 0
    sig_text = (v.stderr or "") + "\n" + (v.stdout or "")
    f = _git(wd, "log", "-1", "--format=%G?%n%GF%n%GP%n%GS%n%GK", sha)
    fields = [ln.strip() for ln in (f.stdout.splitlines() + sig_text.splitlines()) if ln.strip()]
    return sig_ok, fields


def _config_chain(wd: Workdir) -> tuple[dict[str, dict], list[str]]:
    """Walk every config approval commit oldest-first.

    Returns ({artifact: {commit, signer, sig_ok, verified}}, problems).
    The first config approval is trust-on-first-use (signer in its own
    approvers snapshot); every later one must be signed by a key from the
    previous approval's approvers set (§4.5).
    """
    r = _git(wd, "log", "--reverse", "--topo-order", "--diff-filter=A", "--format=%H", "--",
             ".analysis/approvals")
    if r.returncode != 0:
        return {}, []
    entries: list[dict] = []
    for sha in [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]:
        only = _only_added_file(wd, sha)
        if not only or not only.startswith(".analysis/approvals/config-"):
            continue
        try:
            content = _git(wd, "show", f"{sha}:{only}").stdout
            rec = json.loads(content)
        except (ValueError, subprocess.SubprocessError):
            continue
        if not isinstance(rec, dict) or rec.get("kind") != "config" or not rec.get("artifact"):
            continue
        sig_ok, fields = _signer_fields(wd, sha)
        entries.append({"sha": sha, "artifact": rec["artifact"],
                        "approvers": rec.get("approvers") or [], "sig_ok": sig_ok, "fields": fields})
    by_artifact: dict[str, dict] = {}
    problems: list[str] = []
    prev_approvers: list | None = None
    for e in entries:
        name = approver_matches(e["approvers"], *e["fields"])
        if not e["sig_ok"]:
            problems.append(f"{e['sha'][:12]}: bad signature")
            ok = False
        elif prev_approvers is None:
            ok = bool(name)  # TOFU: first approval self-consistent with its own approvers
            if not ok:
                problems.append(f"{e['sha'][:12]}: TOFU signer matches no approver in its own snapshot")
        else:
            ok = approver_matches(prev_approvers, *e["fields"]) is not None
            if not ok:
                problems.append(f"{e['sha'][:12]}: signer not in the previous approved approver set")
        by_artifact[e["artifact"]] = {"commit": e["sha"], "signer": name, "sig_ok": e["sig_ok"],
                                      "verified": ok}
        prev_approvers = e["approvers"]
    return by_artifact, problems


def verify_approval(wd: Workdir, kind: str, artifact: str) -> dict:
    """Check an approval without recording. Returns a verdict dict."""
    from . import doctor as _doctor
    wd.require_initialized()
    check_kind_artifact(kind, artifact)
    rel = approval_rel(kind, artifact)
    path = approval_path(wd, kind, artifact)
    if not path.is_file():
        return {"kind": kind, "artifact": artifact, "verified": False,
                "reason": f"{rel} not found; ask Brad to run `dda approve {kind} {artifact[:16]}`"}
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        return {"kind": kind, "artifact": artifact, "verified": False,
                "reason": f"{rel} is not valid JSON ({exc})"}
    if content.get("kind") != kind or content.get("artifact") != artifact:
        return {"kind": kind, "artifact": artifact, "verified": False,
                "reason": f"{rel} names {content.get('kind')}/{content.get('artifact')}, not {kind}/{artifact}"}
    cands = [s for s in _adding_commits(wd, rel) if _git_ok(wd, "merge-base", "--is-ancestor", s, "HEAD")]
    if not cands:
        return {"kind": kind, "artifact": artifact, "verified": False,
                "reason": f"{rel} is not committed on this branch; approvals must be git commits (§4.5)"}
    sha = cands[0]
    if _only_added_file(wd, sha) != rel:
        return {"kind": kind, "artifact": artifact, "verified": False,
                "reason": f"commit {sha[:12]} touches more than {rel}; an approval commit adds exactly one file"}
    expected = current_artifact(wd, kind)
    if expected is not None and artifact != expected:
        return {"kind": kind, "artifact": artifact, "verified": False, "commit": sha,
                "reason": f"approval covers {artifact[:12]} but the current {kind} is {expected[:12]} "
                          f"(an approval of an older version does not cover this one)"}
    sig_ok, fields = _signer_fields(wd, sha)
    try:
        approvers = load_config(wd).get("approvers") or []
    except DdaError as exc:
        return {"kind": kind, "artifact": artifact, "verified": False, "commit": sha,
                "reason": f"config.yaml does not parse, so no signer can match ({exc})"}
    signer = approver_matches(approvers, *fields)
    chain_note = ""
    if kind == "config":
        by_artifact, problems = _config_chain(wd)
        entry = by_artifact.get(artifact)
        if entry is None or not entry["verified"]:
            detail = "; ".join(problems[-2:]) if problems else "chain walk failed"
            return {"kind": kind, "artifact": artifact, "verified": False, "commit": sha,
                    "signer": signer, "sig_ok": sig_ok,
                    "reason": f"config approver chain does not verify ({detail})"}
        signer = entry["signer"] or signer
        if problems:
            chain_note = f" (earlier chain notes: {'; '.join(problems[-2:])})"
    elif not approvers:
        return {"kind": kind, "artifact": artifact, "verified": False, "commit": sha, "sig_ok": sig_ok,
                "reason": "config.yaml lists no approvers, so no signer can be matched"}
    elif not sig_ok or not signer:
        why = "bad signature" if not sig_ok else "signer matches no approver in config.yaml"
        return {"kind": kind, "artifact": artifact, "verified": False, "commit": sha,
                "signer": signer, "sig_ok": sig_ok, "reason": f"{why}{chain_note}"}
    key_failures = [c for c in _doctor.key_checks(wd) if c["status"] == "fail"]
    if key_failures:
        return {"kind": kind, "artifact": artifact, "verified": False, "commit": sha,
                "signer": signer, "sig_ok": sig_ok,
                "reason": "dda doctor key checks fail now (" +
                          "; ".join(c["name"] for c in key_failures) +
                          "); every approval downgrades to unverified until fixed (§4.5)"}
    return {"kind": kind, "artifact": artifact, "verified": True, "commit": sha,
            "signer": signer, "sig_ok": sig_ok,
            "reason": f"verified: {kind} {artifact[:12]} signed by {signer or 'an approver'}{chain_note}"}


def do_approved(wd: Workdir, kind: str, artifact: str | None = None) -> dict:
    """Verify an approval and record the verdict in approvals.index.jsonl."""
    from . import ledger
    if artifact is None:
        artifact = current_artifact(wd, kind)
        if artifact is None:
            raise DdaError(f"`dda approved {kind}` needs an explicit artifact")
    verdict = verify_approval(wd, kind, artifact)
    chain.append(ledger.approvals_index(wd), {
        "type": "approval", "kind": kind, "artifact": artifact,
        "commit": verdict.get("commit"), "signer": verdict.get("signer"),
        "sig_ok": verdict.get("sig_ok"), "verified": verdict["verified"],
        "reason": verdict["reason"],
    })
    return verdict


def latest_record(wd: Workdir, kind: str, artifact: str) -> dict | None:
    """Newest approvals.index.jsonl verdict for this kind+artifact, else None."""
    from . import ledger
    recs = [r for r in chain.read_records(ledger.approvals_index(wd))
            if r.get("type") == "approval" and r.get("kind") == kind and r.get("artifact") == artifact]
    return recs[-1] if recs else None


def config_status(wd: Workdir) -> dict:
    """Status of the config approval for the current config hash.

    Never raises: unknown states come back as {state: ...} so G4 and the
    footer can report instead of crash.
    """
    try:
        ch = lockhash.config_hash(wd)
    except (DdaError, OSError) as exc:
        return {"state": "unknown", "detail": str(exc)}
    try:
        approvers = load_config(wd).get("approvers") or []
    except DdaError as exc:
        return {"state": "unknown", "config_hash": ch, "detail": str(exc)}
    rec = latest_record(wd, "config", ch)
    fps = fingerprints_of(approvers)
    base = {"config_hash": ch, "approvers": approvers, "fingerprints": fps}
    if rec is None:
        return {**base, "state": "missing", "detail": "no config approval for this config hash"}
    if rec.get("verified"):
        from . import doctor as _doctor
        fails = [c for c in _doctor.key_checks(wd) if c["status"] == "fail"]
        if fails:
            return {**base, "state": "downgraded",
                    "detail": "doctor key checks fail now: " + ", ".join(c["name"] for c in fails),
                    "record": rec}
        return {**base, "state": "verified", "detail": f"commit {str(rec.get('commit') or '')[:12]}",
                "record": rec}
    return {**base, "state": "unverified", "detail": str(rec.get("reason") or "recorded unverified"),
            "record": rec}


__all__ = ["KINDS", "approvals_dir", "approval_rel", "approval_path", "check_kind_artifact",
           "current_artifact", "do_approve", "do_approved", "verify_approval", "latest_record",
           "config_status", "approver_matches", "fingerprints_of"]
