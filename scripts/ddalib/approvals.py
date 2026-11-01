"""Human approval artifacts (spec §4.5) — M1 one-approval-model.

An approval is a git commit, made by an approver in their own terminal with
`dda approve <kind>`, that adds exactly one file
`.analysis/approvals/<kind>-<digest16>.json` and is signed. Kinds:
tier, spec, amendment, signoff, definition, correction, config.

The digest is content-addressed and computed ONLY by dda
(`canonical_payload`): a config digest, a normalized-spec digest, an
amendment digest (prev lock hash + new spec hash + teardown review-history
digest), a canonical-case digest, a normalized-definition digest, and a
signoff release digest (report bytes incl. footer + lock hash + verify.md
hash + gate-verdict digest). The approval file embeds the canonical payload;
gates execute the approved copy read from git (`approved_payload`), never
the working copy.

`verify_approval` returns a typed `ApprovalState` — MISSING, UNCOMMITTED,
STALE, BAD_SIG, UNKNOWN_SIGNER, DOWNGRADED, UNVERIFIED, VERIFIED. Callers
match the enum, never reason substrings. `do_approved` records
(kind, digest, commit, state) in `approvals.index.jsonl`, which the footer
reads.
"""
from __future__ import annotations

import enum
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path

from . import chain, lockhash
from .layout import DdaError, Workdir, load_config, read_text_lf

KINDS = ("tier", "spec", "amendment", "signoff", "definition", "correction", "config")
FORMAT = "dda-approval-v2"
FORMAT_V1 = "dda-approval-v1"
_DIGEST_RE = re.compile(r"^[0-9a-f]{4,64}$")


class ApprovalState(str, enum.Enum):
    """Typed approval verdict. Callers match members, never reason text."""

    MISSING = "missing"            # no committed approval for this digest
    UNCOMMITTED = "uncommitted"    # approval file exists but no commit on this branch
    STALE = "stale"                # approval is authentic but covers older state
    BAD_SIG = "bad_sig"            # commit signature does not verify
    UNKNOWN_SIGNER = "unknown_signer"  # signer matches no approver
    DOWNGRADED = "downgraded"      # doctor key checks fail right now
    UNVERIFIED = "unverified"      # unsigned (agent could have produced it)
    VERIFIED = "verified"          # signed by an approver, covers current state


def approvals_dir(wd: Workdir) -> Path:
    return wd.analysis / "approvals"


def approval_rel(kind: str, artifact: str) -> str:
    return f".analysis/approvals/{kind}-{artifact}.json"


def approval_path(wd: Workdir, kind: str, artifact: str) -> Path:
    return approvals_dir(wd) / f"{kind}-{artifact}.json"


def check_kind_artifact(kind: str, artifact: str | None = None) -> None:
    if kind not in KINDS:
        raise DdaError(f"unknown approval kind {kind!r} (kinds: {', '.join(KINDS)})")
    if artifact is not None and (".." in artifact or "/" in artifact or "\\" in artifact):
        raise DdaError(f"bad artifact {artifact!r}: must be a digest, not a path")


def current_artifact(wd: Workdir, kind: str) -> str | None:
    """Legacy helper: the artifact hash the current workdir state requires.

    Kept for v1-record coverage checks. New code uses `current_digest`.
    """
    if kind == "config":
        return lockhash.config_hash(wd)
    if kind in ("spec", "amendment", "tier"):
        if not wd.spec_path.is_file():
            return None
        return lockhash.sha256_hex(lockhash.normalized_spec(read_text_lf(wd.spec_path)))
    return None


# ---------- typed digests: computed only by dda (M1) ----------

def _review_history_digest(wd: Workdir) -> str:
    """Digest of the teardown-stage review history (goldfish calls + self re-reads).

    Scoped to teardown on purpose: an amendment approved at DECIDE must not
    go stale when post-result reviews land later.
    """
    from . import review as _review
    try:
        teardown_calls = _review.existing_calls(wd, "teardown")
    except (DdaError, OSError):
        teardown_calls = []
    try:
        self_dir = wd.analysis / "reviews" / "self"
        self_manifest = sorted(p.name for p in self_dir.iterdir() if p.is_file()) if self_dir.is_dir() else []
    except OSError:
        self_manifest = []
    canon = json.dumps({"calls": teardown_calls, "self": self_manifest}, sort_keys=True, default=str)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _ledger_last_lock(wd: Workdir) -> dict | None:
    from . import ledger as _ledger
    try:
        return _ledger.last_lock_record(wd)
    except (DdaError, OSError):
        return None


def _amendment_payload(wd: Workdir) -> tuple[str, str]:
    from . import ledger as _ledger
    try:
        comp = lockhash.compute(wd)
    except DdaError as exc:
        raise DdaError(f"cannot digest the amendment: {exc}") from None
    prev = "genesis"
    try:
        recs = [r for r in chain.read_records(_ledger.ledger_path(wd))
                if r.get("type") in ("lock", "amendment") and isinstance(r.get("version"), int)]
        cur_v = (_ledger_last_lock(wd) or {}).get("version")
        older = [r for r in recs if isinstance(cur_v, int) and r["version"] < cur_v]
        if older:
            prev = max(older, key=lambda r: r["version"]).get("lock_hash") or "genesis"
    except (DdaError, OSError):
        pass
    try:
        lock = _ledger_last_lock(wd)
        reason = str((lock or {}).get("reason") or "")
    except (DdaError, OSError):
        reason = ""
    payload = json.dumps({
        "prev_lock_hash": prev,
        "spec_hash": comp.spec_hash,
        "reason": reason,
        "review_history_digest": _review_history_digest(wd),
    }, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest(), payload


def _split_case_sections(text: str) -> dict[str, str]:
    """Split a correction case into {lowercased section title: body}.

    Unlike the spec parser, this accepts any ``##`` header (cases are not
    specs) and never raises on unknown sections — the digest binds content,
    not the section vocabulary.
    """
    sections: dict[str, list[str]] = {}
    current = "__preamble__"
    sections[current] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        m = re.match(r"^##\s+(.+?)\s*#*\s*$", line)
        if m:
            current = m.group(1).strip().rstrip(":").strip().lower()
            sections.setdefault(current, [])
            continue
        sections[current].append(line)
    return {k: "\n".join(v) for k, v in sections.items()}


def _case_trigger_list(sections: dict[str, str]) -> list[str]:
    """Trigger keys from the ``## Trigger keys`` section and any legacy
    inline ``Trigger keys: a, b`` line (pre-template cases)."""
    found: list[str] = []

    def _split_blob(blob: str) -> None:
        # Only key-list lines count: "-" bullets or an explicit
        # "Trigger keys:" line. Prose around them is ignored.
        for line in blob.splitlines():
            s = line.strip()
            if s.lower().startswith("trigger keys:"):
                s = s.split(":", 1)[1]
            elif s.startswith("-"):
                s = s[1:].strip()
            else:
                continue
            for t in re.split(r"[,;]", s):
                t = t.strip().strip("- \t")
                if t:
                    found.append(t)

    _split_blob(sections.get("trigger keys", ""))
    for line in sections.get("__preamble__", "").splitlines():
        if line.strip().lower().startswith("trigger keys:"):
            _split_blob(line)
    return sorted(set(found))


def _case_question(sections: dict[str, str]) -> str:
    q = sections.get("review question", "").strip()
    if q:
        body = "\n".join(
            ln for ln in q.splitlines()
            if not ln.strip().lower().startswith("review question:")
        ).strip()
        inline = next(
            (ln.split(":", 1)[1].strip() for ln in q.splitlines()
             if ln.strip().lower().startswith("review question:")), "")
        return body or inline
    for line in sections.get("__preamble__", "").splitlines():
        if line.strip().lower().startswith("review question:"):
            return line.split(":", 1)[1].strip()
    return ""


def _canonical_case(text: str) -> str:
    """Canonical correction payload: fixed sections in a fixed order.

    Only the bound sections count — Trigger keys (sorted), the verbatim
    Deterministic check block, Review question, Source correction. Edits
    inside them re-key the case (the edited copy is an unapproved draft;
    the approved copy binds). Both the current template (``##`` sections)
    and legacy inline ``Trigger keys:`` / ``Review question:`` lines
    canonicalize, so old approved cases keep verifying.
    """
    sections = _split_case_sections(text)
    triggers = _case_trigger_list(sections)
    parts = [
        "## Trigger keys\n" + "\n".join(f"- {t}" for t in triggers),
        "## Deterministic check\n" + sections.get("deterministic check", "").strip(),
        "## Review question\n" + lockhash.normalize_ws(_case_question(sections)),
        "## Source correction\n" + lockhash.normalize_ws(sections.get("source correction", "")),
    ]
    return "\n".join(parts) + "\n"


def canonical_case(text: str) -> str:
    """Canonical form of a correction case (also used by the matcher)."""
    return _canonical_case(text)


def _correction_payload(wd: Workdir, selector: str) -> tuple[str, str]:
    case = wd.root / "evals" / "corrections" / selector / "case.md"
    if not case.is_file():
        raise DdaError(f"no correction case {selector!r} at evals/corrections/{selector}/case.md")
    try:
        payload = _canonical_case(case.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DdaError(f"cannot read correction case {selector!r}: {exc}") from None
    if not _case_trigger_list(_split_case_sections(payload)):
        raise DdaError(f"correction case {selector!r} names no trigger keys")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest(), payload


def _definition_payload(wd: Workdir, selector: str) -> tuple[str, str]:
    try:
        entry = (wd.definitions / f"{selector}.md").read_text(encoding="utf-8")
    except OSError:
        raise DdaError(f"no registry definition {selector!r} (definitions/{selector}.md)") from None
    payload = lockhash.normalize_ws(entry) + "\n"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest(), payload


def release_reports(wd: Workdir) -> dict[str, str]:
    """Report scope hashed into the signoff digest (mirrors the G8 scope)."""
    out: dict[str, str] = {}
    answer = wd.analysis / "answer.md"
    if answer.is_file():
        try:
            out[".analysis/answer.md"] = hashlib.sha256(answer.read_bytes()).hexdigest()
        except OSError:
            pass
    repdir = wd.root / "reports"
    if repdir.is_dir():
        for p in sorted(repdir.rglob("*.md")):
            if not p.is_file():
                continue
            try:
                rel = p.relative_to(wd.root).as_posix()
            except ValueError:
                continue
            try:
                out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError:
                continue
    return out


def _signoff_payload(wd: Workdir) -> tuple[str, str]:
    lock = _ledger_last_lock(wd)
    if not lock:
        raise DdaError("no lock yet; run `dda lock` before approving a signoff")
    from . import evaluate as _evaluate
    verdicts = _evaluate.evaluate(wd, through="G7")["verdicts"]
    partial = _evaluate.verdict_digest(verdicts)
    verify_file = wd.analysis / "verify.md"
    try:
        verify_hash = hashlib.sha256(verify_file.read_bytes()).hexdigest() if verify_file.is_file() else ""
    except OSError:
        verify_hash = ""
    reports = release_reports(wd)
    if not reports:
        raise DdaError("no report to sign off on (write .analysis/answer.md or reports/<slug>.md)")
    payload = json.dumps({
        "lock_hash": lock.get("lock_hash"),
        "verify_hash": verify_hash,
        "verdict_digest": partial,
        "reports": reports,
    }, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest(), payload


def canonical_payload(wd: Workdir, kind: str, selector: str | None = None) -> tuple[str, str]:
    """The (digest, canonical payload) the current workdir state requires.

    The ONLY place digests are computed. Raises DdaError when the digest is
    not computable from current state.
    """
    check_kind_artifact(kind)
    if kind == "config":
        return lockhash.config_hash(wd), read_text_lf(wd.config_path)
    if kind in ("spec", "tier"):
        if not wd.spec_path.is_file():
            raise DdaError(f"no spec.md; cannot digest {kind}")
        payload = lockhash.normalized_spec(read_text_lf(wd.spec_path))
        return lockhash.sha256_hex(payload), payload
    if kind == "amendment":
        return _amendment_payload(wd)
    if kind == "correction":
        if not selector:
            raise DdaError("`dda approve correction` needs a case selector (e.g. `dda approve correction 001`)")
        return _correction_payload(wd, selector)
    if kind == "definition":
        if not selector:
            raise DdaError("`dda approve definition` needs a definition name")
        return _definition_payload(wd, selector)
    if kind == "signoff":
        return _signoff_payload(wd)
    raise DdaError(f"unknown approval kind {kind!r}")


def current_digest(wd: Workdir, kind: str, selector: str | None = None) -> str | None:
    """Digest for the current state, or None when not computable."""
    try:
        return canonical_payload(wd, kind, selector)[0]
    except (DdaError, OSError):
        return None


# ---------- git plumbing ----------

def _git(wd: Workdir, *args, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(wd.root), *args],
                          capture_output=True, text=True, check=False)


def _git_ok(wd: Workdir, *args) -> bool:
    return _git(wd, *args, check=False).returncode == 0


def _norm_fp(s: str) -> str:
    return re.sub(r"[^0-9A-Za-z]", "", s or "").upper()


def approver_matches(approvers: list, *candidates: str) -> str | None:
    """Return the approver name whose key matches a candidate, else None.

    Exact-only (§4.5): a candidate matches when its WHOLE normalized form
    EQUALS the approver's normalized ``fingerprint``/``key_id``
    (case/punctuation differences ignored), or its whitespace-normalized
    WHOLE form EQUALS the approver's full ``key``. Substrings, tokens, and
    names never match: ``%GS``/``%GK`` signer text and ``git verify-commit``
    output are self-asserted and forgeable without the key (an attacker can
    embed a victim fingerprint in a user ID), so only whole ``%GF``/``%GP``
    values count. Callers holding structured multi-field lines (e.g. the
    ``ssh-add -l`` ``<bits> <fingerprint> <comment> (<type)>`` columns)
    must extract the fingerprint column themselves before calling.
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
        n = _norm_fp(s)
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
    """Compute the content digest, embed the canonical payload, commit it.

    `artifact`, when given, is a selector (correction case id, definition
    name) or must equal the computed digest — free-form tokens are rejected.
    """
    wd.require_initialized()
    check_kind_artifact(kind, artifact)
    selector = artifact if kind in ("correction", "definition") else None
    digest, payload = canonical_payload(wd, kind, selector)
    if artifact is not None and kind not in ("correction", "definition"):
        if not (artifact == digest or digest.startswith(artifact)):
            raise DdaError(f"explicit artifact tokens are removed: `dda approve {kind}` computes "
                           f"the digest from current state (current {digest[:16]}, got {artifact[:16]})")
    try:
        cfg = load_config(wd)
    except DdaError as exc:
        raise DdaError(f"cannot approve with an invalid config.yaml: {exc}") from None
    short = digest[:16]
    rel = approval_rel(kind, short)
    path = approval_path(wd, kind, short)
    record = {
        "format": FORMAT,
        "kind": kind,
        "digest": digest,
        "artifact": digest,  # compat alias; filename and binding key is the digest
        "selector": selector,
        "payload": payload,
        "workdir_id": wd.id,
        "config_hash": lockhash.config_hash(wd),
        "spec_hash": current_artifact(wd, "spec"),
        "approvers": cfg.get("approvers") or [],
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "note": message or "",
    }
    if path.is_file():
        try:
            if json.loads(path.read_text(encoding="utf-8")).get("digest") == digest:
                tracked = _git(wd, "ls-files", "--", rel).stdout.strip()
                if tracked:
                    log = _git(wd, "log", "--diff-filter=A", "--format=%H", "--", rel).stdout.strip()
                    if log:
                        raise DdaError(f"{rel} is already approved (commit {log.split()[0][:12]}); "
                                       f"verify it with `dda approved {kind}`")
        except (ValueError, OSError):
            pass
    approvals_dir(wd).mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    if _git(wd, "rev-parse", "--show-toplevel").returncode != 0:
        raise DdaError(f"{wd.root} is not a git repo; approvals must be committable")
    msg = message or f"dda approve {kind} {short}"
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
    return {"kind": kind, "artifact": digest, "digest": digest, "file": rel,
            "commit": sha, "signed": sign}


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
    # Key material only: whole %GF/%GP values. %GS/%GK signer text and
    # `git verify-commit` output are attacker-influenceable (a forged key
    # can carry a victim fingerprint in its user ID), so they are never
    # match candidates — sig_ok carries the cryptographic verdict.
    f = _git(wd, "log", "-1", "--format=%GF%n%GP", sha)
    fields = [ln.strip() for ln in f.stdout.splitlines() if ln.strip()]
    return sig_ok, fields


def _config_chain(wd: Workdir) -> tuple[dict[str, dict], list[str]]:
    """Walk every config approval commit oldest-first.

    Returns ({digest: {commit, signer, sig_ok, verified}}, problems).
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
        if not isinstance(rec, dict) or rec.get("kind") != "config":
            continue
        digest = rec.get("digest") or rec.get("artifact")
        if not digest:
            continue
        sig_ok, fields = _signer_fields(wd, sha)
        entries.append({"sha": sha, "digest": digest,
                        "approvers": rec.get("approvers") or [], "sig_ok": sig_ok, "fields": fields})
    by_digest: dict[str, dict] = {}
    problems: list[str] = []
    prev_approvers: list | None = None
    for e in entries:
        name = approver_matches(e["approvers"], *e["fields"])
        if not e["sig_ok"] and not e["fields"]:
            problems.append(f"{e['sha'][:12]}: unsigned (agent could have produced it)")
            ok = False
        elif not e["sig_ok"]:
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
        by_digest[e["digest"]] = {"commit": e["sha"], "signer": name, "sig_ok": e["sig_ok"],
                                  "verified": ok}
        prev_approvers = e["approvers"]
    return by_digest, problems


def _record_digest(rec: dict) -> str | None:
    d = rec.get("digest") or rec.get("artifact")
    return d if isinstance(d, str) and d else None


def _resolve_record(wd: Workdir, kind: str, ref: str | None) -> tuple[dict | None, str | None, str | None]:
    """Find the approval record for `ref` among committed approval commits.

    Returns (record, commit_sha, rel). `ref` may be a digest, a digest
    prefix, a selector (correction case id, definition name), or a legacy
    v1 artifact token. Ref None means the current digest.
    """
    want = ref or current_digest(wd, kind)
    if want is None:
        return None, None, None
    r = _git(wd, "log", "--reverse", "--topo-order", "--diff-filter=A", "--format=%H", "--",
             ".analysis/approvals")
    shas = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()] if r.returncode == 0 else []
    cands: list[tuple[dict, str, str]] = []
    for sha in shas:
        only = _only_added_file(wd, sha)
        if not only or not only.startswith(f".analysis/approvals/{kind}-"):
            continue
        try:
            rec = json.loads(_git(wd, "show", f"{sha}:{only}").stdout)
        except (ValueError, subprocess.SubprocessError):
            continue
        if not isinstance(rec, dict) or rec.get("kind") != kind:
            continue
        d = _record_digest(rec)
        if not d:
            continue
        if d == want or d.startswith(want) or want.startswith(d):
            cands.append((rec, sha, only))
        elif kind in ("correction", "definition") and rec.get("selector") == want:
            cands.append((rec, sha, only))
    if not cands:
        return None, None, None
    # Newest commit wins (re-approvals supersede).
    cands.sort(key=lambda c: shas.index(c[1]))
    return cands[-1]


def verify_approval(wd: Workdir, kind: str, artifact: str | None = None) -> dict:
    """Check an approval without recording. Returns a typed verdict dict.

    `state` is an `ApprovalState` value; `verified` is True only for
    VERIFIED. Payload/digest comparison uses the committed copy read from
    git, never the worktree file.
    """
    from . import doctor as _doctor
    wd.require_initialized()
    check_kind_artifact(kind, artifact)
    base = {"kind": kind, "artifact": artifact, "verified": False,
            "state": ApprovalState.MISSING.value}

    def fail(state: ApprovalState, reason: str, **extra) -> dict:
        return {**base, "state": state.value, "reason": reason, **extra}

    rec, sha, rel = _resolve_record(wd, kind, artifact)
    if rec is None:
        hint = f"`dda approve {kind}` in your own terminal, then `dda approved {kind}`"
        if kind in ("correction", "definition") and artifact and not _DIGEST_RE.match(artifact):
            hint = (f"`dda approve {kind} {artifact}` in your own terminal, then "
                    f"`dda approved {kind} {artifact}`")
        return fail(ApprovalState.MISSING,
                    f"no committed {kind} approval covers {artifact or 'current state'}; {hint}")
    assert sha is not None and rel is not None
    if not _git_ok(wd, "merge-base", "--is-ancestor", sha, "HEAD"):
        return fail(ApprovalState.UNCOMMITTED,
                    f"{rel} is committed as {sha[:12]} but that commit is not on this branch "
                    "(approvals must be git commits on this branch, §4.5)",
                    commit=sha, digest=_record_digest(rec))
    path = wd.root / rel
    if not path.is_file():
        return fail(ApprovalState.MISSING,
                    f"{rel} was approved in {sha[:12]} but is deleted from the workdir; "
                    "restore it or re-approve",
                    commit=sha, digest=_record_digest(rec))
    try:
        committed = _git(wd, "show", f"{sha}:{rel}").stdout
        live = path.read_text(encoding="utf-8")
    except OSError as exc:
        return fail(ApprovalState.MISSING, f"{rel} is unreadable ({exc})",
                    commit=sha, digest=_record_digest(rec))
    digest = _record_digest(rec)
    if live != committed:
        return fail(ApprovalState.UNCOMMITTED,
                    f"{rel} has uncommitted changes after {sha[:12]}; the committed copy governs "
                    "(commit the change or restore the file)",
                    commit=sha, digest=digest)
    if _only_added_file(wd, sha) != rel:
        return fail(ApprovalState.BAD_SIG,
                    f"commit {sha[:12]} touches more than {rel}; an approval commit adds exactly one file",
                    commit=sha, digest=digest)
    # Coverage: the approved digest must equal the current digest. A v1
    # record carries no payload — v1 correction/definition records cannot
    # prove coverage and never verify (re-approve under v2); other v1
    # kinds fall back to the legacy artifact comparison.
    current = current_digest(wd, kind, rec.get("selector"))
    if rec.get("format") != FORMAT or rec.get("payload") is None:
        if kind in ("correction", "definition"):
            return fail(ApprovalState.STALE,
                        f"{rel} is a v1 approval with no embedded payload and cannot bind content; re-approve",
                        commit=sha, digest=digest)
        legacy = current_artifact(wd, kind)
        if legacy is not None and digest != legacy:
            current = legacy  # force the stale branch below
    if current is not None and digest != current:
        return fail(ApprovalState.STALE,
                    f"approval covers {(digest or '?')[:12]} but the current {kind} is "
                    f"{current[:12]} (an approval of an older version does not cover this one)",
                    commit=sha, digest=digest)
    sig_ok, fields = _signer_fields(wd, sha)
    unsigned = not sig_ok and not fields
    if isinstance(rec.get("payload"), str) and rec["payload"]:
        # A v2 record whose embedded payload does not hash to its own
        # digest is forged or corrupted (the digest was copied onto
        # different content): it covers nothing. STALE forces
        # re-approval, and this check runs before any signature
        # reasoning so a forged payload can never verify.
        if hashlib.sha256(rec["payload"].encode("utf-8")).hexdigest() != digest:
            return fail(ApprovalState.STALE,
                        f"{rel} embeds a payload that does not hash to its approval digest "
                        f"{(digest or '?')[:12]} (forged or corrupted; re-approve)",
                        commit=sha, digest=digest, sig_ok=sig_ok)
    try:
        approvers = load_config(wd).get("approvers") or []
    except DdaError as exc:
        return fail(ApprovalState.UNKNOWN_SIGNER,
                    f"config.yaml does not parse, so no signer can match ({exc})",
                    commit=sha, digest=digest, sig_ok=sig_ok)
    signer = approver_matches(approvers, *fields)
    chain_note = ""
    if unsigned:
        # SPEC §4.5: an unsigned approval file is recorded as unverified,
        # whether or not the config names approvers — the agent could have
        # produced it. This precedes every signer/chain check: there is no
        # cryptographic claim to evaluate.
        return fail(ApprovalState.UNVERIFIED,
                    f"commit {sha[:12]} is unsigned (agent could have produced it); "
                    f"a human must sign from a trusted key (§4.5)",
                    commit=sha, digest=digest, signer=signer, sig_ok=sig_ok)
    if kind == "config":
        by_digest, problems = _config_chain(wd)
        entry = by_digest.get(digest or "")
        if entry is None or not entry["verified"]:
            detail = "; ".join(problems[-2:]) if problems else "chain walk failed"
            return fail(ApprovalState.BAD_SIG if not sig_ok else ApprovalState.UNKNOWN_SIGNER,
                        f"config approver chain does not verify ({detail})",
                        commit=sha, digest=digest, signer=signer, sig_ok=sig_ok)
        signer = entry["signer"] or signer
        if problems:
            chain_note = f" (earlier chain notes: {'; '.join(problems[-2:])})"
    elif not approvers:
        return fail(ApprovalState.UNKNOWN_SIGNER,
                    "config.yaml lists no approvers, so no signer can be matched",
                    commit=sha, digest=digest, sig_ok=sig_ok)
    elif not sig_ok:
        return fail(ApprovalState.BAD_SIG, f"bad signature on commit {sha[:12]}{chain_note}",
                    commit=sha, digest=digest, signer=signer, sig_ok=sig_ok)
    elif not signer:
        return fail(ApprovalState.UNKNOWN_SIGNER,
                    f"signer matches no approver in config.yaml{chain_note}",
                    commit=sha, digest=digest, signer=signer, sig_ok=sig_ok)
    key_failures = [c for c in _doctor.key_checks(wd) if c["status"] == "fail"]
    if key_failures:
        return fail(ApprovalState.DOWNGRADED,
                    "dda doctor key checks fail now (" +
                    "; ".join(c["name"] for c in key_failures) +
                    "); every approval downgrades to unverified until fixed (§4.5)",
                    commit=sha, digest=digest, signer=signer, sig_ok=sig_ok)
    short = (digest or "")[:12]
    return {**base, "state": ApprovalState.VERIFIED.value, "verified": True, "commit": sha,
            "digest": digest, "signer": signer, "sig_ok": sig_ok,
            "reason": f"verified: {kind} {short} signed by {signer or 'an approver'}{chain_note}"}


def approved_payload(wd: Workdir, kind: str, ref: str | None = None) -> tuple[dict, str]:
    """The approved (record, canonical payload) read from git.

    Gates execute this copy, never the working copy. Raises DdaError when
    no committed approval resolves.
    """
    wd.require_initialized()
    check_kind_artifact(kind)
    rec, sha, rel = _resolve_record(wd, kind, ref)
    if rec is None or sha is None or rel is None:
        raise DdaError(f"no committed {kind} approval covers {ref or 'current state'}")
    if not _git_ok(wd, "merge-base", "--is-ancestor", sha, "HEAD"):
        raise DdaError(f"{kind} approval {sha[:12]} is not on this branch")
    try:
        committed = _git(wd, "show", f"{sha}:{rel}").stdout
        record = json.loads(committed)
    except (ValueError, subprocess.SubprocessError) as exc:
        raise DdaError(f"{kind} approval {sha[:12]} is not readable from git ({exc})") from None
    payload = record.get("payload")
    if not isinstance(payload, str) or not payload:
        raise DdaError(f"{kind} approval {sha[:12]} embeds no canonical payload (v1 record; re-approve)")
    return record, payload


def list_approvals(wd: Workdir, kind: str) -> list[dict]:
    """Every committed approval commit of `kind`, oldest first.

    Each entry: {record, commit, rel}. Used to enumerate bound cases and
    definitions from git history rather than the working dir.
    """
    check_kind_artifact(kind)
    r = _git(wd, "log", "--reverse", "--topo-order", "--diff-filter=A", "--format=%H", "--",
             ".analysis/approvals")
    if r.returncode != 0:
        return []
    out = []
    for sha in [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]:
        only = _only_added_file(wd, sha)
        if not only or not only.startswith(f".analysis/approvals/{kind}-"):
            continue
        if not _git_ok(wd, "merge-base", "--is-ancestor", sha, "HEAD"):
            continue
        try:
            rec = json.loads(_git(wd, "show", f"{sha}:{only}").stdout)
        except (ValueError, subprocess.SubprocessError):
            continue
        if isinstance(rec, dict) and rec.get("kind") == kind and _record_digest(rec):
            out.append({"record": rec, "commit": sha, "rel": only})
    return out


def do_approved(wd: Workdir, kind: str, artifact: str | None = None) -> dict:
    """Verify an approval and record the verdict in approvals.index.jsonl."""
    from . import ledger
    check_kind_artifact(kind)
    if artifact is None and kind in ("correction", "definition"):
        raise DdaError(f"`dda approved {kind}` needs a case/definition selector or digest")
    verdict = verify_approval(wd, kind, artifact)
    index_rec = {
        "type": "approval", "kind": kind, "artifact": verdict.get("digest") or artifact,
        "digest": verdict.get("digest"), "commit": verdict.get("commit"),
        "signer": verdict.get("signer"), "sig_ok": verdict.get("sig_ok"),
        "verified": verdict["verified"], "state": verdict["state"],
        "reason": verdict["reason"],
    }
    # N7: embed the canonical payload so a later history rewrite (`git
    # reset --hard`, rebase, filter-branch, update-ref) cannot drop the
    # binding — match_evals re-resolves index-known approvals from this
    # record even when the commit is no longer on the branch. Best effort:
    # a missing payload only loses the fast path (git object store next).
    try:
        _rec, _payload = approved_payload(wd, kind, artifact)
        if isinstance(_payload, str) and _payload:
            index_rec["payload"] = _payload
    except DdaError:
        pass
    chain.append(ledger.approvals_index(wd), index_rec)
    return verdict


def index_approvals(wd: Workdir, kind: str) -> list[dict]:
    """Every `dda approved` verdict recorded in approvals.index.jsonl.

    The index is an untracked chain that survives `git reset --hard` and
    rebases (unlike `git log` ancestry), so evals matching consults it to
    keep history rewrites from unbinding cases (N7). Returns oldest first.
    """
    from . import ledger
    check_kind_artifact(kind)
    try:
        recs = chain.read_records(ledger.approvals_index(wd))
    except OSError:
        return []
    return [r for r in recs
            if isinstance(r, dict) and r.get("type") == "approval" and r.get("kind") == kind]


def latest_record(wd: Workdir, kind: str, artifact: str) -> dict | None:
    """Newest approvals.index.jsonl verdict for this kind+digest, else None."""
    from . import ledger
    recs = [r for r in chain.read_records(ledger.approvals_index(wd))
            if r.get("type") == "approval" and r.get("kind") == kind
            and (r.get("digest") == artifact or r.get("artifact") == artifact)]
    return recs[-1] if recs else None


def config_status(wd: Workdir) -> dict:
    """Status of the config approval for the current config hash.

    Never raises: unknown states come back as {state: ...} so G4 and the
    footer can report instead of crash. `state` is an ApprovalState value
    (plus "unknown" when the digest itself is not computable).
    """
    try:
        ch = lockhash.config_hash(wd)
    except (DdaError, OSError) as exc:
        return {"state": "unknown", "detail": str(exc)}
    try:
        approvers = load_config(wd).get("approvers") or []
    except DdaError as exc:
        return {"state": "unknown", "config_hash": ch, "detail": str(exc)}
    fps = fingerprints_of(approvers)
    base = {"config_hash": ch, "approvers": approvers, "fingerprints": fps}
    verdict = verify_approval(wd, "config", ch)
    state = verdict["state"]
    if state == ApprovalState.VERIFIED.value:
        return {**base, "state": state,
                "detail": f"commit {str(verdict.get('commit') or '')[:12]}",
                "record": latest_record(wd, "config", ch)}
    if state == ApprovalState.MISSING.value:
        return {**base, "state": state, "detail": "no config approval for this config hash"}
    return {**base, "state": state, "detail": verdict["reason"],
            "record": latest_record(wd, "config", ch)}


__all__ = ["KINDS", "ApprovalState", "approvals_dir", "approval_rel", "approval_path",
           "check_kind_artifact", "current_artifact", "current_digest", "canonical_payload",
           "canonical_case", "release_reports", "approved_payload", "list_approvals",
           "do_approve", "do_approved", "verify_approval", "latest_record",
           "config_status", "approver_matches", "fingerprints_of"]
