"""Phase 9: correction evals (SPEC §14 item 9, §9).

`dda evals new` drafts a case in `evals/corrections/NNN/case.md`,
`dda evals match` performs the mechanical match (every binding case
whose trigger keys intersect the spec's aliases, pins, and declared
pattern tags), and `dda evals run` executes the deterministic checks
of matched cases — the same checks `dda verify` runs. A case becomes
binding only with a (verified, or unverified below PUBLISH) `correction`
approval for its directory; unbound drafts are reported, never blocking.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

from .layout import DdaError, Workdir
from . import lockhash
from . import lockstate

CORRECTIONS_DIR = Path("evals") / "corrections"
CASE_FILE = "case.md"

# Closed pattern-tag vocabulary (§9). Re-exported from lockhash (one copy).
PATTERN_TAGS = lockhash.PATTERN_TAGS

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def parse_triggers(raw: str) -> list[str]:
    """Split comma/semicolon-separated trigger keys, lowercased, deduped.

    M4: trigger keys are typed — `alias:<name>`, `def:<name>`, or
    `tag:<tag>`. Untyped keys are rejected at the CLI so a typo cannot
    silently unbind a case; the matcher still normalizes legacy untyped
    keys found in old approved payloads (alias, then definition, then
    pattern tag) and intersects the resulting typed sets.
    """
    seen: list[str] = []
    for tok in re.split(r"[,;]", raw or ""):
        tok = tok.strip().lower()
        if tok and tok not in seen:
            seen.append(tok)
    return seen


def split_trigger(key: str) -> tuple[str, str] | None:
    """Split a typed trigger key into (kind, name); None when untyped."""
    m = re.match(r"^(alias|def|tag):([a-z0-9][a-z0-9_\-]*)$", key.strip().lower())
    return (m.group(1), m.group(2)) if m else None


def validate_triggers(triggers: list[str]) -> list[str]:
    """Reject empty, untyped, or malformed keys.

    `tag:` names must come from the closed vocabulary; `alias:`/`def:`
    names only need well-formed spellings here — the mechanical match
    decides whether they name a locked alias or definition. Anything
    else is refused so typos cannot silently unbind a case.
    """
    if not triggers:
        raise DdaError("at least one trigger key is required "
                       "(typed: alias:<name>, def:<name>, or tag:<tag> from skills/correct/SKILL.md)")
    bad = [t for t in triggers if not split_trigger(t)]
    if bad:
        raise DdaError(f"bad trigger key(s) {', '.join(bad)} "
                       "(typed keys only: alias:<name>, def:<name>, tag:<tag>)")
    unknown = [t for t in triggers
               if t.startswith("tag:") and t.split(":", 1)[1] not in PATTERN_TAGS]
    if unknown:
        raise DdaError(f"unknown pattern tag(s) {', '.join(unknown)} "
                       f"(closed vocabulary: {len(PATTERN_TAGS)} tags in skills/correct/SKILL.md)")
    return []


def check_path_rel(check_file: str) -> str:
    """Confine a deterministic-check path to outputs/ or derived/."""
    rel = check_file.strip().lstrip("/").replace("\\", "/")
    first = rel.split("/", 1)[0]
    if first not in ("outputs", "derived") or ".." in rel.split("/"):
        raise DdaError(f"check file {check_file!r} escapes outputs//derived/ — refused")
    return rel


def next_case_id(wd: Workdir) -> str:
    base = wd.root / CORRECTIONS_DIR
    taken = []
    if base.is_dir():
        for d in base.iterdir():
            if d.is_dir() and re.fullmatch(r"[0-9]+", d.name):
                taken.append(int(d.name))
    return f"{(max(taken) + 1) if taken else 1:03d}"


def render_case(title: str, triggers: list[str], what_happened: str = "",
                what_wrong: str = "", correct_behavior: str = "",
                check_file: str | None = None, check_sha256: str | None = None,
                review_question: str = "", source: str = "") -> str:
    if check_sha256 and not check_file:
        raise DdaError("--check-sha256 needs --check-file (a check names a file plus its hash)")
    if check_file:
        rel = check_path_rel(check_file)
        if not check_sha256 or not _SHA_RE.match(check_sha256.lower()):
            raise DdaError("--check-sha256 must be 64 lowercase hex digits")
    if not source:
        source = datetime.now(timezone.utc).strftime("%Y-%m-%d (UTC), who: (fill in)")
    lines = [f"# {title.strip() or 'Correction'}", "",
             f"Trigger keys: {', '.join(triggers)}", "",
             "## What the agent did", "",
             what_happened.strip() or "(fill in)", "",
             "## What was wrong", "",
             what_wrong.strip() or "(fill in)", "",
             "## Correct behavior", "",
             correct_behavior.strip() or "(fill in)", "",
             "## Deterministic check", ""]
    if check_file:
        lines += [f"file: {check_path_rel(check_file)}",
                  f"sha256: {check_sha256.lower()}", ""]
    else:
        lines += ["(none: this case carries a review question only)", ""]
    lines += ["## Review question", ""]
    if review_question.strip():
        lines += [f"Review question: {review_question.strip()}", ""]
    else:
        lines += ["(none)", ""]
    lines += ["## Source correction", "",
              f"Source correction: {source.strip()}", ""]
    return "\n".join(lines)


def do_new(wd: Workdir, title: str, triggers_raw: str, what_happened: str = "",
           what_wrong: str = "", correct_behavior: str = "",
           check_file: str | None = None, check_sha256: str | None = None,
           review_question: str = "", source: str = "") -> dict:
    """Draft evals/corrections/NNN/case.md; returns {case, path, warnings}."""
    wd.require_initialized()
    triggers = parse_triggers(triggers_raw)
    validate_triggers(triggers)
    body = render_case(title, triggers, what_happened, what_wrong,
                       correct_behavior, check_file, check_sha256,
                       review_question, source)
    nnn = next_case_id(wd)
    dest = wd.root / CORRECTIONS_DIR / nnn / CASE_FILE
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        raise DdaError(f"case {nnn} already exists (re-run to allocate the next id)")
    dest.write_text(body, encoding="utf-8")
    warnings: list[str] = []
    return {"case": nnn, "path": str(dest), "triggers": triggers,
            "warnings": warnings,
            "case_hash": hashlib.sha256(body.encode("utf-8")).hexdigest()}


def require_lock(wd: Workdir):
    wd.require_initialized()
    state, detail, _ = lockstate.quick_status(wd)
    if state != "valid":
        raise DdaError(f"lock is not valid ({state}: {detail}); lock the spec first (§3.1)")
    try:
        return lockhash.compute(wd)
    except DdaError as exc:
        raise DdaError(f"cannot match evals against an uncomputable spec: {exc}")


def do_match(wd: Workdir) -> list[dict]:
    """Mechanical match (§9). The agent cannot drop a matched case."""
    from . import stage8 as _stage8
    require_lock(wd)
    return _stage8.match_evals(wd)


def do_run(wd: Workdir) -> dict:
    """Run deterministic checks for matched cases.

    Returns {matched, results, failed_bound, failed_unbound}. Bound
    failures block (exit 1); unbound drafts are reported, never blocking.
    """
    from . import stage8 as _stage8
    matched = do_match(wd)
    results = _stage8.run_eval_checks(wd, matched)
    by_case = {m["case"]: m for m in matched}
    failed_bound = [r for r in results
                    if r["status"] == "fail" and by_case.get(r["case"], {}).get("bound")]
    failed_unbound = [r for r in results
                      if r["status"] == "fail" and not by_case.get(r["case"], {}).get("bound")]
    return {"matched": matched, "results": results,
            "failed_bound": failed_bound, "failed_unbound": failed_unbound,
            "ok": not failed_bound}


def declared_tag_answers(wd: Workdir) -> dict[str, bool]:
    """Pattern-tag answers from `## Pattern tags` (M4: every tag yes/no).

    Returns {tag: answered-yes}. A missing section answers nothing; a
    malformed section raises DdaError from the parser.
    """
    try:
        sections = lockhash.parse_sections(wd.spec_path.read_text(encoding="utf-8"))
    except (OSError, DdaError):
        return {}
    return lockhash.parse_tag_answers(sections.get("Pattern tags", ""), PATTERN_TAGS)


def declared_tags(wd: Workdir) -> list[str]:
    """Pattern tags the spec answers yes (matching fires only on yes)."""
    return sorted(t for t, yes in declared_tag_answers(wd).items() if yes)


__all__ = ["PATTERN_TAGS", "parse_triggers", "split_trigger", "validate_triggers", "do_new",
           "do_match", "do_run", "declared_tags", "declared_tag_answers",
           "next_case_id", "CORRECTIONS_DIR", "CASE_FILE"]
