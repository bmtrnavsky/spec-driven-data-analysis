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

# Closed pattern-tag vocabulary (§9). Trigger keys that name a locked
# alias, pin, or definition name are always allowed; anything else must
# come from this list.
PATTERN_TAGS = frozenset({
    "join", "grain", "denominator", "timezone", "window", "filter",
    "definition", "metric", "label", "cohort", "population",
    "time-window", "threshold", "exclusion", "outlier", "nulls",
    "duplicates", "rounding", "currency", "sampling", "attribution",
    "seasonality", "survivorship", "confounder", "simpson",
    "base-rate", "selection-bias", "leakage", "bias",
    "multiple-comparisons", "hypothesis",
})

_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]*$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def parse_triggers(raw: str) -> list[str]:
    """Split comma/semicolon-separated trigger keys, lowercased, deduped."""
    seen: list[str] = []
    for tok in re.split(r"[,;]", raw or ""):
        tok = tok.strip().lower()
        if tok and tok not in seen:
            seen.append(tok)
    return seen


def validate_triggers(triggers: list[str]) -> list[str]:
    """Reject empty or malformed keys; return warnings for unknown tags.

    A key outside the closed vocabulary is still allowed when it names
    something in the spec (alias, pin, definition) — the mechanical
    match decides that. Anything else is refused so typos cannot
    silently unbind a case.
    """
    if not triggers:
        raise DdaError("at least one trigger key is required "
                       "(aliases, definition names, or pattern tags from skills/correct/SKILL.md)")
    bad = [t for t in triggers if not _TAG_RE.match(t)]
    if bad:
        raise DdaError(f"bad trigger key(s) {', '.join(bad)} "
                       "(lowercase letters, digits, '-', '_' only)")
    return [t for t in triggers if t not in PATTERN_TAGS]


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
    unknown = validate_triggers(triggers)
    body = render_case(title, triggers, what_happened, what_wrong,
                       correct_behavior, check_file, check_sha256,
                       review_question, source)
    nnn = next_case_id(wd)
    dest = wd.root / CORRECTIONS_DIR / nnn / CASE_FILE
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        raise DdaError(f"case {nnn} already exists (re-run to allocate the next id)")
    dest.write_text(body, encoding="utf-8")
    warnings = [f"trigger key {t!r} is not a closed-vocabulary pattern tag "
                "(it must name a locked alias, pin, or definition to match)"
                for t in unknown]
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


def declared_tags(wd: Workdir) -> list[str]:
    """Pattern tags declared under `## Pattern tags` (phase 9 spec section)."""
    try:
        sections = lockhash.parse_sections(wd.spec_path.read_text(encoding="utf-8"))
    except (OSError, DdaError):
        return []
    return parse_triggers(sections.get("Pattern tags", ""))


__all__ = ["PATTERN_TAGS", "parse_triggers", "validate_triggers", "do_new",
           "do_match", "do_run", "declared_tags", "next_case_id",
           "CORRECTIONS_DIR", "CASE_FILE"]
