"""Provenance footer parsing and value checks (spec §8, §6.5).

A footer is the H2 section whose heading contains "Provenance". Each field
is one line, `- **Field:** value` or `Field: value`. `check()` returns a
list of problems; empty means every required field is present and every
field recomputable in this build matches the evidence files.

Recomputed now: lock hash, spec version, lock label, tier, amendments,
variants N (ledger spec versions + specs-tried variants), definition pins,
sources, and config-approval status with approver fingerprints (phase 4).
Phase 8 also recomputes data (profile snapshot hashes), kernel (replay env
hash), reproduce (locked variant + `dda verify`), and correction evals
(matched/passed counts) — but only when that evidence exists, so older
reports without a profile/verify keep verifying on presence alone.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import chain, ledger, lockhash, lockstate
from .layout import Workdir, read_text_lf


def review_summary(wd: Workdir) -> str:
    """One-line review state for the footer skeleton: recorded goldfish calls
    (request ids + models) or recorded self re-reads, else none. Imported
    lazily by footer to avoid a cycle (review imports ledger only)."""
    from . import review as _review
    try:
        summary = _review.review_summary(wd)
    except Exception:
        return "none recorded"
    try:
        selfdir = wd.analysis / "reviews" / "self"
        for stage, label in (("teardown", None), ("post-result", "post-result")):
            rounds = set()
            if selfdir.is_dir():
                for p in selfdir.glob(f"{stage}-round*.md"):
                    m = re.match(rf"^{stage}-round([0-9]+[a-z]?)(?:-.*)?\.md$", p.name)
                    if m and p.stat().st_size > 0:
                        rounds.add(m.group(1))
            if rounds:
                tag = f"post-result self re-reads" if label else "self re-reads"
                summary += f"; {tag}: rounds " + ",".join(sorted(rounds))
    except OSError:
        pass
    return summary

FULL_FIELDS = (
    "question", "tier", "spec version", "lock hash", "lock timestamp", "lock label", "amendments", "variants",
    "definitions", "data", "kernel", "reproduce", "review", "approvals", "correction evals", "hook faults",
    "caveats", "generated",
)
SHORT_FIELDS = ("lock hash", "lock label", "sources", "definitions", "variants", "review")
_PLACEHOLDER = re.compile(r"^(?:|-|—|\?|tbd|todo|n/?a\??|xxx|<[^>]*>)$", re.IGNORECASE)
_FIELD_RE = re.compile(r"^\s*(?:[-*]\s+)?(?:\*\*)?([A-Za-z][A-Za-z /]+?)(?::\*\*|\*\*:|:)\s*(.*)$")
_PROVENANCE_HEADING_RE = re.compile(r"^#{2,3}\s+.*provenance", re.IGNORECASE)


def remove_footer(text: str) -> str:
    """Cut a previously stamped Provenance section (full or short) so `dda
    report` can rebuild it idempotently: a short footer already in answer.md
    fails the full report check, so strip it and append a fresh full
    skeleton. The footer always trails the body."""
    lines = text.replace("\r\n", "\n").split("\n")
    for i, line in enumerate(lines):
        if _PROVENANCE_HEADING_RE.match(line):
            return "\n".join(lines[:i])
    return text


def extract(text: str) -> dict[str, str] | None:
    lines = text.replace("\r\n", "\n").split("\n")
    start = None
    for i, line in enumerate(lines):
        if re.match(r"^#{2,3}\s+.*provenance", line, re.IGNORECASE):
            start = i + 1
            break
    if start is None:
        return None
    fields: dict[str, str] = {}
    for line in lines[start:]:
        if re.match(r"^#{1,2}\s", line):
            break
        m = _FIELD_RE.match(line)
        if m:
            fields[m.group(1).strip().lower()] = m.group(2).strip()
    return fields


def expected(wd: Workdir) -> dict | None:
    lock = lockstate.read_lock(wd)
    if not lock:
        return None
    summ = ledger.ledger_summary(wd)
    tried = {r.get("variant") for r in chain.read_records(ledger.specs_tried(wd))
             if r.get("type", "variant") == "variant" and r.get("variant")}
    from . import approvals as _approvals
    cfg_status = _approvals.config_status(wd)
    exp = {
        "lock_hash": lock["lock_hash"], "version": lock["version"], "label": summ["effective_label"] or lock["label"],
        "tier": lock.get("tier"), "pins": sorted(lock.get("pins") or []), "aliases": sorted(lock.get("aliases") or []),
        "amendments": summ["amendments"], "post_data_amendments": summ["post_data_amendments"],
        "n_tried": len(tried) + summ["versions"], "locked_at": lock.get("locked_at"),
        "config_approval": cfg_status.get("state"), "config_hash": cfg_status.get("config_hash") or "",
        "fingerprints": cfg_status.get("fingerprints") or [],
    }
    # Phase-8 evidence, when it exists (profile before results, verify after).
    try:
        from . import stage8 as _stage8
        prof = _stage8.load_profile(wd)
        if isinstance(prof, dict) and prof.get("lock_hash") == lock["lock_hash"]:
            exp["profile"] = prof
        ver = _stage8.load_verify(wd)
        if (isinstance(ver, dict) and ver.get("lock_hash") == lock["lock_hash"]
                and ver.get("status") == "reproduced within tolerance"):
            exp["verify"] = ver
        exp["n_eval_cases"] = len(_stage8.match_evals(wd))
    except Exception:
        pass
    return exp


def _claimed_label(value: str) -> str | None:
    v = value.lower()
    found = [l for l in lockstate.LABELS if l in v]
    return max(found, key=len) if found else None


def check(wd: Workdir, text: str, short: bool = False) -> list[str]:
    exp = expected(wd)
    if exp is None:
        return ["no lock: lock the spec (`dda lock`) before writing a report"]
    state, detail, _ = lockstate.quick_status(wd)
    problems = []
    if state != "valid":
        problems.append(f"lock is not valid ({state}: {detail}); re-lock before reporting")
    fields = extract(text)
    if fields is None:
        return problems + ["missing provenance footer (an H2 '## Provenance' section; see `dda footer`)"]
    required = SHORT_FIELDS if short else FULL_FIELDS
    for f in required:
        if f not in fields:
            problems.append(f"footer field missing: {f}")
        elif _PLACEHOLDER.match(fields[f].strip(" .`*")):
            problems.append(f"footer field empty: {f}")
    g = lambda k: fields.get(k, "")  # noqa: E731
    if g("lock hash"):
        hx = re.findall(r"[0-9a-f]{8,64}", g("lock hash").lower())
        if not hx or not exp["lock_hash"].startswith(hx[0]):
            problems.append(f"footer lock hash wrong (expected {exp['lock_hash'][:12]})")
    if g("spec version") and not re.search(rf"\bv{exp['version']}\b", g("spec version")):
        problems.append(f"footer spec version wrong (expected v{exp['version']})")
    if g("lock label") and _claimed_label(g("lock label")) != exp["label"]:
        problems.append(f"footer lock label wrong (expected '{exp['label']}')")
    if not short and g("tier") and exp["tier"] and exp["tier"] not in g("tier"):
        problems.append(f"footer tier wrong (expected {exp['tier']})")
    if g("amendments"):
        nums = [int(n) for n in re.findall(r"\d+", g("amendments"))]
        if len(nums) < 2 or nums[0] != exp["amendments"] or nums[1] != exp["post_data_amendments"]:
            problems.append(f"footer amendments wrong (expected {exp['amendments']} total, "
                            f"{exp['post_data_amendments']} post-data)")
    if g("variants"):
        nums = re.findall(r"\d+", g("variants"))
        if not nums or int(nums[0]) != exp["n_tried"]:
            problems.append(f"footer variants wrong (expected {exp['n_tried']} tried, incl. spec versions)")
    if g("definitions"):
        pins = sorted(set(re.findall(r"[a-z][a-z0-9_\-]*@[0-9][0-9A-Za-z.\-]*#[0-9a-f]+", g("definitions"))))
        if pins != exp["pins"]:
            problems.append(f"footer definition pins wrong (expected {', '.join(exp['pins']) or 'none'})")
    if short and g("sources"):
        named = sorted(a for a in exp["aliases"] if re.search(rf"(?<![\w-]){re.escape(a)}(?![\w-])", g("sources")))
        if named != exp["aliases"]:
            problems.append(f"footer sources wrong (expected {', '.join(exp['aliases'])})")
    # Review names every recorded round's request id (§5.0 Recording): a
    # stale skeleton that names one id — or just the word "round" — must
    # not verify once more calls exist.
    try:
        from . import review as _review
        goldfish_recs = [r for r in _review.existing_calls(wd, "teardown")
                         + _review.existing_calls(wd, "post-result")
                         if r.get("provider_request_id")]
    except Exception:
        goldfish_recs = []
    if goldfish_recs:
        text = (fields.get("review", "") or "").lower()
        missing = [str(r.get("provider_request_id"))
                   for r in goldfish_recs
                   if str(r.get("provider_request_id") or "").lower() not in text]
        if missing:
            problems.append("footer review omits recorded goldfish request id(s) "
                            f"{', '.join(missing[:4])} "
                            f"({len(goldfish_recs)} call(s) in reviews/goldfish/): "
                            "name every round's request id and model (§5.0 Recording)")
    else:
        try:
            selfdir = wd.analysis / "reviews" / "self"
            has_self = bool(selfdir.is_dir() and (any(selfdir.glob("teardown-round*.md"))
                                                  or any(selfdir.glob("post-result-round*.md"))))
        except OSError:
            has_self = False
        if has_self and "self" not in (fields.get("review", "") or "").lower():
            problems.append("footer review omits recorded self re-reads "
                            "(reviews/self/): say who reviewed (§5.0)")
    # Phase-8 recomputes: data names every profiled alias + snapshot hash;
    # kernel names a replay env hash; reproduce names the locked variant and
    # `dda verify`; correction evals names the matched count.
    prof = exp.get("profile")
    if prof and g("data"):
        dl = g("data").lower()
        for alias in sorted((prof.get("aliases") or {})):
            r = (prof["aliases"] or {})[alias]
            if alias.lower() not in dl:
                problems.append(f"footer data omits profiled source {alias!r}")
            if r.get("kind") == "snapshot" and r.get("combined"):
                if str(r["combined"])[:12].lower() not in dl:
                    problems.append(f"footer data omits snapshot hash for {alias!r} "
                                    f"(expected {str(r['combined'])[:12]})")
    ver = exp.get("verify")
    if ver and g("kernel"):
        envs = {(rp.get("env_hash") or "")[:12].lower() for rp in ver.get("replays", []) if rp.get("env_hash")}
        if envs and not any(e in g("kernel").lower() for e in envs):
            problems.append(f"footer kernel omits the replay environment hash "
                            f"(expected one of {', '.join(sorted(envs))})")
    if ver and g("reproduce"):
        rl = g("reproduce").lower()
        if str(ver.get("variant", "")).lower() not in rl:
            problems.append(f"footer reproduce omits the locked variant {ver.get('variant')!r}")
        if "dda verify" not in rl:
            problems.append("footer reproduce omits the `dda verify` replay command")
    if exp.get("n_eval_cases") and g("correction evals"):
        m = re.search(r"(\d+)\s+matched", g("correction evals"))
        if not m or int(m.group(1)) != exp["n_eval_cases"]:
            problems.append(f"footer correction evals wrong (expected {exp['n_eval_cases']} matched)")
    return problems


def _skeleton_question(wd: Workdir) -> str:
    """Question default for a fresh skeleton: the locked spec's Question section."""
    try:
        sections = lockhash.parse_sections(read_text_lf(wd.spec_path))
        q = " ".join(sections.get("Question", "").split())
        if q:
            return q if len(q) <= 300 else q[:297] + "..."
    except Exception:
        pass
    return "see report body"


def skeleton(wd: Workdir, short: bool = False) -> str:
    exp = expected(wd)
    if exp is None:
        return ""
    data_default = "aggregates only; no row values quoted"
    kernel_default = "see report body"
    reproduce_default = "see report body"
    evals_default = "none"
    prof = exp.get("profile")
    if prof and not short:
        bits = []
        for alias in sorted((prof.get("aliases") or {})):
            r = (prof["aliases"] or {})[alias]
            if r.get("kind") == "live-only":
                bits.append(f"{alias}: live-only fingerprint (no materialized snapshot)")
            else:
                files = ", ".join(f"{f['rel']} sha256 {str(f.get('sha256'))[:12]}"
                                  for f in sorted((r.get("files") or {}).values(),
                                                  key=lambda f: f.get("rel") or ""))
                bits.append(f"{alias}@{r.get('asof')}: combined {str(r.get('combined'))[:12]} ({files})")
        data_default = "aggregates only (no rows/samples). " + "; ".join(bits)
    ver = exp.get("verify")
    if ver and not short:
        envs = sorted({(rp.get("env_hash") or "")[:12] for rp in ver.get("replays", []) if rp.get("env_hash")})
        kernel_default = (f"fresh-kernel double replay of locked variant {ver.get('variant')!r} "
                          f"(env {', '.join(envs)}; {ver.get('stdout_note', '')})".rstrip())
        reproduce_default = (f"locked variant `{ver.get('variant')}` — rerun `dda verify` "
                             "in this workdir (fresh kernel against the profile snapshot)")
        evals_default = f"{ver.get('evals_matched', 0)} matched, {ver.get('evals_passed', 0)} passed (see verify.md)"
    elif exp.get("n_eval_cases") and not short:
        evals_default = f"{exp['n_eval_cases']} matched (run `dda verify` to execute checks)"
    known = {
        "tier": exp["tier"] or "", "spec version": f"v{exp['version']}", "lock hash": exp["lock_hash"][:12],
        "lock timestamp": exp["locked_at"] or "", "lock label": exp["label"],
        "amendments": f"{exp['amendments']} ({exp['post_data_amendments']} post-data)",
        "variants": f"{exp['n_tried']} tried (incl. spec versions), K reported, locked variant <id>",
        "definitions": ", ".join(exp["pins"]) or "none", "sources": ", ".join(exp["aliases"]),
        "review": (f"config approval: {exp['config_approval'] or 'unknown'} "
                   f"({(exp['config_hash'] or '')[:12]}); "
                   f"approver fingerprints: {', '.join(exp['fingerprints']) or 'none configured'}; "
                   f"goldfish: {review_summary(wd)}"),
        "approvals": (f"config {(exp['config_hash'] or '')[:12]}: {exp['config_approval'] or 'unknown'}; "
                      "other kinds verified or unverified per approvals.index.jsonl"),
        # Author-filled fields: fillable non-empty defaults so a fresh skeleton
        # verifies; the author replaces them with the report's real content.
        "question": _skeleton_question(wd),
        "data": data_default,
        "kernel": kernel_default,
        "reproduce": reproduce_default,
        "correction evals": evals_default,
        "hook faults": "none recorded",
        "caveats": "see report body",
        "generated": exp["locked_at"] or "unknown",
    }
    fields = SHORT_FIELDS if short else FULL_FIELDS
    return "## Provenance\n\n" + "\n".join(f"- **{f.capitalize()}:** {known.get(f, '')}" for f in fields) + "\n"


def is_short_target(path: Path | str) -> bool:
    return str(path).replace("\\", "/").lower().endswith("/.analysis/answer.md")


__all__ = ["check", "extract", "remove_footer", "skeleton", "expected", "is_short_target", "FULL_FIELDS", "SHORT_FIELDS"]
