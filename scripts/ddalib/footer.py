"""Provenance footer parsing and value checks (spec §8, §6.5).

A footer is the H2 section whose heading contains "Provenance". Each field
is one line, `- **Field:** value` or `Field: value`. `check()` returns a
list of problems; empty means every required field is present and every
field recomputable in this build matches the evidence files.

Recomputed now: lock hash, spec version, lock label, tier, amendments,
variants N (ledger spec versions + specs-tried variants), definition pins,
sources. Data, kernel, approvals, review and eval fields are presence-
checked only until their build phases land (§14 phases 4, 7-9).
"""
from __future__ import annotations

import re
from pathlib import Path

from . import chain, ledger, lockstate
from .layout import Workdir

FULL_FIELDS = (
    "question", "tier", "spec version", "lock hash", "lock timestamp", "lock label", "amendments", "variants",
    "definitions", "data", "kernel", "reproduce", "review", "approvals", "correction evals", "hook faults",
    "caveats", "generated",
)
SHORT_FIELDS = ("lock hash", "lock label", "sources", "definitions", "variants", "review")
_PLACEHOLDER = re.compile(r"^(?:|-|—|\?|tbd|todo|n/?a\??|xxx|<[^>]*>)$", re.IGNORECASE)
_FIELD_RE = re.compile(r"^\s*(?:[-*]\s+)?(?:\*\*)?([A-Za-z][A-Za-z /]+?)(?::\*\*|\*\*:|:)\s*(.*)$")


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
    variants = [r for r in chain.read_records(ledger.specs_tried(wd)) if r.get("type", "variant") == "variant"]
    return {
        "lock_hash": lock["lock_hash"], "version": lock["version"], "label": summ["effective_label"] or lock["label"],
        "tier": lock.get("tier"), "pins": sorted(lock.get("pins") or []), "aliases": sorted(lock.get("aliases") or []),
        "amendments": summ["amendments"], "post_data_amendments": summ["post_data_amendments"],
        "n_tried": len(variants) + summ["versions"], "locked_at": lock.get("locked_at"),
    }


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
    return problems


def skeleton(wd: Workdir, short: bool = False) -> str:
    exp = expected(wd)
    if exp is None:
        return ""
    known = {
        "tier": exp["tier"] or "", "spec version": f"v{exp['version']}", "lock hash": exp["lock_hash"][:12],
        "lock timestamp": exp["locked_at"] or "", "lock label": exp["label"],
        "amendments": f"{exp['amendments']} ({exp['post_data_amendments']} post-data)",
        "variants": f"{exp['n_tried']} tried (incl. spec versions), K reported, locked variant <id>",
        "definitions": ", ".join(exp["pins"]) or "none", "sources": ", ".join(exp["aliases"]),
    }
    fields = SHORT_FIELDS if short else FULL_FIELDS
    return "## Provenance\n\n" + "\n".join(f"- **{f.capitalize()}:** {known.get(f, '')}" for f in fields) + "\n"


def is_short_target(path: Path | str) -> bool:
    return str(path).replace("\\", "/").lower().endswith("/.analysis/answer.md")


__all__ = ["check", "extract", "skeleton", "expected", "is_short_target", "FULL_FIELDS", "SHORT_FIELDS"]
