"""Phase 6 gate: G1 define (SPEC §3 row 1, §7, §14 item 6).

G1: every metric resolves to a registry pin `name@version#hash` and the hash
recomputes; sources named by config alias; hypotheses, "what would change
the answer", exclusions, and prior exposure stated; no inline formulas.
"""
from __future__ import annotations

import re

from .layout import Workdir, read_text_lf
from . import lockhash
from .layout import DdaError

# Sections that must be non-empty for a defined question (SPEC §3 row 1).
REQUIRED_SECTIONS = (
    "Hypotheses",
    "Thresholds that would change the decision",
    "Exclusion and outlier rules",
    "Prior exposure",
)

# Inline formulas have no place in Metrics: pins only. An `=`, a `/`
# division, an operator (`*`, `+`, `-`, `^`), or a function call outside a
# pin means the spec computes instead of citing (SPEC §7: "Specs cite pins
# only; inline formulas in a spec fail G1").
#
# Notes on the operator arms, so future bypasses stay closed without
# false-positive whack-a-mole:
# - `*`/`+`/`^` must sit between operands (word chars, brackets, parens);
#   markdown emphasis or bullets alone do not match.
# - `-` needs whitespace on at least one side: `revenue - refunds` is a
#   formula, `well-known` is a word. `a-b` is indistinguishable from a
#   hyphenated word and stays a documented residual.
# - function calls are generic (`name(` with no space): the old
#   enumerated list let `stdev(`/`max(` through, and case let `MEAN(`
#   through. A space before the paren (`abc (note)`) is prose, not a call.
_FORMULA_RE = re.compile(
    r"=|/"
    r"|(?<=[\w)\]])\s*[*+^]\s*(?=[\w(\[])"
    r"|(?<=\w)\s+-\s*(?=\w)|(?<=\w)\s*-\s+(?=\w)"
    r"|\b[a-z_][a-z0-9_]*\("
    r"|\b(?:sum|mean|avg|average|median|count|ratio|rate|cohort)\s*\(",
    re.IGNORECASE,
)
# Leading line markers stripped before the formula check: bullets (`-`,
# `*`, `+`, `>`), ordered numbers (`1.`, `2)`), outline brackets. Every
# non-empty Metrics line must name a pin whatever its marker, so markers
# carry no meaning here beyond whitespace.
_MARKER_RE = re.compile(r"^(?:\s*(?:[-*+>•]|\d+[.)]|\[[ xX]\])\s*)+")


def gate_g1(wd: Workdir) -> tuple[bool, str, dict]:
    """Define gate: metrics resolve to recomputing pins, sources to aliases,
    the define-time declarations are stated, and no inline formulas appear."""
    wd.require_initialized()
    try:
        lockhash.compute(wd)
    except DdaError as exc:
        # Unknown config alias (or any other lock-computation failure) fails
        # G1: sources must name config aliases and the spec must lock cleanly.
        return False, f"G1 fail: {exc}", {}
    text = read_text_lf(wd.spec_path)
    sections = lockhash.parse_sections(text)
    problems: list[str] = []
    for sec in REQUIRED_SECTIONS:
        if not lockhash.normalize_ws(sections.get(sec, "")):
            problems.append(f"G1 fail: '## {sec}' is empty (state it before defining metrics)")
    metrics = sections.get("Metrics", "")
    pins = sorted({m.group(0) for m in lockhash.PIN_RE.finditer(metrics)})
    if not pins:
        problems.append("G1 fail: Metrics names no registry pin (name@version#hash)")
    for pin in pins:
        try:
            lockhash.resolve_pin(wd, pin)
        except DdaError as exc:
            problems.append(f"G1 fail: {exc}")
    for line in metrics.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if not lockhash.PIN_RE.search(stripped):
            problems.append(f"G1 fail: metric line names no pin: {stripped[:60]}")
        else:
            rest = lockhash.PIN_RE.sub("", stripped)
            body = _MARKER_RE.sub("", rest)
            if _FORMULA_RE.search(body):
                problems.append(f"G1 fail: inline formula in Metrics: {stripped[:60]}")
        if len(problems) >= 6:
            break
    if problems:
        return False, "; ".join(problems[:6]), {}
    return True, f"G1 pass: {len(pins)} pin(s) resolve, aliases known, define-time declarations stated", {
        "pins": pins,
    }
