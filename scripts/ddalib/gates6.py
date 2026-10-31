"""Phase 6 gate: G1 define (SPEC §3 row 1, §7, §14 item 6).

G1: every metric resolves to a registry pin `name@version#hash` and the hash
recomputes; sources named by config alias; hypotheses, "what would change
the answer", exclusions, and prior exposure stated; no inline formulas.
"""
from __future__ import annotations

import re
import unicodedata

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
# - Unicode math operators are folded first: NFKC maps fullwidth `＝`/`／`
#   (U+FF1D/U+FF0F, plus `＋`/`＊`/etc.) to ASCII, and the explicit arms
#   below catch what NFKC leaves standing — U+2212 MINUS SIGN (NFKC keeps
#   it), U+00D7 MULTIPLICATION SIGN, U+00F7 DIVISION SIGN. En/em dashes
#   (U+2013/U+2014) are prose punctuation, deliberately NOT operators:
#   `none — EXPLORE` must keep passing.
_FORMULA_RE = re.compile(
    r"=|[/÷]"
    r"|(?<=[\w)\]])\s*[*+^×]\s*(?=[\w(\[])"
    r"|(?<=\w)\s+[−-]\s*(?=\w)|(?<=\w)\s*[−-]\s+(?=\w)"
    r"|\b[a-z_][a-z0-9_]*\("
    r"|\b(?:sum|mean|avg|average|median|count|ratio|rate|cohort)\s*\(",
    re.IGNORECASE,
)
# Leading line markers stripped before the formula check: bullets (`-`,
# `*`, `+`, `>`), ordered numbers (`1.`, `2)`), outline brackets. Every
# non-empty Metrics line must name a pin whatever its marker, so markers
# carry no meaning here beyond whitespace.
_MARKER_RE = re.compile(r"^(?:\s*(?:[-*+>•]|\d+[.)]|\[[ xX]\])\s*)+")


def _has_formula(text: str) -> bool:
    """True when `text` computes instead of citing (SPEC §7).

    NFKC-fold first so fullwidth operators (U+FF1D `＝`, U+FF0F `／`,
    U+FF0B/U+FF0A/...) cannot dodge the ASCII arms; the explicit
    U+2212/U+00D7/U+00F7 arms catch what NFKC leaves standing.
    """
    return bool(_FORMULA_RE.search(unicodedata.normalize("NFKC", text)))


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
            if _has_formula(body):
                problems.append(f"G1 fail: inline formula in Metrics: {stripped[:60]}")
        if len(problems) >= 6:
            break
    # Formulas do not become prose outside Metrics: a spec that computes in
    # Method, Planned comparisons, or any other section fails G1 the same
    # way (SPEC §7: "Specs cite pins only"). Metrics lines are already
    # reported above, so they are skipped here to avoid double-counting.
    # Residual: `and/or`, `pre/post`, `a-b` read as prose by the same arms
    # that catch `orders / sessions` — authors must pin or reword.
    for sec, sec_body in sections.items():
        if sec == "Metrics":
            continue
        label = "preamble" if sec == lockhash.PREAMBLE else sec
        for line in sec_body.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue
            rest = lockhash.PIN_RE.sub("", stripped)
            if _has_formula(_MARKER_RE.sub("", rest)):
                problems.append(f"G1 fail: inline formula in {label}: {stripped[:60]}")
                break
        if len(problems) >= 6:
            break
    if problems:
        return False, "; ".join(problems[:6]), {}
    return True, f"G1 pass: {len(pins)} pin(s) resolve, aliases known, define-time declarations stated", {
        "pins": pins,
    }
