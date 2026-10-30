"""Phase 5 gates: G0 intake, G8 report, G9 archive (SPEC §3 rows 0/8/9, §14 item 5)."""
from __future__ import annotations

import re

from .layout import Workdir, read_text_lf
from . import lockhash, lockstate

# Invisible characters stripped before G0 sentence segmentation so they
# cannot hide a boundary (e.g. "?<U+200B>Should" or "?<U+2060>should").
_INVISIBLE_RE = re.compile(
    "[\u00ad\u034f\u180e\u200b\u200c\u200d\u200e\u200f"
    "\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069\u206a\u206b\u206c\u206d\u206e\u206f"
    "\ufeff]"
)

# Abbreviations whose period must not split a sentence (case-insensitive;
# \b keeps "1st."-style numerics and mid-word matches unmasked).
_ABBREV_RE = re.compile(
    r"\b(?:Mr|Mrs|Ms|Dr|Prof|Rev|Gen|Col|Maj|Sgt|Lt|Capt|St|Jr|Sr|vs|etc)\."
    r"|\b[eE]\.[gG]\.|\b[iI]\.[eE]\.",
    re.IGNORECASE,
)


def _sentence_fragments(question: str) -> list[str]:
    """Split on sentence boundaries: . ! ? ; : / — – … ？ ！ ； 。 and line breaks.

    Every terminator run splits, even with no following space and even
    before a lowercase letter (``Rise?Ship it``, ``Rise?ship it`` are two
    sentences). Decimal points, clock times, and letter/letter slashes
    (``v2.5``, ``12:30``, ``A/B``) are masked first so they do not count
    as new sentences, as are common abbreviations (``Mr.``, ``Mrs.``,
    ``Dr.``, ``e.g.``, ...). Zero-width and other invisible characters
    are stripped first so they cannot hide a boundary.
    """
    flat = " ".join(question.split())
    flat = _INVISIBLE_RE.sub("", flat)
    flat = _ABBREV_RE.sub(lambda m: m.group(0).replace(".", "\x00"), flat)
    masked = re.sub(r"(?<=\d)[.:/](?=\d)", "\x00", flat)
    masked = re.sub(r"(?<=[A-Za-z0-9])/(?=[A-Za-z0-9])", "\x01", masked)
    parts = re.split(r"[.!?;:/—–…？！；。]+", masked)
    out = []
    for p in parts:
        p = p.replace("\x00", ".").replace("\x01", "/")
        if p.strip():
            out.append(p)
    return out


def gate_g0(wd: Workdir) -> tuple[bool, str, dict]:
    """Intake gate: question stated as one sentence; decision it informs named."""
    wd.require_initialized()
    text = read_text_lf(wd.spec_path)
    sections = lockhash.parse_sections(text)
    q = sections.get("Question", "").strip()
    d = (sections.get("Decision it informs", "") or sections.get("Decision", "")).strip()
    if not q:
        return False, "G0 fail: no Question section in spec.md", {}
    if not d:
        return False, "G0 fail: no Decision section in spec.md", {}
    if len(_sentence_fragments(q)) > 1:
        return False, "G0 fail: question is not one sentence", {}
    return True, "G0 pass: question and decision stated", {"question": q[:120]}


def gate_g8(wd: Workdir, report: str | None = None) -> tuple[bool, str, dict]:
    """Report gate: footer values recompute; labels present; sign-off at PUBLISH."""
    from . import footer as _footer
    from pathlib import Path as _Path
    wd.require_initialized()
    lock = lockstate.read_lock(wd)
    if not lock:
        return False, "G8 fail: no spec.lock (run `dda lock` first)", {}
    state, detail, _ = lockstate.quick_status(wd)
    if state != "valid":
        return False, "G8 fail: lock not valid (%s: %s)" % (state, detail), {}
    if report is not None:
        p = _Path(report)
        if p.is_absolute() or ".." in p.parts:
            return False, "G8 fail: --report must be a workdir-relative path without '..'", {}
        target = wd.root / p
        try:
            resolved_root = wd.root.resolve()
            target.resolve().relative_to(resolved_root)
        except (OSError, ValueError):
            return False, "G8 fail: --report escapes the workdir", {}
        if not target.is_file():
            return False, "G8 fail: --report %s does not exist" % report, {}
        targets = [target]
        repdir = wd.root / "reports"
        others = 0
        if repdir.is_dir():
            try:
                tres = target.resolve()
            except OSError:
                tres = target
            others = sum(1 for q in repdir.glob("*.md") if q.resolve() != tres)
        scope_note = " (scope: --report %s%s)" % (
            report, "; %d other report(s) not checked" % others if others else "")
    else:
        scope_note = ""
        targets = []
        answer = wd.analysis / "answer.md"
        if answer.is_file():
            if _footer.extract(read_text_lf(answer)) is None:
                return False, ("G8 fail: .analysis/answer.md present without a verifiable "
                                "provenance footer (run `dda report` to stamp it)"), {}
            targets.append(answer)
        repdir = wd.root / "reports"
        if repdir.exists():
            targets.extend(sorted(repdir.glob("*.md")))
        if not targets:
            return False, "G8 fail: no report (write .analysis/answer.md or reports/<slug>.md)", {}
    bad: list[str] = []
    for target in targets:
        short = _footer.is_short_target(target.resolve())
        for problem in _footer.check(wd, read_text_lf(target), short=short):
            bad.append("%s: %s" % (target.name, problem))
            if len(bad) >= 6:
                break
        if len(bad) >= 6:
            break
    if bad:
        return False, "G8 fail: footer does not verify: " + "; ".join(bad[:6]) + scope_note, {}
    tier = (lock.get("tier") or "EXPLORE").upper()
    if tier == "PUBLISH":
        from . import approvals as _approvals
        st = _approvals.config_status(wd).get("state")
        if st != "verified":
            return False, "G8 fail: PUBLISH needs a verified human sign-off for this report", {}
    names = ", ".join(t.name for t in targets)
    return True, "G8 pass: report(s) %s footer verifies%s" % (names, scope_note), {}


def gate_g9(wd: Workdir) -> tuple[bool, str, dict]:
    """Archive gate: everything committed, chains verify, no data/secrets in git."""
    from .ledger import git_safety_scan, verify_all, _git
    wd.require_initialized()
    lock = lockstate.read_lock(wd)
    if not lock:
        return False, "G9 fail: no spec.lock", {}
    problems, _ = verify_all(wd)
    if problems:
        return False, "G9 fail: evidence chains broken: " + "; ".join(problems[:3]), {}
    unsafe = git_safety_scan(wd)
    if unsafe:
        return False, "G9 fail: data/secret files in git: " + "; ".join(unsafe[:3]), {}
    dirty = _git(wd.root, "status", "--porcelain").stdout
    if dirty.strip():
        return False, "G9 fail: uncommitted changes present", {}
    return True, "G9 pass: tree committed, chains verify", {}
