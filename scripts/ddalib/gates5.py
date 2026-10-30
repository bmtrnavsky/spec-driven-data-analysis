"""Phase 5 gates: G0 intake, G8 report, G9 archive (SPEC §3 rows 0/8/9, §14 item 5)."""
from __future__ import annotations

import re

from .layout import Workdir, read_text_lf
from . import lockhash, lockstate


def _sentence_fragments(question: str) -> list[str]:
    """Split on sentence boundaries: . ! ? ; and line breaks.

    A terminator only splits when followed by whitespace/end-of-string, so
    decimals and version numbers (``v2.5``) do not count as new sentences.
    """
    flat = " ".join(question.split())
    parts = re.split(r"[.!?;]+(?:\s+|$)", flat)
    return [p for p in parts if p.strip()]


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
        target = p if p.is_absolute() else wd.root / p
        if not target.is_file():
            return False, "G8 fail: --report %s does not exist" % report, {}
        targets = [target]
    else:
        targets = []
        answer = wd.analysis / "answer.md"
        if answer.is_file() and _footer.extract(read_text_lf(answer)) is not None:
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
        return False, "G8 fail: footer does not verify: " + "; ".join(bad[:6]), {}
    tier = (lock.get("tier") or "EXPLORE").upper()
    if tier == "PUBLISH":
        from . import approvals as _approvals
        st = _approvals.config_status(wd).get("state")
        if st != "verified":
            return False, "G8 fail: PUBLISH needs a verified human sign-off for this report", {}
    names = ", ".join(t.name for t in targets)
    return True, "G8 pass: report(s) %s footer verifies" % names, {}


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
