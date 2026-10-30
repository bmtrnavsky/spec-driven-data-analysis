"""Phase 5 gates: G0 intake, G8 report, G9 archive (SPEC §3 rows 0/8/9, §14 item 5)."""
from __future__ import annotations

from .layout import Workdir, read_text_lf
from . import lockhash, lockstate


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
    if q.count(".") + q.count("?") > 2:
        return False, "G0 fail: question is not one sentence", {}
    return True, "G0 pass: question and decision stated", {"question": q[:120]}


def gate_g8(wd: Workdir) -> tuple[bool, str, dict]:
    """Report gate: footer values recompute; labels present; sign-off at PUBLISH."""
    from . import footer as _footer
    wd.require_initialized()
    lock = lockstate.read_lock(wd)
    if not lock:
        return False, "G8 fail: no spec.lock (run `dda lock` first)", {}
    state, detail, _ = lockstate.quick_status(wd)
    if state != "valid":
        return False, "G8 fail: lock not valid (%s: %s)" % (state, detail), {}
    report = wd.analysis / "answer.md"
    if not report.is_file():
        repdir = wd.root / "reports"
        cands = sorted(repdir.glob("*.md")) if repdir.exists() else []
        if not cands:
            return False, "G8 fail: no report (write .analysis/answer.md or reports/<slug>.md)", {}
        report = cands[0]
    text = read_text_lf(report)
    problems = _footer.check(wd, text)
    if problems:
        return False, "G8 fail: footer does not verify: " + "; ".join(problems[:3]), {}
    tier = (lock.get("tier") or "EXPLORE").upper()
    if tier == "PUBLISH":
        from . import approvals as _approvals
        st = _approvals.config_status(wd).get("state")
        if st != "verified":
            return False, "G8 fail: PUBLISH needs a verified human sign-off for this report", {}
    return True, "G8 pass: report %s footer verifies" % report.name, {}


def gate_g9(wd: Workdir) -> tuple[bool, str, dict]:
    """Archive gate: everything committed, chains verify."""
    from .ledger import verify_all, _git
    wd.require_initialized()
    lock = lockstate.read_lock(wd)
    if not lock:
        return False, "G9 fail: no spec.lock", {}
    problems, _ = verify_all(wd)
    if problems:
        return False, "G9 fail: evidence chains broken: " + "; ".join(problems[:3]), {}
    dirty = _git(wd.root, "status", "--porcelain").stdout
    if dirty.strip():
        return False, "G9 fail: uncommitted changes present", {}
    return True, "G9 pass: tree committed, chains verify", {}
