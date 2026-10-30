"""Phase 7 gate: G3 teardown review (SPEC §3 row 3, §5, §14 item 7).

G3: tier-scaled rounds recorded from `dda review run` calls (§5.0); at
DECIDE, a human spec approval for this spec hash (verified, or unverified
and disclosed); at PUBLISH, verified only (§4.5).
"""
from __future__ import annotations

from . import lockhash
from .layout import DdaError, Workdir
from .review import (
    existing_calls,
    normalize_stage,
    provider_available,
    rounds_for,
    self_response_path,
)

STAGE = "teardown"


def _self_rounds(wd: Workdir, stage: str) -> set[str]:
    rounds = set()
    d = wd.analysis / "reviews" / "self"
    if not d.is_dir():
        return rounds
    import re
    for p in d.glob(f"{stage}-round*.md"):
        m = re.match(rf"^{re.escape(stage)}-round([0-9]+[a-z]?)(?:-.*)?\.md$", p.name)
        try:
            if m and p.stat().st_size > 0:
                rounds.add(m.group(1))
        except OSError:
            continue
    return rounds


def gate_g3(wd: Workdir) -> tuple[bool, str, dict]:
    """Teardown gate: required rounds recorded, objections answered, and the
    human spec approval present at DECIDE+ (verified only at PUBLISH)."""
    wd.require_initialized()
    try:
        comp = lockhash.compute(wd)
    except DdaError as exc:
        return False, f"G3 fail: {exc}", {}
    spec_hash = comp.spec_hash
    try:
        rounds, need_goldfish = rounds_for(STAGE, comp.tier, comp.rung)
    except DdaError as exc:
        return False, f"G3 fail: {exc}", {}
    problems: list[str] = []
    notes: list[str] = [f"tier {comp.tier}, rung {comp.rung}, rounds {','.join(rounds)}"]
    calls = [c for c in existing_calls(wd, STAGE) if c.get("spec_hash") == spec_hash]
    has_history = bool(calls)
    by_round: dict[str, list[dict]] = {}
    for c in calls:
        by_round.setdefault(str(c.get("round")), []).append(c)
    for rs in by_round.values():
        rs.sort(key=lambda c: int(c.get("seq") or 0))

    if not need_goldfish:
        missing = [r for r in rounds if r not in _self_rounds(wd, STAGE)]
        if missing:
            problems.append(f"no self re-read for round(s) {', '.join(missing)} "
                            f"(reviews/self/{STAGE}-round<N>.md, §5.3)")
        else:
            notes.append(f"self cold re-reads recorded for rounds {','.join(rounds)}")
    elif not has_history and not provider_available(wd):
        if comp.tier == "PUBLISH":
            problems.append("no provider key reachable and PUBLISH cannot degrade to self "
                            "re-reads: the analysis parks (§5.0 Fallback)")
        else:
            missing = [r for r in rounds if r not in _self_rounds(wd, STAGE)]
            if missing:
                problems.append(f"no goldfish provider key reachable and no self re-read for "
                                f"round(s) {', '.join(missing)} (footer must carry the caveat, §5.0)")
            else:
                notes.append("no provider key: degraded to self re-reads with footer caveat (§5.0)")
    else:
        for r in rounds:
            rs = by_round.get(r, [])
            if not rs:
                problems.append(f"no goldfish call for round {r} "
                                f"(`dda review run {STAGE} --round {r}`, §5.0)")
                continue
            if len(rs) > 2:
                problems.append(f"round {r} ran {len(rs)} times for this spec — goldfish "
                                "shopping: at most once re-run per round (§5.0)")
                continue
            if rs[-1].get("verdict") != "pass":
                problems.append(f"round {r}: latest call {rs[-1].get('provider_request_id')} "
                                f"is {rs[-1].get('verdict')} — fix the spec and re-run only "
                                "that round, at most once")
                continue
            for earlier in rs[:-1]:
                if earlier.get("verdict") in ("pass",):
                    continue
                resp = self_response_path(wd, STAGE, r)
                try:
                    body = resp.read_text(encoding="utf-8")
                except OSError:
                    body = ""
                rid = str(earlier.get("provider_request_id") or "")
                if not rid or rid not in body:
                    problems.append(f"round {r}: earlier call {rid or '?'} raised objections "
                                    f"with no recorded answer in {resp.relative_to(wd.root).as_posix()}")
                else:
                    notes.append(f"round {r}: earlier {rid} objections answered")
        if comp.tier == "PUBLISH":
            r3 = (by_round.get("3") or [{}])[-1]
            r3b = (by_round.get("3b") or [{}])[-1]
            if r3.get("verdict") == "pass" and r3b.get("verdict") == "pass":
                if r3.get("model") != r3b.get("model"):
                    notes.append("second goldfish on round 3 ran on a different model")
                else:
                    notes.append("second goldfish: same model — correlated blind spots possible (§5.0)")

    # Human spec approval at DECIDE+ (§3 row 3, §4.5).
    if comp.tier in ("DECIDE", "PUBLISH"):
        from . import approvals as _approvals
        verdict = _approvals.verify_approval(wd, "spec", spec_hash)
        if verdict.get("verified"):
            notes.append(f"human spec approval verified ({verdict.get('reason')})")
        elif "not found" in str(verdict.get("reason", "")) or "not committed" in str(
                verdict.get("reason", "")):
            problems.append(f"no human spec approval for this spec hash "
                            f"(`dda approve spec` in your own terminal, then `dda approved spec`; §3.2 case 2)")
        elif comp.tier == "PUBLISH":
            problems.append(f"PUBLISH needs a verified spec approval: "
                            f"{verdict.get('reason')} (§3.2 case 9: parks)")
        else:
            notes.append(f"human spec approval unverified (agent could have produced it): "
                         f"{verdict.get('reason')}")
    if problems:
        return False, "G3 fail: " + "; ".join(problems[:6]), {"rounds": rounds}
    return True, "G3 pass: " + "; ".join(notes), {"rounds": rounds}


__all__ = ["gate_g3", "STAGE"]
