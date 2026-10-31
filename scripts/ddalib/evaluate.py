"""Single gate evaluator (M3): runs G0-G9 in order over one snapshot.

A gate passes only if all earlier APPLICABLE gates pass: once an
applicable gate fails, every later verdict is forced to fail and names the
earliest failing gate. Applicability comes from the requirements table
(`requirements.is_applicable`): a gate not required at the workdir's tier
is vacuously pass as a cascade intermediate. The explicitly requested
gate always evaluates its own condition, so `dda gate G5` still reports
G5's own verdict at EXPLORE.

`dda gate <Gn>` returns `evaluate()[Gn]`; wayfinder lines are written
from these verdicts. The gate-verdict digest (sha256 of the ordered
verdict tuple) is part of the signoff release digest, so a signoff covers
exactly the evaluated state.
"""
from __future__ import annotations

import hashlib

from .layout import Workdir

ORDER = ["G0", "G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8", "G9"]


def _run_gate(wd: Workdir, gate: str, report: str | None = None) -> tuple[bool, str, dict]:
    from . import gates5, gates6, gates7, gates8, ledger
    fn = {
        "G0": gates5.gate_g0,
        "G1": gates6.gate_g1,
        "G2": gates8.gate_g2,
        "G3": gates7.gate_g3,
        "G4": ledger.gate_g4,
        "G5": gates8.gate_g5,
        "G6": ledger.gate_g6,
        "G7": gates8.gate_g7,
        "G8": gates5.gate_g8,
        "G9": gates5.gate_g9,
    }[gate]
    if gate == "G8" and report:
        return fn(wd, report=report)
    return fn(wd)


def evaluate(wd: Workdir, through: str = "G9", report: str | None = None) -> dict:
    """Run gates G0..`through` in order with monotonic cascade.

    Returns {"verdicts": {gate: (passed, reason, info)}, "digest": hex,
    "tier": tier}. Raw checks still run for every applicable gate (for
    diagnostics), but a gate's verdict passes only if all earlier
    applicable gates pass. Gates not applicable at the workdir's tier are
    vacuously pass — except the requested gate, which always evaluates.
    """
    from . import requirements as _requirements
    wd.require_initialized()
    through = through.upper()
    if through not in ORDER:
        raise ValueError(f"unknown gate {through!r}")
    tier = _requirements.tier_of(wd)
    verdicts: dict[str, tuple[bool, str, dict]] = {}
    first_failure: str | None = None
    first_reason = ""
    for gate in ORDER[:ORDER.index(through) + 1]:
        if gate != through and gate not in _requirements.applicable_gates(tier):
            verdicts[gate] = (True, f"{gate} N/A at {tier} (not required)",
                              {"applicable": False, "tier": tier})
            continue
        try:
            passed, reason, info = _run_gate(wd, gate, report)
        except Exception as exc:  # fail closed: a crashing gate fails
            passed, reason, info = False, f"{gate} error: {type(exc).__name__}: {exc}", {}
        if first_failure is not None:
            verdicts[gate] = (False,
                              f"{gate} blocked: {first_failure} fails: {first_reason} "
                              f"({gate} raw: {reason})",
                              {"blocked_by": first_failure, **info})
        else:
            verdicts[gate] = (passed, reason, info)
            if not passed:
                first_failure, first_reason = gate, reason
    return {"verdicts": verdicts, "digest": verdict_digest(verdicts), "tier": tier}


def verdict_digest(verdicts: dict[str, tuple[bool, str, dict]]) -> str:
    """sha256 of the ordered (gate, outcome, reason) verdict tuple."""
    ordered = sorted(verdicts.items(), key=lambda kv: ORDER.index(kv[0]) if kv[0] in ORDER else 99)
    canon = "|".join(f"{g}:{'pass' if p else 'fail'}:{r}" for g, (p, r, _i) in ordered)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


__all__ = ["ORDER", "evaluate", "verdict_digest"]
