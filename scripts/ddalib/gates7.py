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
        m = re.match(rf"^{re.escape(stage)}-round([0-9]+[a-z]?(?:@\d+)?)(?:-.*)?\.md$", p.name)
        try:
            if m and p.stat().st_size > 0:
                rounds.add(m.group(1))
        except OSError:
            continue
    return rounds


def goldfish_calls_gate(wd: Workdir, stage: str,
                        calls: list[dict], rounds: list[str]
                        ) -> tuple[list[str], list[str]]:
    """Shared goldfish binding checks for a review stage (§5.0 Recording).

    Lineage-wide (M2): `calls` spans every spec version in the lineage, the
    at-most-once re-run cap counts across epochs (an amendment never resets
    it), and each packet must bind the calling record's own spec. Every
    call must match a runs.log entry (no forged records), end on a pass,
    and have earlier-round objections — including failures from earlier
    epochs, which stay visible — answered in the matching self response
    file. `rounds` may name epoch rounds (``1@N``) re-due after a post-data
    amendment. Used by G3 (teardown) and G7 (post-result).
    """
    from . import chain as _chain
    from . import ledger as _ledger
    from . import lineage as _lineage
    from .review import packets_dir as _packets_dir
    import json as _json
    problems: list[str] = []
    notes: list[str] = []
    try:
        _chain_recs = _chain.read_records(_ledger.runs_log(wd))
    except Exception:
        _chain_recs = []
    _chain_revs = [e for e in _chain_recs
                   if e.get("kind") == "goldfish" and e.get("stage") == stage]

    def _bound(call: dict) -> bool:
        for e in _chain_revs:
            try:
                # `review_seq` is the per-stage call counter. `chain.append`
                # overwrites a caller `seq` with the global chain position,
                # so fall back to the chain position only for entries written
                # before `review_seq` existed (their positions coincided).
                entry_seq = e.get("review_seq", e.get("seq"))
                same_seq = int(entry_seq or -1) == int(call.get("seq") or -2)
            except (TypeError, ValueError):
                same_seq = False
            if (str(e.get("round") or "") == str(call.get("round") or "")
                    and same_seq
                    and str(e.get("packet_hash") or "") == str(call.get("packet_hash") or "")
                    and str(e.get("request") or "") == str(call.get("provider_request_id") or "")):
                return True
        return False

    _seen_packets: dict[tuple[str, str], bool] = {}

    def _packet_ok(call: dict) -> bool:
        packet_hash = str(call.get("packet_hash") or "")
        key = (packet_hash, str(call.get("spec_hash") or ""))
        if key in _seen_packets:
            return _seen_packets[key]
        ok = False
        if packet_hash:
            man_path = _packets_dir(wd) / packet_hash / "manifest.json"
            try:
                man = _json.loads(man_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                man = None
            ok = (isinstance(man, dict) and man.get("packet_hash") == packet_hash
                  and man.get("stage") == stage
                  and man.get("spec_hash") == call.get("spec_hash"))
        _seen_packets[key] = ok
        return ok

    by_round: dict[str, list[dict]] = {}
    for c in calls:
        by_round.setdefault(str(c.get("round")), []).append(c)
    for rs in by_round.values():
        rs.sort(key=lambda c: int(c.get("seq") or 0))

    for r in rounds:
        base = _lineage.base_round(r)
        rs = by_round.get(r, [])
        if not rs:
            problems.append(f"no goldfish call for round {r} "
                            f"(`dda review run {stage} --round {r}`, §5.0)")
            continue
        for c in rs:
            if not _bound(c):
                problems.append(f"round {r}: call seq {c.get('seq')} (req "
                                f"{c.get('provider_request_id')}) has no matching "
                                f"runs.log entry — forged or unlogged review records "
                                f"do not count (§5.0 Recording)")
            elif not _packet_ok(c):
                problems.append(f"round {r}: packet {str(c.get('packet_hash') or '')[:12]} "
                                f"missing or manifest mismatch — re-run "
                                f"`dda packet {stage}` before review (§5.0)")
        if len(rs) > 2:
            problems.append(f"round {r} ran {len(rs)} times in this lineage — goldfish "
                            "shopping: at most one re-run per round, across amendments (§5.0)")
            continue
        if rs[-1].get("verdict") != "pass":
            problems.append(f"round {r}: latest call {rs[-1].get('provider_request_id')} "
                            f"is {rs[-1].get('verdict')} — fix the spec and re-run only "
                            "that round, at most once")
            continue
        # Earlier failures stay visible and must be answered: same-base-round
        # objections from any epoch — including sibling epoch rounds — need
        # a recorded answer in this round's self response file.
        earlier = [c for c in rs[:-1] if c.get("verdict") != "pass"]
        for c in calls:
            if (c not in rs and _lineage.base_round(str(c.get("round"))) == base
                    and c.get("verdict") != "pass"):
                earlier.append(c)
        resp = self_response_path(wd, stage, r)
        try:
            body = resp.read_text(encoding="utf-8")
        except OSError:
            body = ""
        for fail in earlier:
            rid = str(fail.get("provider_request_id") or "")
            where = f"spec {(str(fail.get('spec_hash')) or '')[:12]}"
            if not rid or rid not in body:
                problems.append(f"round {r}: earlier call {rid or '?'} ({where}) raised objections "
                                f"with no recorded answer in {resp.relative_to(wd.root).as_posix()}")
            else:
                notes.append(f"round {r}: earlier {rid} ({where}) objections answered")
    return problems, notes


def gate_g3(wd: Workdir) -> tuple[bool, str, dict]:
    """Teardown gate: required rounds recorded, objections answered, and the
    human spec approval present at DECIDE+ (verified only at PUBLISH)."""
    wd.require_initialized()
    try:
        comp = lockhash.compute(wd)
    except DdaError as exc:
        return False, f"G3 fail: {exc}", {}
    from . import lineage as _lineage
    try:
        # Epoch rounds: a post-data amendment at DECIDE+ re-dues rounds 1
        # and 3 as new rounds 1@N / 3@N (M2).
        rounds, need_goldfish = _lineage.due_teardown_rounds(wd, comp)
    except DdaError as exc:
        return False, f"G3 fail: {exc}", {}
    problems: list[str] = []
    notes: list[str] = [f"tier {comp.tier}, rung {comp.rung}, rounds {','.join(rounds)}"]
    # Lineage-wide (M2): every epoch counts toward the cap and the pass.
    calls = existing_calls(wd, STAGE)
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
        probs, nts = goldfish_calls_gate(wd, STAGE, calls, rounds)
        problems.extend(probs)
        notes.extend(nts)
        by_round = {}
        for c in calls:
            by_round.setdefault(str(c.get("round")), []).append(c)
        if comp.tier == "PUBLISH":
            due3 = next((r for r in rounds if _lineage.base_round(r) == "3" and r != "3b"), "3")
            r3 = (by_round.get(due3) or [{}])[-1]
            r3b = (by_round.get("3b") or [{}])[-1]
            if r3.get("verdict") == "pass" and r3b.get("verdict") == "pass":
                if r3.get("model") != r3b.get("model"):
                    notes.append("second goldfish on round 3 ran on a different model")
                else:
                    notes.append("second goldfish: same model — correlated blind spots possible (§5.0)")

    # Human spec approval at DECIDE+ (§3 row 3, §4.5): the one requirements
    # table (M1). Below PUBLISH an unverified/downgraded approval is
    # disclosed; at PUBLISH only a verified approval passes.
    if comp.tier in ("DECIDE", "PUBLISH"):
        from . import requirements as _requirements
        ok, req_notes, _info = _requirements.require(wd, "G3")
        if ok:
            notes.append(f"human approval holds ({'; '.join(req_notes)})")
        else:
            problems.append("; ".join(req_notes) + " (§3.2 case 2/9: parks at PUBLISH)")
    if problems:
        return False, "G3 fail: " + "; ".join(problems[:6]), {"rounds": rounds}
    return True, "G3 pass: " + "; ".join(notes), {"rounds": rounds}


__all__ = ["gate_g3", "goldfish_calls_gate", "STAGE"]
