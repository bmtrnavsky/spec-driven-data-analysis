"""Gates G2, G5, G7 (SPEC §3, §14 item 8).

G2 (tier): rung and tier declared, PII/rung overrides, tier triggers from
§2.2, and human tier confirmation when required. G5 (profile): a snapshot
or fingerprint recorded per source (§10.3), schema compared with declared
expectations, snapshot integrity. G7 (verify/reproduce): the locked variant
reproduces from its saved script in a fresh kernel within the declared
tolerance against the snapshot, drift recorded, matched correction evals
pass, post-result goldfish rounds recorded (§5.2).
"""
from __future__ import annotations

import re
from pathlib import Path

from . import ledger, lockhash, lockstate, review
from . import stage8
from .layout import DdaError, Workdir, load_config

STAGE_POST_RESULT = "post-result"

TIER_RANK = {"EXPLORE": 0, "DECIDE": 1, "PUBLISH": 2}

DECISION_NONE_RE = re.compile(r"\s*none\s*(?:\u2014|-|–)?:?\s*explore\s*$", re.IGNORECASE)
AUDIENCE_EXTERNAL_RE = re.compile(
    r"\b(external|public|client|customer|blog|publish|press|partner|regulator|stakeholder)\b",
    re.IGNORECASE)
TOPIC_TRIGGER_RE = re.compile(r"\b(money|trad(?:e|ing)|health(?:care|y)?|medical|patient(?:s)?|diagnos(?:is|es|tic)?|clinic(?:al)?|hospital(?:s)?|disease(?:s)?|drug(?:s)?|treatment(?:s)?)\b",
                              re.IGNORECASE)


def _preamble(wd: Workdir) -> tuple[dict, object]:
    """Lock valid + chains verify. Returns (lock, comp)."""
    wd.require_initialized()
    state, detail, lock = lockstate.quick_status(wd)
    if state != "valid":
        return None, DdaError(f"lock is not valid ({state}: {detail})")
    problems, _ = ledger.verify_all(wd)
    if problems:
        return None, DdaError("evidence chain failed to verify — stop and ask (§3.2 case 8):\n  - "
                              + "\n  - ".join(problems), ledger.EXIT_CHAIN)
    try:
        comp = lockhash.compute(wd)
    except DdaError as exc:
        return None, DdaError(f"spec does not compute: {exc}")
    if not lock or lock.get("lock_hash") != comp.lock_hash:
        return None, DdaError("workdir changed since lock (spec, config, or definitions); "
                              "re-lock or amend before gating (§3.1)")
    return (lock, comp), None


# ---------- G2 ----------

def _sections(wd: Workdir) -> dict:
    try:
        return lockhash.parse_sections(wd.spec_path.read_text(encoding="utf-8"))
    except (OSError, DdaError):
        return {}


def tier_triggers(wd: Workdir, comp) -> tuple[str, list[str]]:
    """Minimum tier from §2.2 triggers. Returns (min_tier, [reasons])."""
    sections = _sections(wd)
    mins = []
    decision = (sections.get("Decision it informs", "") or sections.get("Decision", ""))
    if decision and not DECISION_NONE_RE.match(decision.strip()):
        mins.append(("DECIDE", "G0 names a decision (§2.2: a decision at stake is at least DECIDE)"))
    audience = sections.get("Audience", "")
    if audience and AUDIENCE_EXTERNAL_RE.search(audience):
        mins.append(("PUBLISH", "audience is external (§2.2: PUBLISH is forced)"))
    text = " ".join([sections.get(k, "") for k in ("Question", "Audience")]
                   + [sections.get("Decision it informs", "") or sections.get("Decision", "")])
    if TOPIC_TRIGGER_RE.search(text):
        mins.append(("DECIDE", "topic tags include money/trading/health (§2.2)"))
    try:
        locs = (load_config(wd).get("data_roots") or {})
    except DdaError:
        locs = {}
    for alias in comp.aliases:
        loc = locs.get(alias) or {}
        if loc.get("pii") or loc.get("pii_columns"):
            mins.append(("DECIDE", f"alias {alias!r} is flagged PII/regulated (§2.2)"))
            break
    if not mins:
        return "EXPLORE", []
    rank = max(TIER_RANK[m] for m, _ in mins)
    top = [m for m in ("EXPLORE", "DECIDE", "PUBLISH") if TIER_RANK[m] == rank][0]
    return top, [r for m, r in mins if m == top]


def _tier_confirmation(wd: Workdir, tier: str, kinds: tuple[str, ...] | None = None):
    """Human tier confirmation via the one requirements table (M1)."""
    from . import requirements as _requirements
    ok, notes, _info = _requirements.require(wd, "G2", kinds=kinds)
    if ok:
        return True, "; ".join(notes) if notes else "tier approval holds"
    return False, "; ".join(notes)


def gate_g2(wd: Workdir) -> tuple[bool, str, dict]:
    pre, err = _preamble(wd)
    if err is not None:
        return False, str(err), {}
    lock, comp = pre
    tier, rung = comp.tier, comp.rung
    if not tier or not rung:
        msg = "rung and tier must both be declared in the spec (§2.1)"
        return False, msg, {}
    if rung == "glance" and tier == "PUBLISH":
        msg = "PUBLISH is never glance (§2.1)"
        return False, msg, {}
    try:
        locs = (load_config(wd).get("data_roots") or {})
    except DdaError:
        locs = {}
    pii = any((locs.get(a) or {}).get("pii") or (locs.get(a) or {}).get("pii_columns")
              for a in comp.aliases)
    if pii and rung == "glance":
        msg = "PII or regulated data steps up one rung: glance is not allowed (§2.1)"
        return False, msg, {}
    min_tier, reasons = tier_triggers(wd, comp)
    if TIER_RANK[tier] < TIER_RANK[min_tier]:
        msg = (f"declared tier {tier} is below the triggered minimum {min_tier}: "
               + "; ".join(reasons))
        return False, msg, {"triggers": reasons}
    notes = []
    if tier != "EXPLORE" or reasons:
        ok, why = _tier_confirmation(wd, tier)
        if not ok:
            return False, why, {"min_tier": min_tier, "triggers": reasons}
        notes.append(why)
    else:
        from . import requirements as _rq2
        if _rq2.lowered(wd):
            # Tier lowered mid-run with no triggers: the amendment approval
            # is still required (§2.2).
            ok, why = _tier_confirmation(wd, tier, kinds=("amendment",))
            if not ok:
                return False, why, {"min_tier": min_tier, "tier_lowered": True}
            notes.append(why)
        else:
            notes.append("EXPLORE with no triggers: tier agent-confirmed (§2.2)")
    if TIER_RANK[tier] > TIER_RANK[min_tier]:
        notes.append(f"declared {tier} is above the triggered minimum {min_tier} (allowed)")
    msg = f"G2 pass: rung {rung}, tier {tier}" + (" (" + "; ".join(notes) + ")" if notes else "")
    return True, msg, {"tier": tier, "rung": rung, "min_tier": min_tier,
                       "triggers": reasons, "notes": notes}


# ---------- G5 ----------

def gate_g5(wd: Workdir) -> tuple[bool, str, dict]:
    pre, err = _preamble(wd)
    if err is not None:
        return False, str(err), {}
    lock, comp = pre
    prof = stage8.load_profile(wd)
    if prof is None:
        msg = "no profile: run `dda profile` to snapshot every source before analysis (§10.3)"
        return False, msg, {}
    if prof.get("lock_hash") != comp.lock_hash:
        msg = ("the profile predates the current lock (spec changed or amended): "
               "re-run `dda profile` (G5)")
        return False, msg, {}
    problems = []
    notes = []
    for alias in comp.aliases:
        prec = (prof.get("aliases") or {}).get(alias)
        if prec is None:
            problems.append(f"alias {alias!r} has no snapshot or fingerprint: re-run `dda profile`")
            continue
        if prec.get("kind") == "live-only":
            desc = prec.get("descriptor") or {}
            bits = [f"{k}={','.join(v) if isinstance(v, list) else v}"
                    for k, v in desc.items() if v and k != "note"]
            notes.append(f"{alias}: fingerprint (live-only: {'; '.join(bits) or 'no locators'})")
            continue
        sdir = wd.root / (prec.get("snapshot_dir") or "")
        for live, f in (prec.get("files") or {}).items():
            snap = sdir / (f.get("rel") or "")
            if not snap.is_file():
                problems.append(f"alias {alias!r}: snapshot copy missing: "
                                f"{prec.get('snapshot_dir')}/{f.get('rel')}")
                continue
            if stage8.sha256_file(snap) != f.get("sha256"):
                problems.append(f"alias {alias!r}: snapshot copy changed since profile: "
                                f"{f.get('rel')} (raw data is immutable — stop and ask, §3.2 case 8)")
        # Schema vs declared expectations: the profile baseline is the
        # declaration; a mismatch rides an amendment (enforced by `dda profile`).
        try:
            cur_schema = {live: stage8.schema_of(stage8.header_sig(Path(live) if Path(live).is_absolute()
                                                                   else wd.root / live))
                          for live in (prec.get("files") or {})}
        except DdaError as exc:
            problems.append(f"alias {alias!r}: cannot re-read live schema: {exc}")
            continue
        old_schema = {live: stage8.schema_of(f) for live, f in (prec.get("files") or {}).items()}
        if cur_schema != old_schema:
            problems.append(f"alias {alias!r}: schema changed since profile "
                            "(columns added, removed, renamed, or retyped) — file it as an "
                            "amendment (`dda lock --amend`), then re-profile")
        else:
            notes.append(f"{alias}: schema matches profile, snapshot intact")
    if problems:
        msg = "G5 fails:\n  - " + "\n  - ".join(problems)
        return False, msg, {"profile_asof": prof.get("asof")}
    msg = f"G5 pass: {len(comp.aliases)} source(s) snapshotted/fingerprinted at {prof.get('asof')}"
    if notes:
        msg += " (" + "; ".join(notes) + ")"
    return True, msg, {"profile_asof": prof.get("asof"), "notes": notes}


# ---------- G7 ----------

def _self_gate(wd: Workdir, stage: str, rounds: list[str]) -> tuple[bool, str, dict]:
    from .gates7 import _self_rounds
    missing = [r for r in rounds if r not in _self_rounds(wd, stage)]
    if missing:
        return False, (f"no self re-read for round(s) {', '.join(missing)} "
                       f"(reviews/self/{stage}-round<N>.md, §5.3)"), {"due": rounds}
    return True, f"self cold re-reads recorded for rounds {','.join(rounds)}", {"due": rounds}


def _goldfish_gate(wd: Workdir, comp, spec_hash: str) -> tuple[bool, str, dict]:
    """Post-result rounds: self re-reads, degradation, or bound goldfish calls (mirrors G3)."""
    from .gates7 import _self_rounds, goldfish_calls_gate
    stage = STAGE_POST_RESULT
    try:
        rounds, need_goldfish = review.rounds_for(stage, comp.tier, comp.rung)
    except DdaError as exc:
        return False, f"bad tier/rung for post-result rounds: {exc}", {}
    notes = [f"tier {comp.tier}, rung {comp.rung}, rounds {','.join(rounds)}"]
    # Lineage-wide (M2): every epoch counts toward the cap and the pass.
    calls = review.existing_calls(wd, stage)
    if not need_goldfish:
        ok, msg, _ = _self_gate(wd, stage, rounds)
        return (True, f"{'; '.join(notes)}; {msg}", {"due": rounds}) if ok else (False, msg, {"due": rounds})
    if not calls and not review.provider_available(wd):
        if comp.tier == "PUBLISH":
            return False, ("no provider key reachable and PUBLISH cannot degrade to self "
                           "re-reads: the analysis parks (§5.0 Fallback)"), {"due": rounds}
        ok, msg, _ = _self_gate(wd, stage, rounds)
        if not ok:
            return False, (f"no goldfish provider key reachable and {msg} "
                           "(footer must carry the caveat, §5.0)"), {"due": rounds}
        return True, f"{'; '.join(notes)}; no provider key: degraded to self re-reads with footer caveat (§5.0)", {"due": rounds}
    probs, nts = goldfish_calls_gate(wd, stage, calls, rounds)
    notes.extend(nts)
    if probs:
        return False, "; ".join(probs[:6]), {"due": rounds}
    return True, "; ".join(notes), {"due": rounds}


def gate_g7(wd: Workdir) -> tuple[bool, str, dict]:
    from . import kernel as _kernel
    pre, err = _preamble(wd)
    if err is not None:
        return False, str(err), {}
    lock, comp = pre
    vid = _kernel.locked_variant_id(wd)
    if not vid:
        msg = "no locked variant: mark the reported variant first (`dda variant --locked <id>`, §4.3)"
        return False, msg, {}
    ok5, msg5, _ = gate_g5(wd)
    if not ok5:
        msg = f"G7 fails: profile gate fails:\n{msg5}"
        return False, msg, {}
    prof = stage8.load_profile(wd) or {}
    ver = stage8.load_verify(wd)
    if ver is None:
        msg = "no verify evidence: run `dda verify` (replay the locked script against the snapshot, §10.3)"
        return False, msg, {}
    for key in ("lock_hash", "variant", "body_hash"):
        want = {"lock_hash": comp.lock_hash, "variant": vid,
                "body_hash": _kernel.frozen_hash(wd, vid)}[key]
        if ver.get(key) != want:
            msg = (f"verify evidence is stale ({key} mismatch): re-run `dda verify` "
                   "after re-locking, re-profiling, or re-freezing")
            return False, msg, {}
    if (ver.get("status") or "") != "reproduced within tolerance":
        live_note = ver.get("live_only_note")
        if live_note and comp.tier != "PUBLISH":
            note = f"G7 pass with caveat below PUBLISH: {live_note}"
            return True, note, {"caveat": live_note}
        msg = f"G7 fails: replay did not reproduce: {ver.get('status')}"
        return False, msg, {}
    # Replays really happened: run entries under this lock+body, overlay-bound.
    entries = [e for e in _kernel.run_entries(wd, vid)
               if e.get("type") == "run" and e.get("lock_hash") == comp.lock_hash
               and e.get("body_hash") == ver.get("body_hash")]
    replays = [e for e in entries if e.get("replay") and e.get("returncode") == 0]
    if len(replays) < 2:
        msg = ("verify evidence names replays with no matching successful run entries "
f"({len(replays)} found, need 2): the specs-tried ledger is the binding record (§4.5)")
        return False, msg, {}
    # Profile-before-results (§10.3), lineage-ordered (M2): the snapshot must
    # predate analysis. Sticky: once any non-replay data run precedes the
    # profile the verify replays against, the lineage carries the
    # profile-after-results label — a later amendment and re-profile cannot
    # clear it (chain seq only; no timestamps, no mtimes).
    from . import lineage as _lineage
    lin = _lineage.lineage(wd)
    if lin["results_seen_before_profile"]:
        msg = (f"G7 fails: results were seen before the profile the verify replays against "
               f"(profile-after-results lineage {str(lin['lineage_id'] or '')[:12]}: first data run "
               f"at lineage seq {lin['first_run_seq']} precedes profile seq {lin['results_profile_seq']} "
               f"(lock {str(lin['results_profile_lock_hash'] or '')[:12]})): run `dda profile` before "
               "`dda run`, then re-run `dda verify` (§10.3)")
        return False, msg, {"lineage_id": lin["lineage_id"]}
    # Overlay binding: the replay overlay must equal the profile snapshot map.
    from .matching import canon as _canon
    want_overlay: dict[str, str] = {}
    for alias in comp.aliases:
        prec = (prof.get("aliases") or {}).get(alias) or {}
        if prec.get("kind") == "snapshot":
            sdir = wd.root / (prec.get("snapshot_dir") or "")
            for live, f in (prec.get("files") or {}).items():
                want_overlay[live] = _canon(str(sdir / (f.get("rel") or "")), str(wd.root))
            for live_root, snap_root in (prec.get("roots") or {}).items():
                want_overlay.setdefault(live_root, snap_root)
    for e in replays:
        if (e.get("snapshot_overlay") or {}) != want_overlay:
            msg = ("a replay ran against a different snapshot map than the profile records "
                   "(overlay mismatch): re-run `dda verify` against the current profile")
            return False, msg, {}
    # Matched correction evals: bound cases with failing checks stop DECIDE+.
    matched = stage8.match_evals(wd)
    if len(matched) != ver.get("evals_matched"):
        msg = (f"correction-eval match changed since verify ({ver.get('evals_matched')} then, "
               f"{len(matched)} now): re-run `dda verify` (§9)")
        return False, msg, {}
    for m in matched:
        if not m.get("bound"):
            continue
        if m.get("case_hash") != next((e.get("case_hash") for e in ver.get("evals", [])
                                       if e.get("case") == m["case"]), None):
            msg = f"correction case {m['case']!r} changed since verify: re-run `dda verify` (§9)"
            return False, msg, {}
        status = next((e.get("status") for e in ver.get("evals", []) if e.get("case") == m["case"]), "?")
        if status == "fail":
            msg = (f"G7 fails: matched correction eval {m['case']!r} fails "
                   "(stop and ask, §3.2 case 5)")
            return False, msg, {}
    ok, rmsg, info = _goldfish_gate(wd, comp, comp.spec_hash)
    if not ok:
        msg = f"G7 fails: {rmsg}"
        return False, msg, info
    msg = (f"G7 pass: locked variant {vid!r} reproduces within `{ver.get('tolerance_text')}`; "
           + rmsg)
    return True, msg, {"tolerance": ver.get("tolerance_text")}


__all__ = ["gate_g2", "gate_g5", "gate_g7", "tier_triggers", "TIER_RANK"]
