"""One requirements table (M1): (gate, tier) -> [(kind, digest_fn)].

Gates call `require(wd, gate)` and nothing else — no gate may call
`verify_approval` or `config_status` directly. `min_state` is `"verified"`
at PUBLISH and `"unverified_ok"` below it: below PUBLISH an UNVERIFIED or
DOWNGRADED approval is disclosed and passes; anything else (MISSING,
UNCOMMITTED, STALE, BAD_SIG, UNKNOWN_SIGNER) fails everywhere, and at
PUBLISH only a human state passes: VERIFIED (signed) or CONFIRMED
(Telegram confirmation from an approver's account) — equivalent at every
tier.
"""
from __future__ import annotations

from .layout import DdaError, Workdir

# (gate, tier) -> list of (kinds-any-of, when)
# `when(wd)` selects version-dependent requirements (G3 amendment vs spec).
_TABLE: dict[tuple[str, str], list[tuple[tuple[str, ...], object]]] = {}


def _version(wd: Workdir) -> int:
    from . import ledger as _ledger
    try:
        lock = _ledger.last_lock_record(wd)
        return int((lock or {}).get("version") or 0)
    except (DdaError, OSError, ValueError, TypeError):
        return 0


def _v1(wd: Workdir) -> bool:
    return _version(wd) <= 1


def _v2plus(wd: Workdir) -> bool:
    return _version(wd) > 1


def lowered(wd: Workdir) -> bool:
    """True when the current tier sits below a previously locked tier."""
    from . import chain as _chain
    from . import ledger as _ledger
    try:
        recs = [r for r in _chain.read_records(_ledger.ledger_path(wd))
                if r.get("type") in ("lock", "amendment")]
        cur = _ledger.last_lock_record(wd)
        cur_tier = str((cur or {}).get("tier") or "").upper()
    except (DdaError, OSError):
        return False
    rank = {"EXPLORE": 0, "DECIDE": 1, "PUBLISH": 2}
    if cur_tier not in rank:
        return False
    prev = [str(r.get("tier") or "").upper() for r in recs[:-1] if str(r.get("tier") or "").upper() in rank]
    return bool(prev) and max(rank[t] for t in prev) > rank[cur_tier]


def _always(wd: Workdir) -> bool:
    return True


_TABLE[("G2", "EXPLORE")] = [(("tier", "spec"), _always), (("amendment",), lowered)]
_TABLE[("G2", "DECIDE")] = [(("tier", "spec"), _always), (("amendment",), lowered)]
_TABLE[("G2", "PUBLISH")] = [(("tier", "spec"), _always), (("amendment",), lowered)]
_TABLE[("G3", "DECIDE")] = [(("spec", "amendment"), _always)]
_TABLE[("G3", "PUBLISH")] = [(("spec", "amendment"), _always)]
_TABLE[("G4", "EXPLORE")] = [(("config",), _always)]
_TABLE[("G4", "DECIDE")] = [(("config",), _always)]
_TABLE[("G4", "PUBLISH")] = [(("config",), _always)]
_TABLE[("G8", "PUBLISH")] = [(("signoff",), _always)]


# ---------- gate applicability (M3) ----------
#
# Which gates the G0-G9 cascade runs at each tier. A gate not listed for
# the workdir's tier is vacuously pass in the cascade — tier-awareness
# lives HERE, never in per-gate predicates.
#
# EXPLORE is curiosity/internal: the data path (teardown review G3,
# profile G5, verify G7) is not required, so an EXPLORE report gate
# verifies from the footer and the lock alone. DECIDE and PUBLISH run the
# full path. (The explicitly requested gate always evaluates its own
# condition — N/A only excuses cascade intermediates; see evaluate.py.)
_APPLICABLE: dict[str, frozenset[str]] = {
    "EXPLORE": frozenset({"G0", "G1", "G2", "G4", "G6", "G8", "G9"}),
    "DECIDE": frozenset({"G0", "G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8", "G9"}),
    "PUBLISH": frozenset({"G0", "G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8", "G9"}),
}


def applicable_gates(tier: str) -> frozenset[str]:
    """Gates the cascade runs at `tier` (unknown tiers run everything)."""
    return _APPLICABLE.get((tier or "").upper(), _APPLICABLE["PUBLISH"])


def is_applicable(wd: Workdir, gate: str) -> bool:
    """True when `gate` runs in the cascade at the workdir's tier."""
    return gate.upper() in applicable_gates(tier_of(wd))


def tier_of(wd: Workdir) -> str:
    """Effective tier: the lock tier, else the spec Tier section."""
    from . import ledger as _ledger
    try:
        lock = _ledger.last_lock_record(wd)
        if lock and str(lock.get("tier") or "").strip().upper() in ("EXPLORE", "DECIDE", "PUBLISH"):
            return str(lock["tier"]).strip().upper()
    except (DdaError, OSError):
        pass
    try:
        from . import lockhash
        from .layout import read_text_lf
        sections = lockhash.parse_sections(read_text_lf(wd.spec_path))
        line = lockhash.normalize_ws(sections.get("Tier", "")).upper()
        for t in ("PUBLISH", "DECIDE", "EXPLORE"):
            if t in line:
                return t
    except (DdaError, OSError):
        pass
    return "EXPLORE"


def _acceptable(state: str, tier: str) -> bool:
    from .approvals import ApprovalState, HUMAN_STATES
    # VERIFIED (signed) and CONFIRMED (Telegram) are both a human's own
    # approval and pass at every tier, PUBLISH included.
    if state in HUMAN_STATES:
        return True
    if tier != "PUBLISH" and state in (ApprovalState.UNVERIFIED.value, ApprovalState.DOWNGRADED.value):
        return True
    return False


def require(wd: Workdir, gate: str, kinds: tuple[str, ...] | None = None) -> tuple[bool, list[str], dict]:
    """Check the requirements table for `gate` at the workdir's tier.

    Returns (ok, notes, info). The ONLY entry point gates use for approvals.
    `kinds` optionally limits evaluation to a subset of kinds (still from
    this table) — used for the always-on tier-lowering check on paths that
    need no tier confirmation.
    """
    from . import approvals as _approvals
    tier = tier_of(wd)
    entries = _TABLE.get((gate.upper(), tier), [])
    notes: list[str] = []
    failed: list[str] = []
    info: dict = {"gate": gate.upper(), "tier": tier, "items": []}
    for kinds_row, when in entries:
        if callable(when) and not when(wd):
            continue
        if kinds is not None and not any(k in kinds for k in kinds_row):
            continue
        items: list[dict] = []
        for kind in kinds_row:
            digest = _approvals.current_digest(wd, kind)
            if digest is None:
                items.append({"kind": kind, "state": "missing", "ok": False,
                              "reason": f"no computable {kind} digest (nothing to approve yet)"})
                continue
            v = _approvals.verify_approval(wd, kind, digest)
            ok = _acceptable(v["state"], tier)
            items.append({"kind": kind, "digest": v.get("digest"), "state": v["state"],
                          "ok": ok, "reason": v["reason"], "method": v.get("method"),
                          "method_label": _approvals.method_label(v)})
        info["items"].extend(items)
        rep = next((i for i in items if i["ok"]), items[0] if items else None)
        if rep is None:
            continue
        if rep["ok"]:
            if rep["state"] not in _approvals.HUMAN_STATES:
                notes.append(f"{rep['kind']} approval {rep['state']} (disclosed at {tier})")
            else:
                notes.append(f"{rep['kind']} approval {rep['state']} "
                             f"({str(rep.get('digest') or '')[:12]}; {rep.get('method_label')})")
        else:
            failed.append(f"{rep['kind']}: {rep['reason']}")
    # EXPLORE G4 discloses a missing config instead of failing (legacy
    # behavior: unapproved configs are usable at EXPLORE, §4.5).
    if failed and gate.upper() == "G4" and tier == "EXPLORE":
        if all("no committed config approval" in f or "not computable" in f for f in failed):
            notes.append("unapproved config disclosed at EXPLORE")
            return True, notes, info
    if failed:
        return False, failed, info
    return True, notes, info


__all__ = ["require", "tier_of", "lowered", "applicable_gates", "is_applicable"]
