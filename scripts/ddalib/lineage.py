"""Lineage (M2): one total order across lock epochs (SPEC §3.1/§10.3).

Every lineage event — lock, amendment, profile, run, review, degrade,
verify — stages to a single chain (``.analysis/lineage.jsonl``) through
``chain.append``. Each record carries:

- ``lineage_id``: the lock hash of the first lock record. Survives every
  amendment; never recomputed from file content.
- ``lock_epoch``: the lock ``version`` the event belongs to.
- ``lock_hash``: the lock hash the event belongs to.

History is computed, never stored: :func:`lineage` replays the chain into
the view the gates read. Ordering checks use chain ``seq`` only — no
timestamps, no mtimes anywhere.

The view:

- ``review_calls(stage, round=None)``: goldfish review events across ALL
  spec versions in the lineage. The "at most one re-run per round" cap
  counts lineage-wide: an amendment never resets it.
- ``results_seen_before_profile``: true iff any non-replay data-touching
  run event (any variant, any epoch) has ``seq`` < ``seq`` of the latest
  profile event (the profile a verify replays against). Sticky: a later
  amendment and re-profile cannot clear it — the earlier run seq is still
  below the new profile seq.
- ``goldfish_mode``: true once any provider call exists in the lineage.
  ``degraded``: true only if ``dda`` recorded a ``degrade`` event before
  any goldfish call.
- Post-data amendment at DECIDE+: teardown rounds 1 and 3 are re-due as
  new rounds ``1@N`` / ``3@N`` (N = current epoch). Earlier failures stay
  visible and must be answered; the human amendment approval binds the
  review-history digest (approvals._amendment_payload).
"""
from __future__ import annotations

from pathlib import Path

from . import chain
from .layout import Workdir

LINEAGE_LOG = "lineage.jsonl"

LOCK_EVENT = ("lock", "amendment")


def lineage_log(wd: Workdir) -> Path:
    return wd.analysis / LINEAGE_LOG


def events(wd: Workdir) -> list[dict]:
    """All lineage records in chain order (empty when nothing staged yet)."""
    try:
        return chain.read_records(lineage_log(wd))
    except OSError:
        return []


def lineage_id_of(wd: Workdir) -> str | None:
    """The lineage id: lock hash of the first lock/amendment record.

    Prefers the lineage chain itself; bootstraps from the ledger for
    workdirs locked before lineage staging existed.
    """
    for rec in events(wd):
        if rec.get("type") in LOCK_EVENT and rec.get("lineage_id"):
            return rec["lineage_id"]
    try:
        from . import ledger as _ledger
        for rec in chain.read_records(_ledger.ledger_path(wd)):
            if rec.get("type") in LOCK_EVENT and rec.get("lock_hash"):
                return rec["lock_hash"]
    except OSError:
        pass
    return None


def stage_event(wd: Workdir, event: str, *, lock_hash: str, version: int, **fields) -> dict:
    """Stage one lineage event. Returns the stored record (with seq)."""
    lid = lineage_id_of(wd)
    rec = {"type": event, "lineage_id": lid or lock_hash,
           "lock_epoch": version, "lock_hash": lock_hash, **fields}
    return chain.append(lineage_log(wd), rec)


def review_calls(wd: Workdir, stage: str, round: str | None = None) -> list[dict]:
    """Goldfish review events for `stage` (optionally one round), all epochs."""
    out = [e for e in events(wd)
           if e.get("type") == "review" and e.get("stage") == stage]
    if round is not None:
        out = [e for e in out if str(e.get("round")) == str(round)]
    return out


def base_round(r: str) -> str:
    """Epoch suffix off: ``1@2`` -> ``1``."""
    return str(r).split("@", 1)[0]


def _post_data_amendment_epoch(wd: Workdir) -> int | None:
    """Version of the latest post-data amendment, else None.

    Exposure only grows within a lineage (runs/audit only append), so the
    current epoch's own lock record tells whether this epoch came from a
    post-data amendment.
    """
    try:
        from . import ledger as _ledger
        last = _ledger.last_lock_record(wd)
    except OSError:
        return None
    if last and last.get("type") == "amendment" and last.get("post_data"):
        return last.get("version")
    return None


def due_teardown_rounds(wd: Workdir, comp) -> tuple[list[str], bool]:
    """Teardown rounds due at the current epoch.

    Post-data amendment at DECIDE+: rounds 1 and 3 are re-due as new
    rounds ``1@N`` / ``3@N`` (N = current epoch). Earlier failures stay
    visible and must be answered (gates7).
    """
    from . import review as _review
    rounds, need = _review.rounds_for("teardown", comp.tier, comp.rung)
    if need and comp.tier in ("DECIDE", "PUBLISH"):
        epoch = _post_data_amendment_epoch(wd)
        if epoch is not None and isinstance(comp.lock_hash, str):
            cur = None
            try:
                from . import lockstate as _lockstate
                cur = (_lockstate.read_lock(wd) or {}).get("version")
            except Exception:
                cur = None
            n = cur if isinstance(cur, int) else epoch
            rounds = [f"{r}@{n}" if r in ("1", "3") else r for r in rounds]
    return rounds, need


def lineage(wd: Workdir) -> dict:
    """Computed history view over the lineage chain. Never stored.

    Verified read: when the lineage chain itself fails verification
    (truncated, forked, hand-edited, or deleted with a heads mirror or
    committed checkpoint behind it), the sticky exposure flags pin True
    instead of reading False off the broken prefix — exposure once seen
    is never unread by deleting evidence (fail closed). Gates stay safe
    because they verify first; this keeps the read path from laundering
    exposure away.
    """
    broken = bool(chain.verify(lineage_log(wd)))
    if not broken:
        # I7″ read side: a rolled-back prefix restored together with its
        # rolled-back mirror still verifies, so a committed checkpoint
        # recording a longer chain also marks the view broken. Without this
        # the exposure flags would be unread from the rolled-back prefix.
        try:
            from . import ledger as _ledger
            broken = _ledger.chain_below_checkpoint(wd, lineage_log(wd))
        except Exception:
            pass
    evs = events(wd)
    locks = [e for e in evs if e.get("type") in LOCK_EVENT]
    cur = locks[-1] if locks else None
    profiles = [e for e in evs if e.get("type") == "profile"]
    runs = [e for e in evs if e.get("type") == "run" and not e.get("replay")]
    anchor = profiles[-1] if profiles else None
    first_run = runs[0] if runs else None
    results_seen = bool(anchor and first_run and first_run["seq"] < anchor["seq"])
    goldfish = [e for e in evs if e.get("type") == "review" and e.get("kind") == "goldfish"]
    degrades = [e for e in evs if e.get("type") == "degrade"]
    first_gf = min([e["seq"] for e in goldfish]) if goldfish else None
    degraded = bool(degrades) and (first_gf is None or min(e["seq"] for e in degrades) < first_gf)
    goldfish_mode = bool(goldfish)
    if broken:
        # The chain does not verify, so the replay above proves nothing:
        # hold every sticky flag True rather than report a clean view off
        # deleted or rewritten evidence.
        results_seen = True
        goldfish_mode = True
        degraded = True
    return {
        "lineage_id": lineage_id_of(wd),
        "epoch": cur.get("lock_epoch") if cur else None,
        "lock_hash": cur.get("lock_hash") if cur else None,
        "events": len(evs),
        "results_seen_before_profile": results_seen,
        "results_profile_seq": anchor.get("seq") if anchor else None,
        "results_profile_lock_hash": anchor.get("lock_hash") if anchor else None,
        "first_run_seq": first_run.get("seq") if first_run else None,
        "goldfish_mode": goldfish_mode,
        "degraded": degraded,
    }


__all__ = ["LINEAGE_LOG", "lineage_log", "events", "lineage_id_of", "stage_event",
           "review_calls", "base_round", "due_teardown_rounds", "lineage"]
