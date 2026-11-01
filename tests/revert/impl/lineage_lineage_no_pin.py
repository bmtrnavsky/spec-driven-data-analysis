"""Derived reference impl: lineage.lineage without the broken-chain pin.

The fixed body with the sticky-flag pin removed: when the lineage chain
itself fails verification (or sits below its committed checkpoint), the
exposure flags are read off the broken/rolled-back prefix instead of
pinning True. A pre-I12 rollback of the prefix then launders
results_seen_before_profile back to False.
"""


def lineage(wd: Workdir) -> dict:
    """Computed history view over the lineage chain. Never stored.

    DERIVED no-pin: the verified-read pin is removed (see fixed
    lineage.lineage for what it pins and why).
    """
    broken = bool(chain.verify(lineage_log(wd)))
    if not broken:
        # I7″ read side: a rolled-back prefix restored together with its
        # rolled-back mirror still verifies, so a committed checkpoint
        # recording a longer chain also marks the view broken.
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
    # DERIVED no-pin: the `if broken:` sticky-flag pin is removed. The
    # `broken` computation above is kept so the shape of the function is
    # unchanged; its value is no longer consulted.
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
