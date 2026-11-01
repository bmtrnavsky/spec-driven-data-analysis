"""M7-class: with the touched chain missing and its mirror gone, only the
committed checkpoint stands in the way.

Builds the G3-failed fixture (two failed goldfish rounds plus the spec
approval; the lock/approve commits leave chain checkpoints behind), then
deletes runs.log AND its heads mirror — so the I6/N6 guards have nothing
to anchor on — and appends directly. The append must still be REFUSED on
the committed checkpoint. Prints PREFIX-REFUSED-BY-CHECKPOINT when the
refusal names the checkpoint, else the VULN token (restarted) or a
distinct OTHER-GUARD token.
"""
import shutil

from probelib import new_fixture, finding, cleanup, g3_failed_fixture, g3_verdict
from ddalib import chain as _chain
from ddalib import ledger as _ledger

f = new_fixture("f7", prefix="dda-n-prefixm7-")
try:
    gdir = g3_failed_fixture(f)
    assert not g3_verdict(f), "control G3 should fail"
    assert len(_ledger.chain_checkpoints(f.wd.root)) >= 1, \
        "fixture must leave committed checkpoints behind"
    # Attack setup: runs.log missing AND its mirror gone — I6/N6 blind.
    # Only the M7 checkpoint floor can refuse the next append.
    target = _ledger.runs_log(f.wd)
    assert target.is_file(), "runs.log should exist before deletion"
    target.unlink()
    mirror = _chain.heads_path(target)
    if mirror.is_file():
        mirror.unlink()
    print("runs.log exists:", target.is_file(), "| mirror exists:", mirror.is_file())
    try:
        _chain.append(target, {"type": "note", "probe": "m7"})
        print("append after deletion: RESTARTED (vulnerable)")
        finding("PREFIX-ACCEPTED-VULNERABLE")
    except Exception as e:
        print("append after deletion raised:", str(e)[:200])
        if "committed checkpoint" in str(e):
            finding("PREFIX-REFUSED-BY-CHECKPOINT")
        else:
            finding("PREFIX-BLOCKED-OTHER-GUARD")
finally:
    cleanup(f)
