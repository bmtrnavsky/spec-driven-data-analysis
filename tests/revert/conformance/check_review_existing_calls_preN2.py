"""Conformance for the pre-N2 existing_calls reference impl.

Runs WHILE the revert is applied. Only the untracked call files are
read: after they are deleted, no calls are reported even though the
lineage log and runs.log still record the failed rounds (the N2
backstop is what was removed).
"""
import os
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO))
os.environ.setdefault("DDA_TEST_MODE", "1")

from tests.probes.probelib import new_fixture, cleanup, g3_failed_fixture  # noqa: E402
from ddalib import review as _review  # noqa: E402
from ddalib import lineage as _lin  # noqa: E402

f = new_fixture("f7", prefix="dda-conf-pren2-")
try:
    gdir = g3_failed_fixture(f)
    before = _review.existing_calls(f.wd, "teardown")
    assert len(before) >= 2, f"pre-N2 must read the call files, got {len(before)}"
    assert any(_lin.events(f.wd)), "lineage history must exist for this check"
    shutil.rmtree(gdir)
    after = _review.existing_calls(f.wd, "teardown")
    assert after == [], f"pre-N2 must report no calls once files are gone, got {after}"
    print("CONFORMANCE-OK: pre-N2 existing_calls reads files only, no backstop")
finally:
    cleanup(f)
