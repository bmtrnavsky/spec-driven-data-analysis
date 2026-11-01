"""Positive: valid goldfish flow passes G3 (control both attacks compare against)."""
from probelib import new_fixture, finding, cleanup

EXPECTED = "G3-PASS"

f = new_fixture("f7", prefix="dda-p-g3pass-")
try:
    f.write_spec()
    assert f.cli("lock")[0] == 0
    assert f.cli("packet", "teardown")[0] == 0
    assert f.cli("review", "run", "teardown", stub="pass")[0] == 0
    assert f.cli("approve", "spec", "--no-sign")[0] == 0
    assert f.cli("approved", "spec")[0] == 0
    rc, out = f.cli("gate", "G3")
    print("G3", "PASS" if rc == 0 else "FAIL", out.strip()[:300])
    finding("G3-PASS" if rc == 0 else "G3-FAILED-UNEXPECTED")
finally:
    cleanup(f)
