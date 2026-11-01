"""Positive: a bound correction case with a CORRECT check passes evals run (rc 0)."""
import hashlib
from probelib import new_fixture, finding, cleanup
from tests.test_phase9 import TestEvalsMatchRun

EXPECTED = "EVALS-OK"

f = new_fixture("p8", prefix="dda-p-evalsok-")
try:
    f.lock()
    assert f.cli("profile")[0] == 0
    f.register_and_run()
    blob = (f.wd.root / "outputs" / "summary.csv").read_bytes()
    TestEvalsMatchRun.write_bound_case(f, check=hashlib.sha256(blob).hexdigest())
    rc, out = f.cli("evals", "run", str(f.wd.root))
    print("evals run rc:", rc, out.strip().splitlines()[-1][:200] if out.strip() else "")
    finding("EVALS-OK" if rc == 0 else "EVALS-BLOCKED-UNEXPECTED")
finally:
    cleanup(f)
