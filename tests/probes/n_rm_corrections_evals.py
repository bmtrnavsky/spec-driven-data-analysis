"""N1-class: deleting evals/corrections in-process must not unbind the case."""
import shutil
from probelib import new_fixture, finding, cleanup, evals_blocked_fixture

EXPECTED = "EVALS-STILL-BLOCKED"

f = new_fixture("p8", prefix="dda-n-rmcorr-")
try:
    evals_blocked_fixture(f)
    shutil.rmtree(f.wd.root / "evals" / "corrections")
    rc, out = f.cli("evals", "run", str(f.wd.root))
    print("evals run after rmtree rc:", rc)
    finding("EVALS-STILL-BLOCKED" if rc != 0 else "EVALS-UNBOUND-VULNERABLE")
finally:
    cleanup(f)
