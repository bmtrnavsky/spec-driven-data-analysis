"""N1-class: deleting evals/corrections in-process must not unbind the case."""
import shutil
from probelib import new_fixture, finding, cleanup, evals_blocked_fixture

f = new_fixture("p8", prefix="dda-n-rmcorr-")
try:
    evals_blocked_fixture(f)
    shutil.rmtree(f.wd.root / "evals" / "corrections")
    rc, out = f.cli("evals", "run", str(f.wd.root))
    print("evals run after rmtree rc:", rc)
    if rc == 1 and "bound correction eval(s) failed" in out:
        finding("EVALS-STILL-BLOCKED")
    elif rc == 0:
        finding("EVALS-UNBOUND-VULNERABLE")
    else:
        raise SystemExit(f"unexpected evals rc={rc}")
finally:
    cleanup(f)
