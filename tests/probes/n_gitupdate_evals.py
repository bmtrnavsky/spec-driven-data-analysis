"""N7b: `git update-ref HEAD HEAD~1` (plumbing reset) drops the approval;
evals run must STILL block."""
from probelib import new_fixture, finding, cleanup, evals_blocked_fixture, git_ok

f = new_fixture("p8", prefix="dda-n-gupdate7-")
try:
    sha = evals_blocked_fixture(f)
    git_ok(f, "update-ref", "HEAD", "HEAD~1")
    now = git_ok(f, "rev-parse", "HEAD")
    assert now != sha, "update-ref did not move HEAD"
    rc, out = f.cli("evals", "run", str(f.wd.root))
    print("evals run after update-ref rc:", rc)
    if rc == 1 and "bound correction eval(s) failed" in out:
        finding("EVALS-STILL-BLOCKED")
    elif rc == 0:
        finding("EVALS-UNBOUND-VULNERABLE")
    else:
        raise SystemExit(f"unexpected evals rc={rc}")
finally:
    cleanup(f)
