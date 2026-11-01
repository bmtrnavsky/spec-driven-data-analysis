"""N7a: `git reset --hard HEAD~1` drops the correction approval commit;
evals run must STILL block (index-known approval binds fail-closed)."""
from probelib import new_fixture, finding, cleanup, evals_blocked_fixture, git_ok

EXPECTED = "EVALS-STILL-BLOCKED"

f = new_fixture("p8", prefix="dda-n-greset7-")
try:
    sha = evals_blocked_fixture(f)
    git_ok(f, "reset", "--hard", "HEAD~1", "-q")
    now = git_ok(f, "rev-parse", "HEAD")
    assert now != sha, "reset did not move HEAD"
    rc, out = f.cli("evals", "run", str(f.wd.root))
    print("evals run after reset --hard rc:", rc)
    tail = out.strip().splitlines()[-1][:200] if out.strip() else ""
    print(tail)
    finding("EVALS-STILL-BLOCKED" if rc != 0 else "EVALS-UNBOUND-VULNERABLE")
finally:
    cleanup(f)
