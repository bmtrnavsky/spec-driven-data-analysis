"""N7c: history rewrite via `git rebase --onto` dropping the approval commit;
evals run must STILL block."""
from probelib import new_fixture, finding, cleanup, evals_blocked_fixture, git_ok

f = new_fixture("p8", prefix="dda-n-grebase7-")
try:
    sha = evals_blocked_fixture(f)
    # Commit the dirty workdir state first (lock/ledger writes leave tracked
    # modifications that would block the rebase), then replay everything
    # above the approval onto its parent — dropping it.
    git_ok(f, "add", "-A")
    git_ok(f, "commit", "-q", "-m", "prestate")
    git_ok(f, "rebase", "-q", "--onto", f"{sha}~1", sha)
    log = git_ok(f, "log", "--format=%H")
    assert sha not in log.split(), "rebase did not drop the approval commit"
    rc, out = f.cli("evals", "run", str(f.wd.root))
    print("evals run after rebase rc:", rc)
    if rc == 1 and "bound correction eval(s) failed" in out:
        finding("EVALS-STILL-BLOCKED")
    elif rc == 0:
        finding("EVALS-UNBOUND-VULNERABLE")
    else:
        raise SystemExit(f"unexpected evals rc={rc}")
finally:
    cleanup(f)
