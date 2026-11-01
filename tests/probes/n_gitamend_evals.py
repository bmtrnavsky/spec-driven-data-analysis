"""N7d: `git commit --amend` hollowing the approval (file removed from HEAD);
evals run must STILL block via the index record."""
from probelib import new_fixture, finding, cleanup, evals_blocked_fixture, git, git_ok

f = new_fixture("p8", prefix="dda-n-gamend7-")
try:
    sha = evals_blocked_fixture(f)
    files = git_ok(f, "show", "--pretty=format:", "--name-only", "HEAD").split()
    rel = next(r for r in files if "/approvals/" in r.replace("\\", "/"))
    git_ok(f, "rm", "-q", "--cached", "--", rel)
    # Approval commits add exactly one file, so hollowing one amends to an
    # empty commit — --allow-empty is the realistic attacker flag here.
    p = git(f, "commit", "-q", "--amend", "--allow-empty", "--no-edit")
    assert p.returncode == 0, p.stdout + p.stderr
    gone = git(f, "log", "--diff-filter=A", "--format=%H", "--", rel).stdout.strip()
    assert not gone, "amend did not drop the approval add"
    rc, out = f.cli("evals", "run", str(f.wd.root))
    print("evals run after amend rc:", rc)
    if rc == 1 and "bound correction eval(s) failed" in out:
        finding("EVALS-STILL-BLOCKED")
    elif rc == 0:
        finding("EVALS-UNBOUND-VULNERABLE")
    else:
        raise SystemExit(f"unexpected evals rc={rc}")
finally:
    cleanup(f)
