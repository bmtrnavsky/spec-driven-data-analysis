"""N8: stash the workdir, roll history back, restore the stale prefix.

`git stash -u` carries every untracked file (chains, approvals index,
corrections) away; `git reset --hard` drops the correction approval
commit; `git stash pop` restores the stale workdir prefix with the
heads mirror untouched; `git checkout <prestate> -- .analysis` makes
the tracked chains self-consistent again so the ONLY thing keeping
the case bound is the approvals index (N7). evals run must STILL
block — else the bound case unbound and the probe prints the VULN
token.
"""
from probelib import new_fixture, finding, cleanup, evals_blocked_fixture, git, git_ok

f = new_fixture("p8", prefix="dda-n-prefix8-")
try:
    sha = evals_blocked_fixture(f)
    # Stage TRACKED modifications only (add -u): untracked evidence
    # (chains, approvals index, corrections) must stay untracked so the
    # stash below actually carries it away.
    git_ok(f, "add", "-u")
    git_ok(f, "commit", "-q", "--allow-empty", "-m", "prestate")
    prestate = git_ok(f, "rev-parse", "HEAD")
    p = git(f, "stash", "-u", "-m", "dda-probe-prefix")
    assert p.returncode == 0, p.stdout + p.stderr
    git_ok(f, "reset", "--hard", "-q", f"{sha}~1")
    p = git(f, "stash", "pop", "-q")
    assert p.returncode == 0, p.stdout + p.stderr
    # Tracked chains back to the prestate (mirror-consistent); history
    # stays rolled back, so binding must come from the index (N7).
    git_ok(f, "checkout", prestate, "--", ".analysis")
    rc, out = f.cli("evals", "run", str(f.wd.root))
    print("evals run after stash-reset-pop rc:", rc)
    tail = out.strip().splitlines()[-1][:200] if out.strip() else ""
    print(tail)
    finding("EVALS-STILL-BLOCKED" if rc != 0 else "EVALS-UNBOUND-VULNERABLE")
finally:
    cleanup(f)
