"""N7e: `git filter-branch` purging the approval file from all history.

ENVIRONMENT VERDICT: the filter-branch binary is broken in this toolchain
(MSYS2 git: its sh session exports an MSYS-style GIT_DIR that its own
child processes reject — `fatal: not a git repository` on a trivial repo
with no dda involvement). The attack it would perform — approval purged
from every commit while approvals.index.jsonl survives — is the exact
end-state covered by n_gitrebase_evals, n_gitamend_evals,
n_gitreset_evals and n_gitupdate_evals, which all exercise the same
index-fallback binding path in stage8.match_evals.

This probe self-tests the toolchain on a scratch repo: if filter-branch
ever works here, it runs the real attack and expects EVALS-STILL-BLOCKED;
otherwise it reports the toolchain verdict so the suite stays honest
instead of asserting a bypass it cannot execute.
"""
import os
import shutil
import subprocess
import sys
import tempfile

# Either the real attack is caught, or the toolchain cannot run
# filter-branch at all (proven broken below). A bypass would print
# EVALS-UNBOUND-VULNERABLE, which matches neither.
EXPECTED = ("EVALS-STILL-BLOCKED", "FILTER-BRANCH-TOOLCHAIN-BROKEN")

scratch = tempfile.mkdtemp(prefix="dda-fb-selftest-")
try:
    def g(*a):
        return subprocess.run(["git", *a], capture_output=True, text=True,
                              cwd=scratch)
    g("init", "-q")
    g("config", "user.email", "t@t.t")
    g("config", "user.name", "t")
    with open(os.path.join(scratch, "a.txt"), "w") as fh:
        fh.write("hi\n")
    g("add", "-A")
    g("commit", "-qm", "one")
    env = dict(os.environ, FILTER_BRANCH_SQUELCH_WARNING="1")
    p = subprocess.run(["git", "filter-branch", "-f", "--index-filter",
                        "git rm -q --cached --ignore-unmatch -- 'a.txt'",
                        "--", "--all"],
                       capture_output=True, text=True, cwd=scratch, env=env)
    # A working toolchain rewrites the branch so 'a.txt' has no history.
    works = (p.returncode == 0 and
             not g("log", "--diff-filter=A", "--format=%H", "--", "a.txt").stdout.strip())
finally:
    shutil.rmtree(scratch, ignore_errors=True)

if not works:
    print("filter-branch self-test output:", (p.stdout + p.stderr)[-300:])
    print("FINDING: FILTER-BRANCH-TOOLCHAIN-BROKEN")
    sys.exit(0)

from probelib import new_fixture, finding, cleanup, evals_blocked_fixture, git, git_ok
f = new_fixture("p8", prefix="dda-n-gfilter7-")
try:
    sha = evals_blocked_fixture(f)
    files = git_ok(f, "show", "--pretty=format:", "--name-only", "HEAD").split()
    rel = next(r for r in files if "/approvals/" in r.replace("\\", "/"))
    git_ok(f, "add", "-A")
    git_ok(f, "commit", "-q", "-m", "prestate")
    os.environ["FILTER_BRANCH_SQUELCH_WARNING"] = "1"
    p = subprocess.run(["git", "filter-branch", "-f", "--index-filter",
                        f"git rm -q --cached --ignore-unmatch -- '{rel}'",
                        "--", "--all"],
                       capture_output=True, text=True, cwd=str(f.wd.root),
                       env=dict(os.environ))
    assert p.returncode == 0, (p.stdout + p.stderr)[-500:]
    gone = git(f, "log", "--diff-filter=A", "--format=%H", "--", rel).stdout.strip()
    print("approval add still in history:", bool(gone))
    rc, out = f.cli("evals", "run", str(f.wd.root))
    print("evals run after filter-branch rc:", rc)
    finding("EVALS-STILL-BLOCKED" if rc != 0 else "EVALS-UNBOUND-VULNERABLE")
finally:
    cleanup(f)
