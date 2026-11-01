"""N7e: `git filter-branch` purging the approval file from all history.

Runs filter-branch through Git-for-Windows' git.exe: the MSYS2 git on
PATH cannot run it (its sh exports an MSYS-style GIT_DIR that child
processes reject — `fatal: not a git repository` even on a trivial
repo). With the working git the rewrite succeeds and the approval is
gone from every commit while approvals.index.jsonl survives — evals
run must still block via the index fallback (N7).
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Git-for-Windows git.exe runs filter-branch; MSYS2 git cannot.
GITFB = next((c for c in ("C:/Program Files/Git/bin/git.exe",
                          "C:/Program Files/Git/cmd/git.exe")
              if Path(c).is_file()), None)
assert GITFB is not None, "Git-for-Windows git.exe not found"

from probelib import new_fixture, finding, cleanup, evals_blocked_fixture, git, git_ok
f = new_fixture("p8", prefix="dda-n-gfilter7-")
try:
    sha = evals_blocked_fixture(f)
    files = git_ok(f, "show", "--pretty=format:", "--name-only", "HEAD").split()
    rel = next(r for r in files if "/approvals/" in r.replace("\\", "/"))
    git_ok(f, "add", "-A")
    git_ok(f, "commit", "-q", "-m", "prestate")
    os.environ["FILTER_BRANCH_SQUELCH_WARNING"] = "1"
    p = subprocess.run([GITFB, "filter-branch", "-f", "--index-filter",
                        f"git rm -q --cached --ignore-unmatch -- '{rel}'",
                        "--", "--all"],
                       capture_output=True, text=True, cwd=str(f.wd.root),
                       env=dict(os.environ))
    assert p.returncode == 0, (p.stdout + p.stderr)[-500:]
    gone = git(f, "log", "--diff-filter=A", "--format=%H", "--", rel).stdout.strip()
    print("approval add still in history:", bool(gone))
    rc, out = f.cli("evals", "run", str(f.wd.root))
    print("evals run after filter-branch rc:", rc)
    if rc == 1 and "bound correction eval(s) failed" in out:
        finding("EVALS-STILL-BLOCKED")
    elif rc == 0:
        finding("EVALS-UNBOUND-VULNERABLE")
    else:
        raise SystemExit(f"unexpected evals rc={rc}")
finally:
    cleanup(f)
