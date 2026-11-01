"""N10: the hook judges the git OPERATION, not the path it mentions.

Destructive ops must BLOCK even with no pathspec (`git clean -fdx`
wipes the same untracked chains as `git clean -fdx -- .analysis`):
clean, stash (bare/push/pop), reset --hard, checkout/restore with a
pathspec. Rewrite ops (commit --amend, rebase, update-ref,
filter-branch) must be ALLOWED (recorded in lineage, N7 keeps evals
bound) and benign reads must stay allowed. Blocking the rewrites
would break the real fix workflow; allowing the destructive ops
re-opens N6/N8.
"""
from probelib import new_fixture, finding, cleanup

DESTRUCTIVE = [
    "git clean -fdx",
    "git clean -fdx -- .analysis/reviews",
    "git stash -u -m x",
    "git stash pop",
    "git reset --hard HEAD~1",
    "git checkout -- .analysis/runs.log",
    "git restore --source=HEAD -- .analysis/ledger.md",
]
REWRITE = [
    'git commit --amend -m "reword"',
    "git rebase --onto main~1 main",
    "git update-ref refs/heads/main abc123",
    "git filter-branch --index-filter true -- --all",
]
BENIGN = ["git status", "git log --oneline -3"]


def verdict(f, cmd):
    rc, out = f.hook("evidenceguard", "terminal", {"command": cmd})
    return rc, (out.get("action"), out.get("message", "")[:120])


f = new_fixture("p8", prefix="dda-n-hookgit-")
try:
    f.lock()
    f.bind()
    bad = []
    for cmd in DESTRUCTIVE:
        rc, (action, msg) = verdict(f, cmd)
        ok = rc == 2 and action == "block"
        print(("BLOCK " if ok else "MISS  ") + cmd)
        if not ok:
            bad.append(cmd)
    for cmd in REWRITE + BENIGN:
        rc, (action, msg) = verdict(f, cmd)
        ok = not (rc == 2 and action == "block")
        print(("ALLOW " if ok else "OVERBLOCK ") + cmd + f" rc={rc} {action}")
        if not ok:
            bad.append(cmd)
    finding("HOOK-BLOCKS-GITOPS" if not bad else "HOOK-GITOPS-VULNERABLE")
finally:
    cleanup(f)
