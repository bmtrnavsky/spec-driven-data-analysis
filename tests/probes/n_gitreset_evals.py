"""N7a: `git reset --hard HEAD~1` drops the correction approval commit;
evals run must STILL block via the N7 index-known binding — rc 1 with the
case in failed_bound — never unbind (rc 0), and never pass by accident
through the N9 chain check (rc 4).

Isolation: reset --hard also rolls back the tracked ledger.md (whose
post-lock appends were never committed), so the N9 chain check would
block first with rc 4. Stash the ledger diff into the reflog before the
reset and restore it after, then require verify_all clean — the only
breakage left is the dropped approval commit.
"""
import json as _json

from probelib import new_fixture, finding, cleanup, evals_blocked_fixture, git_ok, git

LEDGER_REL = ".analysis/ledger.md"
PASS = "EVALS-N7-STILL-BLOCKED"
VULN = "EVALS-UNBOUND-VULNERABLE"

f = new_fixture("p8", prefix="dda-n-greset7-")
try:
    sha = evals_blocked_fixture(f)
    from ddalib import ledger as _ledger
    # Stash the uncommitted ledger appends into the reflog (refs/stash)
    # before the reset discards them.
    p = git(f, "stash", "push", "-q", "-m", "dda-probe-ledger", "--", LEDGER_REL)
    assert p.returncode == 0, p.stdout + p.stderr
    git_ok(f, "reset", "--hard", "HEAD~1", "-q")
    now = git_ok(f, "rev-parse", "HEAD")
    assert now != sha, "reset did not move HEAD"
    # Restore ledger.md from the reflog entry, then drop it.
    p = git(f, "checkout", "stash@{0}", "--", LEDGER_REL)
    assert p.returncode == 0, p.stdout + p.stderr
    git(f, "stash", "drop", "-q")
    problems, _merged = _ledger.verify_all(f.wd, merge=False)
    print("verify problems after restore:", problems[:2] if problems else [])
    if problems:
        print("isolation broken: chains do not verify after the restore")
        finding(VULN)
    else:
        rc, out = f.cli("evals", "run", "--json", str(f.wd.root))
        print("evals run after reset --hard rc:", rc)
        bound = []
        try:
            rec = _json.loads(out)
            bound = [r.get("case") for r in rec.get("failed_bound", [])]
        except ValueError:
            rec = None
        print("failed_bound:", bound)
        # rc 1 with the case in failed_bound is the N7 guard firing —
        # not the same as rc 4 (chain broken) and never rc 0 (unbound).
        finding(PASS if rc == 1 and bound else VULN)
finally:
    cleanup(f)
