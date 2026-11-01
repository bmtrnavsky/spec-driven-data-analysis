"""N6b: `git stash -u` removes untracked chains; the next append must FAIL
CLOSED and verify-chain must report the gap (stash entry kept for forensics)."""
from probelib import new_fixture, finding, cleanup, git, git_ok
from ddalib import chain, ledger

f = new_fixture("p8", prefix="dda-n-gstash6-")
try:
    f.lock()
    chain.append(ledger.runs_log(f.wd), {"type": "note", "x": 1})
    p = git(f, "stash", "-u", "-m", "dda-probe-stash")
    assert p.returncode == 0, p.stdout + p.stderr
    print("runs.log exists after stash -u:", ledger.runs_log(f.wd).is_file())
    probs, _merged = ledger.verify_all(f.wd, merge=False)
    print("verify problems:", probs[:3])
    try:
        chain.append(ledger.runs_log(f.wd), {"type": "note", "x": 2})
        print("append after stash: RESTARTED (vulnerable)")
        finding("CHAIN-RESTARTED-VULNERABLE")
    except Exception as e:
        print("append after stash raised:", str(e)[:160])
        closed = "heads mirror" in str(e) and bool(probs)
        finding("CHAIN-FAIL-CLOSED" if closed else "CHAIN-ERROR-UNEXPECTED")
    git(f, "stash", "drop", "-q")
finally:
    cleanup(f)
