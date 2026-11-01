"""N6a: `git clean -fdx` deletes runs.log/lineage.jsonl; the next append must
FAIL CLOSED (heads mirror survives) and verify-chain must report the gap."""
from probelib import new_fixture, finding, cleanup, git
from ddalib import chain, ledger

EXPECTED = "CHAIN-FAIL-CLOSED"

f = new_fixture("p8", prefix="dda-n-gclean6-")
try:
    f.lock()
    chain.append(ledger.runs_log(f.wd), {"type": "note", "x": 1})
    rc, out = f.cli("verify-chain")
    assert rc == 0, f"control verify-chain should pass: {out}"
    p = git(f, "clean", "-fdx", "--", ".analysis")
    assert p.returncode == 0, p.stderr
    print("runs.log exists after clean:", ledger.runs_log(f.wd).is_file())
    probs, _merged = ledger.verify_all(f.wd, merge=False)
    print("verify problems:", probs[:3])
    try:
        chain.append(ledger.runs_log(f.wd), {"type": "note", "x": 2})
        print("append after clean: RESTARTED (vulnerable)")
        finding("CHAIN-RESTARTED-VULNERABLE")
    except Exception as e:
        print("append after clean raised:", str(e)[:160])
        closed = "heads mirror" in str(e) and bool(probs)
        finding("CHAIN-FAIL-CLOSED" if closed else "CHAIN-ERROR-UNEXPECTED")
finally:
    cleanup(f)
