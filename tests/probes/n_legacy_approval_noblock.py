"""Attack: hand-write a pre chat-yes approval record (no `approval` block).

A v2 record can carry a digest and payload with no who/when/yes. It must
never be read as a chat yes: `dda approved` has to report MALFORMED, print
no yes, and leave the content failing every gate (PUBLISH included).
"""
import json

from probelib import cleanup, finding, git_ok, new_fixture

f = new_fixture("p8", prefix="dda-probe-legacy-")
try:
    assert f.cli("lock")[0] == 0, "lock failed"
    from ddalib import approvals

    digest, payload = approvals.canonical_payload(f.wd, "spec")
    rel_dir = f.wd.analysis / "approvals"
    rel_dir.mkdir(parents=True, exist_ok=True)
    rel = f".analysis/approvals/spec-{digest[:16]}.json"
    (f.wd.root / rel).write_text(json.dumps({
        "format": "dda-approval-v2",
        "kind": "spec",
        "digest": digest,
        "artifact": digest,
        "payload": payload,
        "created_at": "2026-11-01T09:00:00-0600",
        "approvers": [{"name": "brad"}],
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    git_ok(f, "add", "--", rel)
    git_ok(f, "-c", "commit.gpgsign=false", "commit", "-q", "--no-verify", "-m",
           "hand-written pre chat-yes record", "--", rel)

    verdict = approvals.verify_approval(f.wd, "spec")
    rc, out = f.cli("approved", "spec")
    state = str(verdict.get("state"))
    printed = " ".join(out.split())
    ok = (state == "malformed" and verdict.get("recorded") is False
          and "MALFORMED" in printed and "chat yes from" not in printed
          and "no chat yes on record" in printed)
    print(f"state={state} rc={rc} out={printed[:240]}")
    finding("LEGACY-NOBLOCK-MALFORMED" if ok else "LEGACY-NOBLOCK-ACCEPTED-VULNERABLE")
finally:
    cleanup(f)
