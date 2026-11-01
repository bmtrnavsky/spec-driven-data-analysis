"""I6-class: restore an older review prefix, then re-run a failed round.

Locks and packets, snapshots the .analysis prefix (T0, before any review
calls), records two failed goldfish rounds and the spec approval so G3
fails (control), then restores the T0 prefix with the heads mirror
untouched — dropping both failures. Re-running the round must be REFUSED:
the anchored append fails closed on the shorter prefix, and the refusal
names the older prefix. Prints PREFIX-REFUSED when contained, else the
VULN token (accepted) or a distinct OTHER-GUARD token.
"""
import shutil
import tempfile
from pathlib import Path

from probelib import new_fixture, finding, cleanup, g3_verdict

f = new_fixture("f7", prefix="dda-n-prefixrerun-")
try:
    f.write_spec()
    assert f.cli("lock")[0] == 0, "lock failed"
    assert f.cli("packet", "teardown")[0] == 0, "packet failed"
    t0 = Path(tempfile.mkdtemp(prefix="dda-n-prefixrerun-t0-"))
    for p in f.wd.analysis.rglob("*"):
        if p.is_file() and ".spill" not in p.parts:
            rel = p.relative_to(f.wd.analysis)
            (t0 / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, t0 / rel)
    for _ in range(2):
        rc, out = f.cli("review", "run", "teardown", stub="fail")
        assert "fail" in out.lower(), f"fail-stub review recorded nothing: {out}"
    assert f.cli("approve", "spec", "--no-sign")[0] == 0
    assert f.cli("approved", "spec")[0] == 0
    assert not g3_verdict(f), "control G3 should fail"
    # Attack: true prefix restore — T0 files back, everything newer gone.
    shutil.rmtree(f.wd.analysis)
    shutil.copytree(t0, f.wd.analysis)
    rc, out = f.cli("review", "run", "teardown", stub="pass")
    print("re-run after restore rc:", rc, "::", out.strip().splitlines()[-1][:160] if out.strip() else "")
    if rc == 0:
        finding("PREFIX-ACCEPTED-VULNERABLE")
    elif "older prefix" in out or "heads mirror records" in out:
        finding("PREFIX-REFUSED")
    else:
        print("refusal did not name the anchored append")
        finding("PREFIX-BLOCKED-OTHER-GUARD")
finally:
    shutil.rmtree(t0, ignore_errors=True)
    cleanup(f)
