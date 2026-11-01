"""End-to-end regression probe (bound to no single guard): restore a
pre-review .analysis prefix, then re-run a round with a PASSING stub.

Locks and packets, snapshots the .analysis prefix (T0, no review calls
yet), then records two failed goldfish rounds and the spec approval so
G3 fails (control). The attack wipes .analysis and restores the T0
prefix with the heads mirror untouched — dropping both failures.
Re-running the round must be REFUSED and G3 must still fail. Prints
G3-STILL-FAILING when contained, else the VULN token.
"""
import shutil
import tempfile
from pathlib import Path

from probelib import new_fixture, finding, cleanup, g3_verdict

f = new_fixture("f7", prefix="dda-n-prefix3-")
try:
    f.write_spec()
    assert f.cli("lock")[0] == 0, "lock failed"
    assert f.cli("packet", "teardown")[0] == 0, "packet failed"
    t0 = Path(tempfile.mkdtemp(prefix="dda-n-prefix3-t0-"))
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
    refused = rc != 0
    print("re-run after restore rc:", rc, "::", out.strip().splitlines()[-1][:160] if out.strip() else "")
    v = g3_verdict(f)
    print("G3 after restore:", "FAILING" if not v else "PASSING")
    finding("G3-STILL-FAILING" if (refused and not v) else "G3-LAUNDERED-VULNERABLE")
finally:
    shutil.rmtree(t0, ignore_errors=True)
    cleanup(f)
