"""N2-class: deleting goldfish call files in-process must not clear G3."""
import shutil
from probelib import new_fixture, finding, cleanup, g3_failed_fixture, g3_verdict

f = new_fixture("f7", prefix="dda-n-rmrev-")
try:
    gdir = g3_failed_fixture(f)
    print("control: goldfish files:", sorted(p.name for p in gdir.iterdir()))
    shutil.rmtree(gdir)  # == what `git clean -fdx` / `git stash -u` do to untracked reviews
    f.cli("packet", "teardown")
    rc, out = f.cli("review", "run", "teardown", stub="pass")
    print("run after deletion rc:", rc)
    failed = not g3_verdict(f)
    print("G3 after laundering attempt:", "FAILING" if failed else "PASSING")
    finding("G3-STILL-FAILING" if failed else "G3-LAUNDERED-VULNERABLE")
finally:
    cleanup(f)
