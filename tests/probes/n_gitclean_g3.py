"""N3-class via real git: `git clean -fdx` on untracked reviews must not clear G3."""
from probelib import new_fixture, finding, cleanup, g3_failed_fixture, g3_verdict, git, git_ok

EXPECTED = "G3-STILL-FAILING"

f = new_fixture("f7", prefix="dda-n-gclean3-")
try:
    gdir = g3_failed_fixture(f)
    st = git(f, "status", "--porcelain", "--", ".analysis/reviews").stdout
    print("git status reviews (untracked => clean removes):", st.strip()[:200])
    p = git(f, "clean", "-fdx", "--", ".analysis/reviews")
    assert p.returncode == 0, p.stderr
    print("after clean, goldfish dir exists:", gdir.is_dir())
    f.cli("packet", "teardown")
    rc, out = f.cli("review", "run", "teardown", stub="pass")
    print("run after clean rc:", rc)
    failed = not g3_verdict(f)
    print("G3 after git-clean laundering:", "FAILING" if failed else "PASSING")
    finding("G3-STILL-FAILING" if failed else "G3-LAUNDERED-VULNERABLE")
finally:
    cleanup(f)
