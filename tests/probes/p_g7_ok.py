"""Positive: lock -> register/lock variant -> profile -> run -> verify -> G7 passes."""
from probelib import new_fixture, finding, cleanup

f = new_fixture("p8", prefix="dda-p-g7ok-")
try:
    f.lock()
    f.register_locked("v1")
    assert f.cli("profile")[0] == 0, "profile failed"
    f.register_and_run("v1")
    rc, out = f.cli("verify")
    assert rc == 0, f"verify failed: {out}"
    # G7 also needs post-result self re-reads at EXPLORE (§5.3).
    (f.wd.analysis / "answer.md").write_text("# Answer\n\nConversion rose.\n", encoding="utf-8")
    d = f.wd.analysis / "reviews" / "self"
    d.mkdir(parents=True, exist_ok=True)
    for r in ("1", "2"):
        (d / f"post-result-round{r}.md").write_text(
            f"# self re-read round {r}\n\nChecked claims against outputs. No objection.\n",
            encoding="utf-8")
    rc, out = f.cli("gate", "G7")
    print("G7", "PASS" if rc == 0 else "BLOCK", out.strip()[:300])
    finding("G7-PASS" if rc == 0 else "G7-BLOCKED-UNEXPECTED")
finally:
    cleanup(f)
