"""N8 on the sticky lineage flag: wipe .analysis, restore a pre-exposure prefix.

Snapshots .analysis right after lock (T0, before any profile/run), then
builds the full exposure (profile, register+run, cosmetic amend,
re-profile, answer+signoff) so results_seen_before_profile is True and
G7 fails. Then deletes .analysis and restores the T0 prefix with the
heads mirror untouched. The restored files no longer show the
exposure — but the mirror is ahead of them, so verify-chain reports a
truncation and the gates must fail closed. G7 passing here would mean
the exposure was laundered away (STICKY-FLIPPED-VULNERABLE).
"""
import shutil
import tempfile
from pathlib import Path

from probelib import new_fixture, finding, cleanup, git_ok
from ddalib import lineage as _lin
from ddalib import evaluate as _ev

f = new_fixture("p9", prefix="dda-n-prefixsticky-")
try:
    f.lock()
    t0 = Path(tempfile.mkdtemp(prefix="dda-n-prefixsticky-t0-"))
    for p in f.wd.analysis.rglob("*"):
        if p.is_file() and ".spill" not in p.parts:
            rel = p.relative_to(f.wd.analysis)
            (t0 / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, t0 / rel)
    assert f.cli("profile")[0] == 0, "profile failed"
    f.register_and_run()
    spec = f.wd.spec_path.read_text(encoding="utf-8")
    if "Compare conversion rates." in spec:
        spec = spec.replace("Compare conversion rates.", "Compare conversion rates!")
    else:
        spec += "\n<!-- cosmetic -->\n"
    f.wd.spec_path.write_text(spec, encoding="utf-8")
    assert f.cli("lock", "--amend", "cosmetic punctuation")[0] == 0, "amend failed"
    assert f.cli("profile")[0] == 0, "re-profile failed"
    (f.wd.analysis / "answer.md").write_text(
        "# Answer\n\nConversion rose.\n", encoding="utf-8")
    assert f.cli("approve", "spec", "--no-sign")[0] == 0
    assert f.cli("approved", "spec")[0] == 0
    assert f.cli("approve", "signoff", "--no-sign")[0] == 0
    assert f.cli("approved", "signoff")[0] == 0
    assert _lin.lineage(f.wd).get("results_seen_before_profile"), \
        "fixture must start EXPOSED"
    assert not _ev.evaluate(f.wd)["verdicts"]["G7"][0], "G7 must start failing"
    # Attack: true prefix restore — T0 files back, everything newer gone.
    shutil.rmtree(f.wd.analysis)
    shutil.copytree(t0, f.wd.analysis)
    flag = _lin.lineage(f.wd).get("results_seen_before_profile")
    from ddalib import ledger as _ledger
    problems, _merged = _ledger.verify_all(f.wd, merge=False)
    try:
        g7 = _ev.evaluate(f.wd)["verdicts"]["G7"][0]
    except Exception as e:
        print("evaluate raised (fail-closed):", str(e)[:160])
        g7 = False
    print("flag after restore:", flag, "| verify problems:", len(problems),
          "| G7:", "PASS" if g7 else "FAIL")
    # Containment is judged on the sticky flag ALONE: the pre-I12 guard is
    # the broken-chain pin in lineage(), so a laundered flag is the exact
    # failure. Problems are printed for forensics only.
    for p in problems[:3]:
        print("problem:", p[:160])
    finding("STICKY-HELD" if flag else "STICKY-FLIPPED-VULNERABLE")
finally:
    shutil.rmtree(t0, ignore_errors=True)
    cleanup(f)
