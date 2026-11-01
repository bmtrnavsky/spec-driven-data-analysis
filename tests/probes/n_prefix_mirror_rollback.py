"""M7: restoring an older prefix TOGETHER WITH its older heads mirror must not launder exposure.

Snapshots .analysis right after lock (T0, before any profile/run) AND the
heads-mirror entries for this workdir, then builds the full exposure
(profile, register+run, cosmetic amend, re-profile, answer+signoff) so
results_seen_before_profile is True and G7 fails. Then deletes .analysis
and the live mirrors and restores the T0 prefix with the T0 mirrors.

The rolled-back chain verifies against its rolled-back mirror, so only
the git-committed chain checkpoints (invariant I7″) can catch the
rollback: verify_all must be non-empty and lineage() must hold the
sticky flag True. Prints ROLLBACK-DETECTED when contained, else the
VULN token.
"""
import shutil
import tempfile
from pathlib import Path

from probelib import new_fixture, finding, cleanup
from ddalib import lineage as _lin
from ddalib import ledger as _ledger
from ddalib import evaluate as _ev
from ddalib.layout import dda_home

f = new_fixture("p9", prefix="dda-n-prefixrollback-")
try:
    f.lock()
    t0 = Path(tempfile.mkdtemp(prefix="dda-n-prefixrollback-t0-"))
    for p in f.wd.analysis.rglob("*"):
        if p.is_file() and ".spill" not in p.parts:
            rel = p.relative_to(f.wd.analysis)
            (t0 / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, t0 / rel)
    heads_dir = dda_home() / "heads"
    m0 = Path(tempfile.mkdtemp(prefix="dda-n-prefixrollback-m0-"))
    if heads_dir.is_dir():
        for p in heads_dir.glob("*.json"):
            shutil.copy2(p, m0 / p.name)
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
    ckpts = _ledger.chain_checkpoints(f.wd.root)
    print("checkpoint commits:", len(ckpts))
    assert len(ckpts) >= 2, "fixture must leave committed checkpoints behind"
    # Attack: true prefix AND mirror rollback — T0 files back, T0 mirrors back.
    shutil.rmtree(f.wd.analysis)
    shutil.copytree(t0, f.wd.analysis)
    if heads_dir.is_dir():
        for p in heads_dir.glob("*.json"):
            p.unlink()
    else:
        heads_dir.mkdir(parents=True, exist_ok=True)
    for p in m0.glob("*.json"):
        shutil.copy2(p, heads_dir / p.name)
    flag = _lin.lineage(f.wd).get("results_seen_before_profile")
    problems, _merged = _ledger.verify_all(f.wd, merge=False)
    print("flag after rollback:", flag, "| verify problems:", len(problems))
    for p in problems[:4]:
        print("problem:", p[:160])
    if problems and flag:
        finding("ROLLBACK-DETECTED")
    else:
        finding("ROLLBACK-LAUNDERED-VULNERABLE")
finally:
    shutil.rmtree(t0, ignore_errors=True)
    shutil.rmtree(m0, ignore_errors=True)
    cleanup(f)
