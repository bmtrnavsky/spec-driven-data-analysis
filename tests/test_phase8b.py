"""Phase 8b: profile/verify + gate G7 scenario half of the phase-8 product tier.

Split byte-for-byte out of tests/test_phase8.py so the two halves run on
two parallel `fast` workers. Every test still runs in `fast` (new
tests/test_*.py files join automatically); nothing was deleted, skipped,
weakened, or moved to the certification tier. The shared P8Setup harness
stays defined once in test_phase8 and is imported here.

Run: DDA_TEST_MODE=1 python -m unittest test_phase8b
"""
import unittest

from tests.test_phase8 import P8Setup  # noqa: E402 -- shared harness, single source


class TestG5(P8Setup):
    def full_path(self):
        self.lock()
        self.assertEqual(self.cli("profile")[0], 0)
        self.register_and_run()

    def test_g5_fails_without_profile(self):
        self.lock()
        rc, out = self.cli("gate", "G5")
        self.assertNotEqual(rc, 0, f"G5 passed with no profile: {out}")

    def test_g5_passes_after_profile(self):
        self.full_path()
        rc, out = self.cli("gate", "G5")
        self.assertEqual(rc, 0, f"G5 failed after profile: {out}")

    def test_g5_fails_on_tampered_snapshot(self):
        self.full_path()
        snaps = list((self.wd.root / "derived" / "snapshots").glob("sales@*/orders.csv"))
        self.assertTrue(snaps)
        snaps[0].write_text("id,amount\n9,99\n", encoding="utf-8")
        rc, out = self.cli("gate", "G5")
        self.assertNotEqual(rc, 0, f"G5 passed with a tampered snapshot: {out}")

    def test_g5_fails_after_relock_until_reprofile(self):
        self.full_path()
        self.write_spec(exposure="saw a dashboard once")
        self.cli("lock", str(self.wd.root), "--amend", "record prior exposure")
        rc, out = self.cli("gate", "G5")
        self.assertNotEqual(rc, 0, f"G5 passed after re-lock without re-profile: {out}")


class TestVerify(P8Setup):
    def full_path(self, **kw):
        self.lock()
        self.assertEqual(self.cli("profile")[0], 0)
        self.register_and_run(**kw)

    def test_verify_replays_and_writes_evidence(self):
        self.full_path()
        rc, out = self.cli("verify")
        self.assertEqual(rc, 0, f"verify failed: {out}")
        ev = (self.wd.analysis / "verify.md").read_text(encoding="utf-8")
        self.assertIn("reproduc", ev.lower())
        self.assertIn("drift", ev.lower())
        rc, out = self.cli("gate", "G7")
        # G7 also needs post-result self re-reads at EXPLORE
        self.assertNotEqual(rc, 0, f"G7 passed with no post-result review: {out}")

    def test_verify_replay_matches_snapshot_after_live_drift(self):
        self.full_path()
        (self.raw / "orders.csv").write_text("id,amount\n1,10\n2,20\n3,30\n", encoding="utf-8")
        rc, out = self.cli("verify")
        self.assertEqual(rc, 0, f"verify failed after live drift: {out}")
        ev = (self.wd.analysis / "verify.md").read_text(encoding="utf-8")
        self.assertIn("drift", ev.lower())
        import re
        self.assertTrue(re.search(r"drift[^\n]*yes|changed since snapshot|drifted", ev.lower()),
                        f"drift must be recorded, not silent: {ev[:2000]}")

    def test_nondeterministic_script_fails_replay(self):
        noisy = ("import os, time\n"
                 "os.makedirs('outputs', exist_ok=True)\n"
                 "open('outputs/summary.csv', 'w').write('t\\n%d\\n' % time.time_ns())\n"
                 "print('done')\n")
        self.full_path(script_body=noisy)
        rc, out = self.cli("verify")
        self.assertEqual(rc, 0, f"verify itself must record evidence, not crash: {out}")
        ev = (self.wd.analysis / "verify.md").read_text(encoding="utf-8")
        self.assertIn("mismatch", ev.lower())
        self.write_self_rereads()
        rc, out = self.cli("gate", "G7")
        self.assertNotEqual(rc, 0, f"G7 passed on a nondeterministic replay: {out}")

    def write_self_rereads(self, stage="post-result", rounds=("1", "2")):
        d = self.wd.analysis / "reviews" / "self"
        d.mkdir(parents=True, exist_ok=True)
        for r in rounds:
            (d / f"{stage}-round{r}.md").write_text(
                f"# self re-read round {r}\n\nChecked claims against outputs. No objection.\n",
                encoding="utf-8")

    def test_tolerance_parsing(self):
        from ddalib import stage8
        self.assertEqual(stage8.parse_tolerance("exact"), ("exact", None))
        self.assertEqual(stage8.parse_tolerance("  EXACT  "), ("exact", None))
        kind, eps = stage8.parse_tolerance("relative 1e-9")
        self.assertEqual(kind, "relative")
        self.assertAlmostEqual(eps, 1e-9)
        kind, eps = stage8.parse_tolerance("absolute 0.5")
        self.assertEqual((kind, eps), ("absolute", 0.5))
        with self.assertRaises(ValueError):
            stage8.parse_tolerance("roughly")
        with self.assertRaises(ValueError):
            stage8.parse_tolerance("relative lots")


class TestG7(P8Setup):
    def full_path(self):
        self.lock()
        # Lawful order (§10.3): snapshot BEFORE results exist, or G7 fails
        # the profile-before-results backstop.
        self.assertEqual(self.cli("profile")[0], 0)
        self.register_and_run()
        self.assertEqual(self.cli("verify")[0], 0)

    def self_rereads(self, rounds=("1", "2")):
        d = self.wd.analysis / "reviews" / "self"
        d.mkdir(parents=True, exist_ok=True)
        for r in rounds:
            (d / f"post-result-round{r}.md").write_text(
                f"# self re-read round {r}\n\nChecked claims against outputs. No objection.\n",
                encoding="utf-8")

    def test_g7_fails_without_verify(self):
        self.lock()
        self.assertEqual(self.cli("profile")[0], 0)
        self.register_and_run()
        rc, out = self.cli("gate", "G7")
        self.assertNotEqual(rc, 0, f"G7 passed with no verify.md: {out}")

    def test_g7_passes_explore_with_self_rereads(self):
        self.full_path()
        self.self_rereads(rounds=("1",))
        rc, out = self.cli("gate", "G7")
        self.assertNotEqual(rc, 0, f"G7 passed with a missing round: {out}")
        self.self_rereads()
        rc, out = self.cli("gate", "G7")
        self.assertEqual(rc, 0, f"G7 failed EXPLORE with replays + self re-reads: {out}")

    def test_g7_decide_needs_goldfish_post_result(self):
        self.write_spec(tier="This is a DECIDE analysis.", decision="Ship v2 or roll back.")
        self.lock()
        self.assertEqual(self.cli("profile")[0], 0)
        self.register_and_run()
        self.assertEqual(self.cli("verify")[0], 0)
        rc, out = self.cli("gate", "G7")
        self.assertNotEqual(rc, 0, f"G7 passed DECIDE with no post-result review: {out}")
        (self.wd.analysis / "answer.md").write_text(
            "## Findings\n\nconversion rose.\n\n## Provenance\n\n- **Lock hash:** tbd\n", encoding="utf-8")
        self.assertEqual(self.cli("packet", "post-result")[0], 0)
        rc, out = self.cli("review", "run", "post-result", stub="pass")
        self.assertEqual(rc, 0, f"post-result review run failed: {out}")
        rc, out = self.cli("gate", "G7")
        self.assertNotEqual(rc, 0, f"G7 passed DECIDE with no tier confirmation: {out}")


class TestEvals8(P8Setup):
    def write_case(self, nnn="001", triggers="alias:sales, def:conversion, tag:join",
                   check=None, signed=True):
        d = self.wd.root / "evals" / "corrections" / nnn
        d.mkdir(parents=True, exist_ok=True)
        body = ("# Correction 001\n\nwrong join grain doubled orders.\n\n"
                f"Trigger keys: {triggers}\n\nWhat was wrong: fanned out.\n\n")
        if check:
            body += f"## Deterministic check\n\nfile: outputs/summary.csv\nsha256: {check}\n"
        (d / "case.md").write_text(body, encoding="utf-8")
        if signed:
            self.assertEqual(self.cli("approve", "correction", nnn, "--no-sign")[0], 0)
            self.assertEqual(self.cli("approved", "correction", nnn)[0], 0)

    def test_no_cases_passes(self):
        self.lock()
        self.assertEqual(self.cli("profile")[0], 0)
        self.register_and_run()
        self.assertEqual(self.cli("verify")[0], 0)
        ev = (self.wd.analysis / "verify.md").read_text(encoding="utf-8")
        self.assertIn("0 matched", ev)

    def test_matched_check_must_pass(self):
        from ddalib import stage8
        self.lock()
        self.assertEqual(self.cli("profile")[0], 0)
        self.register_and_run()
        self.write_case(check="0" * 64)  # wrong hash: must fail
        self.assertEqual(self.cli("verify")[0], 0)
        d = self.wd.root / "evals" / "corrections" / "001"
        matched = stage8.match_evals(self.wd)
        self.assertEqual(len(matched), 1, "mechanical matching must select the case")
        self.write_self_rereads()
        rc, out = self.cli("gate", "G7")
        self.assertNotEqual(rc, 0, f"G7 passed with a failing correction eval: {out}")

    def write_self_rereads(self):
        d = self.wd.analysis / "reviews" / "self"
        d.mkdir(parents=True, exist_ok=True)
        for r in ("1", "2"):
            (d / f"post-result-round{r}.md").write_text(
                f"# self re-read round {r}\n\nNo objection.\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
