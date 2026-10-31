"""Phase 8 (SPEC section 14, item 8): profile/verify + gates G2, G5, G7.

`dda profile` snapshots/fingerprints every source (§10.3); `dda verify`
replays the locked variant's saved script in a fresh kernel against the
snapshot and diffs outputs within the declared tolerance; drift is
recorded, not failed; matched correction evals run; post-result goldfish
rounds are required. G2 enforces rung/tier declarations, overrides, tier
triggers, and human tier confirmation (§2.2).

Run: DDA_TEST_MODE=1 python -m unittest tests.test_phase8
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

SPEC = """# Analysis spec

## Question
{rq}

## Decision it informs
{decision}

## Tier
{tier}

## Rung
{rung}

## Audience
{audience}

## Population and time window
orders in May, UTC

## Data sources
{sources}

## Metrics
{metrics}

## Hypotheses
{hypotheses}

## Planned comparisons and cuts
v1 vs v2, by device.

## Method
Compare conversion rates.

## Exclusion and outlier rules
{exclusion}

## Reproduction tolerance
{tolerance}

## Thresholds that would change the decision
{thresholds}

## Known risks
seasonality

## Prior exposure
{exposure}

## Assumptions
stable traffic

## Out of scope
refunds
"""

SCRIPT = (
    "import csv, os\n"
    "root = {root!r}\n"
    "rows = list(csv.reader(open(os.path.join(root, 'orders.csv'))))\n"
    "n = len(rows) - 1\n"
    "os.makedirs('outputs', exist_ok=True)\n"
    "open('outputs/summary.csv', 'w').write('n,total\\n%d,%d\\n' % (n, sum(int(r[1]) for r in rows[1:])))\n"
    "print('rows=%d' % n)\n"
)


class P8Setup(unittest.TestCase):
    TIER = "This is an EXPLORE analysis."
    RUNG = "quick-cut"
    DECISION = "none \u2014 EXPLORE"
    AUDIENCE = "data team"
    RQ = "Did checkout v2 raise conversion?"
    TOLERANCE = "exact"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p8-"))
        os.environ["DDA_HOME"] = str(self.tmp / "home")
        os.environ["DDA_TEST_MODE"] = "1"
        self.raw = self.tmp / "raw"
        self.raw.mkdir()
        (self.raw / "orders.csv").write_text("id,amount\n1,10\n2,20\n", encoding="utf-8")
        from ddalib.layout import Workdir
        self.wd = Workdir.at(self.tmp / "wd")
        self.env = dict(os.environ)
        self.env["DDA_HOME"] = str(self.tmp / "home")
        self.env["DDA_TEST_MODE"] = "1"
        self.env["PYTHONPATH"] = str(REPO / "scripts") + os.pathsep + self.env.get("PYTHONPATH", "")
        self.cli("init", str(self.wd.root))
        subprocess.run(["git", "init", "-q", str(self.wd.root)], check=True)
        subprocess.run(["git", "-C", str(self.wd.root), "config", "user.email", "t@t.t"])
        subprocess.run(["git", "-C", str(self.wd.root), "config", "user.name", "t"])
        self.write_config()
        (self.wd.definitions / "conversion.md").write_text(
            "---\nname: conversion\nversion: 1\n---\nOrders / sessions, daily grain, UTC.\n",
            encoding="utf-8")
        from ddalib import lockhash
        self.pin = lockhash.load_definition(self.wd, "conversion").pin
        self.write_spec()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_config(self, extra=""):
        self.wd.config_path.write_text(
            "version: 1\ndefault_tier: EXPLORE\ndata_roots:\n  sales:\n"
            f"    paths: [\"{self.raw.as_posix()}\"]\n    tool_patterns: [\"^mcp__warehouse__.*\"]\n"
            "publish_channels:\n  wordpress:\n    tool_patterns: [\"^mcp__wordpress__.*\"]\n"
            + extra,
            encoding="utf-8")

    def write_spec(self, **kw):
        d = dict(rq=self.RQ, decision=self.DECISION, tier=self.TIER, rung=self.RUNG,
                 audience=self.AUDIENCE, sources="- `sales` \u2014 orders table",
                 metrics=None, hypotheses="v2 raises conversion by shortening checkout.",
                 exclusion="exclude staff orders.", tolerance=self.TOLERANCE,
                 thresholds="a drop of 1pt kills v2.", exposure="none known")
        d.update(kw)
        if d["metrics"] is None:
            d["metrics"] = "- %s" % self.pin
        self.wd.spec_path.write_text(SPEC.format(**d), encoding="utf-8")

    def cli(self, *args, stub=None, env=None):
        kw = dict(capture_output=True, text=True, env=dict(env or self.env))
        if stub:
            kw["env"]["DDA_GOLDFISH_STUB"] = stub
        if os.path.isdir(str(self.wd.root)):
            kw["cwd"] = str(self.wd.root)
        p = subprocess.run([sys.executable, "-m", "ddalib.cli"] + list(args), **kw)
        return p.returncode, p.stdout + p.stderr

    # -- shared happy-path helpers -------------------------------------
    def lock(self):
        rc, out = self.cli("lock", str(self.wd.root))
        self.assertEqual(rc, 0, f"lock failed: {out}")
        return out

    def stub_baseline(self):
        d = self.tmp / "stubs"
        d.mkdir(exist_ok=True)
        stubs = {
            "pandas": "",
            "numpy": "",
            "pyarrow": "",
            "polars": "",
            "duckdb": "def connect(*a, **k):\n    raise RuntimeError('stub')\n",
            "scipy": "",
            "statsmodels": "",
            "sklearn": "",
            "matplotlib": "",
            "seaborn": "",
            "openpyxl": "",
            "xlrd": "",
            "ipykernel": "",
            "IPython": "def get_ipython():\n    return None\n",
            "jupyter_client": "",
        }
        for name, body in stubs.items():
            (d / f"{name}.py").write_text(body or '"""stub"""\n', encoding="utf-8")
        os.environ["DDA_BASELINE_DIR"] = str(d)
        self.env["DDA_BASELINE_DIR"] = str(d)
        return d

    def register_and_run(self, vid="v1", script_body=None):
        from ddalib import kernel
        self.stub_baseline()
        kernel.register_variant(self.wd, vid, why="baseline cut",
                                header={"population": "all", "model": "diff"})
        sp = self.wd.analysis / "variants" / f"{vid}.py"
        sp.write_text(script_body or SCRIPT.format(root=self.raw.as_posix()), encoding="utf-8")
        rec = kernel.do_run(self.wd, vid, str(sp), [], session="s-1")
        self.assertEqual(rec["returncode"], 0, rec.get("stderr_tail"))
        kernel.mark_locked(self.wd, vid)
        return rec


class TestFailClosed8(P8Setup):
    def test_evals_built_in_phase_9(self):
        for args in (("evals", "new"), ("evals", "match"), ("evals", "run")):
            rc, out = self.cli(*args)
            self.assertNotEqual(rc, 3, f"dda {' '.join(args)} was built in phase 9: {out}")

    def test_profile_verify_gates_built(self):
        for args in (("profile",), ("verify",), ("gate", "G7"), ("gate", "G5"), ("gate", "G2")):
            rc, out = self.cli(*args)
            self.assertNotEqual(rc, 3, f"dda {' '.join(args)} must be built in phase 8: {out}")

    def test_profile_needs_lock(self):
        rc, out = self.cli("profile")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("lock", out.lower())

    def test_verify_needs_profile(self):
        self.lock()
        self.register_and_run()
        rc, out = self.cli("verify")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("profile", out.lower())

    def test_verify_needs_locked_variant(self):
        self.lock()
        rc, out = self.cli("profile")
        self.assertEqual(rc, 0, out)
        rc, out = self.cli("verify")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("locked", out.lower())


class TestProfile(P8Setup):
    def test_profile_snapshots_and_records(self):
        self.lock()
        rc, out = self.cli("profile")
        self.assertEqual(rc, 0, f"profile failed: {out}")
        prof = (self.wd.analysis / "profile.md").read_text(encoding="utf-8")
        self.assertIn("sales", prof)
        self.assertIn("snapshot", prof.lower())
        snaps = list((self.wd.root / "derived" / "snapshots").glob("sales@*"))
        self.assertTrue(snaps, "file sources must be materialized under derived/snapshots/<alias>@<asof>")
        copied = list(snaps[0].rglob("orders.csv"))
        self.assertTrue(copied, "snapshot must carry the source files")
        # profile.md carries aggregates only — no row values, no samples
        for secret in ("1,10", "2,20"):
            self.assertNotIn(secret, prof, "profile.md must not quote row values")
        manifest = json.loads((self.wd.analysis / "profile.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["lock_hash"], __import__("ddalib.lockstate", fromlist=["x"]).read_lock(self.wd)["lock_hash"])
        self.assertIn("sales", manifest["aliases"])

    def test_profile_twice_is_stable(self):
        self.lock()
        self.assertEqual(self.cli("profile")[0], 0)
        rc, out = self.cli("profile")
        self.assertEqual(rc, 0, f"second profile failed: {out}")

    def test_schema_change_fails_closed_until_amendment(self):
        self.lock()
        self.assertEqual(self.cli("profile")[0], 0)
        (self.raw / "orders.csv").write_text("id,amount,extra\n1,10,x\n2,20,y\n", encoding="utf-8")
        rc, out = self.cli("profile")
        self.assertNotEqual(rc, 0, f"profile passed across a schema change: {out}")
        self.assertIn("amend", out.lower())
        rc, out = self.cli("lock", str(self.wd.root), "--amend", "upstream added a column")
        self.assertEqual(rc, 0, f"amend failed: {out}")
        rc, out = self.cli("profile")
        self.assertEqual(rc, 0, f"profile failed after amendment: {out}")

    def test_live_only_source_gets_fingerprint(self):
        self.wd.config_path.write_text(
            "version: 1\ndefault_tier: EXPLORE\ndata_roots:\n"
            f"  sales:\n    paths: [\"{self.raw.as_posix()}\"]\n"
            "    tool_patterns: [\"^mcp__warehouse__.*\"]\n"
            "  wh:\n    hosts: [\"db.example.internal\"]\n"
            "publish_channels:\n  wordpress:\n    tool_patterns: [\"^mcp__wordpress__.*\"]\n",
            encoding="utf-8")
        self.write_spec(sources="- `sales` — orders table\n- `wh` — warehouse")
        self.lock()
        rc, out = self.cli("profile")
        self.assertEqual(rc, 0, f"profile failed: {out}")
        prof = (self.wd.analysis / "profile.md").read_text(encoding="utf-8")
        self.assertIn("wh", prof)
        self.assertIn("fingerprint", prof.lower())


class TestG5(P8Setup):
    def full_path(self):
        self.lock()
        self.register_and_run()
        self.assertEqual(self.cli("profile")[0], 0)

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
        self.register_and_run(**kw)
        self.assertEqual(self.cli("profile")[0], 0)

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
        self.register_and_run()
        self.assertEqual(self.cli("profile")[0], 0)
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
        self.register_and_run()
        self.assertEqual(self.cli("profile")[0], 0)
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
        self.register_and_run()
        self.assertEqual(self.cli("profile")[0], 0)
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


class TestG2(P8Setup):
    def test_g2_passes_explore_without_triggers(self):
        self.lock()
        rc, out = self.cli("gate", "G2")
        self.assertEqual(rc, 0, f"G2 failed clean EXPLORE: {out}")

    def test_g2_trigger_forces_decide(self):
        self.write_spec(decision="Ship v2 or roll back.")
        self.lock()
        rc, out = self.cli("gate", "G2")
        self.assertNotEqual(rc, 0, f"G2 passed EXPLORE with a decision trigger: {out}")
        self.assertIn("decide", out.lower())

    def test_g2_external_audience_forces_publish(self):
        self.write_spec(decision="Ship v2 or roll back.", audience="external blog readers")
        self.lock()
        rc, out = self.cli("gate", "G2")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("publish", out.lower())

    def test_g2_decide_needs_tier_confirmation(self):
        self.write_spec(tier="This is a DECIDE analysis.", decision="Ship v2 or roll back.")
        self.lock()
        rc, out = self.cli("gate", "G2")
        self.assertNotEqual(rc, 0, f"G2 passed DECIDE with no tier approval: {out}")
        self.assertEqual(self.cli("approve", "tier", "--no-sign")[0], 0)
        self.assertEqual(self.cli("approved", "tier")[0], 0)
        rc, out = self.cli("gate", "G2")
        self.assertEqual(rc, 0, f"G2 failed DECIDE with tier approval: {out}")

    def test_g2_pii_steps_up_rung(self):
        self.write_spec(rung="glance")
        self.wd.config_path.write_text(
            "version: 1\ndefault_tier: EXPLORE\ndata_roots:\n"
            f"  sales:\n    paths: [\"{self.raw.as_posix()}\"]\n"
            "    tool_patterns: [\"^mcp__warehouse__.*\"]\n"
            "    pii_columns: [\"email\"]\n"
            "publish_channels:\n  wordpress:\n    tool_patterns: [\"^mcp__wordpress__.*\"]\n",
            encoding="utf-8")
        self.lock()
        rc, out = self.cli("gate", "G2")
        self.assertNotEqual(rc, 0, f"G2 passed glance with PII: {out}")
        self.assertIn("rung", out.lower())


class TestEvals8(P8Setup):
    def write_case(self, nnn="001", triggers="sales, conversion, join",
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
        self.register_and_run()
        self.assertEqual(self.cli("profile")[0], 0)
        self.assertEqual(self.cli("verify")[0], 0)
        ev = (self.wd.analysis / "verify.md").read_text(encoding="utf-8")
        self.assertIn("0 matched", ev)

    def test_matched_check_must_pass(self):
        from ddalib import stage8
        self.lock()
        self.register_and_run()
        self.write_case(check="0" * 64)  # wrong hash: must fail
        self.assertEqual(self.cli("profile")[0], 0)
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
