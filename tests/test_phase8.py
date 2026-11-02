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

    def hook(self, name, tool, args, session="s-1", event="pre_tool_call", **extra):
        import json as _json
        payload = {"hook_event_name": event, "tool_name": tool, "tool_input": args,
                   "session_id": session, "cwd": str(self.wd.root),
                   "extra": {"tool_call_id": "c-hb", **extra}}
        r = subprocess.run([sys.executable, "-I", "-S", str(REPO / "hooks" / "dda_hook.py"), name],
                           input=_json.dumps(payload), capture_output=True, text=True,
                           env=dict(self.env))
        return r.returncode, _json.loads(r.stdout)

    def bind(self, session="s-1"):
        rc, out = self.cli("start", str(self.wd.root), "--session", session)
        self.assertEqual(rc, 0, f"start failed: {out}")
        return out

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

    def register_locked(self, vid="v1", script_body=None):
        # Register + freeze the reported variant WITHOUT running it:
        # for tests that need a locked variant but must not create
        # results (a run needs a profile first, §10.3).
        from ddalib import kernel
        self.stub_baseline()
        kernel.register_variant(self.wd, vid, why="baseline cut",
                                header={"population": "all", "model": "diff"})
        sp = self.wd.analysis / "variants" / f"{vid}.py"
        sp.write_text(script_body or SCRIPT.format(root=self.raw.as_posix()), encoding="utf-8")
        kernel.mark_locked(self.wd, vid)
        return sp

    def register_and_run(self, vid="v1", script_body=None):
        from ddalib import kernel
        self.stub_baseline()
        # Pair the run session through the real runlog hook (as production
        # runs do): the G6 cascade intermediate requires every session with
        # runs.log lines to have a verifiable heartbeat log (§6.8).
        self.bind("s-1")
        self.hook("runlog", "terminal", {"command": "dda meta sales"}, session="s-1",
                  event="pre_tool_call")
        self.hook("runlog", "terminal", {"command": "dda meta sales"}, session="s-1",
                  event="post_tool_call")
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
        self.register_locked()
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
        self.write_spec(decision="Ship v2 or roll back.", audience="external")
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


if __name__ == "__main__":
    unittest.main()
