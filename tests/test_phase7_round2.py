"""Phase-7 hostile re-review: failing tests for the critical goldfish bypasses.

(P7-a, CRITICAL) goldfish review JSONs are not bound into the chain: a
forged `reviews/goldfish/*.json` with no matching `runs.log` entry passes
G3, and a deleted packet passes G3. G3 must cross-check every record
against runs.log and the packet manifest on disk.
(P7-b, HIGH) DDA_GOLDFISH_STUB is honored in production: anyone can fake
passing reviews. The stub must work only under an explicit test flag.
(P7-c, HIGH) governance JSONs (reviews/goldfish, packet manifests) trip
the extension scan, so committing reviews makes G9 unsatisfiable; exempt
or classify them so G9 can pass with reviews committed.
(P7-d, MED) the footer review field accepts one stray id or the word
"round"; every recorded round's request id must be named.
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
Did checkout v2 raise conversion?

## Decision it informs
Ship v2 or roll back.

## Tier
{tier}

## Rung
{rung}

## Audience
data team

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
exact

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


class P7R2Setup(unittest.TestCase):
    TIER = "This is an EXPLORE analysis."
    RUNG = "quick-cut"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p7r2-"))
        os.environ["DDA_HOME"] = str(self.tmp / "home")
        self.raw = self.tmp / "raw"
        self.raw.mkdir()
        (self.raw / "orders.csv").write_text("id,amount\n1,10\n2,20\n", encoding="utf-8")
        from ddalib.layout import Workdir
        self.wd = Workdir.at(self.tmp / "wd")
        self.env = dict(os.environ)
        self.env["DDA_HOME"] = str(self.tmp / "home")
        self.env["PYTHONPATH"] = str(REPO / "scripts") + os.pathsep + self.env.get("PYTHONPATH", "")
        self.cli("init", str(self.wd.root))
        subprocess.run(["git", "init", "-q", str(self.wd.root)], check=True)
        subprocess.run(["git", "-C", str(self.wd.root), "config", "user.email", "t@t.t"])
        subprocess.run(["git", "-C", str(self.wd.root), "config", "user.name", "t"])
        self.wd.config_path.write_text(
            "version: 1\ndefault_tier: EXPLORE\ndata_roots:\n  sales:\n"
            f"    paths: [\"{self.raw.as_posix()}\"]\n    tool_patterns: [\"^mcp__warehouse__.*\"]\n"
            "publish_channels:\n  wordpress:\n    tool_patterns: [\"^mcp__wordpress__.*\"]\n",
            encoding="utf-8")
        (self.wd.definitions / "conversion.md").write_text(
            "---\nname: conversion\nversion: 1\n---\nOrders / sessions, daily grain, UTC.\n",
            encoding="utf-8")
        from ddalib import lockhash
        self.pin = lockhash.load_definition(self.wd, "conversion").pin
        self.write_spec()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_spec(self, tier=None, rung=None, sources="- `sales` — orders table",
                   metrics=None, hypotheses="v2 raises conversion by shortening checkout.",
                   exclusion="exclude staff orders.",
                   thresholds="a drop of 1pt kills v2.", exposure="none known"):
        if metrics is None:
            metrics = "- %s" % self.pin
        self.wd.spec_path.write_text(SPEC.format(
            tier=tier or self.TIER, rung=rung or self.RUNG, sources=sources,
            metrics=metrics, hypotheses=hypotheses, exclusion=exclusion,
            thresholds=thresholds, exposure=exposure), encoding="utf-8")

    def cli(self, *args, stub=None, env=None):
        import os as _os
        kw = dict(capture_output=True, text=True, env=dict(env if env is not None else self.env))
        if stub:
            kw["env"]["DDA_GOLDFISH_STUB"] = stub
        if _os.path.isdir(str(self.wd.root)):
            kw["cwd"] = str(self.wd.root)
        p = subprocess.run([sys.executable, "-m", "ddalib.cli"] + list(args), **kw)
        return p.returncode, p.stdout + p.stderr


class TestG3BindsChain(P7R2Setup):
    TIER = "This is a DECIDE analysis."
    RUNG = "glance"

    def _valid_flow(self):
        self.write_spec()
        self.assertEqual(self.cli("lock")[0], 0)
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        rc, out = self.cli("review", "run", "teardown", stub="pass")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.cli("approve", "spec", "--no-sign")[0], 0)
        self.assertEqual(self.cli("approved", "spec")[0], 0)
        rc, out = self.cli("gate", "G3")
        self.assertEqual(rc, 0, f"G3 failed a valid goldfish flow: {out}")

    def test_g3_fails_forged_goldfish_record(self):
        self._valid_flow()
        gdir = self.wd.analysis / "reviews" / "goldfish"
        src = sorted(gdir.glob("teardown-*.json"))[0]
        rec = json.loads(src.read_text(encoding="utf-8"))
        rec["provider_request_id"] = "forged-0001"
        rec["seq"] = 99
        (gdir / "teardown-r1-seq99.json").write_text(json.dumps(rec), encoding="utf-8")
        rc, out = self.cli("gate", "G3")
        self.assertNotEqual(rc, 0, f"G3 passed a forged goldfish record with no chain entry: {out}")

    def test_g3_fails_missing_packet(self):
        self._valid_flow()
        import shutil as _shutil
        for child in (self.wd.analysis / "packets").iterdir():
            _shutil.rmtree(child)
        rc, out = self.cli("gate", "G3")
        self.assertNotEqual(rc, 0, f"G3 passed with the packet deleted: {out}")


class TestStubGated(P7R2Setup):
    TIER = "This is a DECIDE analysis."
    RUNG = "glance"

    def test_stub_ignored_without_test_flag(self):
        self.assertEqual(self.cli("lock")[0], 0)
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        env = dict(self.env)
        env["DDA_GOLDFISH_STUB"] = "pass"
        env.pop("PYTEST_CURRENT_TEST", None)
        env.pop("DDA_TEST_MODE", None)
        env.pop("DDA_GOLDFISH_API_KEY", None)
        rc, out = self.cli("review", "run", "teardown", env=env)
        self.assertNotEqual(rc, 0, f"production review run honored the stub: {out}")

    def test_stub_honored_with_test_flag(self):
        self.assertEqual(self.cli("lock")[0], 0)
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        env = dict(self.env)
        env["DDA_GOLDFISH_STUB"] = "pass"
        env.pop("PYTEST_CURRENT_TEST", None)
        env["DDA_TEST_MODE"] = "1"
        rc, out = self.cli("review", "run", "teardown", env=env)
        self.assertEqual(rc, 0, f"review run failed under the test flag: {out}")


class TestGovernanceJsonCommittable(P7R2Setup):
    TIER = "This is a DECIDE analysis."
    RUNG = "glance"

    def test_g9_passes_with_reviews_and_packets_committed(self):
        self.write_spec()
        self.assertEqual(self.cli("lock")[0], 0)
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        rc, out = self.cli("review", "run", "teardown", stub="pass")
        self.assertEqual(rc, 0, out)
        subprocess.run(["git", "add", "-A"], cwd=str(self.wd.root), check=True)
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t.t",
                        "-c", "commit.gpgsign=false", "commit", "-q", "-m", "evidence"],
                       cwd=str(self.wd.root), check=True)
        rc, out = self.cli("gate", "G9")
        self.assertEqual(rc, 0, f"G9 failed with committed governance JSONs: {out}")


class TestFooterPerRoundIds(P7R2Setup):
    TIER = "This is a DECIDE analysis."
    RUNG = "glance"

    def test_footer_requires_every_round_id(self):
        self.assertEqual(self.cli("lock")[0], 0)
        from ddalib import footer as _footer
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        self.assertEqual(self.cli("review", "run", "teardown", stub="pass")[0], 0)
        recs = sorted((self.wd.analysis / "reviews" / "goldfish").glob("teardown-*.json"))
        ids = [json.loads(p.read_text(encoding="utf-8"))["provider_request_id"] for p in recs]
        self.assertGreaterEqual(len(ids), 2, "expected one id per round")
        skel = _footer.skeleton(self.wd)
        for rid in ids:
            self.assertIn(rid, skel, "fresh skeleton must name every recorded id")
        self.assertEqual(_footer.check(self.wd, "# R\n\nbody\n\n" + skel), [])
        partial = skel.replace(ids[1], "REDACTED")
        problems = _footer.check(self.wd, "# R\n\nbody\n\n" + partial)
        self.assertTrue(any(ids[1] in p for p in problems),
                        f"footer passed while round id {ids[1]} is unnamed: {problems}")


if __name__ == "__main__":
    unittest.main()
