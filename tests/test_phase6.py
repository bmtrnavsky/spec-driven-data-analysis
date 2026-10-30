"""Phase 6 (SPEC section 14, item 6): gate G1 over definitions and content-hashed pins.

G1: every metric resolves to a registry pin `name@version#hash` and the hash
recomputes; sources named by config alias; hypotheses, "what would change the
answer", exclusions, and prior exposure stated; no inline formulas.
"""
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
This is an EXPLORE analysis.

## Rung
quick-cut

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


class G1Setup(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p6-"))
        os.environ["DDA_HOME"] = str(self.tmp / "home")
        self.raw = self.tmp / "raw"
        self.raw.mkdir()
        (self.raw / "orders.csv").write_text("id,amount\n1,10\n", encoding="utf-8")
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
        pin = lockhash.load_definition(self.wd, "conversion").pin
        self.h = pin.split("#")[1]
        self.write_spec()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_spec(self, sources="- `sales` \u2014 orders table",
                   metrics=None, hypotheses="v2 raises conversion by shortening checkout.",
                   exclusion="exclude staff orders.",
                   thresholds="a drop of 1pt kills v2.", exposure="none known"):
        if metrics is None:
            metrics = "- conversion@1#%s" % self.h
        self.wd.spec_path.write_text(SPEC.format(
            sources=sources, metrics=metrics, hypotheses=hypotheses,
            exclusion=exclusion, thresholds=thresholds, exposure=exposure),
            encoding="utf-8")

    def cli(self, *args):
        import os as _os
        kw = dict(capture_output=True, text=True, env=self.env)
        if _os.path.isdir(str(self.wd.root)):
            kw["cwd"] = str(self.wd.root)
        p = subprocess.run([sys.executable, "-m", "ddalib.cli"] + list(args), **kw)
        return p.returncode, p.stdout + p.stderr


class TestG1(G1Setup):
    def test_g1_passes_full_spec(self):
        rc, out = self.cli("gate", "G1")
        self.assertEqual(rc, 0, f"G1 failed a full valid spec: {out}")

    def test_g1_fails_unknown_alias(self):
        self.write_spec(sources="- `nosuch` \u2014 mystery table")
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed an unknown config alias: {out}")

    def test_g1_fails_stale_pin(self):
        (self.wd.definitions / "conversion.md").write_text(
            "---\nname: conversion\nversion: 1\n---\nSessions / orders, silently redefined.\n",
            encoding="utf-8")
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed a stale pin hash: {out}")

    def test_g1_fails_inline_formula(self):
        self.write_spec(metrics="- conversion@1#%s (orders / sessions)" % self.h)
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed an inline formula: {out}")

    def test_g1_fails_unpinned_metric_bullet(self):
        self.write_spec(metrics="- checkout conversion rate")
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed an unpinned metric bullet: {out}")

    def test_g1_fails_empty_hypotheses(self):
        self.write_spec(hypotheses="")
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed empty Hypotheses: {out}")

    def test_g1_fails_empty_exclusion(self):
        self.write_spec(exclusion="")
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed empty exclusion rules: {out}")

    def test_g1_fails_empty_thresholds(self):
        self.write_spec(thresholds="")
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed empty change-the-decision thresholds: {out}")

    def test_g1_fails_empty_prior_exposure(self):
        self.write_spec(exposure="")
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed empty prior exposure: {out}")


if __name__ == "__main__":
    unittest.main()
