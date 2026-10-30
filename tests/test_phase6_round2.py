"""Phase-6 hostile re-review: failing tests for the G1 formula/pin bypasses.

(P6-a) the formula regex is case-sensitive: `MEAN(x)`, `Sum(x)` pass.
(P6-b) the formula regex only names a few functions: `stdev(x)`,
`max(x)` pass; any generic `name(` call outside pin syntax must fail.
(P6-c) operators `*`, `+`, `-`, `^` pass: `revenue - refunds`, `a*b`.
(P6-d) only `-`/`*` bullets must name a pin: numbered (`1.`), quoted
(`>`), or bare lines without a pin pass. Every non-empty Metrics line,
whatever its marker, must name a pin.
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


class G1R2Setup(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p6r2-"))
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
        self.pin = "conversion@1#%s" % self.h
        self.write_spec()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_spec(self, sources="- `sales` \u2014 orders table",
                   metrics=None, hypotheses="v2 raises conversion by shortening checkout.",
                   exclusion="exclude staff orders.",
                   thresholds="a drop of 1pt kills v2.", exposure="none known"):
        if metrics is None:
            metrics = "- %s" % self.pin
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


class TestG1FormulaCase(G1R2Setup):
    def test_g1_fails_uppercase_function(self):
        self.write_spec(metrics="- %s MEAN(orders)" % self.pin)
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed an uppercase function call: {out}")

    def test_g1_fails_mixedcase_function(self):
        self.write_spec(metrics="- %s Sum(orders)" % self.pin)
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed a mixed-case function call: {out}")

    def test_g1_fails_generic_function(self):
        self.write_spec(metrics="- %s stdev(orders)" % self.pin)
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed an unlisted function call: {out}")

    def test_g1_fails_generic_max_function(self):
        self.write_spec(metrics="- %s max(amount, sessions)" % self.pin)
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed max() outside pin syntax: {out}")


class TestG1Operators(G1R2Setup):
    def test_g1_fails_minus_operator(self):
        self.write_spec(metrics="- %s revenue - refunds" % self.pin)
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed a minus operator: {out}")

    def test_g1_fails_star_operator(self):
        self.write_spec(metrics="- %s price * quantity" % self.pin)
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed a star operator: {out}")

    def test_g1_fails_plus_operator(self):
        self.write_spec(metrics="- %s mobile + desktop" % self.pin)
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed a plus operator: {out}")

    def test_g1_fails_caret_operator(self):
        self.write_spec(metrics="- %s lift^2" % self.pin)
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed a caret operator: {out}")

    def test_g1_passes_hyphenated_words(self):
        self.write_spec(metrics="- %s well-known cohort cut" % self.pin)
        rc, out = self.cli("gate", "G1")
        self.assertEqual(rc, 0, f"G1 flagged a hyphenated word as a minus: {out}")

    def test_g1_passes_parenthetical_note(self):
        self.write_spec(metrics="- %s (primary)" % self.pin)
        rc, out = self.cli("gate", "G1")
        self.assertEqual(rc, 0, f"G1 flagged a parenthetical note as a function call: {out}")


class TestG1EveryLineNamesPin(G1R2Setup):
    def _mixed(self, bad_line):
        return "- %s\n%s" % (self.pin, bad_line)

    def test_g1_fails_numbered_line_without_pin(self):
        self.write_spec(metrics=self._mixed("1. checkout conversion rate"))
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed a numbered line with no pin: {out}")

    def test_g1_fails_quoted_line_without_pin(self):
        self.write_spec(metrics=self._mixed("> checkout conversion rate"))
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed a quoted line with no pin: {out}")

    def test_g1_fails_bare_line_without_pin(self):
        self.write_spec(metrics=self._mixed("checkout conversion rate"))
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed a bare line with no pin: {out}")

    def test_g1_fails_plus_bullet_without_pin(self):
        self.write_spec(metrics=self._mixed("+ checkout conversion rate"))
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed a +-bullet with no pin: {out}")

    def test_g1_passes_numbered_line_with_pin(self):
        self.write_spec(metrics="1. %s" % self.pin)
        rc, out = self.cli("gate", "G1")
        self.assertEqual(rc, 0, f"G1 failed a numbered line that names a pin: {out}")


if __name__ == "__main__":
    unittest.main()
