"""Phase 5 tests: G0 intake gate, G8 report gate, G9 archive gate, report + gitcheck commands."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from ddalib import gates5, lockhash  # noqa: E402
from ddalib.layout import Workdir  # noqa: E402

SPEC = """# Analysis spec

## Question
Did checkout v2 raise conversion?

## Decision it informs
Ship v2 or roll back.

## Tier
This is an EXPLORE analysis.

## Rung
quick-cut

## Data sources
- `sales` — orders table

## Metrics
- conversion@1#{h}

## Prior exposure
none known
"""


class Phase5Setup(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p5-"))
        os.environ["DDA_HOME"] = str(self.tmp / "home")
        self.raw = self.tmp / "raw"
        self.raw.mkdir()
        (self.raw / "orders.csv").write_text("id,amount\n1,10\n", encoding="utf-8")
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
        self.pin = lockhash.load_definition(self.wd, "conversion").pin
        self.wd.spec_path.write_text(SPEC.format(h=self.pin.split("#")[1]), encoding="utf-8")
    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cli(self, *args):
        import os as _os
        kw = dict(capture_output=True, text=True, env=self.env)
        if _os.path.isdir(str(self.wd.root)):
            kw["cwd"] = str(self.wd.root)
        p = subprocess.run([sys.executable, "-m", "ddalib.cli"] + list(args), **kw)
        return p.returncode, p.stdout + p.stderr

    def test_g0_pass(self):
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertTrue(passed, reason)

    def test_g0_fail_no_question(self):
        self.wd.spec_path.write_text("# Spec\n\nnothing here\n", encoding="utf-8")
        passed, _, _ = gates5.gate_g0(self.wd)
        self.assertFalse(passed)

    def test_g8_fails_without_lock(self):
        passed, _, _ = gates5.gate_g8(self.wd)
        self.assertFalse(passed)

    def test_gate_g0_cli(self):
        rc, out = self.cli("gate", "G0")
        self.assertEqual(rc, 0, out)

    def test_gitcheck_clean(self):
        rc, out = self.cli("lock")
        self.assertEqual(rc, 0, out)
        rc, out = self.cli("gitcheck")
        self.assertEqual(rc, 0, out)

    def test_gitcheck_fails_with_data_staged(self):
        rc, _ = self.cli("lock")
        self.assertEqual(rc, 0)
        with open(self.wd.root / "chunk.csv", "w") as f:
            f.write("a,b\n1,2\n")
        subprocess.run(["git", "add", "-f", "chunk.csv"], cwd=str(self.wd.root), check=True)
        rc, _ = self.cli("gitcheck")
        self.assertNotEqual(rc, 0)

    def test_report_builds(self):
        rc, out = self.cli("lock")
        self.assertEqual(rc, 0, out)
        (self.wd.analysis / "answer.md").write_text(
            "# Answer\n\nConversion rose.\n", encoding="utf-8")
        rc, out = self.cli("report", "--slug", "t1")
        self.assertEqual(rc, 0, out)
        self.assertTrue((self.wd.root / "reports" / "t1.md").is_file())


if __name__ == "__main__":
    unittest.main()
