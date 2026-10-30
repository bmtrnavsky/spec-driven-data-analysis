"""Phase-5 hostile re-review round 3: failing tests for each of the 10 fresh bypasses.

(1) G8 --report accepts paths outside the workdir (absolute, ..).
(2) .analysis/.spill/ dir contents skip content scan.
(3) exact-exempt governance paths (spec.md etc) skip content scan.
(4) secret at 500K offset in a 1.1MB txt missed by head+tail sampling.
(5) quoted-key JSON {"password": "..."} in .txt missed.
(6) Anthropic / bare-sk / Bearer / GCP-temp (ASIA, AIza, ya29.) key formats missed.
(7) G0 lowercase continuation after ?/; without space passes.
(8) zero-width/invisible chars defeat the G0 split.
(9) ideographic period U+3002 is not a G0 terminator.
(10) Mr./Mrs. abbreviations false-split G0.
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

from ddalib import gates5, lockhash  # noqa: E402
from ddalib.layout import Workdir  # noqa: E402

SPEC = """# Analysis spec

## Question
{q}

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


def _spec_with(question, pin):
    return SPEC.format(q=question, h=pin)


class R3Setup(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p5r3-"))
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
        self.wd.spec_path.write_text(
            _spec_with("Did checkout v2 raise conversion?", self.pin.split("#")[1]), encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cli(self, *args):
        import os as _os
        kw = dict(capture_output=True, text=True, env=self.env)
        if _os.path.isdir(str(self.wd.root)):
            kw["cwd"] = str(self.wd.root)
        p = subprocess.run([sys.executable, "-m", "ddalib.cli"] + list(args), **kw)
        return p.returncode, p.stdout + p.stderr

    def lock(self):
        rc, out = self.cli("lock")
        self.assertEqual(rc, 0, out)
        return out

    def answer(self, text="# Answer\n\nConversion rose.\n"):
        (self.wd.analysis / "answer.md").write_text(text, encoding="utf-8")

    def _stage(self, rel, content="a,b\n1,2\n"):
        p = self.wd.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
        subprocess.run(["git", "add", "-f", rel], cwd=str(self.wd.root), check=True)

    def _good_report(self):
        self.lock()
        self.answer()
        rc, out = self.cli("report", "--slug", "good")
        self.assertEqual(rc, 0, out)


class TestG8ReportConfinement(R3Setup):
    def test_g8_report_rejects_absolute_path(self):
        self._good_report()
        abs_outside = str((self.wd.root / "reports" / "good.md").resolve())
        rc, out = self.cli("gate", "G8", "--report", abs_outside)
        self.assertNotEqual(rc, 0, f"G8 --report accepted an absolute path: {out}")

    def test_g8_report_rejects_dotdot_inside(self):
        self._good_report()
        rc, out = self.cli("gate", "G8", "--report", "reports/../reports/good.md")
        self.assertNotEqual(rc, 0, f"G8 --report accepted a .. path: {out}")

    def test_g8_report_rejects_sibling_outside(self):
        self._good_report()
        outside = self.tmp / "evil.md"
        shutil.copyfile(self.wd.root / "reports" / "good.md", outside)
        rc, out = self.cli("gate", "G8", "--report", "../evil.md")
        self.assertNotEqual(rc, 0, f"G8 --report escaped the workdir: {out}")


class TestSpillDirScan(R3Setup):
    def test_gitcheck_scans_dot_spill_dir(self):
        self.lock()
        self._stage(".analysis/.spill/evil.txt",
                     "deploy notes\n-----BEGIN RSA PRIVATE KEY-----\nabc\n")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed a secret inside .analysis/.spill/: {out}")


class TestExactExemptContent(R3Setup):
    def test_gitcheck_scans_exact_exempt_governance_file(self):
        self.lock()
        self._stage(".gitignore", "*.log\npassword = hunter2-exact-exempt-secret\n")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed a secret in an exact-exempt file: {out}")


class TestMiddleSecret(R3Setup):
    def test_gitcheck_catches_secret_at_500k_offset(self):
        self.lock()
        blob = b"x" * 500_000 + b"\npassword = hunter2-middle-offset-secret\n" + b"y" * 600_000
        self._stage("mid.txt", blob)
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed a mid-file secret: {out}")


class TestQuotedKeyJson(R3Setup):
    def test_gitcheck_flags_quoted_password_key(self):
        self.lock()
        self._stage("cfg.txt", '{"password": "hunter2-hunter2-hunter2"}\n')
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed a quoted password key: {out}")


class TestNewKeyFormats(R3Setup):
    def _flagged(self, rel, content):
        self._stage(rel, content)
        rc, out = self.cli("gitcheck")
        # reset the staged file so cases stay independent
        subprocess.run(["git", "rm", "--cached", "-q", rel], cwd=str(self.wd.root), check=True)
        (self.wd.root / rel).unlink()
        return rc, out

    def test_gitcheck_flags_new_token_formats(self):
        self.lock()
        cases = {
            "ant.txt": "key: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
            "bare.txt": "token: sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
            "asia.txt": "aws_session: ASIAAAAAAAAAAAAAAAAA\n",
            "aiza.txt": "gmaps: AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
            "ya.txt": "oauth: ya29.a0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
            "bearer.txt": "auth: Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        }
        for rel, content in cases.items():
            with self.subTest(rel=rel):
                rc, out = self._flagged(rel, content)
                self.assertNotEqual(rc, 0, f"gitcheck missed token format in {rel}: {out}")


class TestG0LowercaseNoSpace(R3Setup):
    def test_g0_rejects_lowercase_no_space_question(self):
        self.wd.spec_path.write_text(_spec_with("Did it rise?should we ship it?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertFalse(passed, f"G0 passed a lowercase no-space split: {reason}")

    def test_g0_rejects_lowercase_no_space_semicolon(self):
        self.wd.spec_path.write_text(_spec_with("Did v2 raise conversion;should we ship it?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertFalse(passed, f"G0 passed a lowercase no-space semicolon split: {reason}")


class TestG0ZeroWidth(R3Setup):
    def test_g0_rejects_zwsp_split(self):
        self.wd.spec_path.write_text(
            _spec_with("Did it rise?\u200bShould we ship it?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertFalse(passed, f"G0 passed a zero-width-space split: {reason}")

    def test_g0_rejects_word_joiner_lowercase_split(self):
        self.wd.spec_path.write_text(
            _spec_with("Did it rise?\u2060should we ship it?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertFalse(passed, f"G0 passed a word-joiner split: {reason}")


class TestG0IdeographicPeriod(R3Setup):
    def test_g0_rejects_ideographic_period_split(self):
        self.wd.spec_path.write_text(_spec_with("Did it rise。Should we ship it?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertFalse(passed, f"G0 passed an ideographic-period split: {reason}")


class TestG0Abbreviations(R3Setup):
    def test_g0_passes_mr_abbreviation(self):
        self.wd.spec_path.write_text(_spec_with("Did Mr. Smith raise conversion?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertTrue(passed, f"G0 false-split on Mr.: {reason}")

    def test_g0_passes_mrs_abbreviation(self):
        self.wd.spec_path.write_text(_spec_with("Did Mrs. Smith raise conversion?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertTrue(passed, f"G0 false-split on Mrs.: {reason}")


if __name__ == "__main__":
    unittest.main()
