"""Phase-5 hostile re-review round 2: failing tests for each of the 8 bypasses.

(1) G0 no-space split: "Rise?Ship it" must fail.
(2) G0 ASCII-only/terminator gaps: : / — – ？ ！ ； … must split; v2.5 and A/B stay one sentence.
(3) .spill suffix exemption smuggles secrets.
(4) evidence-dir prefix exemptions smuggle data/secrets; only known filenames exempt.
(5) format gaps: avro/orc/zip/tar/7z/gz/bz2/xz/zst.
(6) 1MB content cap skips oversize files (secret past the cap).
(7) secret regex gaps: sk-proj-, underscore sides, is/space separators.
(8) G8 --report selective pass + footerless answer.md ignored.
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


class R2Setup(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p5r2-"))
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


class TestG0NoSpace(R2Setup):
    def test_g0_rejects_no_space_split(self):
        self.wd.spec_path.write_text(_spec_with("Did it rise?Should we ship it?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertFalse(passed, f"G0 passed a no-space two-sentence question: {reason}")

    def test_g0_rejects_no_space_exclamation(self):
        self.wd.spec_path.write_text(_spec_with("Did it rise!Ship it now?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertFalse(passed, f"G0 passed a no-space split: {reason}")


class TestG0Terminators(R2Setup):
    def test_g0_rejects_fullwidth_question_mark(self):
        self.wd.spec_path.write_text(_spec_with("Did it rise？Should we ship it?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertFalse(passed, f"G0 passed a fullwidth-？ two-sentence question: {reason}")

    def test_g0_rejects_colon_split(self):
        self.wd.spec_path.write_text(_spec_with("Did it rise: should we ship it?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertFalse(passed, f"G0 passed a colon-spliced question: {reason}")

    def test_g0_rejects_em_dash_split(self):
        self.wd.spec_path.write_text(_spec_with("Did it rise—Should we ship it?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertFalse(passed, f"G0 passed an em-dash-spliced question: {reason}")

    def test_g0_rejects_ellipsis_split(self):
        self.wd.spec_path.write_text(_spec_with("Did it rise…Should we ship it?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertFalse(passed, f"G0 passed an ellipsis-spliced question: {reason}")

    def test_g0_still_passes_decimal_and_time(self):
        self.wd.spec_path.write_text(_spec_with("Did v2.5 raise conversion after 12:30?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertTrue(passed, reason)

    def test_g0_still_passes_ab_slash(self):
        self.wd.spec_path.write_text(_spec_with("Did the A/B test lift conversion?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertTrue(passed, reason)


class TestSpillExemption(R2Setup):
    def test_gitcheck_flags_secret_in_spill_suffix_file(self):
        self.lock()
        self._stage("notes.spill", "deploy notes\n-----BEGIN RSA PRIVATE KEY-----\nabc\n")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed key material in a .spill file: {out}")

    def test_gitcheck_scans_inside_spill_dir(self):
        self.lock()
        self._stage(".analysis/runs.log.spill/99-0.json",
                     '{"type": "done", "password": "hunter2-hunter2-hunter2"}')
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed a secret inside a .spill dir: {out}")


class TestEvidencePrefixes(R2Setup):
    def test_gitcheck_flags_data_under_runs(self):
        self.lock()
        self._stage(".analysis/runs/evil.csv")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed data smuggled under .analysis/runs/: {out}")

    def test_gitcheck_flags_data_under_specs(self):
        self.lock()
        self._stage(".analysis/specs/evil.csv")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed data smuggled under specs/: {out}")

    def test_gitcheck_flags_secret_under_approvals(self):
        self.lock()
        self._stage(".analysis/approvals/evil.txt", "db password=hunter2hunter2\n")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed a secret smuggled under approvals/: {out}")

    def test_gitcheck_clean_after_lock(self):
        self.lock()
        rc, out = self.cli("gitcheck")
        self.assertEqual(rc, 0, out)


class TestFormatGaps(R2Setup):
    def test_gitcheck_flags_new_formats(self):
        self.lock()
        for rel in ("a.avro", "b.orc", "c.zip", "d.tar.gz", "e.7z",
                    "f.gz", "g.bz2", "h.xz", "i.zst"):
            self._stage(rel, b"\x00\x01\x02binary-not-csv")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed new data/archive formats: {out}")


class TestOversizeContent(R2Setup):
    def test_gitcheck_catches_secret_past_1mb(self):
        self.lock()
        blob = b"x" * (1_100_000) + b"\npassword = hunter2-hunter2-secret\n"
        self._stage("big.txt", blob)
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed a secret past the 1MB cap: {out}")

    def test_gitcheck_skips_clean_oversize(self):
        self.lock()
        self._stage("big.txt", b"x" * 1_100_000 + b"\nall clear\n")
        rc, out = self.cli("gitcheck")
        self.assertEqual(rc, 0, out)


class TestSecretRegex(R2Setup):
    def test_gitcheck_flags_sk_proj(self):
        self.lock()
        self._stage("tok.txt", "key: sk-proj-abcdefghij1234567890abcdef\n")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed sk-proj- token: {out}")

    def test_gitcheck_flags_underscore_secret(self):
        self.lock()
        self._stage("cfg.txt", "db_secret=hunter2hunter2value\n")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed secret on underscore sides: {out}")

    def test_gitcheck_flags_is_separator(self):
        self.lock()
        self._stage("cfg.txt", "the password is hunter2hunter2value\n")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed 'password is <value>': {out}")

    def test_gitcheck_flags_space_separator(self):
        self.lock()
        self._stage("cfg.txt", "password hunter2hunter2value\n")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed space-separated password: {out}")


class TestG8Scope(R2Setup):
    def _good_report(self):
        self.lock()
        self.answer()
        rc, out = self.cli("report", "--slug", "good")
        self.assertEqual(rc, 0, out)

    def test_g8_fails_footerless_answer_when_reports_exist(self):
        self._good_report()
        (self.wd.analysis / "answer.md").write_text("# Answer\n\nConversion rose.\n", encoding="utf-8")
        rc, out = self.cli("gate", "G8")
        self.assertNotEqual(rc, 0, f"G8 ignored a footerless answer.md: {out}")

    def test_g8_report_scope_recorded(self):
        self._good_report()
        (self.wd.root / "reports" / "bad.md").write_text("# Bad\n\nNo footer.\n", encoding="utf-8")
        rc, out = self.cli("gate", "G8", "--report", "reports/good.md")
        self.assertNotEqual(rc, 0, f"G8 --report exited 0 with an unchecked report present: {out}")
        self.assertIn("scope", out.lower(), f"--report scope not recorded in verdict: {out}")
        self.assertIn("good.md", out, f"--report target not recorded in verdict: {out}")
        way = (self.wd.analysis / "wayfinder.md").read_text(encoding="utf-8")
        self.assertIn("scope", way.lower(), f"--report scope not recorded in wayfinder: {way}")


if __name__ == "__main__":
    unittest.main()
