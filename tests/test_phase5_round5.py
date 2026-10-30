"""Phase-5 hostile re-review round 5: failing tests for the fresh bypasses.

(P5-a, HIGH) trailing-dot names (`orders.csv.`, `secret.`) evade the safety
scan on Windows-equivalent paths; strip trailing dots/spaces before checks.
(P5-b, HIGH) extensionless data files (CSV rows, no extension) evade the
binary/NUL sniff; sniff delimited tabular content too.
(P5-c, HIGH) 1-char secret values (`password=x`) evade the length floor.
(P5-d, HIGH) camelCase space-separated secrets (`secretKey <value>`) evade
both the `[:=]` glue and the `is` form.
(P5-e, HIGH) G8 `--report X` exits 0 while other reports sit unchecked; a
partial scope must fail.
(P5-f, MED) gitignored files are never scanned, so ignored spills bypass
`gitcheck`/G9.
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


class R5Setup(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p5r5-"))
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
        from ddalib import lockhash
        self.pin = lockhash.load_definition(self.wd, "conversion").pin
        self.wd.spec_path.write_text(
            SPEC.format(q="Did checkout v2 raise conversion?", h=self.pin.split("#")[1]),
            encoding="utf-8")

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

    def _stage(self, rel, content="a,b\n1,2\n"):
        p = self.wd.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
        subprocess.run(["git", "add", "-f", rel], cwd=str(self.wd.root), check=True)

    def _flagged(self, rel, content):
        self._stage(rel, content)
        rc, out = self.cli("gitcheck")
        subprocess.run(["git", "rm", "--cached", "-q", rel], cwd=str(self.wd.root), check=True)
        (self.wd.root / rel).unlink()
        return rc, out


class TestTrailingDotNames(R5Setup):
    def test_unit_trailing_dot_data_name_flagged(self):
        from ddalib import ledger as _ledger
        blob = b"a,b\n1,2\n"
        self.assertIsNotNone(_ledger._scan_reason(None, "orders.csv.", blob, ignored=False),
                             "trailing-dot data name evaded the extension check")

    def test_unit_trailing_dot_secret_name_flagged(self):
        from ddalib import ledger as _ledger
        self.assertIsNotNone(_ledger._scan_reason(None, "secret.", b"nothing\n", ignored=False),
                             "trailing-dot secret name evaded the name check")

    def test_unit_trailing_dot_env_flagged(self):
        from ddalib import ledger as _ledger
        self.assertIsNotNone(_ledger._scan_reason(None, ".env. ", b"nothing\n", ignored=False),
                             "trailing-dot .env evaded the exact-name check")


class TestExtensionlessDataSniff(R5Setup):
    def test_gitcheck_flags_extensionless_csv(self):
        self.lock()
        rc, out = self._flagged("dataset", "a,b\n1,2\n3,4\n5,6\n")
        self.assertNotEqual(rc, 0, f"gitcheck missed extensionless CSV data: {out}")

    def test_gitcheck_flags_extensionless_tsv(self):
        self.lock()
        rc, out = self._flagged("dataset2", "a\tb\n1\t2\n3\t4\n5\t6\n")
        self.assertNotEqual(rc, 0, f"gitcheck missed extensionless TSV data: {out}")

    def test_gitcheck_flags_single_column_numeric(self):
        self.lock()
        rc, out = self._flagged("ids", "id\n1\n2\n3\n4\n5\n")
        self.assertNotEqual(rc, 0, f"gitcheck missed single-column numeric data: {out}")

    def test_gitcheck_passes_extensionless_prose(self):
        self.lock()
        rc, out = self._flagged("scratch", "todo\n- buy milk\n- call mom\n")
        self.assertEqual(rc, 0, f"gitcheck flagged a plain prose file: {out}")


class TestSecretValueShapes(R5Setup):
    def test_gitcheck_flags_single_char_value(self):
        self.lock()
        rc, out = self._flagged("k1.txt", "password=x\n")
        self.assertNotEqual(rc, 0, f"gitcheck missed a 1-char secret value: {out}")

    def test_gitcheck_flags_single_char_colon_value(self):
        self.lock()
        rc, out = self._flagged("k2.txt", "api key: y\n")
        self.assertNotEqual(rc, 0, f"gitcheck missed a 1-char colon value: {out}")

    def test_gitcheck_flags_camelcase_space_separated(self):
        self.lock()
        rc, out = self._flagged("k3.txt", "secretKey hunter2hunter2value\n")
        self.assertNotEqual(rc, 0, f"gitcheck missed a space-separated camelCase secret: {out}")

    def test_gitcheck_flags_camelcase_prefix_space_separated(self):
        self.lock()
        rc, out = self._flagged("k4.txt", "myToken abcdefghijklmnop\n")
        self.assertNotEqual(rc, 0, f"gitcheck missed a prefixed space-separated secret: {out}")

    def test_gitcheck_passes_benign_token_prose(self):
        self.lock()
        rc, out = self._flagged("prose.txt", "access tokens expire soon\n")
        self.assertEqual(rc, 0, f"gitcheck flagged benign prose: {out}")


class TestGitignoredScan(R5Setup):
    def test_gitcheck_flags_secret_in_gitignored_file(self):
        self.lock()
        (self.wd.root / ".git" / "info" / "exclude").write_text("leak.txt\n", encoding="utf-8")
        p = self.wd.root / "leak.txt"
        p.write_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
        try:
            rc, out = self.cli("gitcheck")
        finally:
            p.unlink()
        self.assertNotEqual(rc, 0, f"gitcheck missed a secret in a gitignored file: {out}")


class TestG8ReportScopeFails(R5Setup):
    def _good_report(self):
        self.lock()
        (self.wd.analysis / "answer.md").write_text("# Answer\n\nConversion rose.\n", encoding="utf-8")
        rc, out = self.cli("report", "--slug", "good")
        self.assertEqual(rc, 0, out)

    def test_g8_report_flag_fails_with_unchecked_others(self):
        self._good_report()
        (self.wd.root / "reports" / "bad.md").write_text("# Bad\n\nNo footer.\n", encoding="utf-8")
        rc, out = self.cli("gate", "G8", "--report", "reports/good.md")
        self.assertNotEqual(rc, 0, f"G8 --report exited 0 with an unchecked report present: {out}")
        self.assertIn("scope", out.lower(), f"partial scope not recorded in verdict: {out}")
        self.assertIn("good.md", out, f"--report target not recorded in verdict: {out}")


if __name__ == "__main__":
    unittest.main()
