"""Phase-5 hostile-review holes: failing tests for each of the 6 findings.

(1) G0 counts only ./?.  (2) `dda report` builds over stale/invalid locks and
copies forged footers verbatim.  (3) gitcheck scans only staged diffs, misses
committed data + formats (.tsv/.json/.xlsx/.pkl/.h5), key material in .txt and
extensionless keys.  (4) G8 unpassable via documented workflow (skeleton emits
empty fields that check() flags).  (5) G8 checks only the first report file.
(6) G9 blesses committed data.
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


def _spec_with(question, pin):
    return SPEC.replace("Did checkout v2 raise conversion?", question).format(h=pin)


class HolesSetup(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p5h-"))
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

    def lock(self):
        rc, out = self.cli("lock")
        self.assertEqual(rc, 0, out)
        return out

    def answer(self, text="# Answer\n\nConversion rose.\n"):
        (self.wd.analysis / "answer.md").write_text(text, encoding="utf-8")


class TestG0Segmentation(HolesSetup):
    def test_g0_rejects_exclamation_second_sentence(self):
        self.wd.spec_path.write_text(_spec_with("Did it rise! Should we ship it?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertFalse(passed, f"G0 passed a two-sentence question: {reason}")

    def test_g0_rejects_semicolon_splice(self):
        self.wd.spec_path.write_text(
            _spec_with("Did v2 raise conversion; should we ship it?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertFalse(passed, f"G0 passed a semicolon-spliced question: {reason}")

    def test_g0_rejects_newline_second_sentence(self):
        self.wd.spec_path.write_text(
            _spec_with("Did v2 raise conversion?\nShould we ship it?", self.pin.split("#")[1]))
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertFalse(passed, f"G0 passed a two-line question: {reason}")

    def test_g0_still_passes_one_sentence(self):
        passed, reason, _ = gates5.gate_g0(self.wd)
        self.assertTrue(passed, reason)


class TestReportLockValidity(HolesSetup):
    def test_report_refuses_stale_lock(self):
        self.lock()
        with open(self.wd.spec_path, "a", encoding="utf-8") as fh:
            fh.write("\n## Assumptions\nchanged after lock\n")
        self.answer()
        rc, out = self.cli("report", "--slug", "t1")
        self.assertNotEqual(rc, 0, f"report built over a stale lock: {out}")

    def test_report_refuses_forged_footer(self):
        self.lock()
        rc, sk = self.cli("footer")
        self.assertEqual(rc, 0, sk)
        forged = sk.replace((__import__("re").search(r"[0-9a-f]{12}", sk) or [None])[0] or "deadbeef", "0" * 12)
        self.assertNotEqual(forged, sk, "could not forge the footer (no lock hash found)")
        self.answer("# Answer\n\nConversion rose.\n\n" + forged)
        rc, out = self.cli("report", "--slug", "t1")
        self.assertNotEqual(rc, 0, f"report copied a forged footer verbatim: {out}")


class TestGitcheckHardened(HolesSetup):
    def _stage(self, rel, content="a,b\n1,2\n"):
        p = self.wd.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
        subprocess.run(["git", "add", "-f", rel], cwd=str(self.wd.root), check=True)

    def _commit(self, rel, content="a,b\n1,2\n"):
        self._stage(rel, content)
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t.t",
                        "-c", "commit.gpgsign=false", "commit", "-q", "-m", "x", "--", rel],
                       cwd=str(self.wd.root), check=True)

    def test_gitcheck_committed_csv(self):
        self.lock()
        self._commit("chunk.csv")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed committed data: {out}")

    def test_gitcheck_staged_tsv_json_xlsx_pkl_h5(self):
        self.lock()
        for rel in ("a.tsv", "b.json", "c.xlsx", "d.pkl", "e.h5"):
            self._stage(rel)
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed staged data formats: {out}")

    def test_gitcheck_key_material_in_txt(self):
        self.lock()
        self._stage("notes.txt", "deploy notes\n-----BEGIN RSA PRIVATE KEY-----\nabc\n")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed key material in .txt: {out}")

    def test_gitcheck_extensionless_key(self):
        self.lock()
        self._stage("deploy_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed an extensionless key file: {out}")

    def test_gitcheck_clean_still_passes(self):
        self.lock()
        rc, out = self.cli("gitcheck")
        self.assertEqual(rc, 0, out)


class TestG8Workflow(HolesSetup):
    def test_g8_passes_documented_workflow(self):
        self.lock()
        self.answer()
        rc, out = self.cli("report", "--slug", "t1")
        self.assertEqual(rc, 0, out)
        rc, out = self.cli("gate", "G8")
        self.assertEqual(rc, 0, f"documented workflow does not pass G8: {out}")

    def test_g8_checks_all_reports(self):
        self.lock()
        self.answer()
        rc, out = self.cli("report", "--slug", "good")
        self.assertEqual(rc, 0, out)
        bad = self.wd.root / "reports" / "bad.md"
        bad.write_text("# Bad\n\nNo footer here at all.\n", encoding="utf-8")
        rc, out = self.cli("gate", "G8")
        self.assertNotEqual(rc, 0, f"G8 ignored a footerless second report: {out}")

    def test_g8_report_flag_selects_one(self):
        self.lock()
        self.answer()
        rc, out = self.cli("report", "--slug", "good")
        self.assertEqual(rc, 0, out)
        (self.wd.root / "reports" / "bad.md").write_text("# Bad\n\nNo footer.\n", encoding="utf-8")
        rc, out = self.cli("gate", "G8", "--report", "reports/good.md")
        self.assertNotEqual(rc, 0, f"G8 --report exited 0 with an unchecked report present: {out}")
        self.assertIn("scope", out.lower(), f"partial scope not recorded in verdict: {out}")
        self.assertIn("good.md", out, f"--report target not recorded in verdict: {out}")


class TestG9CommittedData(HolesSetup):
    def test_g9_fails_on_committed_data(self):
        self.lock()
        self.answer()
        rc, out = self.cli("report", "--slug", "t1")
        self.assertEqual(rc, 0, out)
        # Commit every legitimate leftover so the tree is clean; only the
        # smuggled data file should trip G9.
        subprocess.run(["git", "add", "-A"], cwd=str(self.wd.root), check=True)
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t.t",
                        "-c", "commit.gpgsign=false", "commit", "-q", "-m", "evidence"],
                       cwd=str(self.wd.root), check=True)
        rc, out = self.cli("gate", "G9")
        self.assertEqual(rc, 0, f"clean tree should pass G9: {out}")
        p = self.wd.root / "chunk.csv"
        p.write_text("a,b\n1,2\n", encoding="utf-8")
        subprocess.run(["git", "add", "-f", "chunk.csv"], cwd=str(self.wd.root), check=True)
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t.t",
                        "-c", "commit.gpgsign=false", "commit", "-q", "-m", "oops"],
                       cwd=str(self.wd.root), check=True)
        rc, out = self.cli("gate", "G9")
        self.assertNotEqual(rc, 0, f"G9 blessed committed data: {out}")


if __name__ == "__main__":
    unittest.main()
