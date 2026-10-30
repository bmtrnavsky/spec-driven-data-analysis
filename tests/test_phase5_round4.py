"""Phase-5 hostile re-review round 4: failing tests for each of the 6 fresh bypasses.

(1, HIGH) `dda report --slug` accepts separators/absolute/traversal paths,
    writing outside reports/ (G8 --report was confined; the slug was not).
(2, HIGH) G8 default scope is non-recursive: reports/nested/*.md never checked
    (or, equivalently, nested slugs must be rejected at write time).
(3, HIGH) credential regex misses word-char/camelCase continuations after
    keywords (secretKey), JWT shape (eyJ...), secret followed by word chars.
(4, MED) files without ASCII extensions evade the suffix check: sniff content
    (NUL/binary) and NFKC-normalize Unicode homoglyphs before the check.
(5, MED) G0 terminator list needs another per-codepoint patch for every new
    Unicode sentence punctuation; derive the set from Unicode properties.
(6, LOW) second `dda report --slug` fails after the short footer is stamped
    into answer.md (full check runs over a short footer).
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

from ddalib import gates5  # noqa: E402
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


class R4Setup(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p5r4-"))
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


class TestReportSlugConfinement(R4Setup):
    def test_report_slug_rejects_dotdot(self):
        self.lock()
        self.answer()
        rc, out = self.cli("report", "--slug", "../evil")
        self.assertNotEqual(rc, 0, f"report --slug accepted a traversal slug: {out}")
        self.assertFalse((self.tmp / "evil.md").exists(), "traversal slug wrote outside reports/")

    def test_report_slug_rejects_absolute(self):
        self.lock()
        self.answer()
        outside = str(self.tmp / "abs.md")
        rc, out = self.cli("report", "--slug", outside)
        self.assertNotEqual(rc, 0, f"report --slug accepted an absolute slug: {out}")
        self.assertFalse(Path(outside).exists(), "absolute slug wrote outside reports/")

    def test_report_slug_rejects_nested(self):
        self.lock()
        self.answer()
        rc, out = self.cli("report", "--slug", "sub/dir")
        self.assertNotEqual(rc, 0, f"report --slug accepted a nested slug: {out}")
        self.assertFalse((self.wd.root / "reports" / "sub").exists(),
                         "nested slug created subdirectories under reports/")


class TestG8NestedScope(R4Setup):
    def test_g8_default_scope_checks_nested_reports(self):
        self._good_report()
        nested = self.wd.root / "reports" / "nested"
        nested.mkdir(parents=True)
        (nested / "deep.md").write_text("# Deep\n\nNo footer here at all.\n", encoding="utf-8")
        rc, out = self.cli("gate", "G8")
        self.assertNotEqual(rc, 0, f"G8 default scope ignored reports/nested/deep.md: {out}")

    def test_g8_default_scope_passes_valid_nested_report(self):
        self._good_report()
        nested = self.wd.root / "reports" / "nested"
        nested.mkdir(parents=True)
        shutil.copyfile(self.wd.root / "reports" / "good.md", nested / "deep.md")
        rc, out = self.cli("gate", "G8")
        self.assertEqual(rc, 0, f"G8 failed on a valid nested report: {out}")


class TestCredentialContinuations(R4Setup):
    def _flagged(self, rel, content):
        self._stage(rel, content)
        rc, out = self.cli("gitcheck")
        subprocess.run(["git", "rm", "--cached", "-q", rel], cwd=str(self.wd.root), check=True)
        (self.wd.root / rel).unlink()
        return rc, out

    def test_gitcheck_flags_camelcase_secret_key(self):
        self.lock()
        rc, out = self._flagged("k1.txt", 'secretKey = "hunter2-secret-value"\n')
        self.assertNotEqual(rc, 0, f"gitcheck missed camelCase secretKey: {out}")

    def test_gitcheck_flags_jwt(self):
        self.lock()
        jwt = ("token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ."
               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n")
        rc, out = self._flagged("k2.txt", jwt)
        self.assertNotEqual(rc, 0, f"gitcheck missed a JWT: {out}")

    def test_gitcheck_flags_keyword_with_trailing_word_chars(self):
        self.lock()
        rc, out = self._flagged("k3.txt", 'secret2 = "hunter2-secret-value"\n')
        self.assertNotEqual(rc, 0, f"gitcheck missed a keyword with trailing word chars: {out}")


class TestExtensionEvasion(R4Setup):
    def test_gitcheck_flags_homoglyph_extension(self):
        self.lock()
        self._stage("backup\uff0ecsv", "a,b\n1,2\n")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed a fullwidth-stop data file: {out}")

    def test_gitcheck_flags_extensionless_binary(self):
        self.lock()
        self._stage("snapshot", b"PAR1\x15\x00binary-parquet-body\x00\x01\x02")
        rc, out = self.cli("gitcheck")
        self.assertNotEqual(rc, 0, f"gitcheck missed an extensionless binary file: {out}")

    def test_gitcheck_passes_extensionless_text(self):
        self.lock()
        self._stage("notes", "meeting notes\nall clear\n")
        rc, out = self.cli("gitcheck")
        subprocess.run(["git", "rm", "--cached", "-q", "notes"], cwd=str(self.wd.root), check=True)
        (self.wd.root / "notes").unlink()
        self.assertEqual(rc, 0, f"gitcheck flagged a clean extensionless text file: {out}")


class TestG0UnicodeDerived(R4Setup):
    def _g0(self, question):
        self.wd.spec_path.write_text(_spec_with(question, self.pin.split("#")[1]), encoding="utf-8")
        return gates5.gate_g0(self.wd)

    def test_g0_rejects_double_exclamation_split(self):
        passed, reason, _ = self._g0("Did it rise\u203cShould we ship it?")
        self.assertFalse(passed, f"G0 passed a U+203C split: {reason}")

    def test_g0_rejects_devanagari_danda_split(self):
        passed, reason, _ = self._g0("Did it rise\u0964Should we ship it?")
        self.assertFalse(passed, f"G0 passed a U+0964 danda split: {reason}")

    def test_g0_rejects_fullwidth_stop_split(self):
        passed, reason, _ = self._g0("Did it rise\uff0eShould we ship it?")
        self.assertFalse(passed, f"G0 passed a U+FF0E fullwidth-stop split: {reason}")

    def test_g0_passes_symbols_commas_hyphens(self):
        passed, reason, _ = self._g0(
            "Did well-known checkout v2 lift $spend 5% for #1 channel, and should we ship it?")
        self.assertTrue(passed, f"G0 false-split on intra-sentence symbols: {reason}")


class TestReportIdempotency(R4Setup):
    def test_second_report_same_slug_passes(self):
        self._good_report()
        rc, out = self.cli("report", "--slug", "good")
        self.assertEqual(rc, 0, f"second report --slug failed: {out}")

    def test_second_report_new_slug_passes(self):
        self._good_report()
        rc, out = self.cli("report", "--slug", "good2")
        self.assertEqual(rc, 0, f"second report with a new slug failed: {out}")
        rc, out = self.cli("gate", "G8")
        self.assertEqual(rc, 0, f"G8 failed after two reports: {out}")


class TestLockSidecarCleanup(R4Setup):
    def test_filelock_removes_sidecar(self):
        from ddalib import chain
        target = self.wd.analysis / "probe.jsonl"
        chain.append(target, {"probe": 1})
        self.assertTrue(target.is_file())
        self.assertFalse(Path(str(target) + ".lock").exists(),
                         "FileLock left its sidecar behind")

    def test_gitcheck_ignores_filelock_sidecars(self):
        from ddalib import chain
        self.lock()
        chain.append(self.wd.analysis / "approvals.index.jsonl", {"probe": 1})
        # spec.lock is the spec lock file itself, not a FileLock sidecar.
        sidecars = [p for p in self.wd.root.rglob("*.lock") if p.name != "spec.lock"]
        self.assertEqual(sidecars, [], f"lock sidecars left behind: {sidecars}")
        rc, out = self.cli("gitcheck")
        self.assertEqual(rc, 0, f"gitcheck flagged dda's own files: {out}")


if __name__ == "__main__":
    unittest.main()
