"""Phase 9 (SPEC section 14, item 9): `correct` and evals.

`dda evals new` drafts a correction case, `dda evals match` performs the
mechanical match (§9), `dda evals run` executes deterministic checks for
matched cases, and `dda packet` carries only *matched* review questions
(§5.1). Binding still needs a signed `correction` approval.

Run: DDA_TEST_MODE=1 python -m unittest tests.test_phase9
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

from tests.test_phase8 import P8Setup  # noqa: E402


class P9Setup(P8Setup):
    """Same harness as phase 8; spec gains an optional Pattern tags section."""

    def write_spec(self, **kw):
        tags = kw.pop("tags", None)
        super().write_spec(**kw)
        if tags:
            with open(self.wd.spec_path, "a", encoding="utf-8") as fh:
                fh.write(f"\n## Pattern tags\n{tags}\n")


class TestEvalsNew(P9Setup):
    def test_new_creates_numbered_case(self):
        self.lock()
        rc, out = self.cli("evals", "new", "--title", "Join grain",
                           "--triggers", "join, sales",
                           "--what-wrong", "fanned out",
                           str(self.wd.root))
        self.assertEqual(rc, 0, out)
        case = self.wd.root / "evals" / "corrections" / "001" / "case.md"
        self.assertTrue(case.is_file(), out)
        body = case.read_text(encoding="utf-8")
        self.assertIn("Trigger keys:", body)
        self.assertIn("join", body)
        self.assertIn("## Deterministic check", body)

    def test_new_increments(self):
        self.lock()
        for title in ("First", "Second"):
            rc, out = self.cli("evals", "new", "--title", title,
                               "--triggers", "join", str(self.wd.root))
            self.assertEqual(rc, 0, out)
        self.assertTrue((self.wd.root / "evals" / "corrections" / "002" / "case.md").is_file())

    def test_new_rejects_empty_triggers(self):
        self.lock()
        rc, out = self.cli("evals", "new", "--title", "No triggers",
                           "--triggers", " , ", str(self.wd.root))
        self.assertNotEqual(rc, 0, out)

    def test_new_rejects_escaping_check_file(self):
        self.lock()
        rc, out = self.cli("evals", "new", "--title", "Escape",
                           "--triggers", "join",
                           "--check-file", "../secrets.env",
                           "--check-sha256", "0" * 64,
                           str(self.wd.root))
        self.assertNotEqual(rc, 0, out)

    def test_new_rejects_hash_without_file(self):
        self.lock()
        rc, out = self.cli("evals", "new", "--title", "Hash only",
                           "--triggers", "join",
                           "--check-sha256", "0" * 64,
                           str(self.wd.root))
        self.assertNotEqual(rc, 0, out)


class TestEvalsMatchRun(P9Setup):
    def write_bound_case(self, nnn="001", triggers="sales, conversion, join",
                         check=None, question=None):
        d = self.wd.root / "evals" / "corrections" / nnn
        d.mkdir(parents=True, exist_ok=True)
        body = ("# Correction 001\n\nwrong join grain doubled orders.\n\n"
                f"Trigger keys: {triggers}\n\nWhat was wrong: fanned out.\n\n")
        if check:
            body += f"## Deterministic check\n\nfile: outputs/summary.csv\nsha256: {check}\n"
        if question:
            body += f"\nReview question: {question}\n"
        (d / "case.md").write_text(body, encoding="utf-8")
        self.assertEqual(self.cli("approve", "correction", nnn, "--no-sign")[0], 0)
        self.assertEqual(self.cli("approved", "correction", nnn)[0], 0)

    def test_match_selects_binding_case(self):
        self.lock()
        self.write_bound_case()
        rc, out = self.cli("evals", "match", str(self.wd.root))
        self.assertEqual(rc, 0, out)
        self.assertIn("001", out)
        self.assertIn("bound", out.lower())

    def test_match_ignores_unrelated_case(self):
        self.lock()
        self.write_bound_case(triggers="unrelated-thing-xyz")
        rc, out = self.cli("evals", "match", str(self.wd.root))
        self.assertEqual(rc, 0, out)
        self.assertNotIn("001", out)

    def test_match_pattern_tags_section(self):
        self.write_spec(tags="timezone")
        self.lock()
        self.write_bound_case(triggers="timezone")
        rc, out = self.cli("evals", "match", str(self.wd.root))
        self.assertEqual(rc, 0, out)
        self.assertIn("001", out)

    def test_run_passes_on_correct_hash(self):
        import hashlib
        self.lock()
        self.register_and_run()
        blob = (self.wd.root / "outputs" / "summary.csv").read_bytes()
        self.write_bound_case(check=hashlib.sha256(blob).hexdigest())
        rc, out = self.cli("evals", "run", str(self.wd.root))
        self.assertEqual(rc, 0, out)
        self.assertIn("pass", out.lower())

    def test_run_fails_on_wrong_hash(self):
        self.lock()
        self.write_bound_case(check="0" * 64)
        rc, out = self.cli("evals", "run", str(self.wd.root))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("fail", out.lower())

    def test_run_unbound_failure_does_not_block(self):
        self.lock()
        d = self.wd.root / "evals" / "corrections" / "009"
        d.mkdir(parents=True, exist_ok=True)
        (d / "case.md").write_text(
            "# Draft\n\nTrigger keys: sales\n\n"
            "## Deterministic check\n\nfile: outputs/summary.csv\nsha256: " + "0" * 64 + "\n",
            encoding="utf-8")
        rc, out = self.cli("evals", "run", str(self.wd.root))
        self.assertEqual(rc, 0, f"unbound drafts are not binding: {out}")
        self.assertIn("unbound", out.lower())


class TestPacketMatchedOnly(P9Setup):
    def test_packet_carries_only_matched_questions(self):
        self.lock()
        base = self.wd.root / "evals" / "corrections"
        (base / "001").mkdir(parents=True, exist_ok=True)
        (base / "001" / "case.md").write_text(
            "# Matched\n\nTrigger keys: sales\n\nReview question: Did the grain fan out?\n",
            encoding="utf-8")
        self.assertEqual(self.cli("approve", "correction", "001", "--no-sign")[0], 0)
        self.assertEqual(self.cli("approved", "correction", "001")[0], 0)
        (base / "002").mkdir(parents=True, exist_ok=True)
        (base / "002" / "case.md").write_text(
            "# Unmatched\n\nTrigger keys: unrelated-thing-xyz\n\n"
            "Review question: This must never reach the goldfish.\n",
            encoding="utf-8")
        rc, out = self.cli("packet", "teardown", str(self.wd.root))
        self.assertEqual(rc, 0, out)
        from ddalib import review as _review
        pkt = _review.latest_packet(self.wd, "teardown")
        q = (Path(pkt["_dir"]) / ".analysis" / "eval-questions.md").read_bytes().decode("utf-8")
        self.assertIn("Did the grain fan out?", q)
        self.assertNotIn("must never reach the goldfish", q)


class TestPhase9Files(unittest.TestCase):
    def test_correction_case_template(self):
        tmpl = REPO / "templates" / "correction-case.md"
        self.assertTrue(tmpl.is_file(), "SPEC §12 template correction-case.md is missing")
        body = tmpl.read_text(encoding="utf-8")
        for needle in ("Trigger keys:", "## Deterministic check", "Review question:",
                       "What was wrong", "Source correction"):
            self.assertIn(needle, body, needle)

    def test_correct_skill(self):
        skill = REPO / "skills" / "correct" / "SKILL.md"
        self.assertTrue(skill.is_file(), "SPEC §12 `correct` skill is missing")
        body = skill.read_text(encoding="utf-8")
        self.assertIn("mechanical", body.lower())
        self.assertIn("evals match", body)


if __name__ == "__main__":
    unittest.main()
