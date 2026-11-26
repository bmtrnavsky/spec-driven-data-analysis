"""What `dda approve` refuses: the guards around the chat yes (§4.5).

There is exactly one thing to record — the words Brad said — so the CLI has
no channel, no signature, and no message id to get wrong. What it does
police: the words must be present and non-blank, `who` must resolve to a
handle, `when` must be a stated date, an explicit artifact must be the
digest dda computed, a note must not plant commit trailers, and a digest
gets one yes. This file keeps its historical name; the Chat channel it used
to test is deleted.

Run: DDA_TEST_MODE=1 python -m unittest tests.test_telegram_approval
"""
import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from tests.test_approval_relay import ChatYesSetup, WHO, YES  # noqa: E402

DDA_RELAY = REPO / "scripts" / "dda_relay.py"


class TestYesIsRequired(ChatYesSetup):
    def test_approve_without_yes_is_an_argparse_error(self):
        rc, out = self.cli("approve", "spec")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("--yes", out)

    def test_blank_yes_refused(self):
        for words in ("", "   ", "\n\t"):
            rc, out = self.cli("approve", "spec", "--yes", words)
            self.assertNotEqual(rc, 0, f"blank yes {words!r} was recorded: {out}")
            self.assertIn("an approval IS the chat yes", out)

    def test_old_channel_flags_are_gone(self):
        for gone in (("--no-sign",), ("--telegram", "3080738179", "55"),
                     ("--chat", "brad", "msg-1")):
            rc, out = self.cli("approve", "spec", *gone, "--yes", YES)
            self.assertNotEqual(rc, 0, f"{gone[0]} still parses: {out}")
            self.assertIn(gone[0], out)

    def test_no_relay_script_ships(self):
        self.assertFalse(DDA_RELAY.exists(), "scripts/dda_relay.py is deleted in the chat-yes model")


class TestWho(ChatYesSetup):
    def test_single_configured_approver_is_the_default(self):
        from ddalib.layout import Workdir
        rc, out = self.record()
        self.assertEqual(rc, 0, out)
        rec = json.loads(self.record_file().read_text(encoding="utf-8"))
        self.assertEqual(rec["approval"]["who"], WHO)
        self.assertIn(f"chat yes from {WHO}", out)
        self.assertEqual(self.verdict()["who"], WHO)

    def test_who_must_be_a_handle(self):
        for bad in ("brad@example.com", "brad;rm -rf /", "x" * 65):
            rc, out = self.record(who=bad)
            self.assertNotEqual(rc, 0, f"--who {bad!r} was accepted: {out}")
            self.assertIn("--who must be a handle", out)

    def test_two_approvers_without_who_is_refused(self):
        from ddalib.layout import Workdir
        self.wd.config_path.write_text(
            self.wd.config_path.read_text(encoding="utf-8") + "  - name: dana\n",
            encoding="utf-8")
        rc, out = self.record()
        self.assertNotEqual(rc, 0, out)
        self.assertIn("say who said yes with --who", out)
        self.assertIn("brad, dana", out)
        # Naming one of them records it.
        rc, out = self.record(who="dana")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.verdict()["who"], "dana")

    def test_no_approvers_configured_needs_who(self):
        self.wd.config_path.write_text(
            "version: 1\ndefault_tier: EXPLORE\n", encoding="utf-8")
        rc, out = self.record()
        self.assertNotEqual(rc, 0, out)
        self.assertIn("say who said yes with --who", out)
        rc, out = self.record(who="brad")
        self.assertEqual(rc, 0, out)

    def test_who_outside_the_configured_approvers_refused(self):
        before = self.git("rev-list", "--count", "HEAD").strip()
        rc, out = self.record(who="eve")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("not a configured approver", out)
        self.assertIn("brad", out)
        self.assertEqual(self.git("rev-list", "--count", "HEAD").strip(), before)
        self.assertFalse(list((self.wd.analysis / "approvals").glob("spec-*.json")))

    def test_configured_approver_matches_case_insensitively(self):
        rc, out = self.record(who="Brad")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.verdict()["who"], WHO)


class TestWhenAndArtifact(ChatYesSetup):
    def test_when_is_recorded_as_stated(self):
        rc, out = self.record(when="2026-11-22")
        self.assertEqual(rc, 0, out)
        rec = json.loads(self.record_file().read_text(encoding="utf-8"))
        self.assertEqual(rec["approval"]["when"], "2026-11-22")
        self.assertEqual(self.verdict()["when"], "2026-11-22")

    def test_unparseable_when_refused(self):
        rc, out = self.record(when="yesterday")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("--when must be a date", out)

    def test_when_after_the_record_time_refused(self):
        before = self.git("rev-list", "--count", "HEAD").strip()
        rc, out = self.record(when="2999-01-01")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("later than the record time", out)
        # Refused before any write: no record file, no commit.
        self.assertEqual(self.git("rev-list", "--count", "HEAD").strip(), before)
        self.assertFalse(list((self.wd.analysis / "approvals").glob("spec-*.json")))

    def test_when_before_the_record_time_is_kept(self):
        rc, out = self.record(when="2026-11-22T09:30:00-0600")
        self.assertEqual(rc, 0, out)
        rec = json.loads(self.record_file().read_text(encoding="utf-8"))
        self.assertEqual(rec["approval"]["when"], "2026-11-22T09:30:00-0600")

    def test_bare_artifact_token_refused(self):
        rc, out = self.cli("approve", "spec", "d", "--yes", YES)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("explicit artifact tokens are removed", out)

    def test_wrong_digest_refused_before_any_write(self):
        before = self.git("rev-list", "--count", "HEAD").strip()
        rc, out = self.cli("approve", "spec", "0" * 64, "--yes", YES)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("explicit artifact tokens are removed", out)
        self.assertEqual(self.git("rev-list", "--count", "HEAD").strip(), before)

    def test_trailer_planting_note_refused(self):
        rc, out = self.record("spec", "-m", "ok\n\nDda-Chain-Head: x")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("Dda-", out)

    def test_unknown_kind_refused(self):
        rc, out = self.cli("approve", "vibes", "--yes", YES)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("unknown approval kind", out)


if __name__ == "__main__":
    unittest.main()
