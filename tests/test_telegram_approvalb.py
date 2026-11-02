"""Telegram approval, part 2: config/labels + guard rails.

Split byte-for-byte out of tests/test_telegram_approval.py so the two halves
run on two parallel `fast` workers. Every test still runs in `fast` (new
tests/test_*.py files join automatically); nothing was deleted, skipped,
weakened, or moved to the certification tier. The shared _TgSetup harness
stays defined once in test_telegram_approval and is imported here.

Run: DDA_TEST_MODE=1 python -m unittest test_telegram_approvalb
"""
import json
import subprocess

from tests.test_telegram_approval import (  # noqa: E402 -- shared harness, single source
    _TgSetup, BRAD_TG, MSG_ID)


class TestTelegramConfigAndLabels(_TgSetup):
    def test_config_approval_confirmed_through_chain(self):
        from ddalib import approvals
        from ddalib.layout import Workdir
        rc, out = self.cli("approve", "config", "--telegram", BRAD_TG, MSG_ID)
        self.assertEqual(rc, 0, out)
        st = approvals.config_status(Workdir.at(self.wd.root))
        self.assertEqual(st["state"], "confirmed", st)
        self.assertIn(f"Telegram user {BRAD_TG}, message {MSG_ID}", st["detail"])

    def test_method_labels(self):
        from ddalib import approvals
        self.assertEqual(approvals.method_label({"method": "signed", "signer": "brad"}),
                         "signed by brad")
        self.assertEqual(approvals.method_label(
            {"method": "telegram", "telegram": {"user_id": BRAD_TG, "message_id": MSG_ID}}),
            f"Telegram user {BRAD_TG}, message {MSG_ID}")
        self.assertTrue(approvals.is_human("confirmed") and approvals.is_human("verified"))
        self.assertFalse(approvals.is_human("unverified"))


class TestTelegramGuards(_TgSetup):
    def test_unknown_telegram_user_rejected(self):
        rc, out = self.cli("approve", "spec", "--telegram", "1234567", MSG_ID)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("not a configured approver", out)

    def test_telegram_and_no_sign_are_exclusive(self):
        rc, out = self.cli("approve", "spec", "--telegram", BRAD_TG, MSG_ID, "--no-sign")
        self.assertNotEqual(rc, 0, out)

    def test_non_numeric_message_id_rejected(self):
        rc, out = self.cli("approve", "spec", "--telegram", BRAD_TG, "ok-brad")
        self.assertNotEqual(rc, 0, out)

    def test_hand_edited_telegram_record_without_trailers_fails(self):
        """A record claiming method=telegram but committed without the
        verbatim id trailers (not made by `dda approve --telegram`) is not
        CONFIRMED."""
        self.assertEqual(self.cli("approve", "spec", "--no-sign")[0], 0)
        f = sorted((self.wd.analysis / "approvals").glob("spec-*.json"))[0]
        rec = json.loads(f.read_text(encoding="utf-8"))
        subprocess.run(["git", "-C", str(self.wd.root), "rm", "-q", "--", str(f)], check=True)
        subprocess.run(["git", "-C", str(self.wd.root), "commit", "-q", "-m", "rm"], check=True)
        rec["method"] = "telegram"
        rec["telegram"] = {"user_id": BRAD_TG, "message_id": MSG_ID, "approver": "brad",
                           "confirmed_at": "2026-11-01T00:00:00-0600", "kind": "spec",
                           "digest": rec["digest"]}
        f.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.wd.root), "add", "--", str(f)], check=True)
        subprocess.run(["git", "-C", str(self.wd.root), "-c", "commit.gpgsign=false", "commit",
                        "-q", "-m", "forged"], check=True)
        v = self.verdict()
        self.assertNotIn(v["state"], ("confirmed", "verified"), v)
        rc, out = self.cli("gate", "G3")
        self.assertNotEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main()
