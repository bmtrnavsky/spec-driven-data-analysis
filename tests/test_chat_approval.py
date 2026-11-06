"""Chat confirmation is a first-class human approval (§4.5).

Mirrors tests/test_telegram_approval.py on the second CONFIRMED channel: a
regular-chat yes from Brad's sender id records state CONFIRMED and is
accepted wherever a signed (VERIFIED) approval is, PUBLISH included. The
user id must exactly equal an approver's `chat_user_id`; chat ids are
platform tokens (not Telegram numerics) and are kept verbatim for audit.

Run: DDA_TEST_MODE=1 python -m unittest tests.test_chat_approval
"""
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from tests.test_phase7 import P7Setup  # noqa: E402

BRAD_CHAT = "brad"
CHAT_MSG = "msg-2026-11-06-yes-1"


class _ChatSetup(P7Setup):
    TIER = "This is a PUBLISH analysis."

    def setUp(self):
        super().setUp()
        self.wd.config_path.write_text(
            self.wd.config_path.read_text(encoding="utf-8")
            + "approvers:\n  - name: brad\n    chat_user_id: \"brad\"\n",
            encoding="utf-8")
        rc, out = self.cli("lock")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        rc, out = self.cli("review", "run", "teardown", stub="pass")
        self.assertEqual(rc, 0, out)

    def verdict(self, kind="spec"):
        from ddalib import approvals
        from ddalib.layout import Workdir
        return approvals.verify_approval(Workdir.at(self.wd.root), kind)


class TestChatAcceptedAtPublish(_ChatSetup):
    def test_chat_confirmation_passes_publish_gate(self):
        rc, out = self.cli("approve", "spec", "--chat", BRAD_CHAT, CHAT_MSG)
        print("\n[chat approve] rc=%d\n%s" % (rc, out.strip()))
        self.assertEqual(rc, 0, out)
        self.assertIn(f"CONFIRMED via Chat user {BRAD_CHAT}, message {CHAT_MSG}", out)
        rc, out = self.cli("approved", "spec")
        print("[chat approved] rc=%d\n%s" % (rc, out.strip()))
        self.assertEqual(rc, 0, out)
        self.assertIn(f"CONFIRMED - Chat user {BRAD_CHAT}, message {CHAT_MSG}", out)
        v = self.verdict()
        self.assertEqual(v["state"], "confirmed", v)
        self.assertTrue(v["verified"], v)
        self.assertEqual(v["method"], "chat", v)

    def test_footer_names_the_chat_channel(self):
        from ddalib import approvals, footer
        from ddalib.layout import Workdir
        rc, out = self.cli("approve", "spec", "--chat", BRAD_CHAT, CHAT_MSG)
        self.assertEqual(rc, 0, out)
        rc, out = self.cli("approved", "spec")
        self.assertEqual(rc, 0, out)
        wd = Workdir.at(self.wd.root)
        self.assertEqual(approvals.confirmed_channels(wd), ["Chat"])
        skel = footer.skeleton(wd)
        self.assertIn("confirmed (Chat)", skel)


class TestChatConfigAndLabels(_ChatSetup):
    def test_config_approval_confirmed_through_chain(self):
        from ddalib import approvals
        from ddalib.layout import Workdir
        rc, out = self.cli("approve", "config", "--chat", BRAD_CHAT, CHAT_MSG)
        self.assertEqual(rc, 0, out)
        st = approvals.config_status(Workdir.at(self.wd.root))
        self.assertEqual(st["state"], "confirmed", st)
        self.assertIn(f"Chat user {BRAD_CHAT}, message {CHAT_MSG}", st["detail"])

    def test_method_labels(self):
        from ddalib import approvals
        self.assertEqual(approvals.method_label(
            {"method": "chat", "chat": {"user_id": BRAD_CHAT, "message_id": CHAT_MSG}}),
            f"Chat user {BRAD_CHAT}, message {CHAT_MSG}")
        self.assertEqual(approvals.chat_approver([{"name": "brad", "chat_user_id": "brad"}],
                                                 "brad"), "brad")
        self.assertIsNone(approvals.chat_approver([{"name": "brad", "chat_user_id": "brad"}],
                                                  "someone-else"))
        self.assertTrue(approvals.is_human("confirmed") and approvals.is_human("verified"))
        self.assertFalse(approvals.is_human("unverified"))


class TestChatGuards(_ChatSetup):
    def test_unknown_chat_user_rejected(self):
        rc, out = self.cli("approve", "spec", "--chat", "mallory", CHAT_MSG)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("not a configured approver", out)

    def test_chat_and_no_sign_are_exclusive(self):
        rc, out = self.cli("approve", "spec", "--chat", BRAD_CHAT, CHAT_MSG, "--no-sign")
        self.assertNotEqual(rc, 0, out)

    def test_chat_and_telegram_are_exclusive(self):
        rc, out = self.cli("approve", "spec", "--chat", BRAD_CHAT, CHAT_MSG,
                           "--telegram", "3080738179", "11203")
        self.assertNotEqual(rc, 0, out)

    def test_blank_message_id_rejected(self):
        rc, out = self.cli("approve", "spec", "--chat", BRAD_CHAT, "has space")
        self.assertNotEqual(rc, 0, out)

    def test_telegram_user_id_does_not_match_chat(self):
        # Brad's Telegram id must not authenticate the chat channel: the
        # channels check different config keys.
        rc, out = self.cli("approve", "spec", "--chat", "3080738179", "11203")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("not a configured approver", out)


if __name__ == "__main__":
    unittest.main()
