"""Regression: Telegram confirmation is a first-class human approval (§4.5).

Brad's call: at the desktop the key passphrase proves he was there; on
Telegram his signed-in account does. A `--telegram USER_ID MESSAGE_ID`
approval records state CONFIRMED and is accepted wherever a signed
(VERIFIED) approval is, PUBLISH included. A bare `--no-sign` approval stays
UNVERIFIED (the agent's own claim) and is still refused at PUBLISH.

Run: DDA_TEST_MODE=1 python -m unittest tests.test_telegram_approval
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from tests.test_phase7 import P7Setup  # noqa: E402

BRAD_TG = "8919091876"
MSG_ID = "8441"


class _TgSetup(P7Setup):
    TIER = "This is a PUBLISH analysis."

    def setUp(self):
        super().setUp()
        # An approver whose proof of presence is his Telegram account.
        self.wd.config_path.write_text(
            self.wd.config_path.read_text(encoding="utf-8")
            + f"approvers:\n  - name: brad\n    telegram_user_id: \"{BRAD_TG}\"\n",
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


class TestTelegramAcceptedAtPublish(_TgSetup):
    def test_telegram_confirmation_passes_publish_gate(self):
        rc, out = self.cli("approve", "spec", "--telegram", BRAD_TG, MSG_ID)
        print("\n[telegram approve] rc=%d\n%s" % (rc, out.strip()))
        self.assertEqual(rc, 0, out)
        self.assertIn(f"CONFIRMED via Telegram user {BRAD_TG}, message {MSG_ID}", out)
        rc, out = self.cli("approved", "spec")
        print("[telegram approved] rc=%d\n%s" % (rc, out.strip()))
        self.assertEqual(rc, 0, out)
        self.assertIn(f"CONFIRMED - Telegram user {BRAD_TG}, message {MSG_ID}", out)
        v = self.verdict()
        self.assertEqual(v["state"], "confirmed", v)
        self.assertTrue(v["verified"], v)
        self.assertEqual(v["signer"], "brad")
        rc, out = self.cli("gate", "G3")
        print("[telegram gate G3 @PUBLISH] rc=%d\n%s" % (rc, out.strip()))
        self.assertEqual(rc, 0, f"G3 refused a Telegram-confirmed approval at PUBLISH: {out}")

    def test_record_carries_ids_timestamp_kind_digest(self):
        self.assertEqual(self.cli("approve", "spec", "--telegram", BRAD_TG, MSG_ID)[0], 0)
        v = self.verdict()
        rel = sorted((self.wd.analysis / "approvals").glob("spec-*.json"))[0]
        rec = json.loads(rel.read_text(encoding="utf-8"))
        self.assertEqual(rec["method"], "telegram")
        tg = rec["telegram"]
        self.assertEqual((tg["user_id"], tg["message_id"]), (BRAD_TG, MSG_ID))
        self.assertEqual(tg["kind"], "spec")
        self.assertEqual(tg["digest"], v["digest"])
        self.assertTrue(tg["confirmed_at"])
        body = subprocess.run(["git", "-C", str(self.wd.root), "log", "-1", "--format=%B"],
                              capture_output=True, text=True).stdout
        self.assertIn(f"Dda-Telegram-Message: {MSG_ID}", body)
        self.assertIn(f"Dda-Telegram-User: {BRAD_TG}", body)
        # No passphrase on this path: the commit carries no signature.
        sig = subprocess.run(["git", "-C", str(self.wd.root), "log", "-1", "--format=%G?"],
                             capture_output=True, text=True).stdout.strip()
        self.assertEqual(sig, "N")

    def test_requirements_table_accepts_confirmed_at_publish(self):
        from ddalib import requirements
        from ddalib.layout import Workdir
        self.assertEqual(self.cli("approve", "spec", "--telegram", BRAD_TG, MSG_ID)[0], 0)
        ok, notes, info = requirements.require(Workdir.at(self.wd.root), "G3")
        self.assertEqual(info["tier"], "PUBLISH")
        self.assertTrue(ok, notes)


class TestNoSignStillRefusedAtPublish(_TgSetup):
    def test_no_sign_refused_at_same_gate(self):
        rc, out = self.cli("approve", "spec", "--no-sign")
        self.assertEqual(rc, 0, out)
        rc, out = self.cli("approved", "spec")
        print("\n[no-sign approved] rc=%d\n%s" % (rc, out.strip()))
        self.assertIn("UNVERIFIED - unsigned", out)
        self.assertEqual(self.verdict()["state"], "unverified")
        rc, out = self.cli("gate", "G3")
        print("[no-sign gate G3 @PUBLISH] rc=%d\n%s" % (rc, out.strip()))
        self.assertNotEqual(rc, 0, f"G3 passed PUBLISH with only an unsigned approval: {out}")
        self.assertIn("G3 fail: spec: commit", out)
        self.assertIn("is unsigned (agent could have produced it)", out)

    def test_requirements_table_refuses_unverified_at_publish(self):
        from ddalib import requirements
        from ddalib.layout import Workdir
        self.assertEqual(self.cli("approve", "spec", "--no-sign")[0], 0)
        ok, notes, _info = requirements.require(Workdir.at(self.wd.root), "G3")
        self.assertFalse(ok, notes)


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
