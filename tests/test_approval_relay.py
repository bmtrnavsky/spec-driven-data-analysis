"""The approval relay: Brad's chat yes in, CONFIRMED record out (§4.5).

Exercises scripts/dda_relay.py end to end on test ids: unknown senders
are refused before anything is written, and a configured sender's ids come
back as a CONFIRMED record the `dda approved` walk accepts. Live ids from
Brad are never used here — the first live run is a supervised test on its
own fixture (see the run report), not this suite.

Run: DDA_TEST_MODE=1 python -m unittest tests.test_approval_relay
"""
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from tests.test_phase7 import P7Setup  # noqa: E402

RELAY = str(REPO / "scripts" / "dda_relay.py")
BRAD_TG = "3080738179"


class _RelaySetup(P7Setup):
    TIER = "This is a PUBLISH analysis."

    def setUp(self):
        super().setUp()
        self.wd.config_path.write_text(
            self.wd.config_path.read_text(encoding="utf-8")
            + f"approvers:\n  - name: brad\n    telegram_user_id: \"{BRAD_TG}\"\n",
            encoding="utf-8")
        rc, out = self.cli("lock")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        rc, out = self.cli("review", "run", "teardown", stub="pass")
        self.assertEqual(rc, 0, out)

    def relay(self, *args):
        env = dict(self.env)
        p = subprocess.run([sys.executable, RELAY] + list(args),
                           capture_output=True, text=True, env=env, cwd=str(self.wd.root))
        return p.returncode, p.stdout + p.stderr


class TestRelayRefusals(_RelaySetup):
    def test_unknown_sender_refused_before_any_write(self):
        before = subprocess.run(["git", "-C", str(self.wd.root), "rev-list", "--count", "HEAD"],
                                capture_output=True, text=True).stdout.strip()
        approvals_dir = self.wd.root / ".analysis" / "approvals"
        before_files = set(approvals_dir.iterdir()) if approvals_dir.is_dir() else set()
        rc, out = self.relay("relay", "--channel", "telegram",
                             "--user-id", "1234567", "--message-id", "99",
                             "--kind", "spec", str(self.wd.root))
        print("\n[relay refuse] rc=%d\n%s" % (rc, out.strip()))
        self.assertEqual(rc, 2, out)
        self.assertIn("not a configured approver", out)
        after = subprocess.run(["git", "-C", str(self.wd.root), "rev-list", "--count", "HEAD"],
                               capture_output=True, text=True).stdout.strip()
        self.assertEqual(before, after)  # no commit written
        after_files = set(approvals_dir.iterdir()) if approvals_dir.is_dir() else set()
        self.assertEqual(before_files, after_files)  # no approval file written

    def test_unknown_channel_refused(self):
        rc, out = self.relay("relay", "--channel", "smoke", "--user-id", BRAD_TG,
                             "--message-id", "99", "--kind", "spec", str(self.wd.root))
        self.assertEqual(rc, 2, out)

    def test_malformed_ids_refused(self):
        rc, out = self.relay("relay", "--channel", "telegram", "--user-id", BRAD_TG,
                             "--message-id", "not-a-number", "--kind", "spec", str(self.wd.root))
        self.assertNotEqual(rc, 0, out)

    def test_fetch_without_token_refuses(self):
        env = {k: v for k, v in os.environ.items() if k != "TELEGRAM_BOT_TOKEN"}
        env["DDA_HOME"] = str(self.tmp / "home")
        p = subprocess.run([sys.executable, RELAY, "fetch",
                            "--chat-id", "-5534695543", "--user-id", BRAD_TG],
                           capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("TELEGRAM_BOT_TOKEN is not set", p.stdout + p.stderr)


class TestRelayHappyPath(_RelaySetup):
    def test_test_ids_in_confirmed_record_out(self):
        rc, out = self.relay("relay", "--channel", "telegram",
                             "--user-id", BRAD_TG, "--message-id", "7000001",
                             "--kind", "spec", str(self.wd.root))
        print("\n[relay happy] rc=%d\n%s" % (rc, out.strip()))
        self.assertEqual(rc, 0, out)
        self.assertIn(f"CONFIRMED via telegram user {BRAD_TG}, message 7000001", out)
        self.assertIn("CONFIRMED - Telegram user 3080738179, message 7000001", out)
        rc, out = self.cli("approved", "spec")
        self.assertEqual(rc, 0, out)
        self.assertIn("CONFIRMED - Telegram user 3080738179, message 7000001", out)


if __name__ == "__main__":
    unittest.main()
