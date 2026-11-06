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

    def digest(self, kind="spec"):
        from ddalib import approvals
        from ddalib.layout import Workdir
        return approvals.current_digest(Workdir.at(self.wd.root), kind)


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
                             "--message-id", "not-a-number", "--digest", self.digest(),
                             "--kind", "spec", str(self.wd.root))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("numeric id", out)

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
                             "--digest", self.digest(),
                             "--kind", "spec", str(self.wd.root))
        print("\n[relay happy] rc=%d\n%s" % (rc, out.strip()))
        self.assertEqual(rc, 0, out)
        self.assertIn(f"CONFIRMED via telegram user {BRAD_TG}, message 7000001", out)
        self.assertIn("CONFIRMED - Telegram user 3080738179, message 7000001", out)
        rc, out = self.cli("approved", "spec")
        self.assertEqual(rc, 0, out)
        self.assertIn("CONFIRMED - Telegram user 3080738179, message 7000001", out)


class TestRelayPinsAndReplays(_RelaySetup):
    """Opus probe regressions: digest pin, replay, trailer, stale footer."""

    def test_digest_required(self):
        rc, out = self.relay("relay", "--channel", "telegram",
                             "--user-id", BRAD_TG, "--message-id", "7000011",
                             "--kind", "spec", str(self.wd.root))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("--digest", out)

    def test_digest_mismatch_refuses_before_any_write(self):
        before = subprocess.run(["git", "-C", str(self.wd.root), "rev-list", "--count", "HEAD"],
                                capture_output=True, text=True).stdout.strip()
        rc, out = self.relay("relay", "--channel", "telegram",
                             "--user-id", BRAD_TG, "--message-id", "7000012",
                             "--digest", "0" * 64,
                             "--kind", "spec", str(self.wd.root))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("state moved since", out)
        after = subprocess.run(["git", "-C", str(self.wd.root), "rev-list", "--count", "HEAD"],
                               capture_output=True, text=True).stdout.strip()
        self.assertEqual(before, after)

    def test_short_artifact_refused(self):
        # Probe-D2: a bare token where the digest goes does not write.
        rc, out = self.relay("relay", "--channel", "telegram",
                             "--user-id", BRAD_TG, "--message-id", "7000013",
                             "--digest", self.digest(), "--artifact", "d",
                             "--kind", "spec", str(self.wd.root))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("16+", out)

    def test_reused_message_id_refused(self):
        # Probe-B: the same message id cannot confirm twice — after the
        # state moves, relaying the old yes against the new digest fails.
        rc, out = self.relay("relay", "--channel", "telegram",
                             "--user-id", BRAD_TG, "--message-id", "7000055",
                             "--digest", self.digest(),
                             "--kind", "spec", str(self.wd.root))
        self.assertEqual(rc, 0, out)
        self.wd.spec_path.write_text(
            self.wd.spec_path.read_text(encoding="utf-8") + "\nextra line\n", encoding="utf-8")
        rc, out = self.relay("relay", "--channel", "telegram",
                             "--user-id", BRAD_TG, "--message-id", "7000055",
                             "--digest", self.digest(),
                             "--kind", "spec", str(self.wd.root))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("already confirms", out)

    def test_replayed_record_reads_bad_sig(self):
        # Probe-B shape, hand-made: the same message id committed against
        # a different digest verifies BAD_SIG, not CONFIRMED.
        import json
        from ddalib import approvals
        from ddalib.layout import Workdir
        wd = Workdir.at(self.wd.root)
        rc, out = self.relay("relay", "--channel", "telegram",
                             "--user-id", BRAD_TG, "--message-id", "7000077",
                             "--digest", self.digest(),
                             "--kind", "spec", str(self.wd.root))
        self.assertEqual(rc, 0, out)
        self.wd.spec_path.write_text(
            self.wd.spec_path.read_text(encoding="utf-8") + "\nTarnish.\n", encoding="utf-8")
        d2, payload2 = approvals.canonical_payload(wd, "spec")
        f = sorted((self.wd.analysis / "approvals").glob("spec-*.json"))[0]
        rec = json.loads(f.read_text(encoding="utf-8"))
        rec["digest"] = d2
        rec["payload"] = payload2
        rec["telegram"]["digest"] = d2
        g = self.wd.analysis / "approvals" / f"spec-{d2[:16]}.json"
        g.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.wd.root), "add", "--", str(g)], check=True)
        subprocess.run(["git", "-C", str(self.wd.root), "-c", "commit.gpgsign=false", "commit",
                        "-q", "-m", "re-confirm spec",
                        "-m", "Dda-Approval-Method: telegram",
                        "-m", f"Dda-Telegram-User: {BRAD_TG}",
                        "-m", "Dda-Telegram-Message: 7000077"], check=True)
        v = approvals.verify_approval(wd, "spec")
        self.assertEqual(v["state"], "bad_sig", v)
        self.assertIn("already confirms", v["reason"])

    def test_trailer_planting_note_refused(self):
        # Probe-F: a note smuggling a Dda- trailer never reaches a commit.
        rc, out = self.relay("relay", "--channel", "telegram",
                             "--user-id", BRAD_TG, "--message-id", "7000088",
                             "--digest", self.digest(), "-m", "ok\n\nDda-Chain-Head: x",
                             "--kind", "spec", str(self.wd.root))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("Dda-", out)

    def test_stale_confirmation_renders_no_channel(self):
        # Probe-E: after the state moves, no live CONFIRMED approval
        # remains, so the footer names no channel.
        from ddalib import approvals
        from ddalib.layout import Workdir
        wd = Workdir.at(self.wd.root)
        rc, out = self.relay("relay", "--channel", "telegram",
                             "--user-id", BRAD_TG, "--message-id", "7000099",
                             "--digest", self.digest(),
                             "--kind", "spec", str(self.wd.root))
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.cli("approved", "spec")[0], 0)
        self.assertEqual(approvals.confirmed_channels(wd), ["Telegram"])
        self.wd.spec_path.write_text(
            self.wd.spec_path.read_text(encoding="utf-8") + "\nTarnish.\n", encoding="utf-8")
        self.assertEqual(approvals.confirmed_channels(wd), [])
        v = approvals.verify_approval(wd, "spec")
        self.assertNotEqual(v["state"], "confirmed", v)
        from ddalib import footer
        self.assertNotIn("confirmed (Telegram)", footer.skeleton(wd))


if __name__ == "__main__":
    unittest.main()
