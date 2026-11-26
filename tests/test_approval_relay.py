"""The approval record, end to end: Brad's chat yes in, RECORDED out (§4.5).

The relay is deleted. There is no `dda_relay`, no Telegram/chat channel, no
signing passphrase, and no `--no-sign`: an approval IS the words Brad said,
recorded verbatim with who and when, committed as exactly one approval file,
and re-read by `dda approved`. This file keeps its historical name but
exercises the chat-yes path from the CLI through the gate.

Run: DDA_TEST_MODE=1 python -m unittest tests.test_approval_relay
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from tests.test_phase7 import P7Setup  # noqa: E402

YES = "yes — ship it, the numbers check out"
WHO = "brad"


class ChatYesSetup(P7Setup):
    """A PUBLISH workdir with one configured approver, locked and reviewed."""

    TIER = "This is a PUBLISH analysis."
    WHO = WHO

    def setUp(self):
        super().setUp()
        self.wd.config_path.write_text(
            self.wd.config_path.read_text(encoding="utf-8")
            + f"approvers:\n  - name: {self.WHO}\n",
            encoding="utf-8")
        rc, out = self.cli("lock")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        rc, out = self.cli("review", "run", "teardown", stub="pass")
        self.assertEqual(rc, 0, out)

    # --- actions -----------------------------------------------------
    def record(self, kind="spec", *extra, yes=YES, who=None, when=None):
        args = list(extra)
        if who is not None:
            args += ["--who", who]
        if when is not None:
            args += ["--when", when]
        return self.cli("approve", kind, "--yes", yes, *args)

    def approved(self, kind="spec", *extra):
        return self.cli("approved", kind, *extra)

    # --- reads -------------------------------------------------------
    def verdict(self, kind="spec", artifact=None):
        from ddalib import approvals
        from ddalib.layout import Workdir
        return approvals.verify_approval(Workdir.at(self.wd.root), kind, artifact)

    def record_file(self, kind="spec"):
        files = sorted((self.wd.analysis / "approvals").glob(f"{kind}-*.json"))
        self.assertTrue(files, f"no {kind} approval file was written")
        return files[-1]

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.wd.root), *args],
                              capture_output=True, text=True, check=True).stdout


class TestRecordWalks(ChatYesSetup):
    def test_recording_writes_one_committed_v3_record(self):
        rc, out = self.record()
        print("\n[approve] rc=%d\n%s" % (rc, out.strip()))
        self.assertEqual(rc, 0, out)
        self.assertIn("recorded spec", out)
        self.assertIn(f"chat yes from {WHO} at", out)
        self.assertIn(YES, out)

        path = self.record_file()
        rec = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(rec["format"], "dda-approval-v3")
        self.assertEqual(rec["kind"], "spec")
        self.assertEqual(rec["method"], "chat-yes")
        self.assertEqual(rec["approval"]["who"], WHO)
        self.assertEqual(rec["approval"]["yes"], YES)
        self.assertTrue(rec["approval"]["when"])
        self.assertTrue(rec["digest"])
        self.assertEqual(rec["digest"], rec["artifact"])
        # No channel, signature, or message id survives in the record.
        for gone in ("telegram", "chat", "keyid", "signature", "unsigned"):
            self.assertNotIn(gone, rec)
        # The commit adds exactly the one approval file.
        sha = self.git("rev-parse", "HEAD").strip()
        names = self.git("show", "--pretty=format:", "--name-status", sha).strip()
        rel = path.relative_to(self.wd.root).as_posix()
        self.assertEqual(names, f"A\t{rel}")
        msg = self.git("log", "-1", "--format=%s").strip()
        self.assertIn(f"chat yes from {WHO} at", msg)
        # Nothing was signed: the yes is the approval, not a key.
        self.assertEqual(self.git("log", "-1", "--format=%G?").strip(), "N")

    def test_approved_reports_the_recorded_yes(self):
        rc, out = self.record()
        self.assertEqual(rc, 0, out)
        rc, out = self.approved()
        print("\n[approved] rc=%d\n%s" % (rc, out.strip()))
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"spec [0-9a-f]{16}: RECORDED - chat yes from brad at \S+")
        self.assertIn(YES, out)
        v = self.verdict()
        self.assertEqual(v["state"], "recorded", v)
        self.assertTrue(v["recorded"], v)
        self.assertEqual(v["who"], WHO)
        self.assertEqual(v["yes"], YES)
        self.assertEqual(v["method"], "chat-yes")

    def test_approved_indexes_the_verdict(self):
        from ddalib import approvals
        from ddalib.layout import Workdir
        self.assertEqual(self.record()[0], 0)
        self.assertEqual(self.approved()[0], 0)
        rows = approvals.index_approvals(Workdir.at(self.wd.root), "spec")
        self.assertTrue(rows, "`dda approved` wrote no verdict to the index")
        row = rows[-1]
        self.assertEqual(row["state"], "recorded")
        self.assertTrue(row["recorded"])
        self.assertEqual((row["who"], row["yes"]), (WHO, YES))

    def test_recorded_yes_passes_the_publish_gate(self):
        self.assertEqual(self.record()[0], 0)
        rc, out = self.cli("gate", "G3")
        print("\n[gate G3 @PUBLISH] rc=%d\n%s" % (rc, out.strip()))
        self.assertEqual(rc, 0, f"G3 refused a recorded chat yes at PUBLISH: {out}")

    def test_requirements_table_accepts_recorded_at_publish(self):
        from ddalib import requirements
        from ddalib.layout import Workdir
        self.assertEqual(self.record()[0], 0)
        ok, notes, info = requirements.require(Workdir.at(self.wd.root), "G3")
        self.assertEqual(info["tier"], "PUBLISH")
        self.assertTrue(ok, notes)
        self.assertTrue(any("chat yes from brad" in n for n in notes), notes)


class TestNoYesNoApproval(ChatYesSetup):
    def test_no_record_is_missing_and_the_gate_refuses(self):
        rc, out = self.approved()
        print("\n[approved, nothing recorded] rc=%d\n%s" % (rc, out.strip()))
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"spec spec: MISSING - no chat yes on record")
        self.assertIn("dda approve spec --yes", out)
        self.assertEqual(self.verdict()["state"], "missing")
        rc, out = self.cli("gate", "G3")
        self.assertNotEqual(rc, 0, f"G3 passed PUBLISH with no recorded yes: {out}")

    def test_changing_content_needs_a_new_yes(self):
        self.assertEqual(self.record()[0], 0)
        self.assertEqual(self.cli("gate", "G3")[0], 0)
        old = json.loads(self.record_file().read_text(encoding="utf-8"))["digest"]
        # The state moves: the recorded yes covers the old spec, not this one.
        # A spec edit invalidates the lock, so the workdir is amended — the
        # approvals still have to be said again for the new content, which is
        # the point.
        self.write_spec(hypotheses="v2 raises conversion by 3 points.")
        self.assertEqual(self.cli("lock", "--amend", "hypothesis tightened")[0], 0)
        rc, out = self.approved()
        self.assertEqual(rc, 0, out)
        self.assertIn("MISSING", out)
        self.assertFalse(self.verdict()["recorded"])
        rc, out = self.cli("gate", "G3")
        self.assertNotEqual(rc, 0, f"G3 passed an approval of an older spec: {out}")
        # The old digest still reads as a record of the content it covered.
        self.assertEqual(self.verdict("spec", old)["state"], "stale")
        # A yes for the new content restores the gate (tier and spec both
        # cover the new spec, so both are said again).
        rc, out = self.record("tier", yes="yes, the tier still holds")
        self.assertEqual(rc, 0, out)
        rc, out = self.record(yes="yes, the 3pt hypothesis is right")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.verdict()["state"], "recorded")
        rc, out = self.cli("gate", "G3")
        print("\n[gate after re-approve] rc=%d\n%s" % (rc, out.strip()))
        self.assertEqual(rc, 0, out)

    def test_a_second_yes_for_the_same_digest_is_refused(self):
        self.assertEqual(self.record()[0], 0)
        rc, out = self.record(yes="yes again")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("already carries a recorded chat yes", out)
        self.assertIn(".analysis/approvals/spec-", out)


if __name__ == "__main__":
    unittest.main()
