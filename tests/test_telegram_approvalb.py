"""The five approval states: RECORDED, MISSING, UNCOMMITTED, STALE, MALFORMED.

A recorded chat yes is the only human state (§4.5). Every other state is a
refusal to count something, and each one has a different fix: record a yes
(MISSING), commit the record (UNCOMMITTED), re-approve the current content
(STALE), or re-record a complete record (MALFORMED). This file keeps its
historical name; the Telegram channel it used to test is deleted.

Run: DDA_TEST_MODE=1 python -m unittest tests.test_telegram_approvalb
"""
import json
import subprocess
import sys
import unittest

from tests.test_approval_relay import ChatYesSetup, WHO, YES  # noqa: E402


class TestStates(ChatYesSetup):
    def _rec_path(self, kind="spec"):
        return self.record_file(kind)

    def test_missing_names_the_fix(self):
        from ddalib.layout import Workdir
        from ddalib import approvals
        v = approvals.verify_approval(Workdir.at(self.wd.root), "spec")
        self.assertEqual(v["state"], "missing", v)
        self.assertFalse(v["recorded"])
        self.assertIn('dda approve spec --yes "..."', v["reason"])

    def test_uncommitted_when_the_record_has_uncommitted_changes(self):
        self.assertEqual(self.record()[0], 0)
        p = self._rec_path()
        rec = json.loads(p.read_text(encoding="utf-8"))
        rec["note"] = "edited after the commit"
        p.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        v = self.verdict()
        self.assertEqual(v["state"], "uncommitted", v)
        self.assertIn("uncommitted changes", v["reason"])
        self.assertNotEqual(self.cli("gate", "G3")[0], 0)

    def test_malformed_when_the_record_has_no_words(self):
        # A record claiming a chat yes but carrying no verbatim words is not
        # an approval: it cannot be read back as one.
        self.assertEqual(self.record()[0], 0)
        p = self._rec_path()
        rel = p.relative_to(self.wd.root).as_posix()
        rec = json.loads(p.read_text(encoding="utf-8"))
        rec["approval"] = {"who": WHO, "when": rec["approval"]["when"]}
        self.git("rm", "-q", "--", rel)
        self.git("commit", "-q", "-m", "drop record")
        p.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.git("add", "--", rel)
        self.git("-c", "commit.gpgsign=false", "commit", "-q", "-m", "forged record", "--", rel)
        v = self.verdict()
        self.assertEqual(v["state"], "malformed", v)
        self.assertIn("no complete chat-yes record", v["reason"])
        self.assertNotEqual(self.cli("gate", "G3")[0], 0)

    def test_stale_when_the_record_covers_older_content(self):
        self.assertEqual(self.record()[0], 0)
        old = json.loads(self._rec_path().read_text(encoding="utf-8"))["digest"]
        self.write_spec(hypotheses="v2 raises conversion by 3 points.")
        v = self.verdict("spec", old)
        self.assertEqual(v["state"], "stale", v)
        self.assertIn("an approval of an older version does not cover this one", v["reason"])
        rc, out = self.approved("spec", old)
        self.assertEqual(rc, 0, out)
        self.assertIn("STALE", out)
        self.assertIn("no chat yes on record for this content", out)

    def test_forged_payload_is_stale_not_recorded(self):
        # Copying a digest onto different words does not make them approved:
        # the record's own payload must hash to the digest it claims.
        self.assertEqual(self.record()[0], 0)
        p = self._rec_path()
        rel = p.relative_to(self.wd.root).as_posix()
        rec = json.loads(p.read_text(encoding="utf-8"))
        rec["payload"] = rec["payload"] + "\nTarnish.\n"
        p.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.git("add", "--", rel)
        self.git("-c", "commit.gpgsign=false", "commit", "--amend", "-q", "--no-edit", "--", rel)
        v = self.verdict()
        self.assertEqual(v["state"], "stale", v)
        self.assertIn("does not hash to its approval digest", v["reason"])
        self.assertFalse(v["recorded"])


class TestIndexDoesNotFossilize(ChatYesSetup):
    def test_a_stale_row_in_the_index_does_not_render_as_approved(self):
        # The footer/index re-read the state; an approval that has gone stale
        # must not keep rendering as a live yes.
        from ddalib import approvals, footer
        from ddalib.layout import Workdir
        self.assertEqual(self.record()[0], 0)
        self.assertEqual(self.approved()[0], 0)
        self.assertEqual(approvals.index_approvals(Workdir.at(self.wd.root), "spec")[-1]["state"],
                         "recorded")
        self.write_spec(hypotheses="v2 raises conversion by 3 points.")
        self.assertEqual(approvals.recorded_approvals(Workdir.at(self.wd.root)), [])
        skel = footer.skeleton(Workdir.at(self.wd.root))
        self.assertNotIn("chat yes from brad", skel)
        self.assertIn("none recorded", skel)


if __name__ == "__main__":
    unittest.main()
