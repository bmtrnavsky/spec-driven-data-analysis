"""The chat yes as a first-class record: fields, labels, footer, config (§4.5).

The chat yes is the whole model, so this file pins its observable surface:
who/when/words survive the round trip verbatim, `method_label` never dresses
up an absent yes, and the footer and `config_status` read the same record.
This file keeps its historical name (it used to test the Chat channel, now
deleted).

Run: DDA_TEST_MODE=1 python -m unittest tests.test_chat_approval
"""
import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from tests.test_approval_relay import ChatYesSetup, WHO, YES  # noqa: E402


class TestWordsSurvive(ChatYesSetup):
    def test_words_are_stored_verbatim(self):
        words = "yes — go ahead, but note the 3pt caveat (Feb data is thin) 🚢"
        rc, out = self.record(yes=words)
        self.assertEqual(rc, 0, out)
        rec = json.loads(self.record_file().read_text(encoding="utf-8"))
        self.assertEqual(rec["approval"]["yes"], words)
        self.assertEqual(self.verdict()["yes"], words)

    def test_surrounding_whitespace_is_trimmed_not_rewritten(self):
        rc, out = self.record(yes="  yes, ship it  \n")
        self.assertEqual(rc, 0, out)
        rec = json.loads(self.record_file().read_text(encoding="utf-8"))
        self.assertEqual(rec["approval"]["yes"], "yes, ship it")

    def test_note_is_kept_but_is_not_the_approval(self):
        rc, out = self.record("spec", "-m", "quoted from the thread")
        self.assertEqual(rc, 0, out)
        rec = json.loads(self.record_file().read_text(encoding="utf-8"))
        self.assertEqual(rec["note"], "quoted from the thread")
        self.assertEqual(rec["approval"]["yes"], YES)
        self.assertEqual(self.git("log", "-1", "--format=%s").strip(), "quoted from the thread")


class TestLegacyRecordsFailClosed(ChatYesSetup):
    """A record with no `approval` block is MALFORMED, never a chat yes (§4.5)."""

    def _write_legacy_record(self):
        from ddalib import approvals
        digest, payload = approvals.canonical_payload(self.wd, "spec")
        rel = f".analysis/approvals/spec-{digest[:16]}.json"
        path = self.wd.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "format": "dda-approval-v2", "kind": "spec", "digest": digest,
            "artifact": digest, "payload": payload,
            "created_at": "2026-11-01T09:00:00-0600",
            "approvers": [{"name": WHO}],
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        self.git("add", "--", rel)
        self.git("-c", "commit.gpgsign=false", "commit", "-q", "--no-verify",
                 "-m", "hand-written pre chat-yes record", "--", rel)
        return digest

    def test_legacy_record_is_malformed_not_recorded(self):
        from ddalib import approvals
        self._write_legacy_record()
        v = self.verdict()
        self.assertEqual(v["state"], "malformed", v)
        self.assertFalse(v["recorded"], v)
        self.assertEqual(approvals.method_label(v), "no chat yes on record for this content")

    def test_legacy_record_never_prints_as_a_chat_yes(self):
        self._write_legacy_record()
        rc, out = self.approved()
        self.assertIn("MALFORMED", out)
        self.assertNotIn("chat yes from", out)
        self.assertNotIn("RECORDED", out)
        self.assertIn("no chat yes on record", out)

    def test_legacy_record_does_not_satisfy_a_publish_gate(self):
        from ddalib import requirements
        self._write_legacy_record()
        ok, _notes, info = requirements.require(self.wd, "G2")
        self.assertFalse(ok)
        self.assertIn("malformed", [i.get("state") for i in info["items"]])

    def test_legacy_payload_is_not_executable(self):
        from ddalib import approvals
        from ddalib.layout import DdaError
        with self.assertRaises(DdaError):
            approvals.approved_payload(self.wd, "spec")


class TestLabels(unittest.TestCase):
    def test_method_label_names_the_yes(self):
        from ddalib import approvals
        self.assertEqual(
            approvals.method_label({"recorded": True, "who": WHO, "when": "2026-11-22"}),
            "chat yes from brad at 2026-11-22")

    def test_method_label_never_dresses_up_an_absence(self):
        from ddalib import approvals
        self.assertEqual(approvals.method_label({}),
                         "no chat yes on record for this content")
        self.assertEqual(approvals.method_label({"state": "missing", "recorded": False}),
                         "no chat yes on record for this content")

    def test_only_recorded_is_human(self):
        from ddalib import approvals
        self.assertTrue(approvals.is_human("recorded"))
        self.assertTrue(approvals.is_human(approvals.ApprovalState.RECORDED))
        for dead in ("verified", "confirmed", "unverified", "signed", "missing", "stale"):
            self.assertFalse(approvals.is_human(dead), dead)
        self.assertEqual(approvals.HUMAN_STATES, frozenset({"recorded"}))


class TestFooterAndConfig(ChatYesSetup):
    def test_footer_names_the_recorded_yes(self):
        from ddalib import approvals, footer
        from ddalib.layout import Workdir
        self.assertEqual(self.record()[0], 0)
        wd = Workdir.at(self.wd.root)
        self.assertEqual([v["kind"] for v in approvals.recorded_approvals(wd)], ["spec"])
        skel = footer.skeleton(wd)
        self.assertIn("chat yes on record — spec", skel)
        self.assertIn("chat yes from brad at", skel)
        self.assertNotIn("on record — none recorded", skel)

    def test_config_approval_reads_the_word_block(self):
        from ddalib import approvals
        from ddalib.layout import Workdir
        rc, out = self.record("config")
        self.assertEqual(rc, 0, out)
        st = approvals.config_status(Workdir.at(self.wd.root))
        self.assertEqual(st["state"], "recorded", st)
        self.assertIn("chat yes from brad at", st["detail"])
        self.assertEqual((st["who"], st["yes"]), (WHO, YES))

    def test_config_approval_is_not_inherited_by_a_config_edit(self):
        from ddalib import approvals
        from ddalib.layout import Workdir
        self.assertEqual(self.record("config")[0], 0)
        self.wd.config_path.write_text(
            self.wd.config_path.read_text(encoding="utf-8") + "\ndefault_rung: quick-cut\n",
            encoding="utf-8")
        st = approvals.config_status(Workdir.at(self.wd.root))
        self.assertEqual(st["state"], "missing", st)


if __name__ == "__main__":
    unittest.main()
