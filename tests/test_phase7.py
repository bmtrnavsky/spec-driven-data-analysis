"""Phase 7 (SPEC section 14, item 7): goldfish packet + review run + gate G3.

G3: tier-scaled rounds recorded from dda review run calls (§5.0); at DECIDE,
a human spec approval for this spec hash (verified, or unverified and
disclosed); at PUBLISH, verified only (§4.5).
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

SPEC = """# Analysis spec

## Question
Did checkout v2 raise conversion?

## Decision it informs
Ship v2 or roll back.

## Tier
{tier}

## Rung
{rung}

## Audience
data team

## Population and time window
orders in May, UTC

## Data sources
{sources}

## Metrics
{metrics}

## Hypotheses
{hypotheses}

## Planned comparisons and cuts
v1 vs v2, by device.

## Method
Compare conversion rates.

## Exclusion and outlier rules
{exclusion}

## Reproduction tolerance
exact

## Thresholds that would change the decision
{thresholds}

## Known risks
seasonality

## Prior exposure
{exposure}

## Assumptions
stable traffic

## Out of scope
refunds
"""


class P7Setup(unittest.TestCase):
    TIER = "This is an EXPLORE analysis."
    RUNG = "quick-cut"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p7-"))
        os.environ["DDA_HOME"] = str(self.tmp / "home")
        self.raw = self.tmp / "raw"
        self.raw.mkdir()
        (self.raw / "orders.csv").write_text("id,amount\n1,10\n2,20\n", encoding="utf-8")
        from ddalib.layout import Workdir
        self.wd = Workdir.at(self.tmp / "wd")
        self.env = dict(os.environ)
        self.env["DDA_HOME"] = str(self.tmp / "home")
        self.env["PYTHONPATH"] = str(REPO / "scripts") + os.pathsep + self.env.get("PYTHONPATH", "")
        self.cli("init", str(self.wd.root))
        subprocess.run(["git", "init", "-q", str(self.wd.root)], check=True)
        subprocess.run(["git", "-C", str(self.wd.root), "config", "user.email", "t@t.t"])
        subprocess.run(["git", "-C", str(self.wd.root), "config", "user.name", "t"])
        self.wd.config_path.write_text(
            "version: 1\ndefault_tier: EXPLORE\ndata_roots:\n  sales:\n"
            f"    paths: [\"{self.raw.as_posix()}\"]\n    tool_patterns: [\"^mcp__warehouse__.*\"]\n"
            "publish_channels:\n  wordpress:\n    tool_patterns: [\"^mcp__wordpress__.*\"]\n",
            encoding="utf-8")
        (self.wd.definitions / "conversion.md").write_text(
            "---\nname: conversion\nversion: 1\n---\nOrders / sessions, daily grain, UTC.\n",
            encoding="utf-8")
        from ddalib import lockhash
        self.pin = lockhash.load_definition(self.wd, "conversion").pin
        self.write_spec()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_spec(self, tier=None, rung=None, sources="- `sales` — orders table",
                   metrics=None, hypotheses="v2 raises conversion by shortening checkout.",
                   exclusion="exclude staff orders.",
                   thresholds="a drop of 1pt kills v2.", exposure="none known"):
        if metrics is None:
            metrics = "- %s" % self.pin
        self.wd.spec_path.write_text(SPEC.format(
            tier=tier or self.TIER, rung=rung or self.RUNG, sources=sources,
            metrics=metrics, hypotheses=hypotheses, exclusion=exclusion,
            thresholds=thresholds, exposure=exposure), encoding="utf-8")

    def cli(self, *args, stub=None):
        import os as _os
        kw = dict(capture_output=True, text=True, env=dict(self.env))
        if stub:
            kw["env"]["DDA_GOLDFISH_STUB"] = stub
        if _os.path.isdir(str(self.wd.root)):
            kw["cwd"] = str(self.wd.root)
        p = subprocess.run([sys.executable, "-m", "ddalib.cli"] + list(args), **kw)
        return p.returncode, p.stdout + p.stderr


class TestPacket(P7Setup):
    def test_packet_builds_manifest_and_hash_dir(self):
        rc, out = self.cli("packet", "teardown")
        self.assertEqual(rc, 0, f"packet teardown failed: {out}")
        pkts = list((self.wd.analysis / "packets").glob("*/manifest.json"))
        self.assertEqual(len(pkts), 1, f"expected one packet, got {out}")
        import json
        man = json.loads(pkts[0].read_text(encoding="utf-8"))
        self.assertEqual(man["stage"], "teardown")
        self.assertTrue(man["packet_hash"])
        names = [f["path"] for f in man["files"]]
        self.assertIn(".analysis/spec.md", names)
        self.assertTrue(any(n.startswith("definitions/") for n in names))

    def test_packet_excludes_data_rows(self):
        rc, out = self.cli("packet", "teardown")
        self.assertEqual(rc, 0, out)
        blob = ""
        for p in (self.wd.analysis / "packets").rglob("*"):
            if p.is_file():
                blob += p.read_text(encoding="utf-8", errors="replace")
        self.assertNotIn("2,20", blob, "packet must carry no raw rows")

    def test_packet_cap_fails_with_file_list_and_sizes(self):
        cfg = self.wd.config_path.read_text(encoding="utf-8")
        self.wd.config_path.write_text(cfg + "\ngoldfish_max_tokens: 10\n", encoding="utf-8")
        rc, out = self.cli("packet", "teardown")
        self.assertNotEqual(rc, 0, "oversize packet must fail")
        self.assertIn("spec.md", out)
        self.assertRegex(out, r"\d+")

    def test_packet_post_result_requires_profile(self):
        rc, out = self.cli("packet", "post-result")
        self.assertNotEqual(rc, 0, f"post-result packet without profile must fail: {out}")
        (self.wd.analysis / "profile.md").write_text("snapshot: 2 rows\n", encoding="utf-8")
        (self.wd.analysis / "answer.md").write_text("## Provenance\n\n- **Lock hash:** none\n", encoding="utf-8")
        rc, out = self.cli("packet", "post-result")
        self.assertEqual(rc, 0, f"post-result packet with profile+draft failed: {out}")


class TestReviewRun(P7Setup):
    TIER = "This is a DECIDE analysis."
    RUNG = "glance"
    def test_run_records_empty_tools_and_hashes(self):
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        rc, out = self.cli("review", "run", "teardown", stub="pass")
        self.assertEqual(rc, 0, f"review run failed: {out}")
        import json
        recs = sorted((self.wd.analysis / "reviews" / "goldfish").glob("teardown-*.json"))
        self.assertTrue(recs, "review run must record calls")
        rec = json.loads(recs[0].read_text(encoding="utf-8"))
        self.assertEqual(rec["request"]["tools"], [], "goldfish request must carry no tools")
        user_files = " ".join(f["path"] for f in rec["request"]["user_files"])
        self.assertIn("spec.md", user_files)
        from ddalib import lockhash as _lh, review as _review
        manifest = _review.latest_packet(self.wd, "teardown")
        self.assertEqual(sorted(f["path"] for f in rec["request"]["user_files"]),
                         sorted(f["path"] for f in manifest["files"]),
                         "the request carries only the packet files — no chat, memory, or context")
        self.assertEqual(rec["brief_hash"], _lh.sha256_hex(rec["request"]["system"].encode()))
        self.assertEqual(rec["model"], "default")
        self.assertTrue((rec["provider_request_id"] or "").startswith("stub-"))
        runs = (self.wd.analysis / "runs.log").read_text(encoding="utf-8")
        self.assertIn('"type":"review"', runs)

    def test_reroll_is_counted_not_hidden(self):
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        self.write_spec(tier="This is a DECIDE analysis.", rung="glance")
        self.assertEqual(self.cli("review", "run", "teardown", stub="fail")[0], 1)
        self.assertEqual(self.cli("review", "run", "teardown", stub="pass")[0], 0)
        import json
        r1 = sorted((self.wd.analysis / "reviews" / "goldfish").glob("teardown-r1-*.json"))
        self.assertEqual(len(r1), 2, "every call is recorded, including the failed one")

    def test_second_failure_is_stop_and_ask(self):
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        self.assertEqual(self.cli("review", "run", "teardown", "--round", "1", stub="fail")[0], 1)
        rc, out = self.cli("review", "run", "teardown", "--round", "1", stub="fail")
        self.assertEqual(rc, 1)
        self.assertIn("stop-and-ask", out)

    def test_no_key_fails_closed(self):
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        rc, out = self.cli("review", "run", "teardown")
        self.assertNotEqual(rc, 0, "review run with no key and no stub must fail closed")
        self.assertIn("no provider key", out.lower())


class TestG3(P7Setup):
    def self_files(self, stage="teardown", rounds=("1", "3")):
        d = self.wd.analysis / "reviews" / "self"
        d.mkdir(parents=True, exist_ok=True)
        for r in rounds:
            (d / f"{stage}-round{r}.md").write_text(
                f"# self re-read round {r}\n\nChecked the spec cold. No objection.\n", encoding="utf-8")

    def test_g3_explore_self_rereads(self):
        rc, out = self.cli("gate", "G3")
        self.assertNotEqual(rc, 0, f"G3 passed with no review at all: {out}")
        self.self_files(rounds=("1",))
        rc, out = self.cli("gate", "G3")
        self.assertNotEqual(rc, 0, f"G3 passed with a missing round: {out}")
        self.self_files()
        rc, out = self.cli("gate", "G3")
        self.assertEqual(rc, 0, f"G3 failed EXPLORE self re-reads: {out}")

    def test_g3_decide_needs_human_spec_approval(self):
        self.write_spec(tier="This is a DECIDE analysis.", rung="glance")
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        rc, out = self.cli("review", "run", "teardown", stub="pass")
        self.assertEqual(rc, 0, out)
        rc, out = self.cli("gate", "G3")
        self.assertNotEqual(rc, 0, f"G3 passed DECIDE with no spec approval: {out}")
        self.assertIn("approv", out.lower())
        self.assertEqual(self.cli("approve", "spec", "--no-sign")[0], 0)
        self.assertEqual(self.cli("approved", "spec")[0], 0)
        rc, out = self.cli("gate", "G3")
        self.assertEqual(rc, 0, f"G3 failed DECIDE with goldfish + approval: {out}")
        self.assertIn("unverified", out.lower(), "unsigned approval must be disclosed, not hidden")

    def test_g3_publish_unverified_parks(self):
        self.write_spec(tier="This is a PUBLISH analysis.", rung="quick-cut")
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        rc, out = self.cli("review", "run", "teardown", stub="pass")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.cli("approve", "spec", "--no-sign")[0], 0)
        self.assertEqual(self.cli("approved", "spec")[0], 0)
        rc, out = self.cli("gate", "G3")
        self.assertNotEqual(rc, 0, f"G3 passed PUBLISH with only an unverified approval: {out}")

    def test_g3_earlier_objection_needs_answer(self):
        self.write_spec(tier="This is a DECIDE analysis.", rung="glance")
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        self.assertEqual(self.cli("review", "run", "teardown", stub="fail")[0], 1)
        self.assertEqual(self.cli("approve", "spec", "--no-sign")[0], 0)
        self.assertEqual(self.cli("approved", "spec")[0], 0)
        self.assertEqual(self.cli("review", "run", "teardown", stub="pass")[0], 0)
        rc, out = self.cli("gate", "G3")
        self.assertNotEqual(rc, 0, f"G3 passed with unanswered objections: {out}")
        import json
        recs = sorted((self.wd.analysis / "reviews" / "goldfish").glob("teardown-r1-*.json"))
        first = json.loads(recs[0].read_text(encoding="utf-8"))
        d = self.wd.analysis / "reviews" / "self"
        d.mkdir(parents=True, exist_ok=True)
        for rnd in ("1", "3"):
            old = sorted((self.wd.analysis / "reviews" / "goldfish").glob(f"teardown-r{rnd}-*.json"))[0]
            oid = json.loads(old.read_text(encoding="utf-8"))["provider_request_id"]
            (d / f"teardown-round{rnd}.md").write_text(
                f"# response round {rnd}\n\nAnswered {oid}: trimmed the cut as asked.\n", encoding="utf-8")
        self.assertIn("stub-", first["provider_request_id"])
        rc, out = self.cli("gate", "G3")
        self.assertEqual(rc, 0, f"G3 failed after objections answered + latest pass: {out}")


class TestFailClosed(P7Setup):
    TIER = "This is a DECIDE analysis."
    RUNG = "glance"
    def test_unbuilt_still_exit_3(self):
        for args in (("profile",), ("verify",), ("evals",), ("gate", "G7"), ("gate", "G5"), ("gate", "G2")):
            rc, _ = self.cli(*args)
            self.assertEqual(rc, 3, f"dda {' '.join(args)} must fail closed with exit 3")

    def test_review_round_cap(self):
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        self.assertEqual(self.cli("review", "run", "teardown", "--round", "1", stub="pass")[0], 0)
        self.assertEqual(self.cli("review", "run", "teardown", "--round", "1", stub="pass")[0], 0)
        rc, out = self.cli("review", "run", "teardown", "--round", "1", stub="pass")
        self.assertNotEqual(rc, 0, "third call for one round must be refused")
        self.assertIn("at most once", out)


class TestFooterReview(P7Setup):
    TIER = "This is a DECIDE analysis."
    RUNG = "glance"
    def test_footer_names_recorded_goldfish(self):
        self.assertEqual(self.cli("lock")[0], 0)
        from ddalib import footer as _footer
        stale = _footer.skeleton(self.wd)
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        self.assertEqual(self.cli("review", "run", "teardown", stub="pass")[0], 0)
        problems = _footer.check(self.wd, "# R\n\nbody\n\n" + stale)
        self.assertTrue(any("goldfish" in p for p in problems),
                        f"stale footer must not pass once goldfish rounds exist: {problems}")
        fixed = stale.replace("- **Review:**",
                              "- **Review:** goldfish teardown rounds 1,3 (req stub-0001, model default); ")
        self.assertEqual(_footer.check(self.wd, "# R\n\nbody\n\n" + fixed), [])


if __name__ == "__main__":
    unittest.main()
