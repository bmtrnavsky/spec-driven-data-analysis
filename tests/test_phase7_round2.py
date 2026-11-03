"""Phase-7 hostile re-review: failing tests for the critical goldfish bypasses.

(P7-a, CRITICAL) goldfish review JSONs are not bound into the chain: a
forged `reviews/goldfish/*.json` with no matching `runs.log` entry passes
G3, and a deleted packet passes G3. G3 must cross-check every record
against runs.log and the packet manifest on disk.
(P7-b, HIGH) DDA_GOLDFISH_STUB is honored in production: anyone can fake
passing reviews. The stub must work only under an explicit test flag.
(P7-c, HIGH) governance JSONs (reviews/goldfish, packet manifests) trip
the extension scan, so committing reviews makes G9 unsatisfiable; exempt
or classify them so G9 can pass with reviews committed.
(P7-d, MED) the footer review field accepts one stray id or the word
"round"; every recorded round's request id must be named.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from ddalib import review as _review  # noqa: E402

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


class P7R2Setup(unittest.TestCase):
    TIER = "This is an EXPLORE analysis."
    RUNG = "quick-cut"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p7r2-"))
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

    def cli(self, *args, stub=None, env=None):
        import os as _os
        kw = dict(capture_output=True, text=True, env=dict(env if env is not None else self.env))
        if stub:
            kw["env"]["DDA_GOLDFISH_STUB"] = stub
        if _os.path.isdir(str(self.wd.root)):
            kw["cwd"] = str(self.wd.root)
        p = subprocess.run([sys.executable, "-m", "ddalib.cli"] + list(args), **kw)
        return p.returncode, p.stdout + p.stderr

    def hook(self, name, tool, args, session="s-1", event="pre_tool_call", **extra):
        import json as _json
        payload = {"hook_event_name": event, "tool_name": tool, "tool_input": args,
                   "session_id": session, "cwd": str(self.wd.root),
                   "extra": {"tool_call_id": "c-hb", **extra}}
        r = subprocess.run([sys.executable, "-I", "-S", str(REPO / "hooks" / "dda_hook.py"), name],
                           input=_json.dumps(payload), capture_output=True, text=True,
                           env=dict(self.env))
        return r.returncode, _json.loads(r.stdout)

    def bind(self, session="s-1"):
        rc, out = self.cli("start", str(self.wd.root), "--session", session)
        self.assertEqual(rc, 0, f"start failed: {out}")
        return out

    def stub_baseline(self):
        d = self.tmp / "stubs"
        d.mkdir(exist_ok=True)
        for name in ("pandas", "numpy", "pyarrow", "polars", "duckdb", "scipy",
                     "statsmodels", "sklearn", "matplotlib", "seaborn",
                     "openpyxl", "xlrd", "ipykernel", "IPython", "jupyter_client"):
            body = ("def get_ipython():\n    return None\n" if name in ("IPython", "jupyter_client")
                    else ("def connect(*a, **k):\n    raise RuntimeError('stub')\n" if name == "duckdb"
                          else '"""stub"""\n'))
            (d / f"{name}.py").write_text(body, encoding="utf-8")
        os.environ["DDA_BASELINE_DIR"] = str(d)
        self.env["DDA_BASELINE_DIR"] = str(d)

    def answer(self, text="# Answer\n\nConversion rose.\n"):
        (self.wd.analysis / "answer.md").write_text(text, encoding="utf-8")

    def self_rereads(self, stage="post-result", rounds=("1", "2")):
        d = self.wd.analysis / "reviews" / "self"
        d.mkdir(parents=True, exist_ok=True)
        for r in rounds:
            (d / f"{stage}-round{r}.md").write_text(
                f"# self re-read round {r}\n\nChecked claims against outputs. No objection.\n",
                encoding="utf-8")


class TestG3BindsChain(P7R2Setup):
    TIER = "This is a DECIDE analysis."
    RUNG = "glance"

    def _valid_flow(self):
        self.write_spec()
        self.assertEqual(self.cli("lock")[0], 0)
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        rc, out = self.cli("review", "run", "teardown", stub="pass")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.cli("approve", "spec", "--no-sign")[0], 0)
        self.assertEqual(self.cli("approved", "spec")[0], 0)
        rc, out = self.cli("gate", "G3")
        self.assertEqual(rc, 0, f"G3 failed a valid goldfish flow: {out}")

    def test_g3_fails_forged_goldfish_record(self):
        self._valid_flow()
        gdir = self.wd.analysis / "reviews" / "goldfish"
        src = sorted(gdir.glob("teardown-*.json"))[0]
        rec = json.loads(src.read_text(encoding="utf-8"))
        rec["provider_request_id"] = "forged-0001"
        rec["seq"] = 99
        (gdir / "teardown-r1-seq99.json").write_text(json.dumps(rec), encoding="utf-8")
        rc, out = self.cli("gate", "G3")
        self.assertNotEqual(rc, 0, f"G3 passed a forged goldfish record with no chain entry: {out}")

    def test_g3_fails_missing_packet(self):
        self._valid_flow()
        import shutil as _shutil
        for child in (self.wd.analysis / "packets").iterdir():
            _shutil.rmtree(child)
        rc, out = self.cli("gate", "G3")
        self.assertNotEqual(rc, 0, f"G3 passed with the packet deleted: {out}")


class TestStubGated(P7R2Setup):
    TIER = "This is a DECIDE analysis."
    RUNG = "glance"

    def test_stub_ignored_without_test_flag(self):
        self.assertEqual(self.cli("lock")[0], 0)
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        env = dict(self.env)
        env["DDA_GOLDFISH_STUB"] = "pass"
        env.pop("PYTEST_CURRENT_TEST", None)
        env.pop("DDA_TEST_MODE", None)
        env.pop("DDA_GOLDFISH_API_KEY", None)
        rc, out = self.cli("review", "run", "teardown", env=env)
        self.assertNotEqual(rc, 0, f"production review run honored the stub: {out}")

    def test_stub_honored_with_test_flag(self):
        self.assertEqual(self.cli("lock")[0], 0)
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        env = dict(self.env)
        env["DDA_GOLDFISH_STUB"] = "pass"
        env.pop("PYTEST_CURRENT_TEST", None)
        env["DDA_TEST_MODE"] = "1"
        rc, out = self.cli("review", "run", "teardown", env=env)
        self.assertEqual(rc, 0, f"review run failed under the test flag: {out}")


class TestGovernanceJsonCommittable(P7R2Setup):
    TIER = "This is a DECIDE analysis."
    RUNG = "glance"

    SCRIPT = (
        "import csv, os\n"
        "root = {root!r}\n"
        "rows = list(csv.reader(open(os.path.join(root, 'orders.csv'))))\n"
        "n = len(rows) - 1\n"
        "os.makedirs('outputs', exist_ok=True)\n"
        "open('outputs/summary.csv', 'w').write('n,total\\n%d,%d\\n' % (n, sum(int(r[1]) for r in rows[1:])))\n"
        "print('rows=%d' % n)\n")

    def test_g9_passes_with_reviews_and_packets_committed(self):
        from ddalib import kernel
        self.write_spec()
        self.assertEqual(self.cli("lock")[0], 0)
        # Lawful order: profile before results (G5/G7), teardown review (G3).
        self.assertEqual(self.cli("profile")[0], 0)
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        rc, out = self.cli("review", "run", "teardown", stub="pass")
        self.assertEqual(rc, 0, out)
        # Paired run session + heartbeat (G6), then verify the replay (G7).
        self.stub_baseline()
        self.bind("s-1")
        self.hook("runlog", "terminal", {"command": "dda meta sales"}, session="s-1",
                  event="pre_tool_call")
        self.hook("runlog", "terminal", {"command": "dda meta sales"}, session="s-1",
                  event="post_tool_call")
        kernel.register_variant(self.wd, "v1", why="baseline cut",
                                header={"population": "all", "model": "diff"})
        sp = self.wd.analysis / "variants" / "v1.py"
        sp.write_text(self.SCRIPT.format(root=self.raw.as_posix()), encoding="utf-8")
        rec = kernel.do_run(self.wd, "v1", str(sp), [], session="s-1")
        self.assertEqual(rec["returncode"], 0, rec.get("stderr_tail"))
        kernel.mark_locked(self.wd, "v1")
        self.assertEqual(self.cli("verify")[0], 0)
        # Approvals: spec covers the G2/G3 intermediates, config covers G4
        # (unsigned approvals are disclosed, not hidden, at DECIDE).
        self.assertEqual(self.cli("approve", "spec", "--no-sign")[0], 0)
        self.assertEqual(self.cli("approved", "spec")[0], 0)
        self.assertEqual(self.cli("approve", "config", "--no-sign")[0], 0)
        self.assertEqual(self.cli("approved", "config")[0], 0)
        # Post-result review + self re-reads (G7), then the report (G8).
        self.answer()
        self.assertEqual(self.cli("packet", "post-result")[0], 0)
        rc, out = self.cli("review", "run", "post-result", stub="pass")
        self.assertEqual(rc, 0, out)
        self.self_rereads()
        self.assertEqual(self.cli("report", "--slug", "good")[0], 0)
        subprocess.run(["git", "add", "-A"], cwd=str(self.wd.root), check=True)
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t.t",
                        "-c", "commit.gpgsign=false", "commit", "-q", "-m", "evidence"],
                       cwd=str(self.wd.root), check=True)
        rc, out = self.cli("gate", "G9")
        self.assertEqual(rc, 0, f"G9 failed with committed governance JSONs: {out}")


class TestFooterPerRoundIds(P7R2Setup):
    TIER = "This is a DECIDE analysis."
    RUNG = "glance"

    def test_footer_requires_every_round_id(self):
        self.assertEqual(self.cli("lock")[0], 0)
        from ddalib import footer as _footer
        self.assertEqual(self.cli("packet", "teardown")[0], 0)
        self.assertEqual(self.cli("review", "run", "teardown", stub="pass")[0], 0)
        recs = sorted((self.wd.analysis / "reviews" / "goldfish").glob("teardown-*.json"))
        ids = [json.loads(p.read_text(encoding="utf-8"))["provider_request_id"] for p in recs]
        self.assertGreaterEqual(len(ids), 2, "expected one id per round")
        skel = _footer.skeleton(self.wd)
        for rid in ids:
            self.assertIn(rid, skel, "fresh skeleton must name every recorded id")
        self.assertEqual(_footer.check(self.wd, "# R\n\nbody\n\n" + skel), [])
        partial = skel.replace(ids[1], "REDACTED")
        problems = _footer.check(self.wd, "# R\n\nbody\n\n" + partial)
        self.assertTrue(any(ids[1] in p for p in problems),
                        f"footer passed while round id {ids[1]} is unnamed: {problems}")


class TestEpochBrief(unittest.TestCase):
    # M2 epoch rounds (1@N) ask the same review questions as their base
    # round: `review run --round 1@2` must brief, not crash (KeyError).
    def test_brief_resolves_epoch_rounds(self):
        brief = _review.build_brief("teardown", ["1@2", "3@2"])
        self.assertIn("ROUND 1@2:", brief)
        self.assertIn("ROUND 3@2:", brief)
        self.assertIn(_review.TEARDOWN_ROUNDS["1"], brief)
        self.assertIn(_review.TEARDOWN_ROUNDS["3"], brief)

    def test_brief_still_resolves_base_rounds(self):
        brief = _review.build_brief("teardown", ["1", "3"])
        self.assertIn(_review.TEARDOWN_ROUNDS["1"], brief)


if __name__ == "__main__":
    unittest.main()
