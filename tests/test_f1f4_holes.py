"""F1-F4 holes (final review): failing tests first, then the fix.

F1: G1 formula ban evaded by Unicode math operators
    (U+2212, U+00D7, U+00F7, U+FF1D, U+FF0F).
F2: gate_g1 scans only Metrics; formulas in Method / Planned comparisons
    (indeed anywhere in the spec body) pass silently.
F3: G2 health trigger misses patients/healthy/healthcare/clinical/
    hospital/disease/drug/treatment word-forms.
F4: profile-before-results unenforceable: analysis runs recorded before
    any profile still pass G7.

Run: DDA_TEST_MODE=1 python -m unittest tests.test_f1f4_holes
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
{rq}

## Decision it informs
{decision}

## Tier
{tier}

## Rung
quick-cut

## Audience
data team

## Population and time window
orders in May, UTC

## Data sources
- `sales` \u2014 orders table

## Metrics
{metrics}

## Hypotheses
v2 raises conversion by shortening checkout.

## Planned comparisons and cuts
{planned}

## Method
{method}

## Exclusion and outlier rules
exclude staff orders.

## Reproduction tolerance
exact

## Thresholds that would change the decision
a drop of 1pt kills v2.

## Known risks
seasonality

## Prior exposure
none known

## Assumptions
stable traffic

## Out of scope
refunds
"""


class Base(unittest.TestCase):
    TIER = "This is an EXPLORE analysis."
    DECISION = "none \u2014 EXPLORE"
    RQ = "Did checkout v2 raise conversion?"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-f1f4-"))
        os.environ["DDA_HOME"] = str(self.tmp / "home")
        os.environ["DDA_TEST_MODE"] = "1"
        self.raw = self.tmp / "raw"
        self.raw.mkdir()
        (self.raw / "orders.csv").write_text("id,amount\n1,10\n2,20\n", encoding="utf-8")
        from ddalib.layout import Workdir
        self.wd = Workdir.at(self.tmp / "wd")
        self.env = dict(os.environ)
        self.env["DDA_HOME"] = str(self.tmp / "home")
        self.env["DDA_TEST_MODE"] = "1"
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
        pin = lockhash.load_definition(self.wd, "conversion").pin
        self.h = pin.split("#")[1]
        self.pin = f"conversion@1#{self.h}"
        self.write_spec()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_spec(self, metrics=None, planned="v1 vs v2, by device.",
                   method="Compare conversion rates.", rq=None,
                   decision=None, tier=None):
        self.wd.spec_path.write_text(SPEC.format(
            rq=rq or self.RQ, decision=decision or self.DECISION,
            tier=tier or self.TIER,
            metrics=metrics if metrics is not None else f"- {self.pin}",
            planned=planned, method=method), encoding="utf-8")

    def cli(self, *args):
        kw = dict(capture_output=True, text=True, env=self.env)
        if os.path.isdir(str(self.wd.root)):
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
        self.assertEqual(rc, 0, "start failed: " + out)
        return out


class TestF1UnicodeFormulas(Base):
    """Each Unicode operator must fail G1 exactly like its ASCII twin."""

    def test_unicode_minus_u2212(self):
        self.write_spec(metrics=f"- {self.pin} (orders \u2212 refunds)")
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed U+2212 minus formula: {out}")

    def test_multiply_u00d7(self):
        self.write_spec(metrics=f"- {self.pin} (orders \u00d7 sessions)")
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed U+00D7 multiply formula: {out}")

    def test_divide_u00f7(self):
        self.write_spec(metrics=f"- {self.pin} (orders \u00f7 sessions)")
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed U+00F7 divide formula: {out}")

    def test_fullwidth_equals_uff1d(self):
        self.write_spec(metrics=f"- {self.pin} (lift \uff1d v2 \u2212 v1)")
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed fullwidth equals formula: {out}")

    def test_fullwidth_slash_uff0f(self):
        self.write_spec(metrics=f"- {self.pin} (orders \uff0f sessions)")
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed fullwidth slash formula: {out}")


class TestF2WholeSpecFormulas(Base):
    def test_formula_in_method_fails(self):
        self.write_spec(method="Compare conversion as orders / sessions across arms.")
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed a Method formula: {out}")
        self.assertIn("Method", out)

    def test_formula_in_planned_comparisons_fails(self):
        self.write_spec(planned="Compare lift = v2 minus v1, by device.")
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed a Planned-comparisons formula: {out}")

    def test_unicode_formula_in_method_fails(self):
        self.write_spec(method="Compare conversion as orders \u00f7 sessions.")
        rc, out = self.cli("gate", "G1")
        self.assertNotEqual(rc, 0, f"G1 passed a Unicode Method formula: {out}")


class TestF3HealthWordForms(Base):
    WORDS = ["patients", "healthy", "healthcare", "clinical",
             "hospital", "disease", "drug", "treatment"]

    def test_each_health_wordform_forces_decide(self):
        for w in self.WORDS:
            with self.subTest(word=w):
                self.write_spec(rq=f"Do {w} outcomes improve under v2?")
                rc, lock_out = self.cli("lock", str(self.wd.root))
                if rc != 0:
                    rc, lock_out = self.cli("lock", str(self.wd.root), "--amend",
                                            f"ask about {w}")
                self.assertEqual(rc, 0, f"lock failed for {w!r}: {lock_out}")
                rc, out = self.cli("gate", "G2")
                self.assertNotEqual(rc, 0, f"G2 passed EXPLORE with {w!r}: {out}")
                self.assertIn("decide", out.lower())


class TestF4ProfileBeforeResults(Base):
    SCRIPT = (
        "import csv, os\n"
        "root = {root!r}\n"
        "rows = list(csv.reader(open(os.path.join(root, 'orders.csv'))))\n"
        "n = len(rows) - 1\n"
        "os.makedirs('outputs', exist_ok=True)\n"
        "open('outputs/summary.csv', 'w').write('n,total\\n%d,%d\\n' % (n, sum(int(r[1]) for r in rows[1:])))\n"
        "print('rows=%d' % n)\n")

    def _baseline(self):
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

    def _run_first_variant(self):
        from ddalib import kernel
        self._baseline()
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

    def _self_rereads(self):
        d = self.wd.analysis / "reviews" / "self"
        d.mkdir(parents=True, exist_ok=True)
        for r in ("1", "2"):
            (d / f"post-result-round{r}.md").write_text(
                f"# self re-read round {r}\n\nChecked claims against outputs. No objection.\n",
                encoding="utf-8")

    def test_g7_fails_when_first_run_predates_profile(self):
        # The kernel refuses a run before any profile exists (§10.3), so
        # the only way results can predate the profile the verify replays
        # against is across an amendment: v1 results, then amend and
        # re-profile. G7 must fail, and a second amendment must not clear it.
        self.cli("lock", str(self.wd.root))
        self.assertEqual(self.cli("profile")[0], 0)
        self._run_first_variant()  # results under v1
        spec = self.wd.spec_path
        spec.write_text(spec.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        self.assertEqual(self.cli("lock", str(self.wd.root), "--amend", "whitespace")[0], 0)
        self.assertEqual(self.cli("profile")[0], 0)
        self.assertEqual(self.cli("verify")[0], 0)
        self._self_rereads()
        rc, out = self.cli("gate", "G7")
        self.assertNotEqual(rc, 0, f"G7 passed results that predate the profile: {out}")
        self.assertIn("profile", out.lower())

    def test_g7_passes_when_profile_comes_first(self):
        self.cli("lock", str(self.wd.root))
        self.assertEqual(self.cli("profile")[0], 0)
        self._run_first_variant()
        self.assertEqual(self.cli("verify")[0], 0)
        self._self_rereads()
        rc, out = self.cli("gate", "G7")
        self.assertEqual(rc, 0, f"G7 failed the lawful profile-first order: {out}")


if __name__ == "__main__":
    unittest.main()
