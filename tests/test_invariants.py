"""Metamorphic invariant harness: the acceptance bar for the N1/N2 fixes.

Every fixture starts in a FAILING or EXPOSED state. Each cosmetic mutation
class is applied to a fresh fork of the fixture, and the harness asserts
MONOTONICITY against the pre-mutation snapshot:

  1. no gate that failed now passes;
  2. no sticky lineage label disappears (results_seen_before_profile,
     goldfish_mode, degraded-once-true);
  3. approvals only ever move toward invalid; an approval invalidated by a
     content change reports STALE (spec across amend, signoff across a
     report edit);
  4. the DAG holds: a later gate passing implies every earlier gate passes.

Mutation classes (applied to every fixture):
  cosmetic_amend, reprofile, rerun, rename_artifact, delete_artifact,
  touch_mtimes, unset_key, sibling_variant, edit_report, plus the git
  operations exercised by the probe suite: git_clean, git_stash_u,
  git_reset_hard, git_rebase, git_commit_amend, git_filter_branch,
  git_update_ref (see tests/probes/ — each is a real git op whose
  expected finding the regression test asserts).

Fixtures:
  TestInvEvalBinding    N1: bound correction case with a failing check.
  TestInvGoldfishHistory  N2: teardown review with two failed rounds.
  TestInvStickyExposure  sticky results_seen_before_profile exposure.

Plus TestDdaprobeRegression: every tests/probes/p_*.py / n_*.py probe
re-run as a regression test. Each probe declares EXPECTED and prints
`FINDING: <token>`; the test asserts the probe exits 0 AND prints its
expected finding — a bypass that silently succeeds prints a different
finding and fails the suite (exit-code-only assertions were blind to
N1/N2-class bypasses, which exit 0 while laundering evidence).

Run: DDA_TEST_MODE=1 python -m unittest tests.test_invariants
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

from tests.test_phase8 import P8Setup  # noqa: E402
from tests.test_phase9 import P9Setup  # noqa: E402

ORDER = ["G0", "G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8", "G9"]
STICKY_TRUE = ("results_seen_before_profile", "goldfish_mode")
INVALID_STATES = {"stale", "missing", "uncommitted", "bad_sig",
                  "unknown_signer", "downgraded"}
PASSING_STATES = {"verified", "unverified"}

MUTATIONS = ["cosmetic_amend", "reprofile", "rerun", "rename_artifact",
             "delete_artifact", "touch_mtimes", "unset_key",
             "sibling_variant", "edit_report"]


def recorded_artifacts(wd):
    """(kind, artifact) pairs from committed approval filenames.

    Querying by the RECORDED artifact is the path on which an approval
    invalidated by a content change reports STALE (same call the G9
    allowlist and stage8 binding make). Querying by current digest
    instead answers a different question ("is anything approved for
    THESE bytes?") and reports MISSING after a change.
    """
    out = []
    adir = wd.analysis / "approvals"
    if adir.is_dir():
        for p in sorted(adir.glob("*.json")):
            if p.name == "approvals.index.jsonl":
                continue
            kind, _, artifact = p.name[:-len(".json")].partition("-")
            if kind in ("spec", "signoff", "correction", "amendment",
                        "tier", "definition", "config"):
                out.append((kind, artifact or None))
    return out


def snapshot(fx):
    """Fork-local pre/post state: gates, lineage flags, approvals, evals."""
    from ddalib import evaluate, lineage, approvals, stage8
    res = evaluate.evaluate(fx.wd)
    gates = {g: bool(res["verdicts"][g][0]) for g in ORDER}
    lin = lineage.lineage(fx.wd)
    appr = {}
    for kind, artifact in recorded_artifacts(fx.wd):
        if kind not in fx.tracked_kinds():
            continue
        try:
            v = approvals.verify_approval(fx.wd, kind, artifact)
            appr[(kind, artifact)] = str(v.get("state"))
        except Exception as exc:  # fail-closed: record, never crash the harness
            appr[(kind, artifact)] = f"error:{exc}"
    try:
        matched = stage8.match_evals(fx.wd)
        bound = sorted(m["case"] for m in matched if m.get("bound"))
    except Exception:
        matched, bound = [], []
    try:
        from ddalib import evals as _evals
        evals_ok = bool(_evals.do_run(fx.wd)["ok"])
    except Exception:
        evals_ok = None
    return {"gates": gates,
            "lineage": {k: lin.get(k) for k in
                        ("results_seen_before_profile", "goldfish_mode", "degraded")},
            "approvals": appr, "bound": bound, "evals_ok": evals_ok}


class InvMixin:
    # -- fixture plumbing: baseline built once, forked per test ------------
    @classmethod
    def build_baseline(cls, inst):
        raise NotImplementedError

    def tracked_kinds(self):
        return ["correction", "spec", "signoff"]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        os.environ["DDA_TEST_MODE"] = "1"
        inst = cls()
        P8Setup.setUp(inst)  # real fixture setUp, not the fork setUp below
        inst.env["DDA_TEST_MODE"] = "1"
        os.environ["DDA_HOME"] = inst.env["DDA_HOME"]
        cls.build_baseline(inst)
        cls._baseline = inst

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._baseline.tmp, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        base = type(self)._baseline
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-inv-"))
        for child in base.tmp.iterdir():
            dest = self.tmp / child.name
            if child.is_dir():
                shutil.copytree(child, dest, symlinks=True)
            else:
                shutil.copy2(child, dest)
        self.raw = self.tmp / "raw"
        from ddalib.layout import Workdir
        self.wd = Workdir.at(self.tmp / "wd")
        self.env = dict(base.env)
        self.env["DDA_HOME"] = str(self.tmp / "home")
        self.env["DDA_TEST_MODE"] = "1"
        if "DDA_BASELINE_DIR" in base.env:
            self.env["DDA_BASELINE_DIR"] = str(self.tmp / "stubs")
        # The chain heads mirror is keyed by workdir path hash, so a copied
        # workdir needs its own mirror entries (same heads: identical chains).
        from ddalib.layout import workdir_id
        base_key = workdir_id(base.wd.root)
        fork_key = workdir_id(self.wd.root)
        heads = Path(self.env["DDA_HOME"]) / "heads"
        if heads.is_dir():
            for p in list(heads.iterdir()):
                if p.name.startswith(base_key + "."):
                    shutil.copy2(p, heads / (fork_key + p.name[len(base_key):]))
        os.environ["DDA_TEST_MODE"] = "1"
        os.environ["DDA_HOME"] = self.env["DDA_HOME"]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- shared helpers ----------------------------------------------------
    def answer_and_signoff(self):
        (self.wd.analysis / "answer.md").write_text(
            "# Answer\n\nConversion rose.\n", encoding="utf-8")
        rc, out = self.cli("approve", "spec", "--no-sign")
        self.assertEqual(rc, 0, "approve spec failed: " + out)
        rc, out = self.cli("approved", "spec")
        self.assertEqual(rc, 0, "approved spec failed: " + out)
        rc, out = self.cli("approve", "signoff", "--no-sign")
        self.assertEqual(rc, 0, "approve signoff failed: " + out)
        rc, out = self.cli("approved", "signoff")
        self.assertEqual(rc, 0, "approved signoff failed: " + out)

    # -- mutations ----------------------------------------------------------
    def mut_cosmetic_amend(self):
        spec = self.wd.spec_path.read_text(encoding="utf-8")
        # Toggle a punctuation mark (F-sticky's baseline already amended once).
        if "Compare conversion rates." in spec:
            new = spec.replace("Compare conversion rates.", "Compare conversion rates!")
        else:
            self.assertIn("Compare conversion rates!", spec)
            new = spec.replace("Compare conversion rates!", "Compare conversion rates?")
        self.wd.spec_path.write_text(new, encoding="utf-8")
        rc, out = self.cli("lock", "--amend", "cosmetic punctuation")
        self.assertEqual(rc, 0, "amend failed: " + out)

    def mut_reprofile(self):
        rc, out = self.cli("profile")
        self.assertEqual(rc, 0, "re-profile failed: " + out)

    def mut_rerun(self):
        vpy = list((self.wd.analysis / "variants").glob("v1.py")) \
            if (self.wd.analysis / "variants").is_dir() else []
        if vpy:
            from ddalib import kernel
            # Fresh session: the fork copies the baseline binding (s-1 points
            # at the baseline path), so re-running binds its own session.
            self.bind("s-2")
            self.hook("runlog", "terminal", {"command": "dda meta sales"},
                      session="s-2", event="pre_tool_call")
            self.hook("runlog", "terminal", {"command": "dda meta sales"},
                      session="s-2", event="post_tool_call")
            rec = kernel.do_run(self.wd, "v1", str(vpy[0]), [], session="s-2")
            self.assertEqual(rec["returncode"], 0, rec.get("stderr_tail"))
        else:  # no data variant: re-run a failed review round instead
            rc, out = self.cli("review", "run", "teardown",
                               "--round", "1", stub="fail")
            # Either the re-run records another failure, or the lineage-wide
            # cap refuses it. Both are fail-closed; recovery is what is banned.
            self._rerun_rc = rc

    def mut_rename_artifact(self):
        target = self.rename_target()
        bak = target.parent / (target.name + ".bak")
        target.rename(bak)
        self.assertFalse(target.exists())

    def mut_delete_artifact(self):
        target = self.delete_target()
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink()
        self.assertFalse(target.exists())

    def mut_touch_mtimes(self):
        import time
        now = time.time() + 3600
        for p in sorted(self.wd.root.rglob("*")):
            if p.is_file() and ".git/" not in p.as_posix():
                try:
                    os.utime(p, (now, now))
                except OSError:
                    pass

    def mut_unset_key(self):
        env = {k: v for k, v in self.env.items()
               if "KEY" not in k.upper() and "TOKEN" not in k.upper()}
        env.pop("DDA_GOLDFISH_STUB", None)
        rc, out = self.cli("review", "run", "teardown", env=env)
        self.assertNotEqual(rc, 0, "review run without key/stub must refuse: " + out)

    def mut_sibling_variant(self):
        from tests.test_phase8 import SCRIPT
        from ddalib import kernel
        self.stub_baseline()
        kernel.register_variant(self.wd, "v2sib", why="sibling cut",
                                header={"population": "all", "model": "diff"})
        sp = self.wd.analysis / "variants" / "v2sib.py"
        sp.write_text(SCRIPT.format(root=self.raw.as_posix()), encoding="utf-8")
        kernel.mark_locked(self.wd, "v2sib")

    def mut_edit_report(self):
        ans = self.wd.analysis / "answer.md"
        ans.write_text(ans.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    # -- per-fixture targets -------------------------------------------------
    def rename_target(self):
        raise NotImplementedError

    def delete_target(self):
        raise NotImplementedError

    def check_delete_caught(self, before, after):
        raise NotImplementedError

    # -- assertions ----------------------------------------------------------
    def assert_monotone(self, before, after, step):
        for g in ORDER:
            self.assertFalse(not before["gates"][g] and after["gates"][g],
                             f"{step}: {g} flipped fail->pass "
                             f"(invariant harness acceptance bar)")
        for k in STICKY_TRUE:
            if before["lineage"].get(k):
                self.assertTrue(after["lineage"].get(k),
                                f"{step}: sticky lineage flag {k} disappeared")
        for key, st0 in before["approvals"].items():
            st1 = after["approvals"][key]
            self.assertFalse(st0 in INVALID_STATES and st1 in PASSING_STATES,
                             f"{step}: approval {key} recovered "
                             f"{st0}->{st1} without re-approval")
        self.assert_dag(after, step)

    def assert_dag(self, snap, step=""):
        for i, g in enumerate(ORDER):
            if snap["gates"][g]:
                for h in ORDER[:i]:
                    self.assertTrue(snap["gates"][h],
                                    f"{step}: DAG broken: {g} passes while {h} fails")

    def run_mutation(self, name):
        before = snapshot(self)
        getattr(self, "mut_" + name)()
        after = snapshot(self)
        self.assert_monotone(before, after, name)
        if name == "cosmetic_amend":
            states = [st for (k, _), st in after["approvals"].items() if k == "spec"]
            self.assertTrue(states, "no recorded spec approval found")
            for st in states:
                self.assertEqual(st, "stale",
                                 "spec approval invalidated by amend must report STALE")
        if name == "edit_report":
            states = [st for (k, _), st in after["approvals"].items() if k == "signoff"]
            self.assertTrue(states, "no recorded signoff approval found")
            for st in states:
                self.assertEqual(st, "stale",
                                 "signoff invalidated by a report edit must report STALE")
        if name == "delete_artifact":
            self.check_delete_caught(before, after)
        return before, after


def _mutation_tests(cls):
    for _name in MUTATIONS:
        def _t(self, _n=_name):
            self.run_mutation(_n)
        _t.__name__ = f"test_mutation_{_name}"
        setattr(cls, _t.__name__, _t)
    return cls


@_mutation_tests
class TestInvEvalBinding(InvMixin, P9Setup):
    """N1 fixture: bound correction case whose deterministic check fails."""
    TIER = "This is a DECIDE analysis."
    DECISION = "Ship v2 or roll back."

    @classmethod
    def build_baseline(cls, inst):
        inst.lock()
        inst.assertEqual(inst.cli("profile")[0], 0)
        inst.register_and_run()
        from tests.test_phase9 import TestEvalsMatchRun
        TestEvalsMatchRun.write_bound_case(inst, check="0" * 64)
        inst.answer_and_signoff()
        from ddalib import evals as _evals
        assert not _evals.do_run(inst.wd)["ok"], "fixture must start FAILING"
        from ddalib import evaluate as _ev
        assert not _ev.evaluate(inst.wd)["verdicts"]["G7"][0], "G7 must start failing"

    def tracked_approvals(self):
        return [("correction", "001"), ("spec", None), ("signoff", None)]

    def rename_target(self):
        return self.wd.root / "evals" / "corrections" / "001"

    def delete_target(self):
        return self.wd.root / "evals" / "corrections"

    def check_delete_caught(self, before, after):
        self.assertEqual(after["bound"], ["001"],
                         "rm -rf evals/corrections dropped a bound case (N1)")
        self.assertFalse(after["evals_ok"],
                         "bound check must still fail after deletion (N1)")
        rc, out = self.cli("evals", "run", str(self.wd.root))
        print(f"\n[N1 delete caught] rc={rc} :: " + out.strip().splitlines()[0][:300])
        self.assertNotEqual(rc, 0)

    def test_dag(self):
        self.assert_dag(snapshot(self), "baseline")


@_mutation_tests
class TestInvGoldfishHistory(InvMixin, P9Setup):
    """N2 fixture: teardown review with two failed rounds (DECIDE glance)."""
    TIER = "This is a DECIDE analysis."
    RUNG = "glance"
    DECISION = "Ship v2 or roll back."

    @classmethod
    def build_baseline(cls, inst):
        inst.write_spec()
        inst.assertEqual(inst.cli("lock")[0], 0)
        inst.assertEqual(inst.cli("packet", "teardown")[0], 0)
        inst.assertNotEqual(inst.cli("review", "run", "teardown", stub="fail")[0], 0)
        inst.assertNotEqual(inst.cli("review", "run", "teardown", stub="fail")[0], 0)
        inst.answer_and_signoff()
        from ddalib import review as _review
        assert len(_review.existing_calls(inst.wd, "teardown")) >= 4
        from ddalib import evaluate as _ev
        assert not _ev.evaluate(inst.wd)["verdicts"]["G3"][0], "G3 must start failing"

    def rename_target(self):
        gdir = self.wd.analysis / "reviews" / "goldfish"
        return sorted(gdir.glob("teardown-*.json"))[0]

    def delete_target(self):
        return self.wd.analysis / "reviews" / "goldfish"

    def check_delete_caught(self, before, after):
        from ddalib import review as _review
        calls = _review.existing_calls(self.wd, "teardown")
        self.assertGreaterEqual(len(calls), 4,
                                "deleting call files reset review history (N2)")
        self.assertFalse(after["gates"]["G3"], "G3 must stay failing (N2)")
        rc, out = self.cli("review", "run", "teardown", stub="pass")
        print(f"\n[N2 delete caught] re-run rc={rc} :: " + out.strip().splitlines()[0][:300])
        self.assertNotEqual(rc, 0, "passing re-run after deletion must be refused")
        rc, out = self.cli("gate", "G3")
        print(f"[N2 delete caught] gate G3 rc={rc} :: " + out.strip().splitlines()[0][:300])

    def test_dag(self):
        self.assert_dag(snapshot(self), "baseline")


@_mutation_tests
class TestInvStickyExposure(InvMixin, P9Setup):
    """Sticky-exposure fixture: results seen before profile (proof-B shape)."""
    TIER = "This is a DECIDE analysis."
    DECISION = "Ship v2 or roll back."

    @classmethod
    def build_baseline(cls, inst):
        inst.lock()
        inst.assertEqual(inst.cli("profile")[0], 0)
        inst.register_and_run()
        inst.mut_cosmetic_amend()
        inst.assertEqual(inst.cli("profile")[0], 0)
        inst.answer_and_signoff()
        from ddalib import lineage as _lin
        assert _lin.lineage(inst.wd).get("results_seen_before_profile"), \
            "fixture must start EXPOSED"
        from ddalib import evaluate as _ev
        assert not _ev.evaluate(inst.wd)["verdicts"]["G7"][0], "G7 must start failing"

    def rename_target(self):
        return self.wd.analysis / "profile.json"

    def delete_target(self):
        snaps = self.wd.root / "derived" / "snapshots"
        return snaps

    def check_delete_caught(self, before, after):
        from ddalib import lineage as _lin
        self.assertTrue(_lin.lineage(self.wd).get("results_seen_before_profile"),
                        "sticky exposure flag cleared by deletion")
        self.assertFalse(after["gates"]["G7"], "G7 must stay failing")

    def test_dag(self):
        self.assert_dag(snapshot(self), "baseline")


class TestDdaprobeRegression(unittest.TestCase):
    """Re-run every tests/probes/ probe: exit 0 AND expected finding present.

    Probes live in-repo (no scratch-dir dependency) and declare EXPECTED;
    a probe that runs but prints a different FINDING (attack succeeded)
    fails the suite — exit codes alone cannot catch bypasses.
    """

    def _probes(self):
        dd = REPO / "tests" / "probes"
        files = sorted(dd.glob("p_*.py")) + sorted(dd.glob("n_*.py"))
        self.assertTrue(files, f"no ddaprobe probes found in {dd}")
        return files

    @staticmethod
    def _expected(probe: Path) -> tuple:
        import ast as _ast
        import re as _re
        m = _re.search(r"^EXPECTED\s*=\s*(.+?)\s*$",
                       probe.read_text(encoding="utf-8"), _re.M)
        assert m, f"{probe.name} declares no EXPECTED finding"
        val = _ast.literal_eval(m.group(1))
        return (val,) if isinstance(val, str) else tuple(val)

    def test_probe_list_nonempty(self):
        self.assertGreaterEqual(len(self._probes()), 13)

    def test_all_probes(self):
        env = dict(os.environ)
        env["DDA_TEST_MODE"] = "1"
        env["PYTHONPATH"] = str(REPO / "scripts") + os.pathsep + str(REPO) \
            + os.pathsep + env.get("PYTHONPATH", "")
        failures = []
        for probe in self._probes():
            expected = self._expected(probe)
            try:
                p = subprocess.run([sys.executable, str(probe)],
                                   capture_output=True, text=True, env=env,
                                   cwd=str(probe.parent), timeout=600)
            except subprocess.TimeoutExpired:
                failures.append(f"{probe.name}: TIMEOUT")
                continue
            tail = (p.stdout + p.stderr).strip().splitlines()[-3:]
            print(f"[{probe.name}] rc={p.returncode} :: " + " | ".join(t[:160] for t in tail))
            if p.returncode != 0:
                failures.append(f"{probe.name}: rc={p.returncode} (probe did not run clean)")
            elif not any(f"FINDING: {e}" in p.stdout for e in expected):
                got = [ln for ln in p.stdout.splitlines() if ln.startswith("FINDING:")]
                failures.append(f"{probe.name}: expected one of {expected!r} absent; got {got}")
        self.assertEqual(failures, [], f"{len(failures)} probe(s) regressed: {failures}")


if __name__ == "__main__":
    unittest.main()
