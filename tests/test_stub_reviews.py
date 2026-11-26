"""The stub transport is a test fixture, not a review (H1, hostile re-review 2026-11-19).

`DDA_TEST_MODE=1 DDA_GOLDFISH_STUB=pass dda review run teardown` produced passing
goldfish rounds recorded as real calls (`stub-0001`), and G3 accepted them. Any
session can export those variables, so a fabricated passing review was one command
away from satisfying the product's central control. The gate now refuses a stub call
outside a test run; this module proves both halves.
"""
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "tests" / "probes"))

from probelib import new_fixture, cleanup  # noqa: E402
from ddalib import gates7  # noqa: E402

TEST_FLAGS = ("DDA_TEST_MODE", "PYTEST_CURRENT_TEST")


class TestStubReviewCannotSatisfyGate(unittest.TestCase):
    def setUp(self):
        self.f = new_fixture("f7", prefix="dda-h1-")
        f = self.f
        assert f.cli("lock")[0] == 0
        assert f.cli("packet", "teardown")[0] == 0
        env = dict(f.env, DDA_TEST_MODE="1", DDA_GOLDFISH_STUB="pass")
        env.pop("PYTEST_CURRENT_TEST", None)
        p = subprocess.run([sys.executable, "-m", "ddalib.cli", "review", "run", "teardown"],
                           cwd=str(f.wd.root), env=env, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        assert f.cli("approve", "spec", "--yes", "yes, ship it", "--who", "brad")[0] == 0

    def tearDown(self):
        cleanup(self.f)

    def test_stub_call_is_marked_as_a_stub(self):
        recs = sorted((self.f.wd.analysis / "reviews" / "goldfish").glob("teardown-r*.json"))
        self.assertTrue(recs, "stub review recorded nothing")
        import json
        for p in recs:
            rec = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(rec.get("provider"), "stub", rec)
            self.assertEqual(rec.get("model"), "stub", rec)

    def test_gate_accepts_stub_only_in_a_test_run(self):
        ok, reason, _ = gates7.gate_g3(self.f.wd)
        self.assertTrue(ok, f"control: stub should satisfy G3 inside a test run: {reason}")
        saved = {k: os.environ.pop(k, None) for k in TEST_FLAGS}
        try:
            ok, reason, _ = gates7.gate_g3(self.f.wd)
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v
        self.assertFalse(ok, "a stub review satisfied G3 outside a test run")
        self.assertIn("test stub", reason, reason)


if __name__ == "__main__":
    unittest.main()
