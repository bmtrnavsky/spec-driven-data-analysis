"""Harness isolation + checkout independence (SPEC-34478d1 NEW-5 / NEW-6).

NEW-5 / I16 — reverts never touch the source checkout:
  test_interleaved_arms_source_byte_identical — the spec's acceptance test:
    two apply_unit arms interleaved (rA, rB, rA(), rB()) leave the source
    byte-identical (sha256 of raw bytes) AND the sandbox copy pristine. The
    harness mutation "restore via write_text snapshot, no isolation" fails it.
  test_apply_refuses_source_checkout — apply_* on a non-sandbox root raises.
  test_lock_excludes_concurrent_run — a second process holding the repo
    revert lock blocks this one; released when the holder exits.
  test_selfcheck_repairs_stripped_tree — a scratch git repo whose chain.py /
    ledger.py were left stripped by a killed pre-I16 run is detected and
    restored from HEAD on startup; a legit (non-revert) edit is left alone;
    a revert mixed with other edits is refused, never guessed at.

NEW-6 — premise hashes are line-ending independent:
  test_premise_hashes_eol_independent — every registry pair checks FRESH
    against an all-LF copy and an all-CRLF copy of the tree, while raw-byte
    hashing (the harness mutation) would differ.
  test_premise_passes_in_fresh_lf_tree — `unittest tests.test_premise` run
    inside an LF-only copy of the tree (what a clean `eol=lf` clone holds)
    and inside a CRLF copy: both pass.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests"))

from revert.apply import (  # noqa: E402
    RevertIsolationError,
    apply_unit,
    apply_units,
    repo_lock,
    revert_sandbox,
    splice_function,
    startup_selfcheck,
)
from revert.premise import check_pair, find_record, load_premise, sha_file  # noqa: E402
from revert.scenarios import SCENARIOS  # noqa: E402

CHAIN = "scripts/ddalib/chain.py"
LEDGER = "scripts/ddalib/ledger.py"
NO_M7 = "tests/revert/impl/chain_append_locked_no_M7.py"
HISTORIC = "tests/revert/impl/chain_append_locked_historic_d135783.py"
LEDGER_NONE = "tests/revert/impl/ledger_checkpoint_problems_none.py"


def _sha(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def _tree_files(repo: Path) -> list[str]:
    out = subprocess.run(["git", "-C", str(repo), "ls-files", "-co",
                          "--exclude-standard"], capture_output=True, text=True,
                         check=True).stdout.splitlines()
    return [f for f in out if (repo / f).is_file()]


def _copy_tree(repo: Path, dest: Path, eol: str) -> None:
    """Copy the working tree with every text file forced to `eol`."""
    for rel in _tree_files(repo):
        data = (repo / rel).read_bytes()
        if b"\0" not in data:
            data = data.replace(b"\r\n", b"\n")
            if eol == "\r\n":
                data = data.replace(b"\n", b"\r\n")
        t = dest / rel
        t.parent.mkdir(parents=True, exist_ok=True)
        t.write_bytes(data)


class TestRevertIsolation(unittest.TestCase):
    def test_interleaved_arms_source_byte_identical(self):
        src = REPO / CHAIN
        before = _sha(src)
        with revert_sandbox(REPO) as sbx:
            tgt = sbx / CHAIN
            pristine = tgt.read_bytes()
            rA = apply_unit(sbx, CHAIN, "_append_locked", NO_M7)
            self.assertIn("DERIVED no_M7", tgt.read_text(encoding="utf-8"))
            rB = apply_unit(sbx, CHAIN, "_append_locked", HISTORIC)
            rA()
            rB()
            self.assertEqual(tgt.read_bytes(), pristine,
                             "interleaved restore stranded a mutated sandbox file")
            self.assertEqual(_sha(src), before, "source changed while a revert was applied")
        self.assertFalse(sbx.exists(), "sandbox not removed")
        self.assertEqual(_sha(src), before, "source file is not byte-identical")

    def test_apply_refuses_source_checkout(self):
        before = _sha(REPO / CHAIN)
        with self.assertRaises(RevertIsolationError):
            apply_unit(REPO, CHAIN, "_append_locked", NO_M7)
        with self.assertRaises(RevertIsolationError):
            apply_units(REPO, [u for s in SCENARIOS for u in s["units"]
                               if u["kind"] == "patch"][:1])
        self.assertEqual(_sha(REPO / CHAIN), before)

    def test_sandbox_cleaned_on_exception(self):
        holder = {}
        with self.assertRaises(ZeroDivisionError):
            with revert_sandbox(REPO) as sbx:
                holder["sbx"] = sbx
                apply_unit(sbx, CHAIN, "_append_locked", NO_M7)
                1 / 0
        self.assertFalse(holder["sbx"].exists())

    def test_lock_excludes_concurrent_run(self):
        code = textwrap.dedent(f"""
            import sys, time
            sys.path.insert(0, {str(REPO / 'tests')!r})
            from revert.apply import repo_lock
            with repo_lock({str(REPO)!r}):
                print("HELD", flush=True)
                time.sleep(4)
        """)
        child = subprocess.Popen([sys.executable, "-c", code],
                                 stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), "HELD")
            t0 = time.monotonic()
            with self.assertRaises(RevertIsolationError):
                with repo_lock(REPO, timeout=1.0):
                    pass
            self.assertGreaterEqual(time.monotonic() - t0, 0.9)
        finally:
            child.wait(timeout=60)
            child.stdout.close()
        with repo_lock(REPO, timeout=30):
            pass  # released once the holder exits

    def test_selfcheck_repairs_stripped_tree(self):
        tmp = Path(tempfile.mkdtemp(prefix="dda-selfcheck-test-"))
        try:
            repo = tmp / "repo"
            _copy_tree(REPO, repo, "\n")
            git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
                   "-c", "commit.gpgsign=false"]
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(git + ["add", "-A"], check=True)
            subprocess.run(git + ["commit", "-qm", "base"], check=True)
            head_chain = (repo / CHAIN).read_bytes()
            head_ledger = (repo / LEDGER).read_bytes()
            # The permanent strip of a killed / overlapping pre-I16 run:
            # chain.py with no_M7 spliced in, ledger.py with the none impl.
            for rel, func, impl in ((CHAIN, "_append_locked", NO_M7),
                                    (LEDGER, "_checkpoint_problems", LEDGER_NONE)):
                txt = splice_function((repo / rel).read_text(encoding="utf-8"), func,
                                      (repo / impl).read_text(encoding="utf-8"))
                (repo / rel).write_bytes(txt.replace("\n", "\r\n").encode())
            rep = startup_selfcheck(repo, revalidate=False, force=True)
            self.assertEqual(sorted(rep["repaired"]), [CHAIN, LEDGER])
            self.assertEqual((repo / CHAIN).read_bytes(), head_chain)
            self.assertEqual((repo / LEDGER).read_bytes(), head_ledger)
            self.assertEqual(rep["stale_after"], [])
            for b in rep["backups"]:
                self.assertTrue(Path(b).is_file())
            # A legit, non-revert edit is not touched.
            edited = head_chain + b"\n# local dev note\n"
            (repo / CHAIN).write_bytes(edited)
            rep = startup_selfcheck(repo, revalidate=False, force=True)
            self.assertEqual(rep["repaired"], [])
            self.assertEqual((repo / CHAIN).read_bytes(), edited)
            # A revert mixed with other edits is refused, never guessed at.
            txt = splice_function(edited.decode(), "_append_locked",
                                  (repo / NO_M7).read_text(encoding="utf-8"))
            (repo / CHAIN).write_bytes(txt.encode())
            with self.assertRaises(RevertIsolationError):
                startup_selfcheck(repo, revalidate=False, force=True)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestPremiseEolIndependence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="dda-eol-test-"))
        cls.lf = cls.tmp / "lf"
        cls.crlf = cls.tmp / "crlf"
        _copy_tree(REPO, cls.lf, "\n")
        _copy_tree(REPO, cls.crlf, "\r\n")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_premise_hashes_eol_independent(self):
        premise = load_premise(REPO)
        for root in (self.lf, self.crlf):
            fails = []
            for s in SCENARIOS:
                for p in s["probes"]:
                    msg = check_pair(root, s, p, find_record(premise, s["id"], p))
                    if msg:
                        fails.append(msg)
            self.assertEqual(fails, [], f"{root.name}: {fails}")
        # Harness mutation guard: raw-byte hashing differs across checkouts,
        # the normalized hash does not.
        rel = "scripts/ddalib/stage8.py"
        self.assertNotEqual(_sha(self.lf / rel), _sha(self.crlf / rel))
        self.assertEqual(sha_file(self.lf / rel), sha_file(self.crlf / rel))

    def test_premise_passes_in_fresh_lf_tree(self):
        env = dict(os.environ, DDA_TEST_MODE="1")
        for root in (self.lf, self.crlf):
            p = subprocess.run([sys.executable, "-m", "unittest", "tests.test_premise"],
                               cwd=str(root), env=env, capture_output=True, text=True,
                               timeout=600)
            self.assertEqual(p.returncode, 0,
                             f"test_premise failed in {root.name} tree:\n{p.stderr[-3000:]}")


if __name__ == "__main__":
    unittest.main()
