"""Regression: approvals in a workdir NESTED inside a bigger git repo.

Git reports `show --name-status` paths relative to the repo root
(`analysis/.analysis/approvals/...`) while dda builds workdir-relative ones
(`.analysis/approvals/...`). Before the fix every approval in a nested
workdir was written, committed, then rejected by its own exactness check
(§4.5). Both the nested case and the workdir-is-repo-root case must pass.

Run: DDA_TEST_MODE=1 python -m unittest tests.test_nested_workdir
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

from ddalib import approvals, ledger  # noqa: E402
from ddalib.layout import Workdir  # noqa: E402
from tests.test_phase2 import Base  # noqa: E402


class _Approve(Base):
    nested = False

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-nest-"))
        self._env = dict(os.environ)
        os.environ["DDA_HOME"] = str(self.tmp / "home")
        os.environ["DDA_TEST_MODE"] = "1"
        self.raw = self.tmp / "raw"
        self.raw.mkdir()
        (self.raw / "orders.csv").write_text("id,amount\n1,10\n", encoding="utf-8")
        self.repo_root = self.tmp / "project"
        self.repo_root.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo_root)], check=True)
        for k, v in (("user.email", "t@example.com"), ("user.name", "T")):
            subprocess.run(["git", "-C", str(self.repo_root), "config", k, v], check=True)
        if self.nested:
            # Unrelated project content outside the workdir, committed and dirty.
            (self.repo_root / "README.md").write_text("project\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(self.repo_root), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(self.repo_root), "commit", "-q", "-m", "project"],
                           check=True)
            (self.repo_root / "notes.txt").write_text("untracked, outside workdir\n",
                                                      encoding="utf-8")
            wd_dir = self.repo_root / "analysis"
        else:
            wd_dir = self.repo_root
        self.wd = Workdir.at(wd_dir)
        self.cli("init", str(self.wd.root))
        self.wd.config_path.write_text(
            "version: 1\ndefault_tier: DECIDE\ndata_roots:\n  sales:\n"
            f"    paths: [\"{self.raw.as_posix()}\"]\n    tool_patterns: [\"^mcp__warehouse__.*\"]\n",
            encoding="utf-8", newline="\n")
        (self.wd.definitions / "conversion.md").write_text(
            "---\nname: conversion\nversion: 1\n---\nOrders / sessions, daily grain, UTC.\n",
            encoding="utf-8", newline="\n")
        from ddalib import lockhash
        self.pin = lockhash.load_definition(self.wd, "conversion").pin
        self.write_spec()

    def _approve_and_verify(self):
        top = subprocess.run(["git", "-C", str(self.wd.root), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(Path(top).resolve() == self.wd.root.resolve(), not self.nested)
        rc, out, err = self.cli("approve", "tier", "--no-sign", str(self.wd.root))
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn("touches more than", out + err)
        sha = subprocess.run(["git", "-C", str(self.wd.root), "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=True).stdout.strip()
        names = subprocess.run(["git", "-C", str(self.wd.root), "show", "--pretty=format:",
                                "--name-status", sha], capture_output=True, text=True,
                               check=True).stdout.strip()
        want_prefix = "analysis/" if self.nested else ""
        self.assertRegex(names, rf"^A\t{want_prefix}\.analysis/approvals/tier-[0-9a-f]+\.json$")
        only = approvals._only_added_file(self.wd, sha)
        self.assertIsNotNone(only)
        self.assertTrue(only.startswith(".analysis/approvals/tier-"), only)
        rc, out, err = self.cli("approved", "tier", str(self.wd.root))
        self.assertEqual(rc, 0, out + err)
        v = approvals.verify_approval(self.wd, "tier")
        # --no-sign: the commit is accepted as THE approval for the current
        # digest and disclosed as unverified (not missing/uncommitted).
        self.assertEqual(v.get("state"), approvals.ApprovalState.UNVERIFIED, v)
        self.assertEqual(v.get("commit"), sha, v)
        self.assertIn("unsigned", v.get("reason", ""), v)
        self.assertEqual(len(approvals.list_approvals(self.wd, "tier")), 1)
        rec, _ = approvals.approved_payload(self.wd, "tier")
        self.assertEqual(rec.get("kind"), "tier")


class TestApprovalRepoRoot(_Approve):
    nested = False

    def test_approval_accepted_at_repo_root(self):
        self._approve_and_verify()


class TestApprovalNestedWorkdir(_Approve):
    nested = True

    def test_approval_accepted_in_nested_workdir(self):
        self._approve_and_verify()

    def test_safety_scan_ignores_files_outside_workdir(self):
        # Before the fix, porcelain status (repo-root-relative) leaked
        # `analysis/...` and out-of-workdir paths into the workdir scan.
        (self.wd.root / "secret.pem").write_text(
            "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n",
            encoding="utf-8")
        problems = ledger.git_safety_scan(self.wd)
        self.assertTrue(any(p.startswith("secret.pem") for p in problems), problems)
        self.assertFalse(any(p.startswith("analysis/") or p.startswith("notes.txt")
                             for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
