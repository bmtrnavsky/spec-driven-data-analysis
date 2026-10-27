"""Phase-3 regression tests: the five blind-review findings (deleg_5dd221a0).

1. release/abandon laundering — release/abandon append a ledger line; agent
   `dda release`/`dda abandon` invocations block in every blocking hook.
2. rootless workdir hopping — G4/exposure flag session_history (same session
   with data reads in another workdir's log, no shared locator needed) and
   rebind ledger lines.
3. parent-dir reads — naming a data root's direct parent counts as a read.
4. blocked attempts — runlog post with a block signal logs kind=blocked,
   which exposure ignores.
5. unbound watermark — G4 applies the stored unbound watermark as a lower
   bound (lines judged at lock are not re-reported; newer lines still count).

Run: python -m unittest discover -s tests -v
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

from ddalib import binding, chain, ledger  # noqa: E402
from ddalib.layout import Workdir  # noqa: E402

SPEC = """# Analysis spec

## Question
Did checkout v2 raise conversion?

## Tier
This is a EXPLORE analysis.

## Rung
quick-cut

## Data sources
- `sales` — orders table

## Metrics
- conversion@1#{h}

## Prior exposure
none known
"""


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p3-"))
        self._env = dict(os.environ)
        os.environ["DDA_HOME"] = str(self.tmp / "home")
        self.raw = self.tmp / "raw"
        self.raw.mkdir()
        (self.raw / "orders.csv").write_text("id,amount\n1,10\n", encoding="utf-8")
        self.wd = Workdir.at(self.tmp / "wd")
        self.cli("init", str(self.wd.root))
        subprocess.run(["git", "init", "-q", str(self.wd.root)], check=True)
        self.wd.config_path.write_text(
            "version: 1\ndefault_tier: EXPLORE\ndata_roots:\n  sales:\n"
            f"    paths: [\"{self.raw.as_posix()}\"]\n",
            encoding="utf-8", newline="\n")
        (self.wd.definitions / "conversion.md").write_text(
            "---\nname: conversion\nversion: 1\n---\nOrders / sessions, daily grain, UTC.\n",
            encoding="utf-8", newline="\n")
        from ddalib import cli as _cli, lockhash
        self.pin = lockhash.load_definition(self.wd, "conversion").pin
        self.wd.spec_path.write_text(SPEC.format(h=self.pin.split("#")[1]), encoding="utf-8", newline="\n")

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cli(self, *args):
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from ddalib import cli
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.main(list(args))
        return rc, out.getvalue(), err.getvalue()

    def hook(self, name, tool, args, session="b-1", event="pre_tool_call", **extra):
        payload = {"hook_event_name": event, "tool_name": tool, "tool_input": args, "session_id": session,
                   "cwd": str(self.wd.root), "extra": {"tool_call_id": "c1"}, **extra}
        r = subprocess.run([sys.executable, "-I", "-S", str(REPO / "hooks" / "dda_hook.py"), name],
                           input=json.dumps(payload), capture_output=True, text=True, env=dict(os.environ))
        return r.returncode, json.loads(r.stdout)

    def blocked(self, name, tool, args, **kw):
        rc, out = self.hook(name, tool, args, **kw)
        return rc == 2 and out.get("action") == "block", out.get("message", "")

    def bind(self, session="b-1"):
        rc, _, err = self.cli("start", str(self.wd.root), "--session", session)
        self.assertEqual(rc, 0, err)


class ReleaseTests(Base):
    def test_release_ledgers_sessions(self):
        self.bind("s-rel")
        rc, _, err = self.cli("release", str(self.wd.root))
        self.assertEqual(rc, 0, err)
        recs = chain.read_records(ledger.ledger_path(self.wd))
        rel = [r for r in recs if r.get("type") == "release"]
        self.assertEqual(len(rel), 1)
        self.assertIn("s-rel", rel[0].get("sessions"))

    def test_abandon_single_record_with_reason(self):
        self.bind("s-ab")
        rc, _, err = self.cli("abandon", str(self.wd.root), "--reason", "dup")
        self.assertEqual(rc, 0, err)
        recs = chain.read_records(ledger.ledger_path(self.wd))
        ab = [r for r in recs if r.get("type") == "abandon"]
        self.assertEqual(len(ab), 1)
        self.assertEqual(ab[0].get("reason"), "dup")
        self.assertEqual([r for r in recs if r.get("type") == "release"], [])

    def test_agent_release_blocked_everywhere(self):
        self.bind("s-ag")
        for h in ("lockguard", "evidenceguard", "rawguard", "defguard", "footercheck"):
            b, msg = self.blocked(h, "terminal", {"command": f"python dda.py release {self.wd.root}"},
                                  session="s-ag")
            self.assertTrue(b, h)
            self.assertIn("human-only", msg)
        b, _ = self.blocked("lockguard", "terminal", {"command": f"dda abandon {self.wd.root} --reason x"},
                            session="s-ag")
        self.assertTrue(b)


class HoppingTests(Base):
    def _other_workdir(self, name, roots_cfg):
        from ddalib import cli
        other = Workdir.at(self.tmp / name)
        import io
        from contextlib import redirect_stderr, redirect_stdout
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["init", str(other.root)]), 0)
        subprocess.run(["git", "init", "-q", str(other.root)], check=True)
        other.config_path.write_text(roots_cfg, encoding="utf-8", newline="\n")
        return other

    def _log_read(self, wd, session, path):
        """Append a runlog post line to `wd`'s runs.log as `session` (no binding needed)."""
        from ddalib import hooks as _h
        payload = {"hook_event_name": "post_tool_call", "tool_name": "read_file",
                   "tool_input": {"path": str(path)},
                   "session_id": session, "extra": {"tool_call_id": "cx"}}
        ctx = _h.Ctx("runlog", payload, {"session_id": session, "workdir": str(wd.root),
                                         "workdir_id": wd.id})
        _h.runlog(ctx)

    def test_rootless_hopping_flagged(self):
        self.bind("hopper")
        self._log_read(self.wd, "hopper", self.raw / "orders.csv")
        # Second workdir declaring NO shared locator (different root name and path).
        alt_raw = self.tmp / "alt"
        alt_raw.mkdir()
        other = self._other_workdir("wd2", "version: 1\ndefault_tier: EXPLORE\ndata_roots:\n  other:\n"
                                    f"    paths: [\"{alt_raw.as_posix()}\"]\n")
        # Register the second workdir (as a real hop target would be) without
        # moving the hopper session to it.
        rc, _, err = self.cli("start", str(other.root), "--session", "dummy")
        self.assertEqual(rc, 0, err)
        self._log_read(other, "hopper", self.raw / "orders.csv")
        found = ledger.exposure(self.wd, ["sales"], None, None)
        self.assertTrue(found["session_history"], found)
        self.assertEqual(ledger.label_for(found, "none known"), "post-data (unbound access)")

    def test_rebind_flagged(self):
        self.bind("rb")
        self._log_read(self.wd, "rb", self.raw / "orders.csv")
        other = self._other_workdir("wd3", "version: 1\ndefault_tier: EXPLORE\ndata_roots:\n  sales:\n"
                                    f"    paths: [\"{self.raw.as_posix()}\"]\n")
        from ddalib import binding as _b
        _b.start(other, "rb", rebind=True)
        found = ledger.exposure(self.wd, ["sales"], None, None)
        self.assertTrue(found["rebind"], found)
        self.assertEqual(ledger.label_for(found, "none known"), "post-data (unbound access)")

    def test_clean_rebind_not_flagged(self):
        self.bind("clean")
        other = self._other_workdir("wd4", "version: 1\ndefault_tier: EXPLORE\ndata_roots:\n  sales:\n"
                                    f"    paths: [\"{self.raw.as_posix()}\"]\n")
        from ddalib import binding as _b
        _b.start(other, "clean", rebind=True)
        found = ledger.exposure(self.wd, ["sales"], None, None)
        self.assertFalse(found["rebind"])
        self.assertFalse(found["session_history"])


class ParentDirTests(Base):
    def test_parent_dir_read_blocked(self):
        self.bind("p-1")
        # sanity: direct read blocks pre-lock
        b, _ = self.blocked("lockguard", "read_file", {"path": str(self.raw / "orders.csv")}, session="p-1")
        self.assertTrue(b)
        # naming the root's direct parent counts as a read of the root
        b, _ = self.blocked("lockguard", "search_files", {"path": str(self.raw.parent), "pattern": "orders"},
                            session="p-1")
        self.assertTrue(b, "naming the root's direct parent must count as a read of the root")
        b, _ = self.blocked("lockguard", "terminal", {"command": f"ls {self.raw.parent}"}, session="p-1")
        self.assertTrue(b, "listing the root's direct parent must count as a read of the root")

    def test_far_ancestor_still_allowed(self):
        self.bind("p-2")
        b, _ = self.blocked("lockguard", "terminal", {"command": "ls C:/Users"}, session="p-2")
        self.assertFalse(b)


class BlockedKindTests(Base):
    def test_blocked_post_logs_blocked_kind(self):
        self.bind("k-1")
        rc, out = self.hook("runlog", "read_file", {"path": str(self.raw / "orders.csv")},
                            session="k-1", event="post_tool_call", blocked=True)
        self.assertEqual(rc, 0, out)
        recs = [r for r in chain.read_records(ledger.runs_log(self.wd))
                if r.get("type") == "done" and r.get("session") == "k-1"]
        self.assertTrue(recs)
        self.assertEqual(recs[-1]["kind"], "blocked")
        self.assertEqual(recs[-1]["aliases"], [])
        found = ledger.exposure(self.wd, ["sales"], None, None)
        self.assertFalse(found["runs"], "blocked attempts must not count as exposure")


class UnboundWatermarkTests(Base):
    def test_g4_ignores_pre_lock_unbound_lines(self):
        self.bind("w-1")
        from ddalib import hooks as _h
        _h.unbound_runlog({"hook_event_name": "pre_tool_call", "tool_name": "read_file",
                           "tool_input": {"path": str(self.raw / "orders.csv")},
                           "session_id": "ghost", "extra": {}})
        rc, out, err = self.cli("lock", str(self.wd.root))
        self.assertEqual(rc, 0, err + out)
        self.assertIn("post-data (unbound access)", out)
        first = ledger.gate_g4(self.wd)
        # The lock-time label stands (worst-label carry), but G4 does not
        # re-report the watermarked pre-lock line as a new unbound session.
        self.assertIn("post-data (unbound access)", first[1])
        self.assertNotIn("unbound sessions", first[1])
        # Second G4 with no new unbound lines: watermarked lines are not re-reported.
        lock = __import__("ddalib.lockstate", fromlist=["read_lock"]).read_lock(self.wd)
        found = ledger.exposure(self.wd, lock["aliases"], lock.get("watermarks"), lock.get("locked_ts"))
        self.assertFalse(found["unbound"], "pre-lock unbound lines must fall under the watermark at G4")


if __name__ == "__main__":
    unittest.main()
