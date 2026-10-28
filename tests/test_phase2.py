"""Phase-2 tests: chain appender, lock + ledger, lock-state cache, hooks (lockguard,
evidenceguard, rawguard, defguard, footercheck, runlog), unbound-access log, G4.
Run: python -m unittest discover -s tests -v
"""
import json
import multiprocessing as mp
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from ddalib import chain, cli, footer, ledger, lockhash, lockstate  # noqa: E402
from ddalib.layout import DdaError, Workdir  # noqa: E402

SPEC = """# Analysis spec

## Question
Did checkout v2 raise conversion?

## Tier
This is a {tier} analysis.

## Rung
quick-cut

## Data sources
- `sales` — orders table

## Metrics
- conversion@1#{h}

## Prior exposure
none known
"""


def _env_home(home):
    os.environ["DDA_HOME"] = str(home)


def _worker(args):
    home, path, n = args
    _env_home(home)
    out = []
    for i in range(n):
        out.append(chain.append(Path(path), {"type": "t", "pid": os.getpid(), "i": i}, spill_on_busy=True,
                                timeout=0.05))
    return sum(1 for r in out if "spilled" in r)


class Base(unittest.TestCase):
    tier = "EXPLORE"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p2-"))
        self._env = dict(os.environ)
        _env_home(self.tmp / "home")
        self.raw = self.tmp / "raw"
        self.raw.mkdir()
        (self.raw / "orders.csv").write_text("id,amount\n1,10\n", encoding="utf-8")
        self.wd = Workdir.at(self.tmp / "wd")
        self.cli("init", str(self.wd.root))
        subprocess.run(["git", "init", "-q", str(self.wd.root)], check=True)
        self.wd.config_path.write_text(
            "version: 1\ndefault_tier: DECIDE\ndata_roots:\n  sales:\n"
            f"    paths: [\"{self.raw.as_posix()}\"]\n    tool_patterns: [\"^mcp__warehouse__.*\"]\n"
            "publish_channels:\n  wordpress:\n    tool_patterns: [\"^mcp__wordpress__.*\"]\n",
            encoding="utf-8", newline="\n")
        (self.wd.definitions / "conversion.md").write_text(
            "---\nname: conversion\nversion: 1\n---\nOrders / sessions, daily grain, UTC.\n", encoding="utf-8", newline="\n")
        self.pin = lockhash.load_definition(self.wd, "conversion").pin
        self.write_spec()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_spec(self, extra=""):
        h = self.pin.split("#")[1]
        self.wd.spec_path.write_text(SPEC.format(h=h, tier=self.tier) + extra, encoding="utf-8", newline="\n")

    def cli(self, *args):
        import io
        from contextlib import redirect_stderr, redirect_stdout
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.main(list(args))
        return rc, out.getvalue(), err.getvalue()

    def hook(self, name, tool, args, session="b-1", event="pre_tool_call", **extra):
        payload = {"hook_event_name": event, "tool_name": tool, "tool_input": args, "session_id": session,
                   "cwd": str(self.wd.root), "extra": {"tool_call_id": "c1"}, **extra}
        r = subprocess.run([sys.executable, "-I", "-S", str(REPO / "hooks" / "dda_hook.py"), name],
                           input=json.dumps(payload), capture_output=True, text=True, env=dict(os.environ))
        out = json.loads(r.stdout)
        return r.returncode, out

    def blocked(self, name, tool, args, **kw):
        rc, out = self.hook(name, tool, args, **kw)
        return rc == 2 and out.get("action") == "block", out.get("message", "")

    def any_block(self, tool, args, **kw):
        for h in ("lockguard", "evidenceguard", "rawguard", "defguard", "footercheck"):
            b, msg = self.blocked(h, tool, args, **kw)
            if b:
                return h, msg
        return None, ""

    def bind(self, session="b-1"):
        rc, _, err = self.cli("start", str(self.wd.root), "--session", session)
        self.assertEqual(rc, 0, err)

    def lock(self, *extra):
        rc, out, err = self.cli("lock", str(self.wd.root), *extra)
        self.assertEqual(rc, 0, err)
        return out


class TestChain(Base):
    def test_append_verify_and_tamper(self):
        p = ledger.runs_log(self.wd)
        for i in range(5):
            chain.append(p, {"type": "x", "i": i})
        self.assertEqual(chain.verify(p), [])
        recs = chain.read_records(p)
        self.assertEqual([r["seq"] for r in recs], [1, 2, 3, 4, 5])
        good = p.read_bytes()
        # Edit a line in place.
        p.write_bytes(good.replace(b'"i":2', b'"i":9'))
        self.assertTrue(chain.verify(p))
        # Truncate the last line.
        p.write_bytes(b"\n".join(good.split(b"\n")[:4]) + b"\n")
        self.assertTrue(any("truncated" in x for x in chain.verify(p)))
        # Append outside the appender.
        p.write_bytes(good + good.split(b"\n")[0] + b"\n")
        self.assertTrue(chain.verify(p))
        p.write_bytes(good)
        self.assertEqual(chain.verify(p), [])
        # Delete the file entirely.
        p.unlink()
        self.assertTrue(any("missing" in x for x in chain.verify(p)))

    def test_concurrency_and_spill_merge(self):
        p = ledger.runs_log(self.wd)
        n_proc, per = 6, 25
        with mp.get_context("spawn").Pool(n_proc) as pool:
            spilled = sum(pool.map(_worker, [(str(self.tmp / "home"), str(p), per)] * n_proc))
        self.assertEqual(len(chain.pending_spills(p)), spilled)
        merged = chain.merge_spills(p)
        self.assertEqual(merged, spilled)
        self.assertEqual(chain.verify(p), [])
        recs = [r for r in chain.read_records(p) if r.get("type") == "t"]
        self.assertEqual(len(recs), n_proc * per)  # nothing lost
        seqs = [r["seq"] for r in chain.read_records(p)]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))  # no duplicate seq, no fork


class TestLock(Base):
    def test_lock_commit_noop_and_amend(self):
        out = self.lock()
        self.assertIn("lock v1", out)
        self.assertIn("pre-data", out)
        lock = lockstate.read_lock(self.wd)
        self.assertEqual(lock["lock_hash"], lockhash.compute(self.wd).lock_hash)
        self.assertTrue((self.wd.specs_dir / "v1.md").is_file())
        log = subprocess.run(["git", "-C", str(self.wd.root), "log", "--oneline"], capture_output=True, text=True).stdout
        self.assertIn("dda lock v1", log)
        self.assertIn("unchanged", self.lock())
        self.write_spec("\n## Assumptions\nweekdays only\n")
        self.assertEqual(lockstate.quick_status(self.wd)[0], "spec-changed")
        rc, _, err = self.cli("lock", str(self.wd.root))
        self.assertNotEqual(rc, 0)
        self.assertIn("--amend", err)
        out = self.lock("--amend", "add weekday assumption")
        self.assertIn("amendment v2", out)
        summ = ledger.ledger_summary(self.wd)
        self.assertEqual((summ["versions"], summ["amendments"], summ["post_data_amendments"]), (2, 1, 0))
        self.assertEqual(self.cli("verify-chain", str(self.wd.root))[0], 0)

    def test_post_data_and_prior_exposure_labels(self):
        self.write_spec().__class__  # noqa
        txt = self.wd.spec_path.read_text(encoding="utf-8").replace("none known", "saw the Q3 dashboard")
        self.wd.spec_path.write_text(txt, encoding="utf-8", newline="\n")
        self.assertIn("pre-data (prior exposure)", self.lock())
        # A logged data read, then an amendment: post-data.
        chain.append(ledger.runs_log(self.wd), {"type": "done", "kind": "data", "aliases": ["sales"], "session": "s"})
        self.wd.spec_path.write_text(txt + "\n## Assumptions\nx\n", encoding="utf-8", newline="\n")
        out = self.lock("--amend", "after data")
        self.assertIn("post-data", out)
        self.assertEqual(ledger.ledger_summary(self.wd)["post_data_amendments"], 1)

    def test_config_change_and_tamper(self):
        self.lock()
        cfg = self.wd.config_path.read_text(encoding="utf-8")
        self.wd.config_path.write_text(cfg + "# comment\n", encoding="utf-8", newline="\n")
        self.assertEqual(lockstate.quick_status(self.wd)[0], "config-changed")
        self.wd.config_path.write_text(cfg, encoding="utf-8", newline="\n")
        self.assertEqual(lockstate.quick_status(self.wd)[0], "valid")
        lk = json.loads(self.wd.lock_path.read_text(encoding="utf-8"))
        lk["label"] = "pre-data"
        lk["lock_hash"] = "0" * 64
        self.wd.lock_path.write_text(json.dumps(lk), encoding="utf-8")
        self.assertEqual(lockstate.quick_status(self.wd)[0], "tampered")
        rc, _, err = self.cli("lock", str(self.wd.root), "--amend", "x")
        self.assertEqual(rc, ledger.EXIT_CHAIN)

    def test_edited_ledger_stops_lock(self):
        self.lock()
        lp = ledger.ledger_path(self.wd)
        lp.write_bytes(lp.read_bytes().replace(b"pre-data", b"pre-dat4"))
        self.assertEqual(self.cli("verify-chain", str(self.wd.root))[0], ledger.EXIT_CHAIN)
        self.write_spec("\n## Assumptions\nx\n")
        rc, _, err = self.cli("lock", str(self.wd.root), "--amend", "x")
        self.assertEqual(rc, ledger.EXIT_CHAIN)
        self.assertIn("stop and ask", err)


class TestHooks(Base):
    def setUp(self):
        super().setUp()
        self.bind()
        self.rawf = (self.raw / "orders.csv").as_posix()

    def test_lockguard_pre_and_post_lock(self):
        reads = [("read_file", {"path": self.rawf}), ("terminal", {"command": f"cat {self.rawf}"}),
                 ("execute_code", {"code": f"open(r'{self.rawf}').read()"}),
                 ("search_files", {"pattern": "x", "path": self.raw.as_posix()}),
                 ("mcp__warehouse__query", {"sql": "select 1"}),
                 ("tool_call", {"calls": [{"name": "mcp__warehouse__query", "arguments": {}}]})]
        for tool, args in reads:
            b, msg = self.blocked("lockguard", tool, args)
            self.assertTrue(b, tool)
            self.assertIn("dda lock", msg)
        # Unrelated work and derived/ before lock.
        self.assertFalse(self.blocked("lockguard", "read_file", {"path": str(self.wd.spec_path)})[0])
        self.assertFalse(self.blocked("lockguard", "terminal", {"command": "ls C:/Users"})[0])
        self.assertTrue(self.blocked("lockguard", "read_file", {"path": str(self.wd.root / "derived" / "a.csv")})[0])
        self.lock()
        b, msg = self.blocked("lockguard", "read_file", {"path": self.rawf})
        self.assertTrue(b)
        self.assertIn("dda run", msg)
        self.assertFalse(self.blocked("lockguard", "mcp__warehouse__query", {"sql": "select 1"})[0])
        self.assertFalse(self.blocked("lockguard", "terminal", {"command": "dda run v1"})[0])
        # Spec edit after lock: connector read blocks until re-lock.
        self.write_spec("\n## Assumptions\nx\n")
        b, msg = self.blocked("lockguard", "mcp__warehouse__query", {"sql": "select 1"})
        self.assertTrue(b)
        self.assertIn("Re-lock", msg)

    def test_lockguard_signing(self):
        for cmd in ("git commit -S -m x", "git -c commit.gpgsign=true commit -m x", "git tag -s v1 -m x",
                    "dda approve spec", "git config user.signingkey ABC"):
            self.assertTrue(self.blocked("lockguard", "terminal", {"command": cmd})[0], cmd)
        self.assertFalse(self.blocked("lockguard", "terminal", {"command": "git status"})[0])

    def test_evidenceguard_table(self):
        a = self.wd.analysis
        blocked = [("write_file", {"path": str(a / "runs.log"), "content": "x"}),
                   ("patch", {"path": str(a / "spec.lock"), "old_string": "a", "new_string": "b"}),
                   ("write_file", {"path": str(a / "config.yaml"), "content": "x"}),
                   ("write_file", {"path": str(a / "approvals" / "spec-v1.md"), "content": "x"}),
                   ("write_file", {"path": str(a / "specs" / "v1.md"), "content": "x"}),
                   ("terminal", {"command": f"echo x >> {a.as_posix()}/runs.log"}),
                   ("terminal", {"command": "rm .analysis/ledger.md", "workdir": str(self.wd.root)}),
                   ("execute_code", {"code": f"open(r'{a / 'audit.log'}', 'a').write('x')"}),
                   ("write_file", {"path": str(self.tmp / "home" / "sessions" / "b-1.json"), "content": "{}"}),
                   ("terminal", {"command": "git add .analysis/approvals/x.md && git commit -m a",
                                 "workdir": str(self.wd.root)})]
        for tool, args in blocked:
            self.assertTrue(self.blocked("evidenceguard", tool, args)[0], (tool, args))
        allowed = [("write_file", {"path": str(a / "spec.md"), "content": "x"}),
                   ("write_file", {"path": str(a / "notes" / "n.md"), "content": "x"}),
                   ("write_file", {"path": str(a / "variants" / "v1.py"), "content": "x"}),
                   ("read_file", {"path": str(a / "runs.log")}),
                   ("terminal", {"command": f"cat {a.as_posix()}/runs.log"}),
                   ("terminal", {"command": "dda verify-chain"})]
        for tool, args in allowed:
            self.assertFalse(self.blocked("evidenceguard", tool, args)[0], (tool, args))
        # Frozen variant.
        chain.append(ledger.specs_tried(self.wd), {"type": "variant", "variant": "v1", "frozen_hash": "abc"})
        self.assertTrue(self.blocked("evidenceguard", "write_file",
                                     {"path": str(a / "variants" / "v1.py"), "content": "y"})[0])

    def test_rawguard_defguard(self):
        self.assertTrue(self.blocked("rawguard", "terminal", {"command": f"rm {self.rawf}"})[0])
        self.assertTrue(self.blocked("rawguard", "write_file", {"path": self.rawf, "content": "x"})[0])
        self.assertFalse(self.blocked("rawguard", "write_file",
                                      {"path": str(self.wd.root / "derived" / "a.csv"), "content": "x"})[0])
        self.assertTrue(self.blocked("defguard", "write_file",
                                     {"path": str(self.wd.definitions / "conversion.md"), "content": "x"})[0])
        self.assertTrue(self.blocked("defguard", "terminal",
                                     {"command": "mv definitions/proposals/a.md definitions/a.md",
                                      "workdir": str(self.wd.root)})[0])
        self.assertFalse(self.blocked("defguard", "write_file",
                                      {"path": str(self.wd.definitions / "proposals" / "a.md"), "content": "x"})[0])

    def test_footercheck(self):
        rpt = str(self.wd.root / "reports" / "checkout.md")
        b, msg = self.blocked("footercheck", "write_file", {"path": rpt, "content": "# R\n"})
        self.assertTrue(b)
        self.lock()
        b, msg = self.blocked("footercheck", "write_file", {"path": rpt, "content": "# R\nbody\n"})
        self.assertTrue(b)
        self.assertIn("missing provenance footer", msg)
        sk = footer.skeleton(self.wd)
        filled = "\n".join(line + ("x" if line.endswith(":** ") else "") for line in sk.split("\n"))
        filled = filled.replace("K reported, locked variant <id>", "1 reported, locked variant v1")
        self.assertFalse(self.blocked("footercheck", "write_file", {"path": rpt, "content": "# R\n\n" + filled})[0])
        wrong = filled.replace(lockstate.read_lock(self.wd)["lock_hash"][:12], "deadbeef0000")
        b, msg = self.blocked("footercheck", "write_file", {"path": rpt, "content": "# R\n\n" + wrong})
        self.assertTrue(b)
        self.assertIn("lock hash wrong", msg)
        self.assertTrue(self.blocked("footercheck", "terminal", {"command": f"echo x > {Path(rpt).as_posix()}"})[0])
        # Publish channel carrying this report: blocked below PUBLISH; unrelated publish: allowed.
        self.assertTrue(self.blocked("footercheck", "mcp__wordpress__create_post",
                                     {"title": "x", "source": rpt})[0])
        self.assertFalse(self.blocked("footercheck", "mcp__wordpress__create_post", {"title": "unrelated"})[0])
        # CLI check.
        Path(rpt).write_text("# R\n\n" + filled, encoding="utf-8")
        self.assertEqual(self.cli("footer", str(self.wd.root), "--check", rpt)[0], 0)

    def test_runlog_and_heartbeat(self):
        self.hook("runlog", "read_file", {"path": str(self.wd.spec_path)})
        self.hook("runlog", "terminal", {"command": "dda run v1 --variant v1 TOKEN=abc123"}, event="post_tool_call")
        self.hook("lockguard", "read_file", {"path": "x"})
        recs = chain.read_records(ledger.runs_log(self.wd))
        self.assertEqual([r["type"] for r in recs], ["seen", "done"])
        self.assertEqual((recs[1]["kind"], recs[1]["variant"]), ("data", "v1"))
        blob = (self.wd.analysis / recs[1]["blob"]).read_text(encoding="utf-8")
        self.assertNotIn("abc123", blob)
        hb = chain.read_records(ledger.heartbeat_log("b-1"))
        self.assertEqual([(r["hook"], r["decision"]) for r in hb], [("runlog", "logged"), ("runlog", "logged"),
                                                                     ("lockguard", "allow")])
        self.assertEqual(chain.verify(ledger.heartbeat_log("b-1")), [])

    def test_subagent_inherits_parent(self):
        b, _ = self.blocked("lockguard", "read_file", {"path": self.rawf}, session="child-9",
                            parent_session_id="b-1")
        self.assertTrue(b)
        self.hook("runlog", "read_file", {"path": "x"}, session="child-9", extra={"parent_session_id": "b-1"})
        rec = chain.read_records(ledger.runs_log(self.wd))[-1]
        self.assertEqual((rec["session"], rec.get("parent")), ("child-9", "b-1"))


class TestUnbound(Base):
    def test_unbound_access_log_and_g4(self):
        self.bind()
        self.lock()
        rawf = (self.raw / "orders.csv").as_posix()
        for h in ("lockguard", "evidenceguard", "rawguard", "defguard", "footercheck", "runlog"):
            self.assertEqual(self.hook(h, "read_file", {"path": rawf}, session="other-1"), (0, {}))
        self.hook("runlog", "read_file", {"path": "C:/unrelated.txt"}, session="other-1")
        recs = chain.read_records(ledger.unbound_log())
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["matches"][0]["alias"], "sales")
        rc, out, _ = self.cli("gate", "G4", str(self.wd.root))
        self.assertEqual(rc, 0, out)
        self.assertIn("post-data (unbound access)", out)
        self.assertIn("other-1", out)
        self.assertEqual(ledger.ledger_summary(self.wd)["effective_label"], "post-data (unbound access)")
        self.assertIn("G4: pass", self.wd.wayfinder_path.read_text(encoding="utf-8"))
        # After release: no more lines.
        self.cli("release", str(self.wd.root))
        self.hook("runlog", "read_file", {"path": rawf}, session="other-1")
        self.assertEqual(len(chain.read_records(ledger.unbound_log())), 1)

    def test_g4_decide_needs_config_approval(self):
        self.tier = "DECIDE"
        self.write_spec()
        self.lock()
        rc, out, _ = self.cli("gate", "G4", str(self.wd.root))
        self.assertEqual(rc, 1)
        self.assertIn("no config approval", out)
        self.assertIn("dda approve config", out)
        # G6 (phase 3) is built: a fresh lock with no data runs passes vacuously.
        rc, out, _ = self.cli("gate", "G6", str(self.wd.root))
        self.assertEqual(rc, 0, out)
        self.assertIn("G6 pass", out)

    def test_g4_decide_passes_with_unverified_config_approval(self):
        self.tier = "DECIDE"
        self.write_spec()
        self.lock()
        rc, out, _ = self.cli("approve", "config", "--no-sign", str(self.wd.root))
        self.assertEqual(rc, 0, out)
        rc, out, _ = self.cli("approved", "config", str(self.wd.root))
        self.assertEqual(rc, 0, out)
        self.assertIn("UNVERIFIED", out)
        rc, out, _ = self.cli("gate", "G4", str(self.wd.root))
        self.assertEqual(rc, 0, out)
        self.assertIn("unverified", out)


if __name__ == "__main__":
    unittest.main()
