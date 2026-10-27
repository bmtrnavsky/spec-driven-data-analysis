"""Phase-3 tests: `dda meta`, variant registration + freeze-on-first-run, the
kernel runner (audit hook, native wrappers, kernel record), and `dda gate G6`.
Run: python -m unittest discover -s tests -v
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from ddalib import chain, cli, footer, hooks, kernel, kernel_bootstrap, ledger, lockhash, lockstate  # noqa: E402
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

ORDERS = "id,amount\n1,10\n2,20\n3,30\n"
CUSTOMERS = "name,plan\nAlice,pro\nBob,free\nCarol,pro\n"

# Stub baseline modules so the kernel startup check passes in this env
# (importability is the §10.1a check; real libs are absent here).
STUBS = {
    "pandas": "",
    "numpy": "",
    "pyarrow": "",
    "polars": "",
    "duckdb": "def connect(*a, **k):\n    raise RuntimeError('stub')\n",
    "scipy": "",
    "statsmodels": "",
    "sklearn": "",
    "matplotlib": "",
    "seaborn": "",
    "openpyxl": "",
    "xlrd": "",
    "ipykernel": "",
    "IPython": "def get_ipython():\n    return None\n",
    "jupyter_client": "",
}


class Base(unittest.TestCase):
    tier = "EXPLORE"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p3-"))
        self._env = dict(os.environ)
        os.environ["DDA_HOME"] = str(self.tmp / "home")
        os.environ.pop("HERMES_SESSION_ID", None)
        self.raw = self.tmp / "raw"
        self.raw.mkdir()
        (self.raw / "orders.csv").write_text(ORDERS, encoding="utf-8")
        (self.raw / "customers.csv").write_text(CUSTOMERS, encoding="utf-8")
        self.wd = Workdir.at(self.tmp / "wd")
        self.cli("init", str(self.wd.root))
        subprocess.run(["git", "init", "-q", str(self.wd.root)], check=True)
        self.wd.config_path.write_text(
            "version: 1\ndefault_tier: DECIDE\ndata_roots:\n  sales:\n"
            f"    paths: [\"{self.raw.as_posix()}\"]\n    pii_columns: [\"name\"]\n"
            "    tool_patterns: [\"^mcp__warehouse__.*\"]\n  wh:\n"
            "    hosts: [\"db.example.internal\"]\n    url_prefixes: [\"https://data.example.internal/\"]\n"
            "publish_channels:\n  wordpress:\n    tool_patterns: [\"^mcp__wordpress__.*\"]\n",
            encoding="utf-8", newline="\n")
        (self.wd.definitions / "conversion.md").write_text(
            "---\nname: conversion\nversion: 1\n---\nOrders / sessions, daily grain, UTC.\n",
            encoding="utf-8", newline="\n")
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
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.main(list(args))
        return rc, out.getvalue(), err.getvalue()

    def hook(self, name, tool, args, session="b-1", event="pre_tool_call", **extra):
        payload = {"hook_event_name": event, "tool_name": tool, "tool_input": args, "session_id": session,
                   "cwd": str(self.wd.root), "extra": {"tool_call_id": "c1", **extra}}
        r = subprocess.run([sys.executable, "-I", "-S", str(REPO / "hooks" / "dda_hook.py"), name],
                           input=json.dumps(payload), capture_output=True, text=True, env=dict(os.environ))
        return r.returncode, json.loads(r.stdout)

    def lock(self, *extra):
        rc, out, err = self.cli("lock", str(self.wd.root), *extra)
        self.assertEqual(rc, 0, err)
        return out

    def bind_session(self, session="b-1"):
        rc, _, err = self.cli("start", str(self.wd.root), "--session", session)
        self.assertEqual(rc, 0, err)

    def register(self, vid="v1", **kw):
        d = {"why": "baseline cut", "header": {"population": "all", "model": "diff"}}
        d.update(kw)
        return kernel.register_variant(self.wd, vid, parent=d.get("parent"),
                                       why=d["why"], label=d.get("label"), header=d["header"])

    def write_variant_script(self, vid="v1", body=None):
        p = self.wd.analysis / "variants" / f"{vid}.py"
        p.write_text(body if body is not None else (
            "import csv, os\n"
            "root = os.environ.get('DDA_RAW', '')\n"
            "rows = list(csv.reader(open(os.path.join(root, 'orders.csv'))))\n"
            "os.makedirs('derived', exist_ok=True)\n"
            "open('derived/out.csv', 'w').write('n=%d\\n' % (len(rows) - 1))\n"),
            encoding="utf-8", newline="\n")
        return p


class TestMeta(Base):
    def test_meta_lists_names_types_counts_never_values(self):
        rc, out, err = self.cli("meta", "sales", str(self.wd.root))
        self.assertEqual(rc, 0, err)
        self.assertIn("orders.csv", out)
        self.assertIn("customers.csv", out)
        self.assertIn("column name: string", out)
        self.assertIn("column amount: integer", out)
        self.assertIn("3 rows", out)
        for secret in ("Alice", "Bob", "Carol", "pro", "free"):
            self.assertNotIn(secret, out)
        recs = [r for r in chain.read_records(ledger.runs_log(self.wd)) if r.get("kind") == "meta"]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["aliases"], ["sales"])

    def test_meta_locator_alias(self):
        rc, out, err = self.cli("meta", "wh", str(self.wd.root))
        self.assertEqual(rc, 0, err)
        self.assertIn("db.example.internal", out)
        self.assertIn("https://data.example.internal/", out)

    def test_meta_unknown_alias_fails_closed(self):
        rc, out, err = self.cli("meta", "nope", str(self.wd.root))
        self.assertNotEqual(rc, 0)
        self.assertIn("unknown alias", err)

    def test_meta_passthrough_in_hooks(self):
        self.lock()
        self.bind_session()
        rc, out = self.hook("lockguard", "terminal", {"command": "dda meta sales"})
        self.assertEqual(rc, 0, out)


class TestVariants(Base):
    def test_register_and_key_is_mechanical(self):
        self.lock()
        r1 = self.register("v1", header={"population": "all", "model": "diff"})
        r2 = self.register("v2", parent="v1", why="narrow", header={"population": "eu", "model": "diff"})
        self.assertNotEqual(r1["variant_key"], r2["variant_key"])
        self.assertEqual(r2["parent"], "v1")
        self.assertEqual(r2["header_diff"], ["population"])
        self.assertEqual(kernel.variant_key({"b": "1", "a": "2"}), kernel.variant_key({"a": "2", "b": "1"}))

    def test_register_idempotent_same_header(self):
        self.lock()
        r1 = self.register("v1")
        r2 = self.register("v1")
        self.assertEqual(r1["variant_key"], r2["variant_key"])
        self.assertEqual(len(kernel.registrations(self.wd)), 1)

    def test_changed_header_is_new_id(self):
        self.lock()
        self.register("v1")
        with self.assertRaises(DdaError):
            self.register("v1", header={"population": "eu", "model": "diff"})

    def test_register_fail_closed(self):
        with self.assertRaises(DdaError):
            self.register("v1")  # no lock yet
        self.lock()
        for kw in ({"why": ""}, {"header": {}}, {"header": {"bogus": "x"}}, {"parent": "ghost"}):
            with self.assertRaises(DdaError, msg=kw):
                self.register(f"v-{kw.get('parent') or 'x'}", **kw)
        with self.assertRaises(DdaError):
            kernel.register_variant(self.wd, "Bad Id!", why="x", label=None, header={"model": "m"})

    def test_label_defaults_and_lock(self):
        self.lock()
        self.assertEqual(self.register("v1")["label"], "exploratory")  # pre-data lock
        self.assertIsNone(kernel.locked_variant_id(self.wd))
        kernel.mark_locked(self.wd, "v1")
        self.assertEqual(kernel.locked_variant_id(self.wd), "v1")
        with self.assertRaises(DdaError):
            kernel.mark_locked(self.wd, "ghost")

    def test_evidenceguard_freeze(self):
        self.lock()
        self.bind_session()
        self.register("v1")
        p = self.wd.analysis / "variants" / "v1.py"
        rc, _ = self.hook("evidenceguard", "write_file", {"path": str(p), "content": "x"})
        self.assertEqual(rc, 0)  # writable until first run
        chain.append(ledger.specs_tried(self.wd), {"type": "freeze", "variant": "v1", "frozen_hash": "abc"})
        rc, out = self.hook("evidenceguard", "write_file", {"path": str(p), "content": "y"})
        self.assertEqual(rc, 2)
        self.assertIn("frozen", out["message"])


class TestKernelRun(Base):
    def stub_baseline(self):
        d = self.tmp / "stubs"
        d.mkdir(exist_ok=True)
        for name, body in STUBS.items():
            (d / f"{name}.py").write_text(body, encoding="utf-8")
        os.environ["PYTHONPATH"] = str(d) + os.pathsep + os.environ.get("PYTHONPATH", "")
        return d

    def test_run_fails_closed_without_baseline(self):
        # This env has no data stack: the kernel must not start (§10.1a).
        self.lock()
        self.register("v1")
        self.write_variant_script("v1")
        with self.assertRaises(DdaError) as cm:
            kernel.do_run(self.wd, "v1", str(self.wd.analysis / "variants" / "v1.py"), [], seed=1)
        self.assertIn("does not start", str(cm.exception))

    def test_run_fails_closed_preflight(self):
        self.stub_baseline()
        with self.assertRaises(DdaError):
            kernel.do_run(self.wd, "v1", "x.py", [], seed=1)  # no lock
        self.lock()
        with self.assertRaises(DdaError):
            kernel.do_run(self.wd, "ghost", "x.py", [], seed=1)  # orphan: unregistered
        self.register("v1")
        with self.assertRaises(DdaError):
            kernel.do_run(self.wd, "v1", str(self.tmp / "evil.py"), [], seed=1)  # outside variants/

    def test_run_end_to_end_with_stub_stack(self):
        self.stub_baseline()
        self.lock()
        self.register("v1")
        sp = self.write_variant_script("v1")
        env_raw = {"DDA_RAW": str(self.raw)}
        os.environ.update(env_raw)
        rec = kernel.do_run(self.wd, "v1", str(sp), [], session="s-kernel", seed=7)
        self.assertEqual(rec["returncode"], 0)
        self.assertEqual(rec["seed"], 7)
        self.assertEqual(rec["variant"], "v1")
        self.assertIn("environment_hash", rec)
        self.assertTrue((self.wd.analysis / "runs" / "kernels" / f"{rec['run_id']}.json").is_file())
        body_hash = kernel.frozen_hash(self.wd, "v1")
        self.assertTrue(body_hash)
        # Second run, same body: fine.
        rec2 = kernel.do_run(self.wd, "v1", str(sp), [], session="s-kernel")
        self.assertEqual(rec2["returncode"], 0)
        self.assertEqual(kernel.frozen_hash(self.wd, "v1"), body_hash)
        # Changed script: new variant id required.
        sp.write_text(sp.read_text(encoding="utf-8") + "# tweak\n", encoding="utf-8")
        with self.assertRaises(DdaError) as cm:
            kernel.do_run(self.wd, "v1", str(sp), [], session="s-kernel")
        self.assertIn("frozen", str(cm.exception))
        # Evidence: data done with variant, run entries, kernel audit lines.
        dones = [r for r in chain.read_records(ledger.runs_log(self.wd))
                 if r.get("type") == "done" and r.get("kind") == "data"]
        self.assertTrue(all(r.get("variant") == "v1" for r in dones))
        audits = [r for r in chain.read_records(ledger.audit_log(self.wd)) if r.get("type") == "audit"]
        events = {r.get("event") for r in audits}
        self.assertTrue({"kernel-start", "kernel-stop", "open"} <= events)
        opens = [r for r in audits if r.get("event") == "open"]
        self.assertTrue(all(r.get("aliases") == ["sales"] for r in opens))
        # The kernel wrote derived output; the raw root is untouched.
        self.assertTrue((self.wd.root / "derived" / "out.csv").is_file())
        self.assertEqual((self.raw / "orders.csv").read_text(encoding="utf-8"), ORDERS)

    def test_kernel_refuses_raw_write_and_strange_host(self):
        self.lock()
        events = []

        class Ctx(kernel_bootstrap.Ctx):
            pass
        # Build a real Ctx against this workdir, then swap the logger.
        lock = lockstate.read_lock(self.wd)
        ctx = Ctx(self.wd, lock, "v1", "r1", "s", log_fn=lambda rec: events.append(rec))
        kernel_bootstrap.install_audit_hook(ctx)
        with self.assertRaises(kernel_bootstrap.KernelRefusal):
            open(self.raw / "orders.csv", "a").close()
        with self.assertRaises(kernel_bootstrap.KernelRefusal):
            open(self.raw / "orders.csv", "w").close()
        with open(self.raw / "orders.csv", newline="") as fh:
            fh.read(8)  # read allowed under a valid lock
        import socket as _s
        with self.assertRaises(kernel_bootstrap.KernelRefusal):
            _s.socket().connect(("169.254.169.254", 80))
        kinds = [e["event"] for e in events]
        self.assertIn("open-refused", kinds)
        self.assertIn("socket-connect", kinds)

    def test_bootstrap_self_test(self):
        r = subprocess.run([sys.executable, "-m", "ddalib.kernel_bootstrap", "--self-test"],
                           capture_output=True, text=True, cwd=str(REPO / "scripts"),
                           env={**os.environ, "PYTHONPATH": str(REPO / "scripts")})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(all(json.loads(r.stdout)["checks"].values()))


class TestG6(Base):
    def paired_session(self, session="s-g6"):
        self.cli("start", str(self.wd.root), "--session", session)
        self.hook("runlog", "terminal", {"command": "dda meta sales"}, session=session,
                  event="pre_tool_call", **{"tool_call_id": "c-g"})
        self.hook("runlog", "terminal", {"command": "dda meta sales"}, session=session,
                  event="post_tool_call", **{"tool_call_id": "c-g"})

    def test_g6_no_lock_fails(self):
        passed, reason, _ = ledger.gate_g6(self.wd)
        self.assertFalse(passed)
        self.assertIn("no spec.lock", reason)

    def test_g6_orphan_fails(self):
        self.lock()
        self.paired_session()
        chain.append(ledger.runs_log(self.wd), {"type": "done", "session": "s-g6", "tool": "terminal",
                                               "call": "c-orph", "aliases": ["sales"], "kind": "data",
                                               "variant": None})
        passed, reason, _ = ledger.gate_g6(self.wd)
        self.assertFalse(passed)
        self.assertIn("orphan", reason)

    def test_g6_pass_after_clean_run(self):
        d = self.tmp / "stubs"
        d.mkdir(exist_ok=True)
        for name, body in STUBS.items():
            (d / f"{name}.py").write_text(body, encoding="utf-8")
        os.environ["PYTHONPATH"] = str(d) + os.pathsep + os.environ.get("PYTHONPATH", "")
        self.lock()
        self.paired_session()
        self.register("v1")
        sp = self.write_variant_script("v1")
        os.environ["DDA_RAW"] = str(self.raw)
        kernel.do_run(self.wd, "v1", str(sp), [], session="s-g6", seed=3)
        kernel.mark_locked(self.wd, "v1")
        rc, out, err = self.cli("gate", "G6", str(self.wd.root))
        self.assertEqual(rc, 0, err + out)
        self.assertIn("G6 pass", out)
        self.assertIn("heartbeat complete", out)

    def test_g6_missing_kernel_record_fails(self):
        self.lock()
        self.paired_session()
        self.register("v1")
        chain.append(ledger.specs_tried(self.wd), {"type": "freeze", "variant": "v1",
                                                 "frozen_hash": "ab" * 32, "run_id": "r0"})
        chain.append(ledger.specs_tried(self.wd), {"type": "run", "variant": "v1", "run_id": "r0",
                                                  "body_hash": "ab" * 32, "kernel": "runs/kernels/r0.json",
                                                  "returncode": 0})
        passed, reason, _ = ledger.gate_g6(self.wd)
        self.assertFalse(passed)
        self.assertIn("no kernel record", reason)


class TestFooterVariants(Base):
    def test_footer_counts_distinct_variants(self):
        self.lock()
        self.assertEqual(footer.expected(self.wd)["n_tried"], 1)  # spec v1 only
        self.register("v1")
        self.register("v2", parent="v1", why="cut", header={"population": "eu", "model": "diff"})
        self.assertEqual(footer.expected(self.wd)["n_tried"], 3)


if __name__ == "__main__":
    unittest.main()
