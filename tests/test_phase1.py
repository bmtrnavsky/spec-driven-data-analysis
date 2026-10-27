"""Phase-1 unit tests: yamlsub, layout/config, lock hashing, binding, CLI, hook entry.
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

from ddalib import binding, cli, hookentry, lockhash, yamlsub  # noqa: E402
from ddalib.layout import DdaError, Workdir, load_config  # noqa: E402

SPEC = """# Analysis spec

## Question
Did checkout v2 raise conversion?

## Tier
This is a DECIDE analysis.

## Rung
quick-cut

## Data sources
- `sales` — orders table

## Metrics
- conversion@1#{h}
"""


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-test-"))
        self._env = dict(os.environ)
        os.environ["DDA_HOME"] = str(self.tmp / "home")
        self.wd = Workdir.at(self.tmp / "wd")
        self.run_cli("init", str(self.wd.root))
        self.wd.config_path.write_text(
            'version: 1\ndefault_tier: DECIDE\ndata_roots:\n  sales:\n    paths: ["D:/data/sales"]\n',
            encoding="utf-8", newline="\n")
        (self.wd.definitions / "conversion.md").write_text(
            "---\nname: conversion\nversion: 1\n---\nOrders / sessions, daily grain, UTC.\n", encoding="utf-8", newline="\n")
        self.pin_hash = lockhash.load_definition(self.wd, "conversion").content_hash
        self.wd.spec_path.write_text(SPEC.format(h=self.pin_hash), encoding="utf-8", newline="\n")

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.main(list(args))
        return rc, out.getvalue(), err.getvalue()


class TestYamlSubset(unittest.TestCase):
    def test_basic(self):
        d = yamlsub.loads('a: 1\nb:\n  c: "x # y"  # comment\n  d: [p, "q", 3]\ne:\n  - k: v\n    z: true\n  - plain\n')
        self.assertEqual(d, {"a": 1, "b": {"c": "x # y", "d": ["p", "q", 3]}, "e": [{"k": "v", "z": True}, "plain"]})

    def test_rejects(self):
        for bad in ("a: &x 1\n", "a: |\n  t\n", "a: 1\na: 2\n", "a:\n\tb: 1\n", "a: {b: 1}\n", "a: 1\n---\nb: 2\n",
                    "a: b: c\n", '- a\nb: 1\n'):
            with self.subTest(bad=bad), self.assertRaises(yamlsub.YamlSubsetError):
                yamlsub.loads(bad)

    def test_template_parses(self):
        self.assertEqual(yamlsub.load_file(REPO / "templates" / "config.yaml")["version"], 1)


class TestConfig(Base):
    def test_valid(self):
        self.assertIn("sales", load_config(self.wd)["data_roots"])

    def test_invalid_fail_closed(self):
        for body in ('version: 2\n', 'version: 1\ndata_roots:\n  Bad Alias:\n    paths: [x]\n',
                     'version: 1\ndata_roots:\n  a:\n    pii: true\n',
                     'version: 1\ndata_roots:\n  a:\n    paths: [x]\n    conn: "postgres://u:pw@h"\n',
                     'version: 1\ndata_roots:\n  a:\n    tool_patterns: ["(unclosed"]\n',
                     'version: 1\ndefault_tier: YOLO\n'):
            with self.subTest(body=body):
                self.wd.config_path.write_text(body, encoding="utf-8", newline="\n")
                with self.assertRaises(DdaError):
                    load_config(self.wd)


class TestLockHash(Base):
    def h(self, text=None):
        return lockhash.compute(self.wd, text).lock_hash

    def test_components(self):
        c = lockhash.compute(self.wd)
        self.assertEqual(c.pins, [f"conversion@1#{self.pin_hash}"])
        self.assertEqual(c.aliases, ["sales"])
        self.assertEqual((c.tier, c.rung), ("DECIDE", "quick-cut"))
        self.assertEqual(len(c.lock_hash), 64)

    def test_whitespace_and_crlf_invariant(self):
        base = self.h()
        spec = SPEC.format(h=self.pin_hash)
        self.assertEqual(base, self.h(spec.replace("\n", "\r\n")))
        self.assertEqual(base, self.h(spec.replace("Did checkout", "Did   checkout").replace("\n## Tier", "\n\n\n## Tier  ")))

    def test_section_order_invariant(self):
        spec = SPEC.format(h=self.pin_hash)
        a, b = spec.split("## Data sources")
        tier_block = "## Tier\nThis is a DECIDE analysis.\n\n"
        reordered = a.replace(tier_block, "") + "## Data sources" + b + "\n" + tier_block
        self.assertEqual(self.h(), self.h(reordered))

    def test_content_change_changes_hash(self):
        spec = SPEC.format(h=self.pin_hash)
        self.assertNotEqual(self.h(), self.h(spec.replace("conversion?", "revenue?")))

    def test_config_change_changes_hash(self):
        base = self.h()
        self.wd.config_path.write_text(self.wd.config_path.read_text() + "# note\n", encoding="utf-8", newline="\n")
        self.assertNotEqual(base, self.h())

    def test_config_crlf_invariant(self):
        base = self.h()
        self.wd.config_path.write_bytes(self.wd.config_path.read_bytes().replace(b"\n", b"\r\n"))
        self.assertEqual(base, self.h())

    def test_data_contents_not_hashed(self):
        base = self.h()
        (self.wd.root / "derived" / "x.csv").write_text("1,2\n", encoding="utf-8", newline="\n")
        self.assertEqual(base, self.h())

    def test_stale_pin_fails(self):
        d = self.wd.definitions / "conversion.md"
        d.write_text(d.read_text() + "Excludes bots.\n", encoding="utf-8", newline="\n")
        with self.assertRaisesRegex(DdaError, "content hash"):
            self.h()

    def test_wrong_version_fails(self):
        with self.assertRaisesRegex(DdaError, "version"):
            self.h(SPEC.format(h=self.pin_hash).replace("conversion@1#", "conversion@2#"))

    def test_missing_definition_fails(self):
        with self.assertRaisesRegex(DdaError, "not found"):
            self.h(SPEC.format(h=self.pin_hash) + "- aov@1#abcdefabcdef\n")

    def test_unknown_alias_fails(self):
        with self.assertRaisesRegex(DdaError, "not declared"):
            self.h(SPEC.format(h=self.pin_hash).replace("- `sales`", "- `web`"))

    def test_unknown_and_duplicate_sections_fail(self):
        spec = SPEC.format(h=self.pin_hash)
        with self.assertRaisesRegex(DdaError, "unknown section"):
            self.h(spec + "\n## Secret extra plan\nx\n")
        with self.assertRaisesRegex(DdaError, "duplicate"):
            self.h(spec + "\n## Question\nother\n")

    def test_heading_in_code_fence_ignored(self):
        spec = SPEC.format(h=self.pin_hash).replace("## Rung", "```\n## Not a heading\n```\n\n## Rung")
        self.h(spec)

    def test_ambiguous_tier_fails(self):
        with self.assertRaisesRegex(DdaError, "more than one tier"):
            self.h(SPEC.format(h=self.pin_hash).replace("DECIDE analysis", "DECIDE or PUBLISH analysis"))

    def test_definition_whitespace_invariant(self):
        base = self.h()
        d = self.wd.definitions / "conversion.md"
        d.write_bytes(d.read_bytes().replace(b"\n", b"\r\n") + b"\r\n\r\n")
        self.assertEqual(base, self.h())

    def test_cli_hash_matches(self):
        rc, out, _ = self.run_cli("hash", str(self.wd.root))
        self.assertEqual((rc, out.strip()), (0, self.h()))


class TestBindingAndCli(Base):
    def test_start_release_status(self):
        rc, _, err = self.run_cli("start", str(self.wd.root), "--session", "s-1")
        self.assertEqual(rc, 0, err)
        st = binding.status()
        self.assertIn(self.wd.id, st["active"])
        self.assertEqual(st["active"][self.wd.id]["aliases"], ["sales"])
        rc, _, err = self.run_cli("start", str(self.tmp / "other"), "--session", "s-1")
        self.assertNotEqual(rc, 0)
        other = Workdir.at(self.tmp / "other")
        self.run_cli("init", str(other.root))
        rc, _, err = self.run_cli("start", str(other.root), "--session", "s-1")
        self.assertNotEqual(rc, 0)
        self.assertIn("--rebind", err)
        rc, _, _ = self.run_cli("release", str(self.wd.root))
        self.assertEqual(rc, 0)
        st = binding.status()
        self.assertEqual((st["active"], st["sessions"]), ({}, []))

    def test_bad_session_and_milestone(self):
        rc, _, _ = self.run_cli("start", str(self.wd.root), "--session", "../../evil")
        self.assertNotEqual(rc, 0)
        rc, _, _ = self.run_cli("start", str(self.wd.root), "--session", "s", "--milestone", "nope")
        self.assertNotEqual(rc, 0)

    def test_init_refuses_reinit(self):
        rc, _, _ = self.run_cli("init", str(self.wd.root))
        self.assertNotEqual(rc, 0)

    def test_pending_commands_fail_closed(self):
        for name in cli.PENDING:
            with self.subTest(name=name):
                rc, _, err = self.run_cli(name)
                self.assertEqual(rc, cli.EXIT_NOT_IMPLEMENTED)
                self.assertIn("not implemented", err)

    def test_install_block(self):
        rc, out, _ = self.run_cli("install")
        self.assertEqual(rc, 0)
        cfg = yamlsub.loads(out)
        pre = cfg["hooks"]["pre_tool_call"]
        blocking = [h for h in pre if not h["command"].endswith(" runlog")]
        self.assertEqual(len(blocking), 5)
        self.assertTrue(all(h["fail_closed"] is True for h in blocking))
        self.assertTrue(all(" -I -S " in h["command"] for h in pre))


class TestHookEntry(Base):
    def hook(self, name, payload, raw=None):
        r = subprocess.run([sys.executable, "-I", "-S", str(REPO / "hooks" / "dda_hook.py"), name],
                           input=raw if raw is not None else json.dumps(payload),
                           capture_output=True, text=True, env=dict(os.environ))
        return r.returncode, json.loads(r.stdout)

    def test_unbound_never_blocks(self):
        for h in hookentry.BLOCKING + hookentry.SIDE_EFFECT:
            self.assertEqual(self.hook(h, {"session_id": "nobody", "tool_name": "terminal",
                                           "tool_input": {"command": "rm -rf /"}}), (0, {}))

    def test_bound_blocks_and_allows_dda(self):
        self.run_cli("start", str(self.wd.root), "--session", "b-1")
        # Phase 2: a read of a declared root before lock blocks with the fix named.
        rc, out = self.hook("lockguard", {"session_id": "b-1", "tool_name": "read_file",
                                          "tool_input": {"path": "D:/data/sales/x.csv"}})
        self.assertEqual((rc, out["action"]), (2, "block"))
        self.assertIn("dda lock", out["message"])
        self.assertEqual(self.hook("lockguard", {"session_id": "b-1", "tool_name": "terminal",
                                                 "tool_input": {"command": "dda status"}}), (0, {}))
        self.assertEqual(self.hook("runlog", {"session_id": "b-1", "tool_name": "read_file"}), (0, {}))

    def test_no_active_workdir_bad_payload_is_noop(self):
        self.assertEqual(self.hook("lockguard", None, raw="garbage"), (0, {}))

    def test_clean_dda_invocation(self):
        ok = ["dda status", 'python "C:/x/scripts/dda.py" hash', "C:/p/dda.exe status"]
        bad = ["dda approve spec", "dda release", "dda abandon wd --reason x", "dda.cmd release",
               "dda status; cat x", "dda status | tee", "dda $(cat x)", "ddax status",
               "python evil.py dda.py", "cat dda", "dda status\ncat x", "dda `id`", "dda status > out"]
        for c in ok:
            self.assertTrue(hookentry.is_clean_dda_invocation("terminal", {"command": c}), c)
        for c in bad:
            self.assertFalse(hookentry.is_clean_dda_invocation("terminal", {"command": c}), c)
        self.assertFalse(hookentry.is_clean_dda_invocation("execute_code", {"command": "dda status"}))
        self.assertFalse(hookentry.is_clean_dda_invocation("terminal", {"command": "dda status", "background": True}))


if __name__ == "__main__":
    unittest.main()
