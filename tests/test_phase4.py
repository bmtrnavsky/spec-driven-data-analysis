"""Blind-review follow-up regressions (deleg_e545ed3e).

1. `_was_blocked` trusts `extra.status` when present: a tool that ran and
   reported `status == "error"` is a tool error (kind=data), not a blocked
   call — even when the error text contains a block-like word
   (`BlockingIOError`, user code that raised on the word "blocked").
2. Human-only argv parsing: the `py` launcher counts as python, and the
   word-token backstop applies to `execute_code` only (terminal prose that
   merely mentions `dda release` no longer false-positives).
3. Released workdirs stay in exposure: a session that read data, released,
   and rebound elsewhere still labels post-data; a clean session does not.

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

from ddalib import binding, chain, hooks as _h, ledger, lockhash  # noqa: E402
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
        self.tmp = Path(tempfile.mkdtemp(prefix="dda-p4-"))
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
        from ddalib import cli as _cli  # noqa: F401
        self.pin = lockhash.load_definition(self.wd, "conversion").pin
        self.wd.spec_path.write_text(SPEC.format(h=self.pin.split("#")[1]), encoding="utf-8", newline="\n")

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cli(self, *args):
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


class WasBlockedTests(Base):
    def post(self, tool, args, extra, session="k-1", call="c9"):
        """Log a post_tool_call through runlog, return the done record."""
        binding.start(self.wd, session)
        p = {"hook_event_name": "post_tool_call", "tool_name": tool, "tool_input": args,
             "session_id": session, "cwd": str(self.wd.root),
             "extra": {"tool_call_id": call, **extra}}
        _h.runlog(_h.Ctx("runlog", p, {"session_id": session, "workdir": str(self.wd.root),
                                       "workdir_id": self.wd.id}))
        recs = [r for r in chain.read_records(ledger.runs_log(self.wd))
                if r.get("type") == "done" and r.get("call") == call]
        self.assertTrue(recs, f"no done record for {call}")
        return recs[-1]

    def test_real_blocked_status_is_blocked(self):
        rec = self.post("read_file", {"path": str(self.raw / "orders.csv")},
                        {"status": "blocked",
                         "result": json.dumps({"error": "dda lockguard: this call touches data root(s) sales"}),
                         "error_message": "dda lockguard: this call touches data root(s) sales"})
        self.assertEqual(rec["kind"], "blocked")
        self.assertEqual(rec["aliases"], [])

    def test_blocking_io_error_is_tool_error_not_block(self):
        # "BlockingIOError" contains the substring "block" but status=error:
        # the tool ran, the call was not blocked.
        rec = self.post("read_file", {"path": str(self.raw / "orders.csv")},
                        {"status": "error",
                         "result": json.dumps({"error": "BlockingIOError: [Errno 11] Resource temporarily unavailable"}),
                         "error_message": "BlockingIOError: [Errno 11] Resource temporarily unavailable"})
        self.assertEqual(rec["kind"], "data")
        self.assertIn("sales", rec["aliases"])
        self.assertFalse(_h._was_blocked({"extra": {"status": "error",
            "result": json.dumps({"error": "BlockingIOError: x"})}}))

    def test_execute_code_raised_on_word_blocked_is_data(self):
        # The tool ran and produced data output; "blocked" in the raised
        # error text does not make it a blocked call.
        rec = self.post("execute_code", {"code": f"open(r'{self.raw / 'orders.csv'}').read()"},
                        {"status": "error",
                         "result": json.dumps({"status": "error", "output": "id,amount\n1,10\n",
                                               "error": "RuntimeError: blocked"}),
                         "error_message": "RuntimeError: blocked"}, call="c10")
        self.assertEqual(rec["kind"], "data")
        self.assertIn("sales", rec["aliases"])

    def test_plain_file_not_found_is_data(self):
        rec = self.post("read_file", {"path": str(self.raw / "orders.csv")},
                        {"status": "error",
                         "result": json.dumps({"error": "File not found: x"}),
                         "error_message": "File not found: x"}, call="c11")
        self.assertEqual(rec["kind"], "data")

    def test_statusless_dict_body_still_counts_as_blocked(self):
        # Fallback for older/synthetic payloads with no extra.status.
        self.assertTrue(_h._was_blocked({"extra": {"result": {"blocked": True}}}))
        self.assertTrue(_h._was_blocked({"extra": {"result": {"error": "blocked by policy"}}}))
        self.assertFalse(_h._was_blocked({"extra": {"result": {"error": "BlockingIOError: x"}}}))
        self.assertFalse(_h._was_blocked({"extra": {"result": {"content": "id,amount\n1,10\n"}}}))


class HumanOnlyTests(Base):
    def test_py_launcher_release_blocked(self):
        self.bind("h-1")
        for cmd in (f"py {REPO.as_posix()}/scripts/dda.py release {self.wd.root}",
                    f"py -3 {REPO.as_posix()}/scripts/dda.py abandon {self.wd.root} --reason x"):
            b, msg = self.blocked("lockguard", "terminal", {"command": cmd}, session="h-1")
            self.assertTrue(b, cmd)
            self.assertIn("human-only", msg)

    def test_py_launcher_status_still_passes_is_clean(self):
        from ddalib.hookentry import is_clean_dda_invocation
        self.assertTrue(is_clean_dda_invocation(
            "terminal", {"command": f"py {REPO.as_posix()}/scripts/dda.py status"}))
        self.assertFalse(is_clean_dda_invocation(
            "terminal", {"command": f"py {REPO.as_posix()}/scripts/dda.py release {self.wd.root}"}))
        self.assertTrue(is_clean_dda_invocation(
            "terminal", {"command": "python -m ddalib.cli status"}))
        self.assertFalse(is_clean_dda_invocation(
            "terminal", {"command": f"python -m ddalib.cli release {self.wd.root}"}))

    def test_mentioning_release_in_prose_is_allowed(self):
        self.bind("h-2")
        for cmd in ('git commit -m "prep for dda release"',
                    'echo "ask Brad to run dda release" >> C:/x/notes.txt',
                    f"dda lock {self.wd.root} --amend \"release notes\"",
                    "dda status"):
            for h in ("lockguard", "evidenceguard", "rawguard", "defguard", "footercheck"):
                b, _ = self.blocked(h, "terminal", {"command": cmd}, session="h-2")
                self.assertFalse(b, f"{h} blocked {cmd!r}")

    def test_shell_wrapper_release_blocked(self):
        self.bind("h-4")
        cmds = [
            'bash -c "dda release WD"',
            "bash -c 'dda abandon WD --reason x'",
            "sh -c 'dda release WD'",
            "cmd /c dda release WD",
            "cmd.exe /c dda abandon WD --reason x",
            'powershell -Command "dda release WD"',
            'powershell -NoProfile -Command "dda abandon WD --reason x"',
            'pwsh -c "dda release WD"',
            "sudo bash -c 'dda release WD'",
            "dda status && dda release WD",
            "dda status; dda abandon WD --reason x",
            "dda status | cat; dda release WD",
            "(dda release WD)",
            "$(echo dda) release WD",
            "`echo dda` abandon WD --reason x",
            'bash -c "dda status && dda release WD"',
            'powershell -Command "dda status; dda abandon WD --reason x"',
            "bash -lc 'dda release WD'",
            "sh -ic 'dda abandon WD --reason x'",
            "bash -cl 'dda release WD'",
            "bash -ci 'dda abandon WD --reason x'",
            "bash -licsu 'dda release WD'",
            'bash --command "dda release WD"',
            "d''da release WD",
            'bash -c \'sh -c "dda release WD"\'',
            'bash -c "dda release WD>out.txt"',
            "dda release WD>out.txt",
            "python -m ddalib.cli release WD",
            "python -m ddalib.cli abandon WD --reason x",
            "python -mddalib.cli release WD",
            "python -mdda abandon WD --reason x",
            "python scripts/ddalib/cli.py release WD",
            "python -W ignore scripts/ddalib/cli.py release WD",
            "python -W ignore -m ddalib.cli release WD",
            "python -u -X utf8 -m ddalib.cli abandon WD --reason x",
        ]
        for raw in cmds:
            cmd = raw.replace("WD", str(self.wd.root))
            for h in ("lockguard", "evidenceguard", "rawguard", "defguard", "footercheck"):
                b, msg = self.blocked(h, "terminal", {"command": cmd}, session="h-4")
                self.assertTrue(b, f"{h} missed {cmd!r}")
                self.assertIn("human-only", msg)

    def test_shell_wrapper_status_still_allowed(self):
        self.bind("h-5")
        for cmd in ('bash -c "dda status"',
                    "cmd /c dda status",
                    '(dda status)',
                    'echo "ask Brad to run dda release"',
                    'python -m ddalib.cli status',
                    'python -c "print(1 if a<b else 2)"',
                    'echo "a>b"',
                    'dda status > C:/x/notes.txt'):
            for h in ("lockguard", "evidenceguard", "rawguard", "defguard", "footercheck"):
                b, _ = self.blocked(h, "terminal", {"command": cmd}, session="h-5")
                self.assertFalse(b, f"{h} blocked {cmd!r}")

    def test_execute_code_subprocess_list_still_blocked(self):
        self.bind("h-3")
        b, msg = self.blocked(
            "lockguard", "execute_code",
            {"code": f"import subprocess; subprocess.run([\"dda\", \"release\", r\"{self.wd.root}\"])"},
            session="h-3")
        self.assertTrue(b)
        self.assertIn("human-only", msg)


class ReleasedExposureTests(Base):
    def log_read(self, wd, session, call, path=None):
        p = {"hook_event_name": "post_tool_call", "tool_name": "read_file",
             "tool_input": {"path": str(path or self.raw / "orders.csv")},
             "session_id": session, "extra": {"tool_call_id": call, "status": "ok"}}
        _h.runlog(_h.Ctx("runlog", p, {"session_id": session, "workdir": str(wd.root),
                                       "workdir_id": wd.id}))

    def log_call(self, wd, session, call, tool="terminal", args=None):
        p = {"hook_event_name": "post_tool_call", "tool_name": tool,
             "tool_input": args or {"command": "dda status"},
             "session_id": session, "extra": {"tool_call_id": call, "status": "ok"}}
        _h.runlog(_h.Ctx("runlog", p, {"session_id": session, "workdir": str(wd.root),
                                       "workdir_id": wd.id}))

    def second_workdir(self, name, alias="sales", raw=None):
        raw = raw or self.raw
        wd = Workdir.at(self.tmp / name)
        self.cli("init", str(wd.root))
        subprocess.run(["git", "init", "-q", str(wd.root)], check=True)
        wd.config_path.write_text(
            "version: 1\ndefault_tier: EXPLORE\ndata_roots:\n"
            f"  {alias}:\n    paths: [\"{raw.as_posix()}\"]\n",
            encoding="utf-8", newline="\n")
        (wd.definitions / "conversion.md").write_text(
            "---\nname: conversion\nversion: 1\n---\nOrders / sessions, daily grain, UTC.\n",
            encoding="utf-8", newline="\n")
        pin = lockhash.load_definition(wd, "conversion").pin
        spec = SPEC.replace("`sales`", f"`{alias}`").format(h=pin.split("#")[1])
        wd.spec_path.write_text(spec, encoding="utf-8", newline="\n")
        return wd

    def test_release_keeps_session_history_in_new_workdir(self):
        other = self.second_workdir("wd2")
        binding.start(self.wd, "hop")
        self.log_read(self.wd, "hop", "r1")
        rc, _, err = self.cli("release", str(self.wd.root))
        self.assertEqual(rc, 0, err)
        reg = binding.read_registry()
        self.assertIn(self.wd.id, reg["released"])
        self.assertNotIn(self.wd.id, reg["workdirs"])
        binding.start(other, "hop")
        self.log_call(other, "hop", "b1")  # session seen in B: hop attribution applies
        exp = ledger.exposure(other, ["sales"], None, None)
        self.assertTrue(exp["session_history"], "released reads must stay visible via session_history")
        self.assertIn("post-data", ledger.label_for(exp, "none known"))

    def test_abandon_keeps_session_history_in_new_workdir(self):
        other = self.second_workdir("wd2")
        binding.start(self.wd, "hop-a")
        self.log_read(self.wd, "hop-a", "r1")
        rc, _, err = self.cli("abandon", str(self.wd.root), "--reason", "x")
        self.assertEqual(rc, 0, err)
        reg = binding.read_registry()
        self.assertIn(self.wd.id, reg["released"])
        binding.start(other, "hop-a")
        self.log_call(other, "hop-a", "b1")
        exp = ledger.exposure(other, ["sales"], None, None)
        self.assertTrue(exp["session_history"])
        self.assertIn("post-data", ledger.label_for(exp, "none known"))

    def test_rootless_hop_detected_via_session_history(self):
        # No shared locator between C (where the read landed) and B: only
        # the session hopped, so session_history is the signal.
        alt = self.tmp / "alt"
        alt.mkdir()
        (alt / "o.csv").write_text("x\n", encoding="utf-8")
        a = self.second_workdir("wda", alias="other", raw=alt)
        c = self.second_workdir("wdc", alias="other", raw=alt)
        b = self.second_workdir("wdb")
        binding.start(c, "dummy")
        binding.start(a, "so")
        self.log_read(c, "so", "rc1", path=alt / "o.csv")
        rc, _, err = self.cli("release", str(a.root))
        self.assertEqual(rc, 0, err)
        binding.start(b, "so")
        self.log_call(b, "so", "b1")
        exp = ledger.exposure(b, ["sales"], None, None)
        self.assertFalse(exp["other_workdirs"])
        self.assertTrue(exp["session_history"], "rootless hop must attribute via session_history")
        self.assertIn("post-data", ledger.label_for(exp, "none known"))

    def test_release_line_attributes_session_without_done_lines(self):
        # The session never left a done line in A's log, but A's release
        # line names it and it read data (in B's own log): session_history
        # carries a kind=release entry.
        binding.start(self.wd, "so")
        rc, _, err = self.cli("release", str(self.wd.root))
        self.assertEqual(rc, 0, err)
        other = self.second_workdir("wd2")
        binding.start(other, "so")
        self.log_read(other, "so", "rb1")
        exp = ledger.exposure(other, ["sales"], None, None)
        kinds = [f.get("kind") for f in exp["session_history"]]
        self.assertIn("release", kinds, "release-line attribution must name the session")
        self.assertIn("post-data", ledger.label_for(exp, "none known"))

    def test_unrelated_session_not_charged_with_hopping(self):
        # A different session did the reads: no session_history for the
        # fresh session — but the released analysis of the same data still
        # counts as prior exposure via other_workdirs (anti-laundering).
        binding.start(self.wd, "other")
        self.log_read(self.wd, "other", "o1")
        self.cli("release", str(self.wd.root))
        other = self.second_workdir("wd2")
        binding.start(other, "fresh")
        self.log_call(other, "fresh", "b1")
        exp = ledger.exposure(other, ["sales"], None, None)
        self.assertFalse(exp["session_history"])
        self.assertTrue(exp["other_workdirs"])
        self.assertIn("post-data", ledger.label_for(exp, "none known"))

    def test_no_reads_anywhere_is_pre_data(self):
        other = self.second_workdir("wd2")
        binding.start(other, "fresh")
        self.log_call(other, "fresh", "b1")
        exp = ledger.exposure(other, ["sales"], None, None)
        self.assertFalse(exp["session_history"])
        self.assertFalse(exp["other_workdirs"])
        self.assertEqual(ledger.label_for(exp, "none known"), "pre-data")

    def test_deleted_released_workdir_is_pre_data(self):
        binding.start(self.wd, "del")
        self.log_read(self.wd, "del", "d1")
        self.cli("release", str(self.wd.root))
        shutil.rmtree(self.wd.root, ignore_errors=True)
        other = self.second_workdir("wd2")
        binding.start(other, "del")
        self.log_call(other, "del", "b1")
        exp = ledger.exposure(other, ["sales"], None, None)
        self.assertFalse(exp["session_history"])
        self.assertEqual(ledger.label_for(exp, "none known"), "pre-data")


class ApprovalsTests(Base):
    """Phase-4 approvals: `dda approve` / `dda approved`, config chain, G4."""

    def lock(self, *extra):
        rc, out, err = self.cli("lock", str(self.wd.root), *extra)
        self.assertEqual(rc, 0, err)
        return out

    def test_config_approvers_validation(self):
        self.wd.config_path.write_text(
            "version: 1\ndefault_tier: EXPLORE\napprovers:\n  - name: brad\n", encoding="utf-8")
        from ddalib.layout import DdaError, load_config
        with self.assertRaises(DdaError):
            load_config(self.wd)
        self.wd.config_path.write_text(
            "version: 1\ndefault_tier: EXPLORE\napprovers:\n  - name: brad\n    fingerprint: SHA256:abc123\n",
            encoding="utf-8")
        cfg = load_config(self.wd)
        self.assertEqual(cfg["approvers"][0]["name"], "brad")

    def test_approve_records_unverified_and_gates(self):
        self.lock()
        rc, out, err = self.cli("approve", "config", "--no-sign", str(self.wd.root))
        self.assertEqual(rc, 0, err)
        self.assertIn("UNSIGNED (unverified)", out)
        from ddalib import approvals
        ch = approvals.current_artifact(self.wd, "config")
        self.assertTrue((self.wd.analysis / "approvals" / f"config-{ch}.json").is_file())
        rc, out, err = self.cli("approved", "config", str(self.wd.root))
        self.assertEqual(rc, 0, err)
        self.assertIn("UNVERIFIED", out)
        recs = [r for r in chain.read_records(ledger.approvals_index(self.wd))
                if r.get("type") == "approval"]
        self.assertEqual(len(recs), 1)
        self.assertFalse(recs[0]["verified"])
        # EXPLORE gate passes with disclosure.
        rc, out, _ = self.cli("gate", "G4", str(self.wd.root))
        self.assertEqual(rc, 0, out)
        self.assertIn("unverified", out)

    def test_approve_rejects_unknown_kind_and_bad_artifact(self):
        self.lock()
        rc, _, err = self.cli("approve", "bogus", "--no-sign", str(self.wd.root))
        self.assertNotEqual(rc, 0)
        rc, _, _ = self.cli("approve", "config", "../evil", "--no-sign", str(self.wd.root))
        self.assertNotEqual(rc, 0)

    def test_approved_missing_file_fails(self):
        self.lock()
        rc, out, _ = self.cli("approved", "config", str(self.wd.root))
        self.assertEqual(rc, 0)  # recorded, but UNVERIFIED
        self.assertIn("UNVERIFIED", out)

    def test_g4_rejects_stale_config_approval(self):
        self.lock()
        from ddalib import approvals
        old = approvals.current_artifact(self.wd, "config")
        self.assertEqual(self.cli("approve", "config", "--no-sign", str(self.wd.root))[0], 0)
        self.assertEqual(self.cli("approved", "config", str(self.wd.root))[0], 0)
        # Change the config: the old approval no longer covers the new hash.
        cfg = self.wd.config_path.read_text(encoding="utf-8")
        self.wd.config_path.write_text(cfg + "# touch\n", encoding="utf-8")
        self.lock("--amend", "touch config")
        self.assertNotEqual(approvals.current_artifact(self.wd, "config"), old)
        rc, out, _ = self.cli("gate", "G4", str(self.wd.root))
        self.assertEqual(rc, 0, out)  # EXPLORE discloses the unapproved config
        self.assertIn("no config approval", out)

    def test_agent_cannot_approve_through_hooks(self):
        self.bind()
        for cmd in ("dda approve config", "dda release", "git commit -S -m x"):
            b, _ = self.blocked("lockguard", "terminal", {"command": cmd})
            self.assertTrue(b, cmd)


class DoctorTests(Base):
    def test_doctor_json_shape(self):
        rc, out, err = self.cli("doctor", "--json")
        self.assertIn(rc, (0, 1), err)
        rep = json.loads(out)
        self.assertIn("sections", rep)
        self.assertIn("keys", rep["sections"])
        self.assertIn("hooks", rep["sections"])
        self.assertIn("interpreter", rep["sections"])
        names = [c["name"] for c in rep["sections"]["keys"]]
        self.assertIn("gpg-agent", names)
        self.assertIn("ssh-agent", names)
        self.assertIn("git-signing-config", names)
        for checks in rep["sections"].values():
            for c in checks:
                self.assertIn(c["status"], ("pass", "fail", "skip"))

    def test_doctor_sees_auto_signing(self):
        rc, out, err = self.cli("doctor", "--json")
        self.assertIn(rc, (0, 1), err)
        before = json.loads(out)
        subprocess.run(["git", "config", "--global", "commit.gpgsign", "true"], check=True)
        try:
            rc2, out2, _ = self.cli("doctor", "--json")
        finally:
            subprocess.run(["git", "config", "--global", "--unset", "commit.gpgsign"], check=True)
        after = json.loads(out2)
        git_checks = [c for c in after["sections"]["keys"] if c["name"] == "git-signing-config"]
        self.assertTrue(git_checks and git_checks[0]["status"] == "fail")
        self.assertEqual(rc2, 1)
        self.assertIn("git-signing-config", after["key_failures"])

    def test_doctor_workdir_section(self):
        rc, out, _ = self.cli("lock", str(self.wd.root))
        self.assertEqual(rc, 0)
        rc, out, _ = self.cli("doctor", str(self.wd.root), "--json")
        rep = json.loads(out)
        self.assertIn("workdir", rep["sections"])
        names = [c["name"] for c in rep["sections"]["workdir"]]
        self.assertIn("lock-state", names)
        self.assertIn("evidence-chains", names)
        self.assertIn("heartbeat-live", names)


if __name__ == "__main__":
    unittest.main()
