"""Shared fixture helpers for the in-repo ddaprobe suite (tests/probes/).

Probes run as scripts (subprocess per probe from TestDdaprobeRegression)
and assert on OUTCOMES, not exit codes: the manifest
(tests/probes/MANIFEST.json) maps each probe filename to its one
expected token, and the regression test requires the probe to print
EXACTLY ONE `FINDING: <token>` line equal to it. An attack that
silently succeeds prints a different finding and fails the suite
(exit-code-only assertions were blind to N1/N2-class bypasses, which
exit 0 while laundering evidence).
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO))
os.environ["DDA_TEST_MODE"] = "1"

from tests.test_phase8 import P8Setup  # noqa: E402
from tests.test_phase7_round2 import P7R2Setup  # noqa: E402
from tests.test_phase9 import P9Setup  # noqa: E402


class F8(P8Setup):
    def runTest(self):
        pass


class F9(P9Setup):
    TIER = "This is a DECIDE analysis."
    DECISION = "Ship v2 or roll back."

    def runTest(self):
        pass


class F7(P7R2Setup):
    TIER = "This is a DECIDE analysis."
    RUNG = "glance"

    def runTest(self):
        pass


def new_fixture(kind="p8", prefix="dda-probe-"):
    """Fresh isolated workdir: git repo, identity, config, definitions, spec."""
    F = {"p8": F8, "f7": F7, "p9": F9}[kind]
    f = F()
    f.tmp = Path(tempfile.mkdtemp(prefix=prefix))
    os.environ["DDA_HOME"] = str(f.tmp / "home")
    os.environ["DDA_TEST_MODE"] = "1"
    f.raw = f.tmp / "raw"
    f.raw.mkdir()
    (f.raw / "orders.csv").write_text("id,amount\n1,10\n2,20\n", encoding="utf-8")
    from ddalib.layout import Workdir
    f.wd = Workdir.at(f.tmp / "wd")
    f.env = dict(os.environ)
    f.env["DDA_HOME"] = str(f.tmp / "home")
    f.env["DDA_TEST_MODE"] = "1"
    f.env["PYTHONPATH"] = str(REPO / "scripts") + os.pathsep + f.env.get("PYTHONPATH", "")
    f.cli("init", str(f.wd.root))
    git(f, "init", "-q")
    git(f, "config", "user.email", "t@t.t")
    git(f, "config", "user.name", "t")
    # Isolate the guard under test from line-ending noise: with the global
    # core.autocrlf=true, git workdir rewrites (stash pop, checkout,
    # reset) smudge chains to CRLF and every probe would block on
    # "not in canonical form" instead of the guard it targets.
    git(f, "config", "core.autocrlf", "false")
    git(f, "commit", "-q", "--allow-empty", "-m", "dda probe seed")
    if kind == "p8":
        f.write_config()
    else:
        f.wd.config_path.write_text(
            "version: 1\ndefault_tier: DECIDE\ndata_roots:\n  sales:\n"
            f"    paths: [\"{f.raw.as_posix()}\"]\n    tool_patterns: [\"^mcp__warehouse__.*\"]\n"
            "publish_channels:\n  wordpress:\n    tool_patterns: [\"^mcp__wordpress__.*\"]\n",
            encoding="utf-8")
    (f.wd.definitions / "conversion.md").write_text(
        "---\nname: conversion\nversion: 1\n---\nOrders / sessions, daily grain, UTC.\n",
        encoding="utf-8")
    from ddalib import lockhash
    f.pin = lockhash.load_definition(f.wd, "conversion").pin
    f.write_spec()
    return f


def git(f, *args):
    p = subprocess.run(["git", "-C", str(f.wd.root), *args],
                       capture_output=True, text=True)
    return p


def git_ok(f, *args):
    p = git(f, *args)
    assert p.returncode == 0, f"git {' '.join(args)} failed: {p.stdout + p.stderr}"
    return p.stdout.strip()


def finding(token):
    print(f"FINDING: {token}", flush=True)


def cleanup(f):
    import shutil
    shutil.rmtree(f.tmp, ignore_errors=True)


def evals_blocked_fixture(f):
    """Bound correction case with a FAILING deterministic check.

    Returns (approval_commit_sha,). Control: `evals run` exits 1.
    """
    from tests.test_phase9 import TestEvalsMatchRun
    f.lock()
    assert f.cli("profile")[0] == 0, "profile failed"
    f.register_and_run()
    TestEvalsMatchRun.write_bound_case(f, check="0" * 64)
    rc, out = f.cli("evals", "run", str(f.wd.root))
    assert rc == 1, f"control evals run should block (rc=1), got rc={rc}: {out}"
    sha = git_ok(f, "rev-parse", "HEAD")
    return sha


def g3_failed_fixture(f):
    """DECIDE/glance workdir where ONLY G3 fails (two failed goldfish rounds).

    Returns the goldfish dir. Control: G3 verdict is False.
    """
    from ddalib import evaluate as _ev
    f.write_spec()
    assert f.cli("lock")[0] == 0, "lock failed"
    assert f.cli("packet", "teardown")[0] == 0, "packet failed"
    for _ in range(2):
        rc, out = f.cli("review", "run", "teardown", stub="fail")
        assert "fail" in out.lower(), f"fail-stub review run recorded nothing: {out}"
    assert f.cli("approve", "spec", "--no-sign")[0] == 0
    assert f.cli("approved", "spec")[0] == 0
    v = _ev.evaluate(f.wd, "G3")["verdicts"]
    assert v["G3"][0] is False, f"control G3 should fail, got: {v['G3']}"
    return f.wd.analysis / "reviews" / "goldfish"


def g3_verdict(f):
    from ddalib import evaluate as _ev
    return _ev.evaluate(f.wd, "G3")["verdicts"]["G3"][0]
