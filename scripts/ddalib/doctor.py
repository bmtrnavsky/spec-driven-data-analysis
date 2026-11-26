"""`dda doctor` health checks (spec §6.8, §6.9, §4.5).

Sections: interpreter, hook entry point (imports + dry-run of every
blocking hook), and, for a given workdir, lock state, evidence chains,
heartbeat liveness, and the active-workdir registry.

Approvals carry no key material (owner order, 2026-11-25): a chat yes
recorded by `dda approve` is the approval, so there is no approver key,
agent, or git-signing config to check and nothing to downgrade.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .layout import REPO_ROOT, DdaError, Workdir, dda_home

BLOCKING_HOOKS = ("lockguard", "evidenceguard", "rawguard", "defguard", "footercheck")


def _check(status: str, name: str, detail: str = "") -> dict:
    return {"status": status, "name": name, "detail": detail}


# Approver keys are gone (owner order, 2026-11-25): DDA records Brad's chat
# yes and never a signature, so there is no key, agent, or signing config to
# check. The section is kept (empty) so old `doctor` output schemas and the
# sections the CLI prints do not shift under a reader.

# ---------- runtime checks (§6.9) ----------

def interpreter_checks() -> list[dict]:
    out = []
    exe = Path(sys.executable)
    if exe.is_file() and sys.version_info >= (3, 11):
        out.append(_check("pass", "interpreter",
                          f"{exe} (Python {sys.version_info.major}.{sys.version_info.minor})"))
    else:
        out.append(_check("fail", "interpreter", f"{sys.executable}: missing or Python < 3.11"))
    try:
        import ddalib.chain  # noqa: F401
        import ddalib.hookentry  # noqa: F401
        import ddalib.hooks  # noqa: F401
        import ddalib.ledger  # noqa: F401
        out.append(_check("pass", "venv-imports", "ddalib imports clean"))
    except Exception as exc:
        out.append(_check("fail", "venv-imports", f"{type(exc).__name__}: {exc}"))
    return out


def hook_entry_checks() -> list[dict]:
    hook = REPO_ROOT / "hooks" / "dda_hook.py"
    out = []
    if hook.is_file():
        out.append(_check("pass", "hook-entry-present", str(hook)))
    else:
        return [_check("fail", "hook-entry-present", f"{hook} missing")]
    try:
        from .cli import hooks_yaml
        block = hooks_yaml(Path(sys.executable).as_posix())
        if hook.as_posix() in block and all(h in block for h in BLOCKING_HOOKS) and "fail_closed" in block:
            out.append(_check("pass", "hook-registration",
                              "install block names the absolute interpreter, the entry point, and every hook"))
        else:
            out.append(_check("fail", "hook-registration", "`dda install` block is incomplete"))
    except Exception as exc:
        out.append(_check("fail", "hook-registration", f"{type(exc).__name__}: {exc}"))
    for name in (*BLOCKING_HOOKS, "runlog", "driftnudge"):
        try:
            # A well-formed UNBOUND payload: a healthy hook answers {} rc 0
            # without touching anything. Any nonzero exit (including the
            # fail-closed block exit 2) is a failure, never a pass: exit 2
            # here means the hook would block sessions it must let through.
            probe = json.dumps({"hook_event_name": "pre_tool_call", "tool_name": "read_file",
                                "tool_input": {"path": "dda-doctor-dry-run"},
                                "session_id": "dda-doctor-dry-run-unbound", "extra": {}})
            r = subprocess.run([sys.executable, "-I", "-S", str(hook), name], input=probe,
                               capture_output=True, text=True, timeout=30)
            body = json.loads(r.stdout)
            if not isinstance(body, dict):
                raise ValueError("entry point did not emit a JSON object")
            if r.returncode == 0:
                out.append(_check("pass", f"hook-dry-run:{name}", "entry point returns valid JSON"))
            else:
                out.append(_check("fail", f"hook-dry-run:{name}",
                                  f"rc={r.returncode} on an unbound dry-run {r.stderr[-200:]}"))
        except Exception as exc:
            out.append(_check("fail", f"hook-dry-run:{name}", f"{type(exc).__name__}: {exc}"))
    return out


# ---------- workdir checks ----------

def workdir_checks(wd: Workdir) -> list[dict]:
    from . import chain, ledger, lockstate
    from .binding import read_registry
    out = []
    try:
        wd.require_initialized()
        out.append(_check("pass", "workdir-initialized", str(wd.root)))
    except DdaError as exc:
        return [_check("fail", "workdir-initialized", str(exc))]
    state, detail, _ = lockstate.quick_status(wd)
    out.append(_check("pass" if state == "valid" else "fail", "lock-state", f"{state}: {detail}"))
    problems, _ = ledger.verify_all(wd, merge=False)
    if problems:
        out.append(_check("fail", "evidence-chains", "; ".join(problems[:3])))
    else:
        out.append(_check("pass", "evidence-chains", "all chains verify (unmerged spills would fail)"))
    sessions = {str(r.get("session") or "") for r in chain.read_records(ledger.runs_log(wd))} - {""}
    missing = [s for s in sorted(sessions) if not ledger.heartbeat_log(s).is_file()]
    if missing:
        out.append(_check("fail", "heartbeat-live",
                          f"sessions with runs.log lines but no heartbeat log: {', '.join(missing[:3])}"))
    else:
        bad = []
        for s in sorted(sessions):
            bad += [f"{s}: {p}" for p in chain.verify(ledger.heartbeat_log(s))[:1]]
        if bad:
            out.append(_check("fail", "heartbeat-live", "; ".join(bad[:3])))
        else:
            out.append(_check("pass", "heartbeat-live",
                              f"{len(sessions)} session(s) with logs" if sessions else "no sessions yet"))
    try:
        reg = read_registry()
        n = len(reg.get("workdirs", {}))
        out.append(_check("pass", "active-workdirs", f"{n} active workdir(s) in the registry"))
    except DdaError as exc:
        out.append(_check("fail", "active-workdirs", str(exc)))
    try:
        home = dda_home()
        out.append(_check("pass" if home.is_dir() else "fail", "dda-home", str(home)))
    except Exception as exc:
        out.append(_check("fail", "dda-home", f"{type(exc).__name__}: {exc}"))
    return out


def run(wd: Workdir | None = None) -> dict:
    """Run every section. Returns {ok, sections: {name: [checks]}}.

    There is no `keys` section and no downgrade flag: approvals carry no key
    material, so nothing an agent could borrow can downgrade them (§4.5).
    """
    sections = {
        "interpreter": interpreter_checks(),
        "hooks": hook_entry_checks(),
    }
    if wd is not None:
        sections["workdir"] = workdir_checks(wd)
    fails = [c for checks in sections.values() for c in checks if c["status"] == "fail"]
    return {"ok": not fails,
            "failures": [c["name"] for c in fails],
            "sections": sections}


__all__ = ["run", "workdir_checks", "hook_entry_checks", "interpreter_checks", "BLOCKING_HOOKS"]
