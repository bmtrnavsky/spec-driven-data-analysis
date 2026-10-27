"""Platform probe: runs INSIDE the Hermes agent's venv and drives Hermes's own
shell-hook evaluation path (`agent.shell_hooks.run_once`, the same function
`hermes hooks test` uses, which shares `_spawn` + `_evaluate_result` with the
live callback). Prints one JSON object with every result.

Usage: <hermes-venv-python> hermes_probe.py <dda_hook.py> <python-for-hooks> <dda_home> <bound-session-id>
"""
import json
import os
import sys
import time

hook_py, hook_python, dda_home, bound_sid = sys.argv[1:5]
os.environ["DDA_HOME"] = dda_home
sys.path.insert(0, os.getcwd())  # caller runs us with cwd = hermes-agent checkout

from agent import shell_hooks as sh  # noqa: E402


def spec(command, fail_closed, timeout=5, event="pre_tool_call"):
    return sh.ShellHookSpec(event=event, command=command, timeout=timeout, fail_closed=fail_closed)


READ_PATH = os.environ.get("DDA_PROBE_READ_PATH", "x")  # a declared data root (phase 2 hooks are real)


def run(command, *, fail_closed, timeout=5, session=bound_sid, tool="read_file", args=None):
    kwargs = {"tool_name": tool, "args": args or {"path": READ_PATH}, "session_id": session}
    t0 = time.monotonic()
    r = sh.run_once(spec(command, fail_closed, timeout), kwargs)
    return {"parsed": r.get("parsed"), "error": r.get("error"), "timed_out": r.get("timed_out"),
            "returncode": r.get("returncode"), "elapsed": round(time.monotonic() - t0, 3)}


q = lambda p: '"' + p + '"'  # noqa: E731
real = f"{q(hook_python)} -I -S {q(hook_py)}"
missing = f"{q(os.path.join(os.path.dirname(hook_python), 'no-such-python.exe'))} {q(hook_py)} lockguard"
sleeper = f"{q(hook_python)} -c \"import time; time.sleep(4)\""
garbage = f"{q(hook_python)} -c \"print('Traceback: boom')\""
crash = f"{q(hook_python)} -c \"import sys; sys.exit(1)\""

out = {"hermes_shell_hooks_file": sh.__file__, "probes": {}}
P = out["probes"]
P["real_bound_lockguard"] = run(f"{real} lockguard", fail_closed=True)
P["real_unbound_lockguard"] = run(f"{real} lockguard", fail_closed=True, session="redteam-unbound")
P["missing_interp_fail_closed"] = run(missing, fail_closed=True)
P["missing_interp_fail_open"] = run(missing, fail_closed=False)
P["timeout_fail_closed"] = run(sleeper, fail_closed=True, timeout=1)
P["timeout_fail_open"] = run(sleeper, fail_closed=False, timeout=1)
P["garbage_stdout_fail_closed"] = run(garbage, fail_closed=True)
P["garbage_stdout_fail_open"] = run(garbage, fail_closed=False)
P["exit1_no_output_fail_closed"] = run(crash, fail_closed=True)
P["exit1_no_output_fail_open"] = run(crash, fail_closed=False)
os.environ["DDA_HOOK_FAULT_INJECT"] = "lockguard"
P["injected_exception_bound"] = run(f"{real} lockguard", fail_closed=False)
del os.environ["DDA_HOOK_FAULT_INJECT"]

# Payload shape: what does the hook actually receive? Use a hook that echoes stdin back as a block message.
echo = f"{q(hook_python)} -c \"import sys,json; d=sys.stdin.read(); print(json.dumps({{'action':'block','message':d}}))\""
r = sh.run_once(spec(echo, False), {"tool_name": "read_file", "args": {"path": "p"}, "session_id": "child-1",
                                     "parent_session_id": "parent-1", "task_id": "t1", "tool_call_id": "c1"})
try:
    out["payload_seen"] = json.loads((r.get("parsed") or {}).get("message", "null"))
except Exception as exc:  # pragma: no cover
    out["payload_seen"] = {"error": repr(exc)}

# Does Hermes's own config parser accept the `dda install` block, with fail_closed on every blocking hook?
if len(sys.argv) > 5:
    import hermes_yaml
    with open(sys.argv[5], "r", encoding="utf-8") as fh:
        cfg = hermes_yaml.safe_load(fh.read())
    specs = sh._parse_hooks_block(cfg.get("hooks"))
    out["install_specs"] = [{"event": s.event, "command": s.command, "fail_closed": s.fail_closed,
                             "timeout": s.timeout, "matcher": s.matcher} for s in specs]
    # Fire the parsed lockguard spec itself (exact command string from dda install).
    lg = [s for s in specs if s.command.endswith(" lockguard")]
    if lg:
        r = sh.run_once(lg[0], {"tool_name": "read_file", "args": {"path": READ_PATH}, "session_id": bound_sid})
        out["install_lockguard_parsed"] = r.get("parsed")
print(json.dumps(out))
