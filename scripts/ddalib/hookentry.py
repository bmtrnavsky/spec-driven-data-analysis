"""Bound-session hook dispatch (spec §6). Called only by hooks/dda_hook.py
after it has established the session is bound to a workdir.

Phase 1 ships the dispatch skeleton. The real gate logic for each blocking
hook lands in later build phases (§14). Until a hook is implemented it is
**fail-closed**: in a bound session it blocks every tool call except a
clean `dda` invocation (so `dda status` / `dda release` still work).
"""
from __future__ import annotations

import os
import re
import shlex
from typing import Any

from .layout import DdaError

BLOCKING = ("lockguard", "evidenceguard", "rawguard", "defguard", "footercheck")
SIDE_EFFECT = ("runlog", "driftnudge")

# Hooks with real logic in this build. Everything else in BLOCKING is a fail-closed stub.
IMPLEMENTED: dict[str, Any] = {}

_DDA_NAMES = frozenset({"dda", "dda.cmd", "dda.bat", "dda.exe"})
_PYTHON_RE = re.compile(r"^python(3(\.\d+)?)?(\.exe)?$")
_SHELL_META_RE = re.compile(r"[;&|`<>\n\r]|\$\(")


def is_clean_dda_invocation(tool_name: str, tool_input: dict | None) -> bool:
    """A terminal call that runs exactly one `dda` command with no shell chaining.
    `dda` subcommands enforce their own rules (§6.2), so hooks pass them through."""
    if tool_name != "terminal" or not isinstance(tool_input, dict):
        return False
    cmd = tool_input.get("command")
    if not isinstance(cmd, str) or tool_input.get("background"):
        return False
    if _SHELL_META_RE.search(cmd):
        return False
    try:
        tokens = [t.strip('"\'') for t in shlex.split(cmd, posix=False)]
    except ValueError:
        return False
    if not tokens:
        return False
    base = lambda t: re.split(r"[\\/]", t)[-1].lower()  # noqa: E731
    if base(tokens[0]) in _DDA_NAMES:
        rest = tokens[1:]
    elif _PYTHON_RE.match(base(tokens[0])) and len(tokens) > 1 and base(tokens[1]) == "dda.py":
        rest = tokens[2:]
    else:
        return False
    # `dda approve` is human-only (§4.5): never pass it through.
    return not (rest and rest[0] == "approve")


def dispatch(hook: str, payload: dict, binding: dict) -> tuple[dict, int]:
    """Return (stdout_object, exit_code). Exit 2 accompanies every block."""
    tool_name = payload.get("tool_name") or ""
    tool_input = payload.get("tool_input")
    if os.environ.get("DDA_HOOK_FAULT_INJECT") == hook:
        raise RuntimeError("injected fault (red-team)")
    if hook in SIDE_EFFECT:
        return {}, 0
    if hook not in BLOCKING:
        return block(f"dda: unknown hook {hook!r} in a bound session; check the hooks config (`dda install --print`)")
    if hook in IMPLEMENTED:
        return IMPLEMENTED[hook](payload, binding)
    if is_clean_dda_invocation(tool_name, tool_input):
        return {}, 0
    return block(
        f"dda {hook}: not implemented in this build, so bound sessions fail closed. "
        f"Session is bound to {binding.get('workdir')}; run `dda release` to unbind."
    )


def block(message: str) -> tuple[dict, int]:
    return {"action": "block", "message": message}, 2


__all__ = ["dispatch", "is_clean_dda_invocation", "BLOCKING", "SIDE_EFFECT", "DdaError"]
