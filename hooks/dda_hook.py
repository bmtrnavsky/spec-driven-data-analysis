#!/usr/bin/env python
"""dda hook entry point: `dda_hook.py <hook-name>` (spec §6.0, §6.9).

Contract with Hermes shell hooks: JSON payload on stdin, one JSON object
on stdout, every exit path. A block is printed as
{"action": "block", "message": ...} AND the process exits 2, so Hermes
blocks even if stdout were lost (exit 2 on pre_tool_call = block).

Fail-closed rules (phase 0 asserts every one of these):
  * unbound session                      -> {} (never block Brad's other work)
  * bound session, blocking hook          -> hook logic; any exception -> block
  * payload unparseable / no session id   -> block if any workdir is active, else {}
  * binding file unreadable               -> block
  * unknown hook name                     -> block if bound, else {}

This file is stdlib-only and does the unbound fast path itself, so a
broken `ddalib` import can only affect bound sessions (which then block).
"""
import json
import os
import re
import sys

BLOCKING = frozenset({"lockguard", "evidenceguard", "rawguard", "defguard", "footercheck"})
SIDE_EFFECT = frozenset({"runlog", "driftnudge"})
_SESSION_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")


def _dda_home():
    if os.environ.get("DDA_HOME"):
        return os.environ["DDA_HOME"]
    hh = os.environ.get("HERMES_HOME") or os.path.join(os.path.expanduser("~"), ".hermes-home")
    return os.path.join(hh, "dda")


def _emit(obj, code=0):
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()
    sys.exit(code)


def _block(msg):
    _emit({"action": "block", "message": msg}, 2)


def _any_active():
    try:
        with open(os.path.join(_dda_home(), "active.json"), "r", encoding="utf-8") as fh:
            return bool(json.load(fh).get("workdirs"))
    except FileNotFoundError:
        return False
    except Exception:
        return True  # registry unreadable: assume something is active


def main():
    hook = sys.argv[1] if len(sys.argv) > 1 else ""
    blocking = hook in BLOCKING
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("payload is not a JSON object")
    except Exception as exc:
        if (blocking or hook not in SIDE_EFFECT) and _any_active():
            _block(f"dda hook error: unparseable payload ({type(exc).__name__}); run `dda doctor`")
        _emit({})

    sid = payload.get("session_id") or ""
    if not isinstance(sid, str) or not _SESSION_RE.match(sid):
        if (blocking or hook not in SIDE_EFFECT) and _any_active():
            _block("dda hook error: payload has no usable session_id while a dda workdir is active; run `dda doctor`")
        _emit({})

    bfile = os.path.join(_dda_home(), "sessions", sid + ".json")
    if not os.path.exists(bfile):
        # Unbound fast path (§6.0). Phase 2 adds runlog's unbound-access logging here.
        _emit({})

    # Bound session from here on: every failure blocks.
    try:
        with open(bfile, "r", encoding="utf-8") as fh:
            binding = json.load(fh)
        if not isinstance(binding, dict) or not binding.get("workdir"):
            raise ValueError("binding file malformed")
        here = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, os.path.join(os.path.dirname(here), "scripts"))
        from ddalib import hookentry
        result, code = hookentry.dispatch(hook, payload, binding)
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - fail closed on anything
        if blocking or hook not in SIDE_EFFECT:
            _block(f"dda hook error: {type(exc).__name__} in {hook or '<none>'}; run `dda doctor`")
        _emit({})
    _emit(result, code)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException as exc:  # last-resort guard: still valid JSON
        sys.stdout.write(json.dumps({"action": "block", "message": f"dda hook error: {type(exc).__name__}; run `dda doctor`"}))
        sys.stdout.flush()
        sys.exit(2)
