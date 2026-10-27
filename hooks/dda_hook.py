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
  * unbound session, runlog               -> unbound-access log line if the
                                             call matches an ACTIVE workdir's
                                             roots (never blocks, errors -> {})
  * child session, bound parent visible   -> judged with the parent's binding

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


def _ddalib():
    here = os.path.dirname(os.path.abspath(__file__))
    scripts = os.path.join(os.path.dirname(here), "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)


def _parent_id(payload):
    extra = payload.get("extra") if isinstance(payload.get("extra"), dict) else {}
    for src in (payload, extra):
        for key in ("parent_session_id", "parent_session"):
            v = src.get(key)
            if isinstance(v, str) and _SESSION_RE.match(v):
                return v
    return None


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
    parent = None
    if not os.path.exists(bfile):
        # Subagents inherit a bound parent's binding when the payload names the parent (§6.0).
        parent = _parent_id(payload)
        pfile = os.path.join(_dda_home(), "sessions", parent + ".json") if parent else None
        if pfile and os.path.exists(pfile):
            bfile = pfile
        else:
            # Unbound fast path (§6.0): blocking hooks return {}; runlog logs root matches of active workdirs.
            if hook == "runlog" and _any_active():
                try:
                    _ddalib()
                    from ddalib import hooks
                    hooks.unbound_runlog(payload)
                except BaseException:  # noqa: BLE001 - never block or fail an unbound session
                    pass
            _emit({})

    # Bound session from here on: every failure blocks.
    try:
        with open(bfile, "r", encoding="utf-8") as fh:
            binding = json.load(fh)
        if not isinstance(binding, dict) or not binding.get("workdir"):
            raise ValueError("binding file malformed")
        if parent:
            binding = dict(binding, parent=parent)
        _ddalib()
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
