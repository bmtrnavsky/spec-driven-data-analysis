"""`dda` command-line interface (phase 1 skeleton).

Implemented: init, status, start, release, hash, install, version.
Everything else in the spec's command set is registered but fails closed
(exit 3, "not implemented in this build") so a script or gate that calls
it can never mistake a missing feature for a pass.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__, binding, lockhash
from .layout import LAYOUT_DIRS, LAYOUT_FILES, REPO_ROOT, TEMPLATES_DIR, DdaError, Workdir, dda_home

EXIT_NOT_IMPLEMENTED = 3

# Spec commands not yet built, with the build phase that delivers them (§14).
PENDING = {
    "lock": 2, "verify-chain": 2, "gate": 2, "meta": 3, "run": 3, "variant": 3, "approve": 4,
    "approved": 4, "doctor": 4, "footer": 5, "gitcheck": 5, "evals": 9, "packet": 7,
    "review": 7, "profile": 8, "verify": 8, "abandon": 2,
}

BLOCKING_HOOKS = ("lockguard", "evidenceguard", "rawguard", "defguard", "footercheck")


def _wd(args) -> Workdir:
    return Workdir.at(getattr(args, "workdir", None) or os.getcwd(), getattr(args, "milestone", None))


def cmd_init(args) -> int:
    root = Path(os.path.abspath(args.path))
    wd = Workdir.at(root)
    if wd.config_path.exists() and not args.force:
        raise DdaError(f"{root} is already a dda workdir (use --force to re-seed missing files only)")
    root.mkdir(parents=True, exist_ok=True)
    for d in LAYOUT_DIRS:
        (root / d).mkdir(parents=True, exist_ok=True)
    created = []
    for rel, tmpl in LAYOUT_FILES.items():
        dest = root / rel
        if dest.exists():
            continue
        shutil.copyfile(TEMPLATES_DIR / tmpl, dest)
        created.append(rel)
    for keep in ("definitions/proposals", "evals/corrections", ".analysis/approvals"):
        k = root / keep / ".gitkeep"
        if not k.exists():
            k.write_text("", encoding="utf-8")
    print(f"initialized dda workdir at {root}")
    for rel in created:
        print(f"  + {rel}")
    print(f"workdir id: {wd.id}")
    return 0


def cmd_status(args) -> int:
    st = binding.status()
    if args.json:
        print(json.dumps(st, indent=2, sort_keys=True))
        return 0
    print(f"dda home: {st['dda_home']}")
    if not st["active"]:
        print("active workdirs: none")
    for wid, w in sorted(st["active"].items()):
        print(f"active: {w['path']}  (id {wid}; aliases: {', '.join(w['aliases']) or '-'})")
    for s in st["sessions"]:
        ms = f" milestone={s['milestone']}" if s.get("milestone") else ""
        print(f"bound session: {s['session_id']} -> {s['workdir']}{ms}")
    return 0


def _session_id(args) -> str:
    sid = args.session or os.environ.get("HERMES_SESSION_ID") or ""
    if not sid:
        raise DdaError("no session id: pass --session <id> or run inside a Hermes session (HERMES_SESSION_ID)")
    return sid


def cmd_start(args) -> int:
    wd = _wd(args)
    b = binding.start(wd, _session_id(args), rebind=args.rebind)
    print(f"bound session {b['session_id']} -> {b['workdir']}" + (f" (milestone {b['milestone']})" if b["milestone"] else ""))
    return 0


def cmd_release(args) -> int:
    wd = _wd(args)
    released = binding.release(wd)
    print(f"released {wd.root}: {len(released)} session(s) unbound; workdir inactive")
    return 0


def cmd_hash(args) -> int:
    comp = lockhash.compute(_wd(args))
    if args.json:
        print(json.dumps(comp.as_dict(), indent=2))
    else:
        print(comp.lock_hash)
    return 0


def _plugin_python() -> tuple[str, bool]:
    venv_py = REPO_ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if venv_py.is_file():
        return venv_py.as_posix(), True
    return Path(sys.executable).as_posix(), False


def hooks_yaml(python: str) -> str:
    hook = (REPO_ROOT / "hooks" / "dda_hook.py").as_posix()
    # -I: ignore PYTHON* env and user site (an agent can't redirect imports); -S: stdlib only, faster start.
    python = f"{python} -I -S"
    lines = ["hooks:", "  pre_tool_call:"]
    for h in BLOCKING_HOOKS:
        lines += [f'    - command: "{python} {hook} {h}"', "      timeout: 5", "      fail_closed: true"]
    lines += [f'    - command: "{python} {hook} runlog"', "      timeout: 5"]
    lines += ["  post_tool_call:", f'    - command: "{python} {hook} runlog"', "      timeout: 5"]
    lines += ["  pre_llm_call:", f'    - command: "{python} {hook} driftnudge"', "      timeout: 5"]
    return "\n".join(lines) + "\n"


def cmd_install(args) -> int:
    if args.venv:
        uv = shutil.which("uv")
        if not uv:
            raise DdaError("uv not found on PATH; install uv or create .venv manually (Python >= 3.11)")
        subprocess.run([uv, "venv", "--python", ">=3.11", str(REPO_ROOT / ".venv")], check=True)
    python, is_venv = _plugin_python()
    if not is_venv:
        print(f"# WARNING: plugin venv missing ({REPO_ROOT / '.venv'}); using {python}. Run `dda install --venv`.",
              file=sys.stderr)
    print("# Add to the Hermes profile config.yaml (blocking hooks need first-use approval;")
    print("# gateway/cron need hooks_auto_accept: true). Absolute interpreter path by design (SPEC §6.9).")
    sys.stdout.write(hooks_yaml(python))
    return 0


def cmd_version(args) -> int:
    print(f"dda {__version__}")
    return 0


def cmd_pending(args) -> int:
    phase = PENDING[args.command]
    print(f"dda {args.command}: not implemented in this build (arrives in build phase {phase}, SPEC §14). "
          "Failing closed.", file=sys.stderr)
    return EXIT_NOT_IMPLEMENTED


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dda", description="Disciplined data analysis CLI")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="create the workdir layout")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("status", help="active workdirs and bound sessions")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("start", help="bind this session to a workdir")
    s.add_argument("workdir", nargs="?")
    s.add_argument("--milestone")
    s.add_argument("--session")
    s.add_argument("--rebind", action="store_true")
    s.set_defaults(func=cmd_start)

    s = sub.add_parser("release", help="unbind all sessions from a workdir and deactivate it")
    s.add_argument("workdir", nargs="?")
    s.set_defaults(func=cmd_release)

    s = sub.add_parser("hash", help="compute the lock hash for the current spec (no side effects)")
    s.add_argument("workdir", nargs="?")
    s.add_argument("--milestone")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_hash)

    s = sub.add_parser("install", help="print the Hermes hooks block (optionally create the plugin venv)")
    s.add_argument("--venv", action="store_true", help="create <plugin>/.venv with uv first")
    s.add_argument("--print", action="store_true", help="print only (default)")
    s.set_defaults(func=cmd_install)

    s = sub.add_parser("version")
    s.set_defaults(func=cmd_version)

    for name in PENDING:
        s = sub.add_parser(name, help=f"(build phase {PENDING[name]}; fails closed)")
        s.add_argument("rest", nargs=argparse.REMAINDER)
        s.set_defaults(func=cmd_pending)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except DdaError as exc:
        print(f"dda: {exc}", file=sys.stderr)
        return exc.code
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
