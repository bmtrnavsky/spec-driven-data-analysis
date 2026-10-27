"""`dda` command-line interface.

Implemented: init, status, start, release, hash, install, version (phase 1);
lock, verify-chain, gate (G4), footer, abandon (phase 2).
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

from . import __version__, binding, chain, footer, ledger, lockhash, lockstate
from .layout import LAYOUT_DIRS, LAYOUT_FILES, REPO_ROOT, TEMPLATES_DIR, DdaError, Workdir, dda_home

EXIT_NOT_IMPLEMENTED = 3

# Spec commands not yet built, with the build phase that delivers them (§14).
PENDING = {
    "meta": 3, "run": 3, "variant": 3, "approve": 4,
    "approved": 4, "doctor": 4, "gitcheck": 5, "evals": 9, "packet": 7,
    "review": 7, "profile": 8, "verify": 8,
}
# Gates and the phase that builds each one's checks (§3, §14). G4 is built in phase 2.
GATE_PHASE = {"G0": 5, "G1": 6, "G2": 4, "G3": 7, "G5": 8, "G6": 3, "G7": 8, "G8": 5, "G9": 5}

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


def cmd_lock(args) -> int:
    wd = _wd(args)
    lock = ledger.do_lock(wd, amend=args.amend)
    if lock.get("noop"):
        print(f"spec unchanged: lock v{lock['version']} {lock['lock_hash'][:12]} already current ({lock['label']})")
        return 0
    kind = "amendment" if args.amend else "lock"
    print(f"{kind} v{lock['version']} {lock['lock_hash'][:12]} — {lock['label']}")
    exp = {k: len(v) for k, v in lock["exposure"].items() if v}
    if exp:
        print(f"  prior data reads found: {json.dumps(exp, sort_keys=True)}")
    print(f"  committed {lock['commit'][:12]}")
    return 0


def cmd_verify_chain(args) -> int:
    wd = _wd(args)
    wd.require_initialized()
    problems, merged = ledger.verify_all(wd, merge=not args.no_merge)
    out = {"ok": not problems, "problems": problems, "merged_spills": merged,
           "chains": [str(p) for p in ledger.workdir_chains(wd) + [ledger.unbound_log()] if p.exists()]}
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        if merged:
            print(f"merged {merged} spill file(s)")
        for p in problems:
            print(f"FAIL {p}")
        print("chains: ok" if not problems else "chains: FAILED — stop and ask (§3.2 case 8)")
    return 0 if not problems else ledger.EXIT_CHAIN


def cmd_gate(args) -> int:
    wd = _wd(args)
    g = args.gate.upper()
    if g == "G4":
        passed, reason, _ = ledger.gate_g4(wd)
        ledger.write_wayfinder(wd, g, passed, reason)
        print(f"{g}: {'pass' if passed else 'fail'} — {reason}")
        return 0 if passed else 1
    if g in GATE_PHASE:
        print(f"dda gate {g}: not implemented in this build (arrives in build phase {GATE_PHASE[g]}, SPEC §14). "
              "Failing closed.", file=sys.stderr)
        return EXIT_NOT_IMPLEMENTED
    raise DdaError(f"unknown gate {args.gate!r} (G0-G9)")


def cmd_footer(args) -> int:
    wd = _wd(args)
    wd.require_initialized()
    if args.check:
        path = Path(args.check)
        text = path.read_text(encoding="utf-8")
        short = args.short or footer.is_short_target(path.resolve())
        problems = footer.check(wd, text, short=short)
        for p in problems:
            print(f"FAIL {p}")
        print("footer: ok" if not problems else "footer: FAILED")
        return 0 if not problems else 1
    sk = footer.skeleton(wd, short=args.short)
    if not sk:
        raise DdaError("no lock yet; run `dda lock` first")
    sys.stdout.write(sk)
    return 0


def cmd_abandon(args) -> int:
    wd = _wd(args)
    wd.require_initialized()
    released = binding.release(wd, cause="abandon", reason=args.reason)
    print(f"abandoned {wd.root}: {len(released)} session(s) unbound; workdir inactive")
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

    s = sub.add_parser("lock", help="lock the spec (git commit + ledger entry)")
    s.add_argument("workdir", nargs="?")
    s.add_argument("--milestone")
    s.add_argument("--amend", metavar="REASON", help="re-lock a changed spec as an amendment")
    s.set_defaults(func=cmd_lock)

    s = sub.add_parser("verify-chain", help="merge spill files and verify every evidence chain")
    s.add_argument("workdir", nargs="?")
    s.add_argument("--milestone")
    s.add_argument("--no-merge", action="store_true", help="verify only; unmerged spills count as faults")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_verify_chain)

    s = sub.add_parser("gate", help="run a gate check and write its Wayfinder line (G4 built)")
    s.add_argument("gate")
    s.add_argument("workdir", nargs="?")
    s.add_argument("--milestone")
    s.set_defaults(func=cmd_gate)

    s = sub.add_parser("footer", help="print a provenance footer skeleton, or --check a report")
    s.add_argument("workdir", nargs="?")
    s.add_argument("--milestone")
    s.add_argument("--check", metavar="FILE")
    s.add_argument("--short", action="store_true", help="glance footer (answer.md)")
    s.set_defaults(func=cmd_footer)

    s = sub.add_parser("abandon", help="record abandonment in the ledger and release the workdir")
    s.add_argument("workdir", nargs="?")
    s.add_argument("--milestone")
    s.add_argument("--reason", required=True)
    s.set_defaults(func=cmd_abandon)

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
