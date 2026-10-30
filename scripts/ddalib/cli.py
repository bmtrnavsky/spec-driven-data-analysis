"""`dda` command-line interface.

Implemented: init, status, start, release, hash, install, version (phase 1);
lock, verify-chain, gate (G4), footer, abandon (phase 2); meta, variant, run,
gate G6 (phase 3); approve, approved, doctor (phase 4).
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

from . import __version__, approvals, binding, chain, doctor, footer, kernel, ledger, lockhash, lockstate
from .layout import LAYOUT_DIRS, LAYOUT_FILES, REPO_ROOT, TEMPLATES_DIR, DdaError, Workdir, dda_home, read_text_lf

EXIT_NOT_IMPLEMENTED = 3

# Spec commands not yet built, with the build phase that delivers them (§14).
PENDING = {
    "evals": 9, "packet": 7,
    "review": 7, "profile": 8, "verify": 8,
}
# Gates and the phase that builds each one's checks (§3, §14). G4 and G6 are built.
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
    try:
        from .layout import load_config as _load
        fps = [f"{a.get('name')}:{str(a.get('fingerprint') or a.get('key_id') or a.get('key') or '')[:64]}"
               for a in (_load(wd).get("approvers") or [])]
        if fps:
            print("approver fingerprints (confirm these are Brad's keys before the first config approval):")
            for f in fps:
                print(f"  {f}")
        else:
            print("approvers: none configured — add Brad's keys under `approvers:` in .analysis/config.yaml, "
                  "then `dda approve config` (TOFU, §4.5)")
    except DdaError as exc:
        print(f"approvers: could not read ({exc})")
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
    if g == "G6":
        passed, reason, _ = ledger.gate_g6(wd)
        ledger.write_wayfinder(wd, g, passed, reason)
        print(f"{g}: {'pass' if passed else 'fail'} — {reason}")
        return 0 if passed else 1
    if g in ("G0", "G8", "G9"):
        from . import gates5
        fn = {"G0": gates5.gate_g0, "G8": gates5.gate_g8, "G9": gates5.gate_g9}[g]
        if g == "G8" and getattr(args, "report", None):
            passed, reason, _ = fn(wd, report=args.report)
        else:
            passed, reason, _ = fn(wd)
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


def cmd_report(args) -> int:
    wd = _wd(args)
    wd.require_initialized()
    lock = lockstate.read_lock(wd)
    if not lock:
        raise DdaError("no spec.lock (run `dda lock` first)")
    state, detail, _ = lockstate.quick_status(wd)
    if state != "valid":
        raise DdaError(f"report: lock is not valid ({state}: {detail}); re-lock before reporting")
    repdir = wd.root / "reports"
    repdir.mkdir(exist_ok=True)
    slug = args.slug
    body = wd.analysis / "answer.md"
    if not body.is_file():
        raise DdaError("no .analysis/answer.md to assemble the report from")
    text = read_text_lf(body)
    if footer.extract(text) is None:
        sk = footer.skeleton(wd)
        if not sk:
            raise DdaError("no lock footer available")
        text = text.rstrip() + "\n\n" + sk
    problems = footer.check(wd, text)
    if problems:
        raise DdaError("report: footer does not verify: " + "; ".join(problems[:5]))
    out = repdir / (slug + ".md")
    out.write_text(text, encoding="utf-8")
    print(f"report: wrote {out}")
    return 0


def cmd_gitcheck(args) -> int:
    wd = _wd(args)
    wd.require_initialized()
    from .ledger import git_safety_scan
    problems = git_safety_scan(wd)
    if problems:
        for p in problems:
            print("FAIL " + p)
        return 1
    print("gitcheck: ok")
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


def _kind_artifact_workdir(args) -> tuple:
    """Split `approve(d) kind [artifact] [workdir]`: a lone path-like positional is the workdir."""
    kind, artifact, workdir = args.kind, args.artifact, args.workdir
    if artifact is not None and workdir is None and (
            os.sep in artifact or "/" in artifact or Path(artifact).is_dir()):
        workdir, artifact = artifact, None
    return kind, artifact, workdir


def cmd_approve(args) -> int:
    kind, artifact, workdir = _kind_artifact_workdir(args)
    wd = Workdir.at(workdir or os.getcwd(), args.milestone)
    res = approvals.do_approve(wd, kind, artifact=artifact, key=args.key,
                               sign=not args.no_sign, message=args.message)
    print(f"approved {res['kind']} {res['artifact'][:16]} — commit {res['commit'][:12]} "
          f"({'signed' if res['signed'] else 'UNSIGNED (unverified)'}); "
          f"run `dda approved {res['kind']} {res['artifact'][:16]}` to record the verification")
    return 0


def cmd_approved(args) -> int:
    kind, artifact, workdir = _kind_artifact_workdir(args)
    wd = Workdir.at(workdir or os.getcwd(), args.milestone)
    verdict = approvals.do_approved(wd, kind, artifact=artifact)
    state = "verified" if verdict["verified"] else "UNVERIFIED"
    print(f"{args.kind} {verdict['artifact'][:16]}: {state} — {verdict['reason']}")
    return 0


def cmd_doctor(args) -> int:
    wd = None
    if args.workdir or args.milestone:
        wd = _wd(args)
    elif Path(os.getcwd(), ".analysis", "config.yaml").is_file():
        wd = _wd(args)
    rep = doctor.run(wd)
    if args.json:
        print(json.dumps(rep, indent=2))
        return 0 if rep["ok"] else 1
    for section, checks in rep["sections"].items():
        print(f"[{section}]")
        for c in checks:
            mark = {"pass": "ok", "fail": "FAIL", "skip": "skip"}[c["status"]]
            print(f"  {mark} {c['name']}" + (f": {c['detail']}" if c.get("detail") else ""))
    if rep["downgrade"]:
        print("doctor: FAIL — key checks fail, so every approval downgrades to unverified (§4.5)")
        return 1
    print("doctor: ok" if rep["ok"] else "doctor: FAIL")
    return 0 if rep["ok"] else 1


def cmd_meta(args) -> int:
    wd = _wd(args)
    text, _rec = kernel.do_meta(wd, args.alias, session=args.session or os.environ.get("HERMES_SESSION_ID") or "")
    print(text, end="")
    return 0


def _parse_sets(pairs: list[str]) -> dict:
    header = {}
    for p in pairs or []:
        if "=" not in p:
            raise DdaError(f"bad --set {p!r} (want field=value; fields: {', '.join(kernel.HEADER_FIELDS)})")
        k, v = p.split("=", 1)
        k = k.strip().lower().replace("-", "_")
        if k not in kernel.HEADER_FIELDS:
            raise DdaError(f"unknown header field {k!r} (fields: {', '.join(kernel.HEADER_FIELDS)})")
        header[k] = v.strip()
    return header


def cmd_variant(args) -> int:
    wd = _wd(args)
    if args.list:
        regs = kernel.registrations(wd)
        if not regs:
            print("no variants registered")
            return 0
        locked = kernel.locked_variant_id(wd)
        for vid in sorted(regs):
            r = regs[vid]
            frozen = kernel.frozen_hash(wd, vid)
            nruns = len(kernel.run_entries(wd, vid))
            mark = " [locked]" if vid == locked else ""
            print(f"{vid}{mark}: key={(r.get('variant_key') or '')[:12]} label={r.get('label')} "
                  f"frozen={frozen[:12] if frozen else '-'} runs={nruns} why={r.get('why')}")
        return 0
    if args.locked:
        rec = kernel.mark_locked(wd, args.locked)
        print(f"locked variant: {rec['variant']}")
        return 0
    if not args.id:
        raise DdaError("usage: `dda variant <id> --why \"...\" [--parent P] [--label L] [--set k=v ...]`; "
                       "`dda variant --locked <id>`; `dda variant --list`")
    rec = kernel.register_variant(wd, args.id, parent=args.parent, why=args.why or "",
                                  label=args.label, header=_parse_sets(args.set))
    print(f"variant {rec['variant']}: key={rec['variant_key'][:12]} label={rec['label']}")
    return 0


def cmd_run(args) -> int:
    wd = _wd(args)
    rest = list(args.rest or [])
    if rest[:1] == ["--"]:
        rest = rest[1:]
    rec = kernel.do_run(wd, args.variant, args.script, rest,
                        session=args.session or os.environ.get("HERMES_SESSION_ID") or "",
                        seed=args.seed)
    print(f"run {rec['run_id']} (variant {rec['variant']}, seed {rec['seed']}): "
          f"record runs/kernels/{rec['run_id']}.json, blob {rec['blob']}")
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

    s = sub.add_parser("gate", help="run a gate check and write its Wayfinder line (G4, G6 built)")
    s.add_argument("gate")
    s.add_argument("workdir", nargs="?")
    s.add_argument("--milestone")
    s.add_argument("--report", default=None, help="G8 only: check just this report file")
    s.set_defaults(func=cmd_gate)

    s = sub.add_parser("meta", help="metadata-only access to a data-root alias (names, types, counts)")
    s.add_argument("alias")
    s.add_argument("workdir", nargs="?")
    s.add_argument("--milestone")
    s.add_argument("--session")
    s.set_defaults(func=cmd_meta)

    s = sub.add_parser("variant", help="register an analytic variant (freeze-on-first-run)")
    s.add_argument("id", nargs="?")
    s.add_argument("workdir", nargs="?")
    s.add_argument("--milestone")
    s.add_argument("--why", default="")
    s.add_argument("--parent")
    s.add_argument("--label", choices=list(kernel.VARIANT_LABELS))
    s.add_argument("--set", action="append", default=[], metavar="FIELD=value")
    s.add_argument("--locked", metavar="ID")
    s.add_argument("--list", action="store_true")
    s.set_defaults(func=cmd_variant)

    s = sub.add_parser("run", help="run a variant script in the locked-down kernel")
    s.add_argument("--variant", required=True)
    s.add_argument("script", help="variant script; dda options must come before this path")
    s.add_argument("rest", nargs=argparse.REMAINDER, help="script arguments (after an optional `--`)")
    # NOTE: REMAINDER swallows a trailing positional, so the workdir is a flag here.
    s.add_argument("--workdir")
    s.add_argument("--milestone")
    s.add_argument("--session")
    s.add_argument("--seed", type=int)
    s.set_defaults(func=cmd_run)

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

    s = sub.add_parser("report", help="assemble reports/<slug>.md from answer.md + footer")
    s.add_argument("--slug", required=True)
    s.add_argument("workdir", nargs="?")
    s.add_argument("--milestone")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("gitcheck", help="fail if data or secret files are tracked, staged, or untracked-in-git-reach")
    s.add_argument("workdir", nargs="?")
    s.add_argument("--milestone")
    s.set_defaults(func=cmd_gitcheck)

    s = sub.add_parser("approve", help="commit a human approval file (signed; run in your own terminal)")
    s.add_argument("kind", help=f"approval kind: {', '.join(approvals.KINDS)}")
    s.add_argument("artifact", nargs="?", help="artifact hash (defaults from the workdir for config/spec/amendment)")
    s.add_argument("workdir", nargs="?")
    s.add_argument("--milestone")
    s.add_argument("--key", help="signing key id passed to git (default: the key's own default)")
    s.add_argument("--no-sign", action="store_true", help="commit unsigned: recorded as UNVERIFIED")
    s.add_argument("-m", "--message", help="approval note recorded in the approval file")
    s.set_defaults(func=cmd_approve)

    s = sub.add_parser("approved", help="verify an approval and record the verdict in approvals.index.jsonl")
    s.add_argument("kind", help=f"approval kind: {', '.join(approvals.KINDS)}")
    s.add_argument("artifact", nargs="?", help="artifact hash (defaults from the workdir for config/spec/amendment)")
    s.add_argument("workdir", nargs="?")
    s.add_argument("--milestone")
    s.set_defaults(func=cmd_approved)

    s = sub.add_parser("doctor", help="health checks: interpreter, hooks, approver keys, workdir, heartbeat")
    s.add_argument("workdir", nargs="?")
    s.add_argument("--milestone")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_doctor)

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
