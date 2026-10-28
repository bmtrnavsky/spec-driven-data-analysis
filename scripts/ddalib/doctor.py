"""`dda doctor` health checks (spec §6.8, §6.9, §4.5).

Sections: interpreter, hook entry point (imports + dry-run of every
blocking hook), approver key setup (gpg-agent cache, reachable ssh-agent
keys, git signing config — any failure downgrades every approval to
unverified), and, for a given workdir, lock state, evidence chains,
heartbeat liveness, and the active-workdir registry.

Key checks never fail merely because a tool is absent: with no gpg-agent,
no ssh-agent, and no git auto-signing configured, there is nothing an
agent could borrow, so the check passes. Anything reachable that matches
an approver key fails.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .layout import REPO_ROOT, DdaError, Workdir, dda_home

BLOCKING_HOOKS = ("lockguard", "evidenceguard", "rawguard", "defguard", "footercheck")


def _check(status: str, name: str, detail: str = "") -> dict:
    return {"status": status, "name": name, "detail": detail}


# ---------- key checks (§4.5) ----------

def _gpg_agent_check(approvers: list) -> dict:
    gpgconf = shutil.which("gpgconf")
    if not gpgconf:
        return _check("pass", "gpg-agent", "gpg not installed: no passphrase cache to abuse")
    try:
        r = subprocess.run([gpgconf, "--list-options", "gpg-agent"],
                           capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return _check("skip", "gpg-agent", "gpgconf did not run; assuming no cache")
    if r.returncode != 0:
        return _check("pass", "gpg-agent", "gpg-agent not running: nothing cached")
    vals = {}
    for line in r.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 10 and parts[0] in ("ignore-cache-for-signing", "default-cache-ttl", "max-cache-ttl"):
            vals[parts[0]] = parts[9]
    if not vals:
        return _check("fail", "gpg-agent", "gpgconf output unparseable; cannot confirm the cache is off")
    if vals.get("ignore-cache-for-signing") == "1":
        return _check("pass", "gpg-agent", "ignore-cache-for-signing is set")
    if vals.get("default-cache-ttl") == "0" and vals.get("max-cache-ttl") == "0":
        return _check("pass", "gpg-agent", "default-cache-ttl and max-cache-ttl are 0")
    return _check("fail", "gpg-agent",
                  "passphrase caching is on (set ignore-cache-for-signing or both cache-ttls to 0); "
                  "every approval downgrades to unverified until fixed")


def _ssh_lines() -> tuple[list[str], str]:
    ssh_add = shutil.which("ssh-add")
    if not ssh_add:
        return [], "ssh-add not installed"
    # Fingerprints (-l), not full public keys (-L): fingerprints are what
    # approver entries carry, and full key material must not land in logs.
    try:
        r = subprocess.run([ssh_add, "-l"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return [], "ssh-add did not run"
    if r.returncode != 0:
        # Some agents only answer -L; still enumerate rather than pass blind.
        try:
            r2 = subprocess.run([ssh_add, "-L"], capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            return [], "ssh-add did not run"
        if r2.returncode != 0:
            return [], "no ssh-agent reachable (ssh-add -l failed)"
        return [ln for ln in r2.stdout.splitlines() if ln.strip()], ""
    return [ln for ln in r.stdout.splitlines() if ln.strip()], ""


def _is_sk_keytype(line: str) -> bool:
    parts = line.split()
    if parts and parts[0].lower().startswith("sk-"):
        return True  # ssh-add -L full-key form
    return "-SK)" in line.upper()  # ssh-add -l fingerprint form, e.g. (ED25519-SK)


def _ssh_agent_check(approvers: list) -> dict:
    from .approvals import approver_matches
    lines, note = _ssh_lines()
    if not lines:
        return _check("pass", "ssh-agent", note or "no keys loaded")
    bad = []
    for line in lines:
        if _is_sk_keytype(line):
            continue  # FIDO2 touch key: the agent cannot use it unattended
        # approver_matches is whole-value-only (no word-splitting), so pull
        # the structured fingerprint column out of `ssh-add -l` output
        # ("<bits> <fingerprint> <comment> (<type>)") explicitly. Full-key
        # (`ssh-add -L`) lines are passed whole: only a full-key equality
        # counts, never a fragment.
        cands: list[str] = [line]
        parts = line.split()
        if len(parts) >= 2 and not parts[0].lower().startswith(("sk-", "ssh-", "ecdsa-")):
            cands.append(parts[1])
        if approver_matches(approvers, *cands):
            bad.append(line.split()[0] + " ...")
    if bad:
        return _check("fail", "ssh-agent",
                      "approver key(s) reachable without touch: " + ", ".join(bad) +
                      "; remove them from the agent")
    return _check("pass", "ssh-agent", f"{len(lines)} key(s) listed, none matches an approver")


def _git_config_check(wd: Workdir | None, approvers: list) -> dict:
    from .approvals import approver_matches
    if not shutil.which("git"):
        return _check("skip", "git-signing-config", "git not installed")
    scopes = ["--system", "--global"]
    cfgs: list[tuple[str, str, str]] = []
    for scope in scopes:
        for key in ("commit.gpgsign", "tag.gpgSign", "user.signingkey"):
            try:
                r = subprocess.run(["git", "config", scope, "--get", key],
                                   capture_output=True, text=True, timeout=15)
            except (OSError, subprocess.SubprocessError):
                continue
            if r.returncode == 0 and r.stdout.strip():
                cfgs.append((scope, key, r.stdout.strip()))
    if wd is not None:
        for key in ("commit.gpgsign", "tag.gpgSign", "user.signingkey"):
            try:
                r = subprocess.run(["git", "-C", str(wd.root), "config", "--get", key],
                                   capture_output=True, text=True, timeout=15)
            except (OSError, subprocess.SubprocessError):
                continue
            if r.returncode == 0 and r.stdout.strip():
                cfgs.append(("workdir", key, r.stdout.strip()))
    auto = [f"{s} {k}={v}" for s, k, v in cfgs if k != "user.signingkey" and v.lower() in ("true", "yes", "on", "1")]
    if auto:
        return _check("fail", "git-signing-config",
                      "auto-signing is on (" + "; ".join(auto) +
                      "); agent commits would sign without -S, which lockguard cannot see")
    signers = [v for _, k, v in cfgs if k == "user.signingkey"]
    hit = approver_matches(approvers, *signers) if signers else None
    if hit:
        return _check("fail", "git-signing-config",
                      f"user.signingkey names approver {hit}; dda's own commits force signing off, "
                      "but a bare `git commit` would borrow it")
    detail = f"checked {len(scopes) + 1} scopes"
    if signers:
        detail += "; user.signingkey set but matches no approver"
    return _check("pass", "git-signing-config", detail)


def key_checks(wd: Workdir | None = None, approvers: list | None = None) -> list[dict]:
    """Approver-key checks (§4.5). Any 'fail' downgrades approvals."""
    if approvers is None:
        try:
            from .layout import load_config
            approvers = load_config(wd).get("approvers") or [] if wd is not None else []
        except DdaError:
            approvers = []
    gpg = _gpg_agent_check(approvers)
    ssh = _ssh_agent_check(approvers)
    gitc = _git_config_check(wd, approvers)
    return [gpg, ssh, gitc, _windows_agent_check(ssh["detail"])]


def _windows_agent_check(ssh_note: str) -> dict:
    """Windows-only agents ssh-add may not see (§4.5): Pageant, the Windows
    OpenSSH agent pipe, 1Password's agent. A present-but-unenumerated agent
    fails: its keys are borrowable and invisible to the ssh-agent check."""
    if os.name != "nt":
        return _check("pass", "windows-agents", "not a Windows host")
    procs = ""
    try:
        r = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            procs = r.stdout.lower()
    except (OSError, subprocess.SubprocessError):
        pass
    if "pageant.exe" in procs:
        return _check("fail", "windows-agents",
                      "pageant.exe is running: PuTTY/Pageant keys are invisible to ssh-add; "
                      "unload approver keys or stop Pageant")
    pipe_present = False
    try:
        pipe_present = Path(r"\\.\pipe\openssh-ssh-agent").exists()
    except OSError:
        pipe_present = False
    unenumerated = any(s in (ssh_note or "") for s in
                       ("not installed", "did not run", "no ssh-agent reachable"))
    if pipe_present and unenumerated:
        return _check("fail", "windows-agents",
                      "the Windows OpenSSH agent pipe is present but ssh-add could not "
                      "enumerate it; confirm no approver key is loaded there")
    detail = "no Pageant; Windows OpenSSH agent pipe " + \
        ("enumerated via ssh-add" if pipe_present else "absent")
    if "1password" in procs:
        detail += "; 1Password is running — if its SSH agent is enabled, confirm no approver key is stored there"
    return _check("pass", "windows-agents", detail)


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
    """Run every section. Returns {ok, downgrade, sections: {name: [checks]}}."""
    approvers: list = []
    if wd is not None:
        try:
            from .layout import load_config
            approvers = load_config(wd).get("approvers") or []
        except DdaError:
            approvers = []
    sections = {
        "interpreter": interpreter_checks(),
        "hooks": hook_entry_checks(),
        "keys": key_checks(wd, approvers),
    }
    if wd is not None:
        sections["workdir"] = workdir_checks(wd)
    fails = [c for checks in sections.values() for c in checks if c["status"] == "fail"]
    key_fails = [c for c in sections["keys"] if c["status"] == "fail"]
    return {"ok": not fails, "downgrade": bool(key_fails),
            "failures": [c["name"] for c in fails],
            "key_failures": [c["name"] for c in key_fails],
            "sections": sections}


__all__ = ["run", "key_checks", "workdir_checks", "hook_entry_checks", "interpreter_checks", "BLOCKING_HOOKS"]
