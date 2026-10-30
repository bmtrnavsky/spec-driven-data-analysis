"""Real hook logic for bound sessions (spec §6.1-§6.6, §6.8) and the unbound
runlog path (§6.0).

Every function returns (stdout_object, exit_code); exit 2 accompanies a block.
Hooks string-match tool inputs: they stop slips, not determined evasion
(§0.1); every rule here is re-checked by a gate or a chain.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from . import chain, footer, ledger, lockstate
from .layout import REPO_ROOT, DdaError, Workdir, canonical_path, dda_home, load_config
from .matching import (CODE_TOOLS, FILE_WRITERS, ToolView, agent_writable, analysis_refs, analysis_tail, canon,
                       connector_aliases, human_only_violation, norm_text, referenced_aliases, signing_violation, under,
                       write_targets, written_paths_under)

BUSY = "dda: evidence log busy, retry the tool call (§4.4)"
# Tools whose output goes straight to the model: never a sanctioned data path after lock (§6.1).
_DIRECT_READERS = ("read_file", "search_files", "web_extract", "web_search", "vision_analyze", "browser_exec",
                   "terminal", "execute_code")


def block(message: str) -> tuple[dict, int]:
    return {"action": "block", "message": message}, 2


def allow() -> tuple[dict, int]:
    return {}, 0


# ---------- context ----------

class Ctx:
    def __init__(self, hook: str, payload: dict, binding: dict):
        self.hook = hook
        self.payload = payload
        self.binding = binding
        self.session = payload.get("session_id") or ""
        self.wd = Workdir.at(binding["workdir"], binding.get("milestone"))
        extra = payload.get("extra") if isinstance(payload.get("extra"), dict) else {}
        self.call_id = extra.get("tool_call_id") or payload.get("tool_call_id")
        self.event = payload.get("hook_event_name") or "pre_tool_call"
        self.tool = payload.get("tool_name") or ""
        ti = payload.get("tool_input")
        self.tool_input = ti if isinstance(ti, dict) else ({"value": ti} if ti is not None else {})
        self.view = ToolView(self.tool, self.tool_input, payload.get("cwd"))
        self._roots = None
        self.config_error = None

    @property
    def roots(self) -> dict:
        """Data roots from config.yaml, relative paths resolved against the workdir.
        Falls back to the registry copy if config.yaml does not parse (fail toward blocking)."""
        if self._roots is None:
            try:
                raw = load_config(self.wd)["data_roots"]
            except DdaError as exc:
                self.config_error = str(exc)
                from .binding import read_registry
                raw = (read_registry()["workdirs"].get(self.wd.id) or {}).get("roots") or {}
            self._roots = resolve_roots(raw, self.wd.root)
        return self._roots


def resolve_roots(raw: dict, base: Path) -> dict:
    out = {}
    for alias, loc in raw.items():
        if not isinstance(loc, dict):
            continue
        loc = dict(loc)
        loc["paths"] = [canon(p, str(base)) or norm_text(p) for p in loc.get("paths") or []]
        out[alias] = loc
    return out


def heartbeat(ctx: Ctx, decision: str, spill: bool) -> bool:
    """Append this hook's heartbeat line. Returns False when the log was busy and not spilled."""
    rec = {"type": "hook", "hook": ctx.hook, "event": ctx.event, "session": ctx.session, "call": ctx.call_id,
           "tool": ctx.tool, "decision": decision, "workdir_id": ctx.wd.id}
    if ctx.binding.get("parent"):
        rec["parent"] = ctx.binding["parent"]
    try:
        chain.append(ledger.heartbeat_log(ctx.session), rec, spill_on_busy=spill)
        return True
    except chain.ChainBusy:
        return False


def finish(ctx: Ctx, result: tuple[dict, int]) -> tuple[dict, int]:
    decision = "block" if result[1] == 2 else "allow"
    if not heartbeat(ctx, decision, spill=False):
        return block(BUSY)
    return result


def is_clean_dda(ctx: Ctx) -> bool:
    from .hookentry import is_clean_dda_invocation
    return is_clean_dda_invocation(ctx.tool, ctx.tool_input)


def dda_subcommand(ctx: Ctx) -> list[str]:
    import shlex
    cmd = ctx.tool_input.get("command") or ""
    try:
        toks = [t.strip("\"'") for t in shlex.split(cmd, posix=False)]
    except ValueError:
        return []
    base = lambda t: re.split(r"[\\/]", t)[-1].lower()  # noqa: E731
    if toks and base(toks[0]).startswith("dda"):
        return toks[1:]
    if len(toks) > 1 and base(toks[1]) == "dda.py":
        return toks[2:]
    return []


def protected_home_mentioned(view: ToolView) -> list[str]:
    home = canonical_path(dda_home()).lower()
    hits = sorted(p for p in view.paths if under(p, home))
    if not hits and (home in view.blob or ".hermes-home/dda" in view.blob or "dda_home" in view.blob):
        hits = [home]
    return hits


def plugin_code_mentioned(view: ToolView) -> list[str]:
    repo = canonical_path(REPO_ROOT).lower()
    targets = [repo + "/hooks", repo + "/scripts"]
    return sorted(p for p in view.paths if any(under(p, t) for t in targets))


# ---------- human-only subcommands (§6.0) ----------

def human_only_block(ctx: Ctx) -> tuple[dict, int] | None:
    """`dda release` / `dda abandon` from an agent tool call always block.

    Releasing launders later reads (the roots leave the active set), so the
    release itself is ledgered (binding.release) and only a human runs it.
    Checked before the clean-dda passthrough in every blocking hook.
    """
    hit = human_only_violation(ctx.view)
    if hit:
        return block(f"dda {hit} from an agent tool call is blocked (human-only, §6.0). Ask Brad to run it in "
                     "their own terminal; the release is ledgered with the sessions it unbinds.")
    return None


# ---------- lockguard (§6.1) ----------

def lockguard(ctx: Ctx) -> tuple[dict, int]:
    hb = human_only_block(ctx)
    if hb:
        return hb
    sig = signing_violation(ctx.view)
    if sig:
        return block(f"dda lockguard: {sig} is human-only (§4.5). Approvals are signed by an approver in their own "
                     "terminal with `dda approve`; dda's own commits never sign.")
    if is_clean_dda(ctx):
        return allow()
    if ctx.tool in FILE_WRITERS:
        return allow()  # writing is not reading; rawguard/evidenceguard/defguard judge writes
    roots = ctx.roots
    aliases = referenced_aliases(ctx.view, roots)
    state, detail, lock = lockstate.quick_status(ctx.wd)
    if state == "none":
        derived = [p for p in ("derived", "outputs", "reports") if ctx.view.mentions_path(str(ctx.wd.root / p))]
        if derived and not aliases:
            return block(f"dda lockguard: before lock, {', '.join(d + '/' for d in derived)} count as data roots "
                         "(earlier results from these sources, §4.1). Lock the spec first (`dda lock`), or declare "
                         "what you already saw under '## Prior exposure'.")
    if not aliases:
        return allow()
    names = ", ".join(sorted(aliases))
    cfg_note = f" (config.yaml did not parse: {ctx.config_error}; using the registered roots)" if ctx.config_error else ""
    if state == "none":
        return block(f"dda lockguard: this call touches data root(s) {names} before the spec is locked{cfg_note}. "
                     "Lock the spec (`dda lock`). Before lock the only allowed access is `dda meta <alias>` "
                     "(names, types, counts — no values, §3.3).")
    if state == "tampered":
        return block(f"dda lockguard: lock state tampered ({detail}). Stop and ask (§3.2 case 8); "
                     "`dda verify-chain` shows what changed.")
    if state == "config-changed":
        return block(f"dda lockguard: config.yaml changed since lock v{lock['version']}; data reads stay blocked. "
                     "Re-lock as an amendment (`dda lock --amend \"<reason>\"`); the new config needs a human "
                     "config approval (`dda approve config` in your own terminal).")
    if state != "valid":
        return block(f"dda lockguard: {detail}. Re-lock after your spec edit "
                     "(`dda lock --amend \"<reason>\"`); data reads require hash(spec.md) == lock hash (§3.1).")
    unlocked = sorted(aliases - set(lock.get("aliases") or []))
    if unlocked:
        return block(f"dda lockguard: data root(s) {', '.join(unlocked)} are not in the locked spec "
                     f"(lock v{lock['version']} lists {', '.join(lock.get('aliases') or []) or 'none'}). "
                     "Add them under '## Data sources' and re-lock as an amendment.")
    via_connector = connector_aliases(ctx.view, roots)
    direct = aliases - via_connector
    if direct or ctx.tool in _DIRECT_READERS:
        return block(f"dda lockguard: after lock, data root(s) {', '.join(sorted(direct or aliases))} are read only "
                     "through the kernel runner or a declared connector tool. Use `dda run` "
                     "(direct reads bypass masking and the audit log, §6.1, §10.2).")
    return allow()


# ---------- evidenceguard (§6.2) ----------

def _frozen_variant(ctx: Ctx, tail: str) -> bool:
    m = re.match(r"^variants/([^/]+)\.(?:py|sql)$", tail)
    if not m:
        return False
    vid = m.group(1)
    return any(r.get("variant") == vid and r.get("frozen_hash") for r in chain.read_records(ledger.specs_tried(ctx.wd)))


def evidenceguard(ctx: Ctx) -> tuple[dict, int]:
    hb = human_only_block(ctx)
    if hb:
        return hb
    if is_clean_dda(ctx):
        return allow()
    view = ctx.view
    code = "\n".join(view.texts) if ctx.tool in CODE_TOOLS else ""
    if code and re.search(r"\bgit\b[^\n;&|]*\b(?:add|commit)\b", code) and "approvals" in view.blob \
            and any(t.startswith("approvals") for t in analysis_refs(view)):
        return block("dda evidenceguard: approval files are committed by a human approver with `dda approve` in "
                     "their own terminal (§4.5); an agent commit of approvals/ would be a forgery.")
    intent, targets = write_targets(view)
    if not intent:
        return allow()
    if targets is not None:
        tails = {t2 for t in targets for t2 in [analysis_tail(t)] if t2 is not None}
        home_hits = [t for t in targets if under(t, canonical_path(dda_home()).lower())]
        plugin_hits = [t for t in targets if any(under(t, canonical_path(REPO_ROOT).lower() + s)
                                                 for s in ("/hooks", "/scripts"))]
    else:
        tails = analysis_refs(view)
        home_hits = protected_home_mentioned(view)
        plugin_hits = plugin_code_mentioned(view)
    if home_hits:
        return block("dda evidenceguard: the dda home (session bindings, heads mirror, lock-state cache, logs) is "
                     "written only by dda and its hooks (§6.2). A bound agent never touches it (and never runs "
                     "`dda release`/`dda abandon` itself — those are human-only); ask Brad.")
    if plugin_hits:
        return block("dda evidenceguard: the dda plugin's hooks and scripts are read-only in a bound session.")
    bad = sorted(t for t in tails if not agent_writable(t))
    if bad:
        shown = ", ".join(".analysis/" + t if t else ".analysis/" for t in bad[:4])
        return block(f"dda evidenceguard: {shown} is evidence written only by its named writer (§6.2 table: "
                     "dda lock, runlog, the kernel, a human). The agent may write spec.md, wayfinder.md, "
                     "variants/<id> (until first run), answer.md, reviews/self/, notes/, kernel.yaml.")
    frozen = sorted(t for t in tails if _frozen_variant(ctx, t))
    if frozen:
        return block(f"dda evidenceguard: {frozen[0]} is frozen after its first run (§4.3). "
                     "Copy it to a new variant id instead.")
    return allow()


# ---------- rawguard (§6.3) ----------

def rawguard(ctx: Ctx) -> tuple[dict, int]:
    hb = human_only_block(ctx)
    if hb:
        return hb
    if is_clean_dda(ctx):
        return allow()
    intent, targets = write_targets(ctx.view)
    if not intent:
        return allow()
    for alias, loc in ctx.roots.items():
        for p in loc.get("paths") or []:
            hit, _ = written_paths_under(ctx.view, p)
            if hit:
                return block(f"dda rawguard: this call may write, move, or delete inside data root '{alias}'. "
                             "Raw data is immutable; write derived data to derived/ (§6.3).")
    snaps = canon(str(ctx.wd.root / "derived" / "snapshots"))
    cands = targets if targets is not None else ctx.view.paths
    for p in cands:
        if under(p, snaps) and p != snaps and os.path.exists(p):
            return block("dda rawguard: snapshot files in derived/snapshots/ are never overwritten in place; "
                         "write a new snapshot (§6.3, §10.3).")
    return allow()


# ---------- defguard (§6.4) ----------

def defguard(ctx: Ctx) -> tuple[dict, int]:
    hb = human_only_block(ctx)
    if hb:
        return hb
    if is_clean_dda(ctx):
        return allow()
    intent, targets = write_targets(ctx.view)
    if not intent:
        return allow()
    defs = canon(str(ctx.wd.definitions))
    props = defs + "/proposals"
    cands = targets if targets is not None else ctx.view.paths
    bad = [p for p in cands if under(p, defs) and not under(p, props)]
    if targets is None and not bad and re.search(r"(?:^|[^a-z0-9_.\-])definitions/(?!proposals(?:/|\b))", ctx.view.blob):
        bad = ["definitions/"]
    if bad:
        return block("dda defguard: definitions/ is the human-owned registry (§7). Propose new or changed "
                     "definitions in definitions/proposals/; a human merges and bumps the version.")
    return allow()


# ---------- footercheck (§6.5) ----------

def _patched_content(path: str, inp: dict) -> str | None:
    old, new = inp.get("old_string"), inp.get("new_string")
    if not isinstance(old, str) or not isinstance(new, str):
        return None
    try:
        with open(path, "r", encoding="utf-8", newline="") as fh:
            cur = fh.read()
    except FileNotFoundError:
        return None
    if old not in cur:
        return ""
    return cur.replace(old, new) if inp.get("replace_all") else cur.replace(old, new, 1)


def _publish_channels(ctx: Ctx) -> dict:
    try:
        from . import yamlsub
        cfg = yamlsub.load_file(ctx.wd.config_path)
    except Exception:
        return {}
    pc = cfg.get("publish_channels") if isinstance(cfg, dict) else None
    return pc if isinstance(pc, dict) else {}


def footercheck(ctx: Ctx) -> tuple[dict, int]:
    hb = human_only_block(ctx)
    if hb:
        return hb
    if is_clean_dda(ctx):
        return allow()
    reports = canon(str(ctx.wd.root / "reports"))
    answer = canon(str(ctx.wd.analysis / "answer.md"))
    view = ctx.view
    if ctx.tool in FILE_WRITERS:
        t = view.target_path()
        if t and (under(t, reports) and t.endswith(".md") or t == answer):
            if ctx.tool == "write_file":
                content = ctx.tool_input.get("content")
            else:
                content = _patched_content(t, ctx.tool_input)
                if content == "":
                    return allow()  # old_string absent: the patch fails on its own
            if not isinstance(content, str):
                return block("dda footercheck: cannot compute the patched report text; write the whole file with "
                             "write_file so the footer can be checked.")
            problems = footer.check(ctx.wd, content, short=(t == answer))
            if problems:
                return block("dda footercheck: provenance footer check failed (§8):\n  - " + "\n  - ".join(problems)
                             + "\n`dda footer` prints a skeleton with the recomputable fields filled in.")
            return allow()
    elif ctx.tool in CODE_TOOLS:
        hit_r, _ = written_paths_under(view, str(ctx.wd.root / "reports"))
        hit_a, _ = written_paths_under(view, str(ctx.wd.analysis / "answer.md"))
        if hit_r or hit_a:
            return block("dda footercheck: write reports and answer.md with write_file or patch so the provenance "
                         "footer can be checked (§6.5).")
    channels = _publish_channels(ctx)
    if channels:
        names = view.inner_tool_names()
        hit = None
        for name, loc in channels.items():
            if not isinstance(loc, dict):
                continue
            if any(re.search(p, n) for p in loc.get("tool_patterns") or [] for n in names) or \
                    any(view.mentions_path(p) for p in loc.get("paths") or []):
                hit = name
                break
        if hit and _carries_workdir_report(ctx):
            lock = lockstate.read_lock(ctx.wd) or {}
            if lock.get("tier") != "PUBLISH":
                return block(f"dda footercheck: publishing this workdir's report through '{hit}' needs tier PUBLISH "
                             "and a verified human sign-off. Raise the tier (amendment) and get sign-off first.")
            return block(f"dda footercheck: publishing through '{hit}' needs a verified human sign-off for this "
                         "report hash; verify it with `dda approved signoff <hash>` — until the report gate "
                         "lands, publish stays parked.")
    return allow()


def _carries_workdir_report(ctx: Ctx) -> bool:
    view = ctx.view
    if view.mentions_path(str(ctx.wd.root / "reports")) or view.mentions_path(str(ctx.wd.analysis / "answer.md")):
        return True
    try:
        lock = lockstate.read_lock(ctx.wd)
    except DdaError:
        return True
    if lock and lock["lock_hash"][:12] in view.blob:
        return True
    rdir = ctx.wd.root / "reports"
    if rdir.is_dir():
        for f in rdir.glob("*.md"):
            if re.search(rf"(?<![a-z0-9_\-]){re.escape(f.stem.lower())}(?![a-z0-9_\-])", view.blob) and len(f.stem) >= 6:
                return True
    return False


# ---------- runlog (§6.6) ----------

_SECRET_RES = [
    (re.compile(r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|auth)[a-z0-9_]*\s*[=:]\s*)(['\"]?)[^\s'\";&]+"),
     r"\1\2<redacted>"),
    (re.compile(r"(?i)(bearer\s+)[a-z0-9._\-~+/]+=*"), r"\1<redacted>"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "<redacted-jwt>"),
    (re.compile(r"([a-z][a-z0-9+.\-]*://[^:/\s@]+:)[^@\s]+@", re.IGNORECASE), r"\1<redacted>@"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<redacted-aws-key>"),
    (re.compile(r"\b(?:ghp|gho|ghs|github_pat|sk|xox[abp])[-_][A-Za-z0-9_\-]{16,}\b"), "<redacted-token>"),
]


def scrub(text: str) -> str:
    for rx, rep in _SECRET_RES:
        text = rx.sub(rep, text)
    return text


def _run_text(ctx: Ctx, aliases: set[str]) -> str | None:
    if ctx.tool == "terminal":
        return ctx.tool_input.get("command") if isinstance(ctx.tool_input.get("command"), str) else None
    if ctx.tool == "execute_code":
        return ctx.tool_input.get("code") if isinstance(ctx.tool_input.get("code"), str) else None
    if aliases and connector_aliases(ctx.view, ctx.roots):
        import json
        return json.dumps(ctx.tool_input, sort_keys=True)
    return None


def write_blob(wd: Workdir, text: str) -> tuple[str, str]:
    body = scrub(text)
    h = hashlib.sha256(body.encode("utf-8")).hexdigest()
    d = ledger.blobs_dir(wd)
    d.mkdir(parents=True, exist_ok=True)
    f = d / h
    if not f.exists():
        tmp = d / f".{h}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)
        try:
            os.replace(tmp, f)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return h, f"runs/blobs/{h}"


_BLOCKED_EXACT = ("block", "blocked")
_BLOCK_WORD_RE = re.compile(r"\bblock(?:ed|ing)?\b")


def _status_is_blocked(v) -> bool:
    return isinstance(v, str) and v.strip().lower() in _BLOCKED_EXACT


def _result_body_blocked(res) -> bool:
    """A tool-result body (dict or its JSON string) naming a block.

    Hermes delivers the result as a JSON *string*; a blocked call's body is
    `{"error": <block message>}`. Plain tool errors (status "error", no
    block marker) never count: the tool ran, the call was not blocked.
    """
    if isinstance(res, str):
        s = res.strip()
        if not s.startswith("{"):
            return False
        try:
            res = json.loads(s)
        except Exception:
            return False
    if not isinstance(res, dict):
        return False
    if res.get("blocked") is True:
        return True
    for key in ("status", "action", "decision", "outcome"):
        if _status_is_blocked(res.get(key)):
            return True
    err = res.get("error")
    return isinstance(err, str) and bool(_BLOCK_WORD_RE.search(err.lower()))


def _was_blocked(payload: dict) -> bool:
    """post_tool_call fired but the tool never ran (a sibling hook blocked it).

    Real Hermes shape (`_blocked_tool_result` → post hook → shell-hook
    payload): the block signal is `extra.status == "blocked"` ("block" never
    occurs on the wire) and `extra.result` is the JSON *string*
    `{"error": msg}`. Older/synthetic payloads may carry top-level
    `blocked: true` or a dict result body — those still count. A blocked
    call is logged kind=blocked and exposure ignores it.

    `extra.status` is authoritative when present: a tool that ran and
    reported `status == "error"` (e.g. `BlockingIOError`, or user code that
    raised on the word "blocked") is a tool error, not a blocked call, even
    if the error text contains a block-like word. Only when `extra` carries
    no status do the result-body / error-text fallbacks apply.
    """
    if not isinstance(payload, dict):
        return False
    if payload.get("blocked") is True:
        return True
    extra = payload.get("extra")
    if isinstance(extra, dict) and "status" in extra:
        return _status_is_blocked(extra.get("status"))
    for key in ("decision", "hook_decision", "hook_action", "outcome", "status", "action"):
        if _status_is_blocked(payload.get(key)):
            return True
    if isinstance(extra, dict):
        if extra.get("blocked") is True:
            return True
        for key in ("decision", "hook_decision", "hook_action", "outcome", "status", "action"):
            if _status_is_blocked(extra.get(key)):
                return True
        for rkey in ("tool_result", "result", "tool_output", "output", "function_result"):
            if _result_body_blocked(extra.get(rkey)):
                return True
    for rkey in ("tool_result", "result", "tool_output", "output"):
        if _result_body_blocked(payload.get(rkey)):
            return True
    err = payload.get("error")
    return (isinstance(err, str) and "dda" in err.lower()
            and bool(_BLOCK_WORD_RE.search(err.lower())))


def runlog(ctx: Ctx) -> tuple[dict, int]:
    """Side effect only: never blocks (busy logs spill, §4.4)."""
    aliases = referenced_aliases(ctx.view, ctx.roots) if ctx.tool not in FILE_WRITERS else set()
    base = {"session": ctx.session, "tool": ctx.tool, "call": ctx.call_id}
    if ctx.binding.get("parent"):
        base["parent"] = ctx.binding["parent"]
    if ctx.event == "post_tool_call":
        sub = dda_subcommand(ctx) if is_clean_dda(ctx) else []
        variant = None
        if "--variant" in sub and sub.index("--variant") + 1 < len(sub):
            variant = sub[sub.index("--variant") + 1]
        if _was_blocked(ctx.payload):
            kind, aliases = "blocked", set()
        elif sub[:1] == ["meta"]:
            kind = "meta"
        elif sub[:1] == ["run"]:
            kind = "data"
            try:
                lock = lockstate.read_lock(ctx.wd) or {}
                aliases = set(lock.get("aliases") or [])
            except DdaError:
                pass
        elif sub:
            kind, aliases = "other", set()
        else:
            kind = "data" if aliases else "other"
        rec = {"type": "done", **base, "aliases": sorted(aliases), "kind": kind, "variant": variant}
        text = _run_text(ctx, aliases)
        if text:
            h, ptr = write_blob(ctx.wd, text)
            rec["code_hash"], rec["blob"] = h, ptr
        chain.append(ledger.runs_log(ctx.wd), rec, spill_on_busy=True)
    else:
        chain.append(ledger.runs_log(ctx.wd), {"type": "seen", **base, "aliases": sorted(aliases)}, spill_on_busy=True)
    heartbeat(ctx, "logged", spill=True)
    return allow()


def unbound_runlog(payload: dict) -> None:
    """Unbound session: log declared-root matches of ACTIVE workdirs (and writes into their .analysis/)
    to the unbound-access log. Never blocks, never raises to the caller."""
    from .binding import read_registry
    if (payload.get("hook_event_name") or "pre_tool_call") != "pre_tool_call":
        return
    reg = read_registry()["workdirs"]
    if not reg:
        return
    tool = payload.get("tool_name") or ""
    ti = payload.get("tool_input")
    view = ToolView(tool, ti if isinstance(ti, dict) else {"value": ti}, payload.get("cwd"))
    matches, writes = [], []
    intent, targets = write_targets(view)
    for wid, w in sorted(reg.items()):
        roots = resolve_roots(w.get("roots") or {}, Path(w["path"]))
        hits = referenced_aliases(view, roots) if tool not in FILE_WRITERS else set()
        matches += [{"workdir_id": wid, "workdir": w["path"], "alias": a} for a in sorted(hits)]
        if intent:
            hit, paths = written_paths_under(view, str(Path(w["path"]) / ".analysis"))
            if hit:
                writes.append({"workdir_id": wid, "workdir": w["path"], "paths": paths[:5]})
    if not matches and not writes:
        return
    extra = payload.get("extra") if isinstance(payload.get("extra"), dict) else {}
    rec = {"type": "unbound", "session": payload.get("session_id"), "tool": tool, "call": extra.get("tool_call_id"),
           "matches": matches}
    if writes:
        rec["analysis_writes"] = writes
    chain.append(ledger.unbound_log(), rec, spill_on_busy=True)


HOOKS = {
    "lockguard": lockguard,
    "evidenceguard": evidenceguard,
    "rawguard": rawguard,
    "defguard": defguard,
    "footercheck": footercheck,
}


def run_bound(hook: str, payload: dict, binding: dict) -> tuple[dict, int]:
    ctx = Ctx(hook, payload, binding)
    if hook == "runlog":
        return runlog(ctx)
    return finish(ctx, HOOKS[hook](ctx))


__all__ = ["run_bound", "unbound_runlog", "scrub", "HOOKS", "resolve_roots"]
