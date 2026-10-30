"""Goldfish review: packet assembly, one-shot review calls, recording (§5.0).

`dda packet <stage>` assembles the fixed file set (spec, lock if present,
definition excerpts, plus post-result: profile, specs-tried ledger,
aggregate draft report, footer; never data files, derived/, or raw rows)
under `.analysis/packets/<packet-hash>/`.

`dda review run <stage>` sends ONE request to the provider API directly
(not through the Hermes agent loop): system prompt = the
goldfish-packet.md template filled with only the stage and round list,
user message = the packet inlined as delimited files, `tools` empty, no
memory, no context files, no hooks, no prior turns. Every call is
recorded under `reviews/goldfish/`, including failed ones, and a `review`
line is appended to runs.log — so G3/G7 count every call for the packet
and stage and the elephant cannot re-roll until it gets a pass.

Fail-closed throughout: oversize packets fail with the file list and
sizes; review runs with no provider key fail (below PUBLISH the gate
degrades to self re-reads with a footer caveat; at PUBLISH it parks).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.request
from pathlib import Path

from . import chain, ledger, lockhash
from .layout import DdaError, Workdir, TEMPLATES_DIR, load_config, read_text_lf

FORMAT_PACKET = "dda-packet-v1"
FORMAT_CALL = "dda-goldfish-v1"

DEFAULT_MAX_TOKENS = 150_000
DEFAULT_KEY_ENV = "DDA_GOLDFISH_API_KEY"
DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "default"
STUB_ENV = "DDA_GOLDFISH_STUB"
# The stub transport fakes a passing provider. It exists for tests and the
# red-team harness only, and is honored exclusively under an explicit
# test flag: `DDA_TEST_MODE=1` (harness opt-in) or `PYTEST_CURRENT_TEST`
# (set automatically by pytest). In production the variable is ignored and
# the run fails closed on the missing provider key. An attacker or a
# sloppy session that exports DDA_GOLDFISH_STUB=pass in a real terminal
# gets no fake reviews.
TEST_ENV = "DDA_TEST_MODE"


def _stub_allowed() -> bool:
    return os.environ.get(TEST_ENV) == "1" or "PYTEST_CURRENT_TEST" in os.environ


def _stub_verdict() -> str | None:
    if not _stub_allowed():
        return None
    stub = os.environ.get(STUB_ENV)
    return stub if stub in ("pass", "fail") else None

STAGE_ALIASES = {
    "teardown": "teardown", "pre-data": "teardown", "predata": "teardown",
    "3": "teardown", "stage3": "teardown", "stage-3": "teardown",
    "post-result": "post-result", "postresult": "post-result",
    "post_result": "post-result", "7": "post-result",
    "stage7": "post-result", "stage-7": "post-result", "verify": "post-result",
}

# Round definitions, verbatim from SPEC §5.1 (teardown) and §5.2 (post-result).
TEARDOWN_ROUNDS = {
    "1": "Zoom-out — does the question match the decision? Would any answer change anything?",
    "2": "Comprehension — could a stranger run this from the spec alone? Every metric resolves; every source named.",
    "3": "Design critique — confounders, selection bias, leakage, base rates, multiple comparisons, "
          "grain mismatches in joins, survivorship, time window effects.",
    "4": "Intermediate zoom-out — after critique, is this still the smallest analysis that answers it "
          "(ponytail)? Cut unneeded cuts now, before they become forks.",
    "5": "Lockability — are thresholds, comparisons, and tolerance concrete enough that "
          "\"we changed the plan\" would be detectable?",
}
POST_RESULT_ROUNDS = {
    "1": "Claim-to-evidence — every claim in the draft maps to a logged output, variant id, and run id.",
    "2": "Forking paths — the reported variant is the locked one, or it is labelled post-data-locked or "
          "exploratory; N tried is disclosed.",
    "3": "Alternative explanations — could a confounder, Simpson's paradox, selection effect, or "
          "data-quality artifact produce the same result?",
    "4": "Definitions conformance — computed metrics match registry definitions (grain, filters, time basis).",
    "5": "Lean — every table and chart carries a claim; delete the rest.",
}
# PUBLISH runs round 3 twice (the "second goldfish", §5.0 independence).
SECOND_GOLDFISH_ROUND = "3b"

ROUND_LINE_RE = re.compile(r"^ROUND\s+([0-9]+[a-z]?)\s*:\s*(PASS|FAIL)\b(.*)$", re.IGNORECASE)


def normalize_stage(stage: str) -> str:
    key = (stage or "").strip().lower()
    if key not in STAGE_ALIASES:
        raise DdaError(f"unknown review stage {stage!r} (stages: teardown, post-result)")
    return STAGE_ALIASES[key]


def required_rounds(tier: str | None, rung: str | None) -> tuple[list[str], bool]:
    """(rounds, need_goldfish) for the teardown stage per SPEC §5.3."""
    if tier == "EXPLORE":
        return ["1", "3"], False
    if tier == "DECIDE":
        if rung == "glance":
            return ["1", "3"], True
        if rung in ("quick-cut", "full analysis", "study"):
            return ["1", "2", "3", "4", "5"], True
    elif tier == "PUBLISH":
        if rung in ("quick-cut", "full analysis", "study"):
            return ["1", "2", "3", SECOND_GOLDFISH_ROUND, "4", "5"], True
        if rung == "glance":
            raise DdaError("PUBLISH is never glance (SPEC §2.1); step the rung up before review")
    raise DdaError(f"cannot scale review rounds: tier {tier!r}, rung {rung!r} "
                   "(declare both in the spec, §2)")


def post_result_rounds(tier: str | None, rung: str | None) -> tuple[list[str], bool]:
    """(rounds, need_goldfish) for the post-result stage per SPEC §5.3."""
    if tier == "EXPLORE":
        return ["1", "2"], False
    if tier == "DECIDE":
        if rung == "glance":
            return ["1", "2"], True
        if rung in ("quick-cut", "full analysis", "study"):
            return ["1", "2", "3", "4", "5"], True
    elif tier == "PUBLISH":
        if rung in ("quick-cut", "full analysis", "study"):
            return ["1", "2", "3", SECOND_GOLDFISH_ROUND, "4", "5"], True
        if rung == "glance":
            raise DdaError("PUBLISH is never glance (SPEC §2.1); step the rung up before review")
    raise DdaError(f"cannot scale review rounds: tier {tier!r}, rung {rung!r} "
                   "(declare both in the spec, §2)")


def rounds_for(stage: str, tier: str | None, rung: str | None) -> tuple[list[str], bool]:
    if stage == "teardown":
        return required_rounds(tier, rung)
    return post_result_rounds(tier, rung)


def goldfish_config(wd: Workdir) -> dict:
    cfg = load_config(wd)
    cap = cfg.get("goldfish_max_tokens", DEFAULT_MAX_TOKENS)
    if isinstance(cap, bool) or not isinstance(cap, int) or cap <= 0:
        raise DdaError("config.yaml: goldfish_max_tokens must be a positive integer")
    models = cfg.get("goldfish_models", [])
    if models is None:
        models = []
    if not isinstance(models, list) or not all(isinstance(m, str) and m for m in models):
        raise DdaError("config.yaml: goldfish_models must be a list of non-empty model ids")
    key_env = cfg.get("goldfish_api_key_env", DEFAULT_KEY_ENV)
    if not isinstance(key_env, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key_env):
        raise DdaError("config.yaml: goldfish_api_key_env must be an env var name")
    base_url = cfg.get("goldfish_base_url", DEFAULT_BASE_URL)
    if not isinstance(base_url, str) or not re.match(r"^https?://", base_url):
        raise DdaError("config.yaml: goldfish_base_url must be an http(s) URL")
    return {"max_tokens": cap, "models": models, "key_env": key_env, "base_url": base_url.rstrip("/")}


def provider_available(wd: Workdir) -> bool:
    """A goldfish call can run: stub transport (tests/redteam only, gated
    on the test flag) or a real key."""
    if _stub_verdict() is not None:
        return True
    return bool(os.environ.get(goldfish_config(wd)["key_env"]))


def estimate_tokens(data: bytes) -> int:
    return max(1, len(data) // 4)


# ---------- packet ----------

def packets_dir(wd: Workdir) -> Path:
    return wd.analysis / "packets"


def _existing(wd: Workdir, *rel: str) -> Path | None:
    p = wd.analysis.joinpath(*rel) if rel[0] != "." else wd.root.joinpath(*rel[1:])
    return p if p.is_file() else None


def packet_files(wd: Workdir, stage: str, comp: lockhash.LockComponents) -> list[tuple[str, bytes]]:
    """Fixed file set per SPEC §5.0. Never data files, derived/, or raw rows."""
    from . import footer as _footer
    files: list[tuple[str, bytes]] = []
    spec_bytes = wd.spec_path.read_bytes()
    files.append((".analysis/spec.md", spec_bytes))
    lock_path = wd.analysis / "spec.lock"
    if lock_path.is_file():
        files.append((".analysis/spec.lock", lock_path.read_bytes()))
    else:
        pending = (f"no spec.lock yet (pre-lock {stage} review)\n"
                   f"spec_hash: {comp.spec_hash}\nconfig_hash: {comp.config_hash}\n"
                   f"pins: {', '.join(comp.pins) or 'none'}\naliases: {', '.join(comp.aliases) or 'none'}\n"
                   f"tier: {comp.tier}\nrung: {comp.rung}\n").encode()
        files.append((".analysis/lock-pending.txt", pending))
    for pin in comp.pins:
        name = pin.split("@")[0]
        dpath = wd.root / "definitions" / f"{name}.md"
        if dpath.is_file():
            files.append((f"definitions/{name}.md", dpath.read_bytes()))
    ledger_path = wd.analysis / "ledger.md"
    if ledger_path.is_file():
        files.append((".analysis/ledger.md", ledger_path.read_bytes()))
    wayfinder = wd.analysis / "wayfinder.md"
    if wayfinder.is_file():
        files.append((".analysis/wayfinder.md", wayfinder.read_bytes()))
    files.append((".analysis/eval-questions.md", _eval_questions(wd)))
    if stage == "post-result":
        profile = wd.analysis / "profile.md"
        if not profile.is_file():
            raise DdaError("post-result packet needs .analysis/profile.md (run the profile stage first)")
        files.append((".analysis/profile.md", profile.read_bytes()))
        tried = wd.analysis / "specs-tried.jsonl"
        if tried.is_file():
            files.append((".analysis/specs-tried.jsonl", tried.read_bytes()))
        drafts = []
        answer = wd.analysis / "answer.md"
        if answer.is_file():
            drafts.append(answer)
        reports = wd.root / "reports"
        if reports.is_dir():
            drafts += sorted(p for p in reports.glob("*.md") if p.is_file())
        if not drafts:
            raise DdaError("post-result packet needs a draft report (.analysis/answer.md or reports/*.md)")
        for d in drafts:
            rel = d.relative_to(wd.root).as_posix()
            files.append((rel, d.read_bytes()))
        foot = _footer.extract(read_text_lf(drafts[0])) if drafts else None
        files.append((".analysis/footer.txt",
                      ("\n".join(f"{k}: {v}" for k, v in (foot or {}).items()) + "\n").encode()))
        inv = _outputs_inventory(wd)
        files.append((".analysis/outputs-inventory.txt", inv.encode()))
    return files


def _eval_questions(wd: Workdir) -> bytes:
    """Review question of every matched correction eval (§5.1). Phase 9 not
    built: mechanically collect `Review question:` lines from
    evals/corrections/*/case.md when present, else an empty section."""
    out = ["# Matched correction-eval review questions (§5.1)", ""]
    base = wd.root / "evals" / "corrections"
    found = 0
    if base.is_dir():
        for case in sorted(base.glob("*/case.md")):
            try:
                text = case.read_text(encoding="utf-8")
            except OSError:
                continue
            for line in text.splitlines():
                m = re.match(r"^\s*[Rr]eview question\s*:\s*(.+)$", line)
                if m and m.group(1).strip():
                    out.append(f"- [{case.parent.name}] {m.group(1).strip()}")
                    found += 1
    if not found:
        out.append("(none: no correction evals matched)")
    return ("\n".join(out) + "\n").encode()


def _outputs_inventory(wd: Workdir) -> str:
    lines = ["# outputs/ inventory — names and sizes only, never contents (§5.0, §11)", ""]
    outdir = wd.root / "outputs"
    if outdir.is_dir():
        for p in sorted(outdir.rglob("*")):
            if p.is_file():
                try:
                    size = p.stat().st_size
                except OSError:
                    size = -1
                lines.append(f"- {p.relative_to(wd.root).as_posix()}: {size} bytes")
    if len(lines) == 2:
        lines.append("(no outputs)")
    return "\n".join(lines) + "\n"


def do_packet(wd: Workdir, stage: str) -> dict:
    wd.require_initialized()
    stage = normalize_stage(stage)
    comp = lockhash.compute(wd)
    cfg = goldfish_config(wd)
    files = packet_files(wd, stage, comp)
    digest = hashlib.sha256(f"{FORMAT_PACKET}\n{stage}\n".encode())
    manifest_files = []
    total = 0
    for rel, data in files:
        digest.update(f"{rel}\n{len(data)}\n".encode() + data)
        tokens = estimate_tokens(data)
        total += tokens
        manifest_files.append({"path": rel, "bytes": len(data), "tokens": tokens,
                               "sha256": hashlib.sha256(data).hexdigest()})
    packet_hash = digest.hexdigest()[:16]
    if total > cfg["max_tokens"]:
        listing = "\n".join(f"  {f['path']}: {f['bytes']} bytes (~{f['tokens']} tokens)"
                            for f in manifest_files)
        raise DdaError(f"packet exceeds goldfish_max_tokens ({total} > {cfg['max_tokens']}); "
                       f"trim outputs or split rounds — never drop the spec or lock:\n{listing}")
    dest = packets_dir(wd) / packet_hash
    dest.mkdir(parents=True, exist_ok=True)
    for rel, data in files:
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    manifest = {"format": FORMAT_PACKET, "stage": stage, "packet_hash": packet_hash,
                "spec_hash": comp.spec_hash, "config_hash": comp.config_hash,
                "tier": comp.tier, "rung": comp.rung, "lock_present": (wd.analysis / "spec.lock").is_file(),
                "files": manifest_files, "tokens_total": total, "cap": cfg["max_tokens"],
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                                        encoding="utf-8", newline="\n")
    return {"stage": stage, "packet_hash": packet_hash, "files": len(files),
            "tokens": total, "dir": str(dest), "spec_hash": comp.spec_hash}


def latest_packet(wd: Workdir, stage: str) -> dict:
    """Newest packet manifest for a stage. Fails closed when none exists."""
    stage = normalize_stage(stage)
    base = packets_dir(wd)
    best: dict | None = None
    if base.is_dir():
        for man_path in base.glob("*/manifest.json"):
            try:
                man = json.loads(man_path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            if man.get("format") == FORMAT_PACKET and man.get("stage") == stage:
                if best is None or man.get("created_at", "") >= best.get("created_at", ""):
                    man["_dir"] = str(man_path.parent)
                    best = man
    if best is None:
        raise DdaError(f"no packet for stage {stage!r}; run `dda packet {stage}` first")
    return best


# ---------- brief + call ----------

def load_brief_template() -> str:
    path = TEMPLATES_DIR / "goldfish-packet.md"
    if not path.is_file():
        raise DdaError("missing templates/goldfish-packet.md (repo install incomplete)")
    return read_text_lf(path)


def build_brief(stage: str, rounds: list[str]) -> str:
    """Fill the template with ONLY the stage and round list. The elephant
    cannot add prose: this is the whole system prompt (§5.0)."""
    table = TEARDOWN_ROUNDS if stage == "teardown" else POST_RESULT_ROUNDS
    lines = []
    for r in rounds:
        if r == SECOND_GOLDFISH_ROUND:
            lines.append(f"ROUND 3 (second goldfish, independent re-read): {TEARDOWN_ROUNDS['3'] if stage == 'teardown' else POST_RESULT_ROUNDS['3']}")
        else:
            lines.append(f"ROUND {r}: {table[r]}")
    tmpl = load_brief_template()
    brief = tmpl.replace("{{STAGE}}", stage).replace("{{ROUNDS}}", "\n".join(lines) + "\n")
    if "{{" in brief and re.search(r"{{[A-Z_]+}}", brief):
        raise DdaError("goldfish-packet.md template has unfilled placeholders")
    return brief


def _stub_response(rounds: list[str], verdict: str) -> tuple[str, str]:
    if verdict == "pass":
        body = "\n".join(f"ROUND {r}: PASS" for r in rounds) + "\n"
    else:
        body = "".join(
            f"ROUND {r}: FAIL — objection: the spec does not rule out selection bias in this cut.\n"
            for r in rounds)
    return body, "stub"


def _provider_call(cfg: dict, model: str, system: str, user: str) -> tuple[str, str, int, int]:
    stub = _stub_verdict()
    if stub is not None:
        return _stub_response([], stub)  # rounds filled by caller
    key = os.environ.get(cfg["key_env"], "")
    if not key:
        raise DdaError(f"no provider key reachable ({cfg['key_env']} is unset and no vault entry); "
                       "goldfish rounds cannot run — below PUBLISH they degrade to self re-reads "
                       "with a footer caveat; at PUBLISH the analysis parks (§5.0 Fallback)")
    import ssl as _ssl
    payload = json.dumps({"model": model,
                          "messages": [{"role": "system", "content": system},
                                       {"role": "user", "content": user}],
                          "temperature": 0}).encode()
    req = urllib.request.Request(cfg["base_url"] + "/chat/completions", data=payload,
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {key}"})
    ctx = _ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
            raw = resp.read()
    except Exception as exc:
        raise DdaError(f"goldfish provider call failed ({exc}); failing closed") from None
    try:
        body = json.loads(raw.decode("utf-8"))
        text = body["choices"][0]["message"]["content"]
        usage = body.get("usage") or {}
        rid = str(body.get("id") or "")
    except (ValueError, KeyError, IndexError, TypeError):
        raise DdaError("goldfish provider returned an unparseable response; failing closed") from None
    tin = int(usage.get("prompt_tokens") or estimate_tokens((system + user).encode()))
    tout = int(usage.get("completion_tokens") or estimate_tokens(text.encode()))
    return text, rid, tin, tout


def reviews_dir(wd: Workdir) -> Path:
    return wd.analysis / "reviews" / "goldfish"


def existing_calls(wd: Workdir, stage: str) -> list[dict]:
    out = []
    base = reviews_dir(wd)
    if not base.is_dir():
        return out
    for p in sorted(base.glob(f"{stage}-r*.json")):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if rec.get("format") == FORMAT_CALL and rec.get("stage") == stage:
            out.append(rec)
    return out


def parse_verdicts(text: str, rounds: list[str]) -> dict[str, tuple[str, str]]:
    """Map each requested round to (verdict, objection). Missing rounds fail closed."""
    found: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        m = ROUND_LINE_RE.match(line.strip())
        if m and m.group(1) in rounds:
            found[m.group(1)] = (m.group(2).upper(), m.group(3).strip())
    missing = [r for r in rounds if r not in found]
    if missing:
        raise DdaError(f"goldfish response names no verdict for round(s) {', '.join(missing)}; "
                       "recorded as-is and the round does not pass")
    return found


def _request_envelope(model: str, brief: str, manifest: dict) -> dict:
    return {"model": model, "system": brief,
            "user_files": [{"path": f["path"], "sha256": f["sha256"], "bytes": f["bytes"]}
                           for f in manifest["files"]],
            "tools": []}


def _request_hash(model: str, brief: str, packet_dir: Path, manifest: dict) -> str:
    digest = hashlib.sha256(f"{FORMAT_CALL}\n{model}\n".encode() + brief.encode() + b"\n[]\n")
    for f in manifest["files"]:
        data = (packet_dir / f["path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != f["sha256"]:
            raise DdaError(f"packet file changed on disk: {f['path']} (re-run `dda packet`)")
        digest.update(data)
    return digest.hexdigest()


def do_review_run(wd: Workdir, stage: str, round_: str | None = None,
                  model: str | None = None) -> dict:
    wd.require_initialized()
    stage = normalize_stage(stage)
    comp = lockhash.compute(wd)
    cfg = goldfish_config(wd)
    rounds, need_goldfish = rounds_for(stage, comp.tier, comp.rung)
    if not need_goldfish:
        raise DdaError(f"{comp.tier} {stage} review is a self cold re-read, not a goldfish call "
                       f"(rounds {', '.join(rounds)} go in reviews/self/ as `self`, §5.3)")
    if round_ is not None:
        rn = round_.strip().lower()
        if rn not in rounds:
            raise DdaError(f"round {round_!r} is not in the {comp.tier} {stage} round list "
                           f"({', '.join(rounds)})")
        rounds = [rn]
    manifest = latest_packet(wd, stage)
    packet_dir = Path(manifest["_dir"])
    if manifest.get("spec_hash") != comp.spec_hash:
        raise DdaError("packet covers spec "
                       f"{(manifest.get('spec_hash') or '')[:12]} but the spec is now "
                       f"{comp.spec_hash[:12]}; re-run `dda packet {stage}` before review")
    model = model or (cfg["models"][0] if cfg["models"] else DEFAULT_MODEL)
    prior = [c for c in existing_calls(wd, stage) if c.get("spec_hash") == comp.spec_hash]
    for r in rounds:
        if sum(1 for c in prior if c.get("round") == r) >= 2:
            raise DdaError(f"round {r} already ran twice for this spec — fix the spec or report, "
                           "re-run only the failed round, at most once per round. "
                           "A second failure is stop-and-ask (§3.2 case 4, §5.3)")
    brief = build_brief(stage, rounds)
    brief_hash = lockhash.sha256_hex(brief.encode())
    stub = _stub_verdict()
    if stub is not None:
        text, rid_base = _stub_response(rounds, stub)
        tin = estimate_tokens((brief).encode())
        tout = estimate_tokens(text.encode())
        rid = ""
    else:
        user_msg = _inline_packet(packet_dir, manifest)
        text, rid_base, tin, tout = _provider_call(cfg, model, brief, user_msg)
        rid = rid_base
    request_hash = _request_hash(model, brief, packet_dir, manifest)
    try:
        verdicts = parse_verdicts(text, rounds)
    except DdaError as exc:
        verdicts = {r: ("FAIL", str(exc)) for r in rounds}
    try:
        seq_start = max([int(c.get("seq") or 0) for c in existing_calls(wd, stage)] + [0]) + 1
    except ValueError:
        seq_start = 1
    results = {}
    base = reviews_dir(wd)
    base.mkdir(parents=True, exist_ok=True)
    for i, r in enumerate(rounds):
        verdict, objection = verdicts[r]
        call_seq = seq_start + i
        if stub in ("pass", "fail"):
            rid = f"stub-{call_seq:04d}"
        rec = {"format": FORMAT_CALL, "stage": stage, "round": r, "seq": call_seq,
               "spec_hash": comp.spec_hash, "packet_hash": manifest["packet_hash"],
               "brief_hash": brief_hash, "request_hash": request_hash,
               "request": _request_envelope(model, brief, manifest),
               "response": text, "verdict": verdict.lower(),
               "objections": [objection] if verdict == "FAIL" and objection else [],
               "model": model, "provider_request_id": rid or f"stub-{call_seq:04d}",
               "tokens_in": tin, "tokens_out": tout,
               "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        if not rec["provider_request_id"]:
            rec["provider_request_id"] = f"stub-{call_seq:04d}"
        (base / f"{stage}-r{r}-{call_seq:03d}.json").write_text(
            json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        chain.append(ledger.runs_log(wd),
                     {"type": "review", "kind": "goldfish", "stage": stage, "round": r,
                      "seq": call_seq, "verdict": rec["verdict"], "spec_hash": comp.spec_hash,
                      "packet_hash": manifest["packet_hash"], "request": rec["provider_request_id"],
                      "model": model})
        with open(base / f"{stage}.md", "a", encoding="utf-8", newline="\n") as fh:
            fh.write(f"- round {r} seq {call_seq}: {rec['verdict']} "
                     f"(req {rec['provider_request_id']}, model {model}, packet "
                     f"{manifest['packet_hash'][:12]})\n")
        results[r] = rec
    fails = sorted(r for r, rec in results.items() if rec["verdict"] != "pass")
    summary = "; ".join(f"round {r}: {results[r]['verdict']}" for r in rounds)
    if fails:
        second = any(sum(1 for c in prior if c.get("round") == r) >= 1 for r in fails)
        note = ""
        if second:
            note = " Second failure in a round is stop-and-ask (§3.2 case 4): park and ask Brad."
        raise DdaError(f"goldfish {stage} recorded ({summary}); "
                       f"fix the spec and re-run only the failed round(s) (`--round N`), at most once.{note}")
    return {"stage": stage, "rounds": rounds, "summary": summary, "results": results}


def _inline_packet(packet_dir: Path, manifest: dict) -> str:
    """The user message: the packet inlined as delimited files. Nothing else
    is in the request — no chat, no memory, no context files (§5.0)."""
    parts = []
    for f in manifest["files"]:
        data = (packet_dir / f["path"]).read_bytes()
        parts.append(f"===== FILE {f['path']} =====\n" + data.decode("utf-8", errors="replace"))
    return "\n".join(parts) + "\n"


def self_response_path(wd: Workdir, stage: str, rnd: str) -> Path:
    return wd.analysis / "reviews" / "self" / f"{stage}-round{rnd}.md"


def review_summary(wd: Workdir) -> str:
    """Canonical one-line review state for footers and gates."""
    calls = existing_calls(wd, "teardown") + existing_calls(wd, "post-result")
    if not calls:
        return "none recorded"
    bits = []
    for c in sorted(calls, key=lambda c: (c.get("stage"), c.get("round"), c.get("seq"))):
        bits.append(f"{c.get('stage')} round {c.get('round')}: {c.get('verdict')} "
                    f"(req {c.get('provider_request_id')}, model {c.get('model')})")
    return "goldfish: " + "; ".join(bits)


__all__ = ["normalize_stage", "required_rounds", "post_result_rounds", "rounds_for",
           "goldfish_config", "provider_available", "estimate_tokens", "do_packet",
           "latest_packet", "build_brief", "do_review_run", "existing_calls",
           "parse_verdicts", "review_summary", "self_response_path",
           "STAGE_ALIASES", "TEARDOWN_ROUNDS", "POST_RESULT_ROUNDS"]
