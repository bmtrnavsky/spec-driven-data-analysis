"""Phase 8: profile / verify (SPEC §14 item 8, §10.3) + correction-eval matching (§9).

`dda profile` snapshots every source *before* analysis results exist: file
sources are content-hashed and materialized under
`derived/snapshots/<alias>@<asof>/` (X: never committed); sources that
cannot be copied (hosts, URLs, connector patterns) get a fingerprint
record — descriptor plus as-of query, never row values. `profile.md`
carries aggregates only (names, types, counts, hashes).

`dda verify` replays the locked variant's saved script in a fresh kernel
against the snapshot (parent-owned overlay; SPEC §10.3), runs it twice,
and diffs outputs within the declared Reproduction tolerance. Source
drift is recorded in `verify.md`, not failed. Matched correction evals
(§9, phase-8 subset) run their deterministic checks. Post-result goldfish
rounds are a G7 gate check, not part of verify itself.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .layout import DdaError, Workdir, load_config
from . import lockhash
from . import lockstate

PROFILE_JSON = "profile.json"
VERIFY_JSON = "verify.json"
PROFILE_MD = "profile.md"
VERIFY_MD = "verify.md"

# Outputs/delta tracking covers these dirs; snapshots themselves are excluded.
_TRACK_DIRS = ("outputs", "derived")
_SNAPSHOTS_DIRNAME = "snapshots"


class ToleranceError(DdaError, ValueError):
    """A bad Reproduction tolerance: a user-facing DdaError that is also a ValueError."""

_CSV_SUFFIXES = {".csv", ".tsv", ".txt", ".tab"}


# ---------- small utilities ----------

def utc_asof() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _canon(wd: Workdir, p: str) -> str:
    from .matching import canon
    return canon(p, str(wd.root))


def _require_lock(wd: Workdir):
    wd.require_initialized()
    state, detail, lock = lockstate.quick_status(wd)
    if state != "valid":
        raise DdaError(f"lock is not valid ({state}: {detail}); lock the spec first (§3.1)")
    try:
        comp = lockhash.compute(wd)
    except DdaError as exc:
        raise DdaError(f"cannot profile an uncomputable spec: {exc}")
    return lock, comp


def _alias_paths(wd: Workdir, loc: dict) -> list[Path]:
    out = []
    for p in loc.get("paths") or []:
        base = Path(p if os.path.isabs(p) else str(wd.root / p))
        if base.is_dir():
            out.extend(sorted(e for e in base.iterdir() if e.is_file()))
        elif base.is_file():
            out.append(base)
    return out


def header_sig(path: Path) -> dict:
    """Aggregate file signature: size, sha256, and (for CSV) columns + row count.

    Column names and inferred types only — values are read for type
    inference but never returned.
    """
    from .kernel import _infer_types
    sig: dict = {"name": path.name, "bytes": None, "sha256": None,
                 "columns": None, "rows": None, "note": None}
    try:
        sig["bytes"] = path.stat().st_size
    except OSError as exc:
        sig["note"] = f"unreadable ({exc.strerror or exc})"
        return sig
    try:
        sig["sha256"] = sha256_file(path)
    except OSError as exc:
        sig["note"] = f"unreadable ({exc.strerror or exc})"
        return sig
    if path.suffix.lower() not in _CSV_SUFFIXES:
        sig["note"] = "non-tabular: content hash only (column listing needs a reader; see `dda run`)"
        return sig
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as fh:
            sample = fh.read(65536)
    except (OSError, UnicodeDecodeError):
        sig["note"] = "unreadable as text (size and hash only)"
        return sig
    lines = sample.splitlines()
    if not lines:
        sig.update(columns=[], rows=0)
        return sig
    try:
        dialect = csv.Sniffer().sniff(lines[0] + ("\n" + lines[1] if len(lines) > 1 else ""))
    except Exception:
        dialect = csv.excel
    try:
        rows = list(csv.reader(lines, dialect))
    except Exception:
        sig["note"] = "unparseable header (size and hash only)"
        return sig
    if not rows:
        sig.update(columns=[], rows=0)
        return sig
    header, data = rows[0], rows[1:1001]
    try:
        with open(path, "rb") as fh:
            total_nl = sum(chunk.count(b"\n") for chunk in iter(lambda: fh.read(65536), b""))
    except OSError:
        total_nl = len(lines)
    try:
        kinds = _infer_types(data, len(header))
    except Exception:
        kinds = ["string"] * len(header)
    sig["columns"] = [{"name": (n or "?")[:80], "type": t} for n, t in zip(header, kinds)]
    if len(header) != len(set(header)):
        sig["note"] = "duplicate column names present"
    sig["rows"] = max(total_nl - 1, 0)
    return sig


def schema_of(sig: dict):
    """The schema-relevant projection of a header signature."""
    cols = sig.get("columns")
    if cols is None:
        return None
    return [(c["name"], c["type"]) for c in cols]


# ---------- tolerance ----------

_TOL_RE = re.compile(r"^(relative|absolute)\s+([0-9]+(?:\.[0-9]*)?(?:[eE][-+]?[0-9]+)?|\.[0-9]+(?:[eE][-+]?[0-9]+)?)\s*$")
_PER_PATH_RE = re.compile(r"^(\S+?)\s*:\s*(relative|absolute)\s+(\S+)\s*$")
_NUM_RE = re.compile(r"[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")


def parse_tolerance(text: str) -> tuple[str, float | None]:
    """Global reproduction tolerance: ('exact', None) or (kind, eps)."""
    line = (text or "").strip().splitlines()
    first = line[0].strip() if line else ""
    if not first or first.lower() == "exact":
        return "exact", None
    m = _TOL_RE.match(first)
    if not m:
        raise ToleranceError(f"bad Reproduction tolerance {first!r}: want `exact`, "
                       f"`relative <eps>`, or `absolute <eps>` (one per-output line `path: <kind> <eps>` also allowed)")
    eps = float(m.group(2))
    if not (eps > 0) or math.isnan(eps) or math.isinf(eps):
        raise ToleranceError(f"bad Reproduction tolerance {first!r}: eps must be a positive number")
    return m.group(1), eps


def parse_tolerances(text: str) -> tuple[tuple[str, float | None], dict[str, tuple[str, float | None]]]:
    """Global tolerance plus per-output overrides (`outputs/x.csv: relative 1e-9`)."""
    per: dict[str, tuple[str, float | None]] = {}
    first_global = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _PER_PATH_RE.match(line)
        if m:
            eps = float(m.group(3))
            if not (eps > 0) or math.isnan(eps) or math.isinf(eps):
                raise ToleranceError(f"bad per-output tolerance {line!r}: eps must be a positive number")
            per[m.group(1)] = (m.group(2), eps)
            continue
        if first_global is None:
            first_global = line
    if first_global is None:
        return ("exact", None), per
    return parse_tolerance(first_global), per


def tolerance_for(path: str, glob: tuple[str, float | None],
                  per: dict[str, tuple[str, float | None]]):
    if path in per:
        return per[path]
    for key, val in per.items():
        if path.endswith(key) or key.endswith(path):
            return val
    return glob


def compare_outputs(old: bytes, new: bytes, kind: str, eps: float | None,
                    path: str = "") -> tuple[bool, str]:
    """Diff two outputs within tolerance. Exact order; numeric tolerance only."""
    if kind == "exact" or eps is None:
        if old == new:
            return True, "byte-identical"
        return False, f"bytes differ ({len(old)} vs {len(new)} bytes)"
    try:
        olds, news = old.decode("utf-8"), new.decode("utf-8")
    except UnicodeDecodeError:
        if old == new:
            return True, "byte-identical (non-text)"
        return False, "non-text bytes differ (tolerance applies to text outputs only)"
    old_nums = _NUM_RE.findall(olds)
    new_nums = _NUM_RE.findall(news)
    skeleton = _NUM_RE.sub("\x00", olds) == _NUM_RE.sub("\x00", news)
    if not skeleton:
        return False, "non-numeric content differs (tolerance covers numbers only)"
    if len(old_nums) != len(new_nums):
        return False, f"numeric count differs ({len(old_nums)} vs {len(new_nums)})"
    for a, b in zip(old_nums, new_nums):
        try:
            fa, fb = float(a), float(b)
        except ValueError:
            if a != b:
                return False, f"non-numeric token differs ({a!r} vs {b!r})"
            continue
        if kind == "relative":
            ok = math.isclose(fa, fb, rel_tol=eps, abs_tol=0.0) or (fa == 0 and fb == 0)
        else:
            ok = math.isclose(fa, fb, rel_tol=0.0, abs_tol=eps)
        if not ok:
            return False, f"number {a} vs {b} outside {kind} {eps}"
    return True, f"{len(old_nums)} numbers within {kind} {eps}"


# ---------- profile ----------

def load_profile(wd: Workdir) -> dict | None:
    p = wd.analysis / PROFILE_JSON
    if not p.is_file():
        return None
    try:
        rec = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return rec if isinstance(rec, dict) else None


def _snapshot_alias(wd: Workdir, alias: str, loc: dict, asof: str, snap_root: Path) -> dict:
    files = _alias_paths(wd, loc)
    rec: dict = {"kind": "snapshot", "asof": asof, "files": {}, "combined": None,
                 "snapshot_dir": None, "roots": {}}
    if not files:
        # Declared paths but nothing on disk (or no paths at all): if the
        # alias has no file locators either, this is a live-only source.
        if not (loc.get("paths") or []):
            rec = {"kind": "live-only", "asof": asof,
                   "descriptor": {"hosts": sorted(loc.get("hosts") or []),
                                  "url_prefixes": sorted(loc.get("url_prefixes") or []),
                                  "tool_patterns": sorted(loc.get("tool_patterns") or []),
                                  "conn": loc.get("conn"),
                                  "pii": bool(loc.get("pii")),
                                  "note": "no materialized snapshot: replay runs against live data; "
                                          "a mismatch is reported as `irreproducible: live source drifted` (§10.3)"}}
            return rec
        rec["note"] = "declared paths resolve to no files from here"
    sdir = snap_root / f"{alias}@{asof}"
    sdir.mkdir(parents=True, exist_ok=True)
    rec["snapshot_dir"] = f"derived/snapshots/{alias}@{asof}"
    h = hashlib.sha256()
    used: set[str] = set()
    for src in files:
        rel = src.name
        i = 1
        while rel in used:
            i += 1
            rel = f"{src.stem}-{i}{src.suffix}"
        used.add(rel)
        dst = sdir / rel
        try:
            data = src.read_bytes()
        except OSError as exc:
            raise DdaError(f"cannot snapshot {src}: {exc}")
        dst.write_bytes(data)
        sig = header_sig(src)
        entry = {"rel": rel, "live": _canon(wd, str(src)), "bytes": sig["bytes"],
                 "sha256": sig["sha256"], "columns": sig["columns"], "rows": sig["rows"],
                 "note": sig["note"]}
        rec["files"][_canon(wd, str(src))] = entry
        h.update((entry["live"] or "").encode() + b"\x00" + (sig["sha256"] or "").encode() + b"\x00")
        # Root-level overlay entry: the snapshot mirrors the live layout.
        live_root = _canon(wd, str(src.parent))
        snap_dir_canon = _canon(wd, str(sdir))
        rec["roots"].setdefault(live_root, snap_dir_canon)
    rec["combined"] = h.hexdigest()
    manifest = {"alias": alias, "asof": asof, "combined": rec["combined"], "files": rec["files"]}
    (sdir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                                        encoding="utf-8")
    return rec


def do_profile(wd: Workdir) -> dict:
    """Snapshot/fingerprint every locked source. Returns the profile record."""
    lock, comp = _require_lock(wd)
    cfg = load_config(wd)
    asof = utc_asof()
    snap_root = wd.root / "derived" / "snapshots"
    snap_root.mkdir(parents=True, exist_ok=True)
    aliases: dict[str, dict] = {}
    for alias in sorted(comp.aliases):
        loc = (cfg.get("data_roots") or {}).get(alias) or {}
        aliases[alias] = _snapshot_alias(wd, alias, loc, asof, snap_root)
    new_schema = {a: {live: schema_of(f) for live, f in (r.get("files") or {}).items()}
                  for a, r in aliases.items()}
    prev = load_profile(wd)
    if prev is not None and isinstance(prev.get("aliases"), dict):
        old_schema = {a: {live: (schema_of(f) if isinstance(f, dict) else None)
                           for live, f in ((prev["aliases"].get(a) or {}).get("files") or {}).items()}
                      for a in aliases}
        if new_schema != old_schema and lock.get("version") == prev.get("lock_version"):
            raise DdaError("schema changed since the last profile (columns added, removed, "
                           "renamed, or retyped) with no intervening amendment — file it as an "
                           "amendment first (`dda lock --amend \"...\"`), then re-run `dda profile` (G5)")
    rec = {"lock_hash": comp.lock_hash, "lock_version": lock.get("version"),
           "asof": asof, "tier": comp.tier, "rung": comp.rung,
           "aliases": aliases}
    (wd.analysis / PROFILE_JSON).write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n",
                                            encoding="utf-8")
    (wd.analysis / PROFILE_MD).write_text(render_profile_md(wd, rec), encoding="utf-8")
    return rec


def render_profile_md(wd: Workdir, rec: dict) -> str:
    lines = ["# Profile", "",
             f"- lock hash: `{rec['lock_hash']}`",
             f"- as of: {rec['asof']} (UTC)", "",
             "Aggregates only: names, types, counts, content hashes. No row values, no samples (§3.3).",
             ""]
    for alias in sorted(rec["aliases"]):
        r = rec["aliases"][alias]
        lines.append(f"## {alias}")
        lines.append("")
        if r.get("kind") == "live-only":
            d = r["descriptor"]
            lines.append("- fingerprint: live-only source (no materialized snapshot)")
            for k in ("hosts", "url_prefixes", "tool_patterns"):
                if d.get(k):
                    lines.append(f"- {k}: {', '.join(d[k])}")
            if d.get("conn"):
                lines.append(f"- conn: {d['conn']}")
            lines.append(f"- as-of query: {json.dumps(d, sort_keys=True)}")
            lines.append("")
            continue
        lines.append(f"- snapshot: `derived/snapshots/{alias}@{r['asof']}/`")
        lines.append(f"- combined hash: `{r.get('combined')}`")
        for live in sorted(r.get("files") or {}):
            f = r["files"][live]
            lines.append(f"- `{f['rel']}`: {f['bytes']} bytes, sha256 `{f['sha256']}`")
            if f.get("columns") is not None:
                cols = ", ".join(f"{c['name']}: {c['type']}" for c in f["columns"])
                lines.append(f"  - columns: {cols}")
                lines.append(f"  - rows: ~{f['rows']}")
            elif f.get("note"):
                lines.append(f"  - {f['note']}")
        if r.get("note"):
            lines.append(f"- note: {r['note']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------- correction-eval matching (phase-8 subset of §9) ----------

def _case_triggers(case_md: str) -> list[str]:
    for line in case_md.splitlines():
        if line.strip().lower().startswith("trigger keys:"):
            rest = line.split(":", 1)[1]
            return [t.strip().lower() for t in re.split(r"[,;]", rest) if t.strip()]
    return []


def _eval_check(case_md: str) -> dict | None:
    """Parse the `## Deterministic check` block: `file:` + `sha256:` lines."""
    in_block = False
    file, want = None, None
    for line in case_md.splitlines():
        s = line.strip()
        if s.startswith("##"):
            in_block = s.lower() == "## deterministic check"
            continue
        if not in_block:
            continue
        m = re.match(r"^file:\s*(\S+)\s*$", s)
        if m:
            file = m.group(1)
            continue
        m = re.match(r"^sha256:\s*([0-9a-fA-F]+)\s*$", s)
        if m:
            want = m.group(1).lower()
    if file and want:
        return {"file": file, "sha256": want}
    return None


def match_evals(wd: Workdir) -> list[dict]:
    """Mechanically match correction cases to the locked spec (§9).

    A case matches when a trigger key names a locked alias, a metric pin,
    or a definition name. Binding needs a `correction` approval for the
    case directory (verified, or unverified below PUBLISH — the G3 rule).
    Full `correct`/`evals` UX arrives in build phase 9.
    """
    try:
        lock, comp = _require_lock(wd)
    except DdaError:
        return []
    from . import approvals as _approvals
    spec_text = ""
    try:
        spec_text = wd.spec_path.read_text(encoding="utf-8")
    except OSError:
        pass
    hay = " ".join([spec_text.lower()] + [a.lower() for a in comp.aliases]
                   + [p.lower() for p in getattr(comp, "pins", [])]
                   + [str(getattr(comp, "metrics", "")).lower()])
    base = wd.root / "evals" / "corrections"
    if not base.is_dir():
        return []
    matched = []
    for d in sorted(p for p in base.iterdir() if p.is_dir()):
        case = d / "case.md"
        if not case.is_file():
            continue
        try:
            body = case.read_text(encoding="utf-8")
        except OSError:
            continue
        triggers = _case_triggers(body)
        if not triggers:
            continue
        hit = [t for t in triggers if t and t in hay]
        if not hit:
            continue
        verdict = _approvals.verify_approval(wd, "correction", d.name)
        reason = str(verdict.get("reason", ""))
        bound = verdict.get("verified") or ("not found" not in reason and "not committed" not in reason
                                            and comp.tier != "PUBLISH")
        matched.append({"case": d.name, "triggers": hit, "bound": bound,
                        "verified": bool(verdict.get("verified")),
                        "approval_reason": reason,
                        "case_hash": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                        "check": _eval_check(body)})
    return matched


def run_eval_checks(wd: Workdir, matched: list[dict]) -> list[dict]:
    """Run deterministic checks for matched cases. Paths are confined to outputs/ and derived/."""
    results = []
    for m in matched:
        check = m.get("check")
        if not check:
            results.append({"case": m["case"], "status": "no-check",
                            "note": "review questions only (flow to the goldfish packet in phase 9)"})
            continue
        rel = check["file"].lstrip("/").replace("\\", "/")
        first = rel.split("/", 1)[0]
        if first not in ("outputs", "derived") or ".." in rel.split("/"):
            results.append({"case": m["case"], "status": "fail",
                            "note": f"check path {check['file']!r} escapes outputs//derived/ — refused"})
            continue
        target = wd.root / rel
        if not target.is_file():
            results.append({"case": m["case"], "status": "fail",
                            "note": f"check file {check['file']!r} is missing"})
            continue
        got = sha256_file(target)
        if got == check["sha256"]:
            results.append({"case": m["case"], "status": "pass",
                            "note": f"{check['file']} sha256 matches"})
        else:
            results.append({"case": m["case"], "status": "fail",
                            "note": f"{check['file']} sha256 {got[:12]} != expected {check['sha256'][:12]}"})
    return results


# ---------- verify ----------

def load_verify(wd: Workdir) -> dict | None:
    p = wd.analysis / VERIFY_JSON
    if not p.is_file():
        return None
    try:
        rec = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return rec if isinstance(rec, dict) else None


def _variant_script_path(wd: Workdir, vid: str) -> Path:
    from .kernel import RUN_SCRIPT_SUFFIXES
    for suffix in RUN_SCRIPT_SUFFIXES:
        sp = wd.analysis / "variants" / f"{vid}{suffix}"
        if sp.is_file():
            return sp
    raise DdaError(f"locked variant script is missing (variants/{vid}.py|.sql); "
                   "the saved script must exist to replay (§4.3)")


def _tracked_hashes(wd: Workdir) -> dict[str, str]:
    """sha256 of every file under outputs/ and derived/ (minus snapshots)."""
    out: dict[str, str] = {}
    for dirname in _TRACK_DIRS:
        base = wd.root / dirname
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            try:
                rel = p.relative_to(wd.root).as_posix()
            except ValueError:
                continue
            if rel == f"derived/{_SNAPSHOTS_DIRNAME}" or rel.startswith(f"derived/{_SNAPSHOTS_DIRNAME}/"):
                continue
            try:
                out[rel] = sha256_file(p)
            except OSError:
                continue
    return out


def _delta(before: dict[str, str], after: dict[str, str]) -> dict[str, str | None]:
    changed: dict[str, str | None] = {}
    for rel, h in after.items():
        if before.get(rel) != h:
            changed[rel] = h
    for rel in before:
        if rel not in after:
            changed[rel] = None
    return changed


def render_verify_md(wd: Workdir, rec: dict) -> str:
    lines = ["# Verify", "",
             f"- lock hash: `{rec['lock_hash']}`",
             f"- locked variant: `{rec['variant']}` (body `{rec['body_hash'][:12]}`)",
             f"- tolerance: `{rec['tolerance_text']}`",
             f"- status: {rec['status']}", ""]
    lines.append("## Snapshots and drift")
    lines.append("")
    for alias in sorted(rec["aliases"]):
        r = rec["aliases"][alias]
        if r.get("kind") == "live-only":
            lines.append(f"- {alias}: fingerprint (live-only, no materialized snapshot)")
        else:
            lines.append(f"- {alias}: snapshot `{r.get('snapshot_dir')}`, combined `{str(r.get('combined'))[:12]}`")
        drift = r.get("drift")
        if drift:
            lines.append(f"  - drift: {drift}")
        else:
            lines.append("  - drift: none since profile")
    lines.append("")
    lines.append("## Replays")
    lines.append("")
    for rp in rec.get("replays", []):
        lines.append(f"- run `{rp['run_id']}` (seed {rp['seed']}): exit {rp['returncode']}, "
                     f"{'against snapshot overlay' if rp.get('overlay') else 'against live data'}")
    if rec.get("agreement"):
        lines.append(f"- agreement: {rec['agreement']}")
    lines.append("")
    lines.append("## Correction evals")
    lines.append("")
    matched = rec.get("evals_matched", 0)
    passed = rec.get("evals_passed", 0)
    lines.append(f"- {matched} matched, {passed} passed")
    for e in rec.get("evals", []):
        lines.append(f"- {e['case']}: {e['status']} — {e['note']}")
    if rec.get("live_only_note"):
        lines.append("")
        lines.append(f"NOTE: {rec['live_only_note']}")
    lines.append("")
    lines.append(f"Reproduce: `dda verify` in this workdir (locked variant `{rec['variant']}`).")
    return "\n".join(lines).rstrip() + "\n"


def do_verify(wd: Workdir) -> dict:
    """Replay the locked variant twice against the snapshot; record evidence.

    Writes `.analysis/verify.json` + `.analysis/verify.md` and returns the
    record. Exits are the caller's job: mismatches are evidence (G7 fails),
    replay crashes raise.
    """
    from . import kernel as _kernel
    lock, comp = _require_lock(wd)
    vid = _kernel.locked_variant_id(wd)
    if not vid:
        raise DdaError("no locked variant: mark the reported variant first "
                       "(`dda variant --locked <id>`, §4.3)")
    sp = _variant_script_path(wd, vid)
    body = sp.read_text(encoding="utf-8")
    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    frozen = _kernel.frozen_hash(wd, vid)
    if frozen and frozen != body_hash:
        raise DdaError(f"locked variant {vid!r} changed since its freeze "
                       f"({frozen[:12]} vs {body_hash[:12]}); a changed script is a new variant id (§4.3)")
    prof = load_profile(wd)
    if prof is None:
        raise DdaError("no profile yet: run `dda profile` first (snapshots before results, §10.3)")
    if prof.get("lock_hash") != comp.lock_hash:
        raise DdaError("the profile predates the current lock (spec changed or amended): "
                       "re-run `dda profile` before `dda verify` (G5)")
    try:
        tol_text = lockhash.parse_sections(wd.spec_path.read_text(encoding="utf-8")).get(
            "Reproduction tolerance", "")
    except (OSError, DdaError):
        tol_text = ""
    glob, per_path = parse_tolerances(tol_text or "exact")

    # Snapshot integrity + live drift, per alias.
    alias_recs: dict[str, dict] = {}
    overlay: dict[str, str] = {}
    drift_any = False
    for alias in sorted(comp.aliases):
        prec = (prof.get("aliases") or {}).get(alias)
        if prec is None:
            raise DdaError(f"profile has no entry for locked alias {alias!r}: re-run `dda profile`")
        if prec.get("kind") == "live-only":
            from .layout import load_config as _lc
            loc = (_lc(wd).get("data_roots") or {}).get(alias) or {}
            now_desc = {"hosts": sorted(loc.get("hosts") or []),
                        "url_prefixes": sorted(loc.get("url_prefixes") or []),
                        "tool_patterns": sorted(loc.get("tool_patterns") or []),
                        "conn": loc.get("conn"), "pii": bool(loc.get("pii"))}
            old_desc = {k: v for k, v in (prec.get("descriptor") or {}).items() if k in now_desc}
            changed = now_desc != old_desc
            drift_any = drift_any or changed
            alias_recs[alias] = {"kind": "live-only",
                                 "drift": ("locator changed since profile" if changed else None)}
            continue
        # Verify the snapshot copies themselves (G7 snapshot re-check).
        sdir = wd.root / (prec.get("snapshot_dir") or "")
        files = prec.get("files") or {}
        for live, f in files.items():
            snap = sdir / (f.get("rel") or "")
            if not snap.is_file():
                raise DdaError(f"snapshot copy is missing: {prec.get('snapshot_dir')}/{f.get('rel')} "
                               f"(re-run `dda profile`, §10.3)")
            if sha256_file(snap) != f.get("sha256"):
                raise DdaError(f"snapshot copy changed since profile: "
                               f"{prec.get('snapshot_dir')}/{f.get('rel')} "
                               f"(raw data is immutable; investigate before re-profiling, §3.2 case 8)")
        # Live drift: rehash the live files.
        drifts = []
        for live, f in files.items():
            lp = Path(live)
            if not lp.is_absolute():
                lp = wd.root / live
            try:
                now = sha256_file(lp) if lp.is_file() else None
            except OSError:
                now = None
            if now != f.get("sha256"):
                drifts.append(f.get("rel") or live)
        if drifts:
            drift_any = drift_any or True
        alias_recs[alias] = {"kind": "snapshot", "snapshot_dir": prec.get("snapshot_dir"),
                             "combined": prec.get("combined"),
                             "drift": (f"live files changed since snapshot: {', '.join(sorted(drifts))}"
                                       if drifts else None)}
        # Overlay: longest-prefix match wants file entries before roots.
        for live in files:
            snap = _canon(wd, str(sdir / files[live]["rel"]))
            overlay[live] = snap
        for live_root, snap_root in (prec.get("roots") or {}).items():
            overlay.setdefault(live_root, snap_root)

    # Reference run: latest successful run of the locked body under this lock.
    ref = None
    for e in reversed(_kernel.run_entries(wd, vid)):
        if (e.get("type") == "run" and e.get("lock_hash") == comp.lock_hash
                and e.get("body_hash") == body_hash and e.get("returncode") == 0):
            ref = e
            break
    seed = int(ref["seed"]) if ref and ref.get("seed") is not None else None

    tmp = Path(tempfile.mkdtemp(prefix="dda-verify-"))
    before = _tracked_hashes(wd)
    replays = []
    try:
        r1 = _kernel.do_run(wd, vid, str(sp), [], session="", seed=seed,
                            overlay=overlay or None, capture_dir=tmp / "r1")
    except DdaError as exc:
        rec = {"lock_hash": comp.lock_hash, "variant": vid, "body_hash": body_hash,
               "tolerance_text": (tol_text or "exact").strip() or "exact", "aliases": alias_recs,
               "replays": replays, "agreement": None, "status": f"error: replay crashed: {exc}",
               "evals_matched": 0, "evals_passed": 0, "evals": [], "live_only_note": None}
        (wd.analysis / VERIFY_JSON).write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n",
                                              encoding="utf-8")
        (wd.analysis / VERIFY_MD).write_text(render_verify_md(wd, rec), encoding="utf-8")
        raise
    mid = _tracked_hashes(wd)
    r2 = _kernel.do_run(wd, vid, str(sp), [], session="", seed=r1["seed"],
                        overlay=overlay or None, capture_dir=tmp / "r2")
    after = _tracked_hashes(wd)

    # Diff: full stdout + outputs/derived deltas, replay1 vs replay2.
    s1 = (tmp / "r1" / "stdout.txt").read_bytes()
    s2 = (tmp / "r2" / "stdout.txt").read_bytes()
    gkind, geps = tolerance_for("stdout", glob, per_path)
    ok_out, note_out = compare_outputs(s1, s2, gkind, geps, "stdout")
    deltas = []
    for rel in sorted(set(_delta(before, mid)) | set(_delta(mid, after))):
        h1 = mid.get(rel)
        h2 = after.get(rel)
        deltas.append((rel, h1, h2))
    mismatches = []
    agreements = [f"stdout: {note_out}"]
    if not ok_out:
        mismatches.append(f"stdout differs beyond tolerance ({note_out})")
    for rel, h1, h2 in deltas:
        if h1 is None or h2 is None:
            mismatches.append(f"{rel}: present in one replay only")
            continue
        if h1 == h2:
            agreements.append(f"{rel}: byte-identical")
            continue
        # Both replays write the same path in place, so equal hashes mean
        # the replays agreed; different hashes mean they did not. (Numeric
        # tolerance across replays applies to captured stdout, above.)
        mismatches.append(f"{rel}: bytes differ between replays")
    # Per-replay distinct files (only in one delta side) were handled above.
    agreement = "; ".join(agreements)
    for rp, rr in ((r1, "r1"), (r2, "r2")):
        replays.append({"run_id": rp["run_id"], "seed": rp["seed"],
                        "returncode": rp["returncode"],
                        "overlay": bool(overlay),
                        "env_hash": rp.get("environment_hash")})

    matched = match_evals(wd)
    check_results = run_eval_checks(wd, matched)
    evals_passed = sum(1 for e in check_results if e["status"] in ("pass", "no-check"))
    evals_failed = [e for e in check_results if e["status"] == "fail"]
    live_only = [a for a, r in alias_recs.items() if r.get("kind") == "live-only"]
    live_note = None
    if live_only and mismatches:
        live_note = ("irreproducible: live source drifted — aliases "
                     + ", ".join(sorted(live_only)) + " have no materialized snapshot, "
                     "so the replay ran against live data (§10.3)")

    if live_note:
        status = "mismatch (live-only source)"
    elif mismatches:
        status = "mismatch: " + "; ".join(mismatches[:3])
    else:
        status = "reproduced within tolerance"
    rec = {"lock_hash": comp.lock_hash, "variant": vid, "body_hash": body_hash,
           "tolerance_text": (tol_text or "exact").strip() or "exact",
           "tolerance": {"global": list(glob), "per_path": {k: list(v) for k, v in per_path.items()}},
           "aliases": alias_recs, "replays": replays,
           "stdout_note": note_out,
           "agreement": agreement if not mismatches else None,
           "mismatches": mismatches,
           "status": status,
           "evals_matched": len(matched), "evals_passed": evals_passed,
           "evals": [{"case": m["case"], "bound": m["bound"], "verified": m["verified"],
                      "case_hash": m["case_hash"],
                      "status": (next((c["status"] for c in check_results if c["case"] == m["case"]), "?")),
                      "note": (next((c["note"] for c in check_results if c["case"] == m["case"]), ""))}
                     for m in matched],
           "live_only_note": live_note}
    (wd.analysis / VERIFY_JSON).write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n",
                                          encoding="utf-8")
    (wd.analysis / VERIFY_MD).write_text(render_verify_md(wd, rec), encoding="utf-8")
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    return rec


__all__ = ["do_profile", "do_verify", "load_profile", "load_verify", "match_evals",
           "run_eval_checks", "parse_tolerance", "parse_tolerances", "tolerance_for",
           "compare_outputs", "render_profile_md", "render_verify_md", "header_sig",
           "PROFILE_JSON", "VERIFY_JSON", "PROFILE_MD", "VERIFY_MD"]
