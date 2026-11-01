"""Premise validator (SPEC-504ed55 §2, I14): certify probe↔anchor bindings.

Usage:
  python -m tests.revert validate [--scenario ID] [--probe NAME] [--matrix]
                                   [--timeout SECONDS]

For every (scenario, probe) pair the validator runs the arm matrix and
writes the observed tokens, the computed dependency set, and the content
hashes into tests/revert/PREMISE.json:

  (a) fixed        — clean tree: probe must print its expected token, rc 0.
  (b) reverted     — all scenario units applied (+ conformance checks):
                     probe must print its vuln token, rc 0. Anything else
                     rejects the binding and writes no record.
  (c) attribution  — single-unit arms always; leave-one-out arms with
                     --matrix. The dependency set is the units whose
                     single revert flips the probe; a conjunctive case
                     (only the joint revert flips) must be declared.
  (d) cross        — the probe under every OTHER scenario's units: it must
                     not print its vuln token unless that cross-flip is
                     declared in the scenario's declared_cross.
  (e) historic     — the current probe + probelib copied into a worktree at
                     fix_commit^: records the observed token, or
                     {status: infeasible, reason} when probelib API drift
                     (or a missing fix_commit) makes it impossible. Never
                     silently skipped.

Fast path (every suite run): the flip tests in tests/test_invariants.py
re-run arms (a) and (b), and tests/test_premise.py verifies every record
is present and hash-fresh — STALE-PREMISE on any drift.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests"))

from revert.apply import CONFORMANCE, IncoherentRevert, apply_unit  # noqa: E402
from revert.premise import (  # noqa: E402
    audit_oracle,
    check_pair,
    find_record,
    load_premise,
    pair_hashes,
    sha_file,
)
from revert.scenarios import SCENARIOS  # noqa: E402

TIMEOUT = 600


def _env(repo: Path) -> dict:
    env = dict(os.environ)
    env["DDA_TEST_MODE"] = "1"
    env["PYTHONPATH"] = str(repo / "scripts") + os.pathsep + str(repo) \
        + os.pathsep + env.get("PYTHONPATH", "")
    return env


def run_probe(repo: Path, probe: str, timeout: int) -> tuple[int | None, list[str], str]:
    """(rc or None on timeout, FINDING lines, tail). Never raises."""
    p_path = repo / "tests" / "probes" / probe
    try:
        p = subprocess.run(
            [sys.executable, str(p_path)], capture_output=True, text=True,
            env=_env(repo), cwd=str(p_path.parent), timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, ["TIMEOUT"], "TIMEOUT"
    findings = [ln for ln in p.stdout.splitlines() if ln.startswith("FINDING:")]
    tail = (p.stdout + p.stderr).strip().splitlines()[-2:]
    return p.returncode, findings, " | ".join(t[:160] for t in tail)


def apply_all(repo: Path, scenario: dict) -> list:
    """Apply every unit of the scenario. Returns restore closures (call
    reversed). Patch anchors missing from the tree raise IncoherentRevert."""
    restores = []
    try:
        for u in scenario["units"]:
            if u["kind"] == "function":
                restores.append(apply_unit(repo, u["module"], u["func"], u["impl"]))
            elif u["kind"] == "patch":
                fp = repo / u["module"]
                text = fp.read_text(encoding="utf-8")
                saved = text
                for old, new in u["patches"]:
                    if old not in text:
                        raise IncoherentRevert(
                            f"{u['module']}: revert anchor not found: {old[:80]!r}")
                    text = text.replace(old, new, 1)
                fp.write_text(text, encoding="utf-8")

                def _restore(fp=fp, saved=saved):
                    fp.write_text(saved, encoding="utf-8")
                restores.append(_restore)
            else:
                raise IncoherentRevert(f"unknown unit kind: {u['kind']!r}")
    except Exception:
        for r in reversed(restores):
            r()
        raise
    return restores


def run_conformance(repo: Path, scenario: dict, timeout: int,
                    label: str) -> list[str]:
    """Run the §3 conformance check for each applied function unit.
    Returns failure lines ([] = all coherent)."""
    failures = []
    env = _env(repo)
    for u in scenario["units"]:
        if u["kind"] != "function":
            continue
        check = CONFORMANCE.get(u["impl"])
        if check is None:
            failures.append(f"[{label}] INCOHERENT-REVERT: no conformance "
                            f"check recorded for {u['impl']}")
            continue
        try:
            c = subprocess.run([sys.executable, str(repo / check)],
                               capture_output=True, text=True, env=env,
                               cwd=str(repo), timeout=timeout)
        except subprocess.TimeoutExpired:
            failures.append(f"[{label}] INCOHERENT-REVERT: {check} TIMEOUT")
            continue
        print(f"[revert:{label}] conformance {Path(check).name} rc={c.returncode}")
        if c.returncode != 0:
            failures.append(
                f"[{label}] INCOHERENT-REVERT: {check} rc={c.returncode}; "
                f"the reverted unit does not behave like its pre-fix self")
    return failures


def historic_token(repo: Path, scenario: dict, probe: str,
                   timeout: int) -> dict:
    """Arm (e): current probe + probelib in a worktree at fix_commit^."""
    fix = scenario.get("fix_commit")
    if not fix:
        return {"status": "infeasible", "reason": "no fix commit recorded"}
    tmp = Path(tempfile.mkdtemp(prefix="dda-validate-historic-"))
    try:
        add = subprocess.run(
            ["git", "-C", str(repo), "worktree", "add", "--detach",
             str(tmp / "wt"), f"{fix}^"],
            capture_output=True, text=True, timeout=120)
        if add.returncode != 0:
            return {"status": "infeasible",
                    "reason": f"worktree at {fix}^ failed: "
                              f"{(add.stdout + add.stderr)[-200:]}"}
        wt = tmp / "wt"
        dest = wt / "tests" / "probes"
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo / "tests/probes" / probe, dest / probe)
        shutil.copy2(repo / "tests/probes/probelib.py", dest / "probelib.py")
        env = dict(os.environ)
        env["DDA_TEST_MODE"] = "1"
        env["PYTHONPATH"] = str(wt / "scripts") + os.pathsep + str(wt)
        try:
            p = subprocess.run(
                [sys.executable, str(dest / probe)], capture_output=True,
                text=True, env=env, cwd=str(dest), timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"status": "infeasible",
                    "reason": f"probe TIMEOUT at {fix}^ (probelib API drift?)"}
        findings = [ln for ln in p.stdout.splitlines()
                    if ln.startswith("FINDING:")]
        tail = (p.stdout + p.stderr).strip().splitlines()[-2:]
        if p.returncode == 0 and len(findings) == 1:
            return {"commit": f"{fix}^", "token": findings[0][len("FINDING: "):],
                    "rc": 0}
        return {"status": "infeasible",
                "reason": f"probe at {fix}^ rc={p.returncode} "
                          f"findings={findings} :: "
                          + " | ".join(t[:120] for t in tail)}
    finally:
        subprocess.run(["git", "-C", str(repo), "worktree", "remove",
                        "--force", str(tmp / "wt")],
                       capture_output=True, timeout=120)
        shutil.rmtree(tmp, ignore_errors=True)


def validate_pair(repo: Path, scenario: dict, probe: str, manifest: dict,
                  matrix: bool, timeout: int) -> tuple[dict | None, list[str]]:
    """Run the arm matrix for one pair. Returns (record or None, failures)."""
    label = scenario["id"]
    expected, vuln = manifest[probe]["expected"], manifest[probe]["vuln"]
    failures: list[str] = []

    oracle_errors = audit_oracle(repo / "tests/probes" / probe, expected)
    if oracle_errors:
        return None, [f"[{label}] ORACLE-REJECTED: {e}" for e in oracle_errors]

    # Arm (a): fixed.
    rc, findings, tail = run_probe(repo, probe, timeout)
    print(f"[fixed:{label}] {probe} rc={rc} findings={findings} :: {tail}")
    if rc != 0 or findings != [f"FINDING: {expected}"]:
        return None, [f"[{label}] {probe}: fixed arm must print exactly "
                      f"[FINDING: {expected}] rc=0; got {findings} rc={rc}"]

    # Arm (b): full revert + conformance.
    restores = []
    try:
        try:
            restores = apply_all(repo, scenario)
        except IncoherentRevert as e:
            return None, [f"[{label}] INCOHERENT-REVERT: {e}"]
        coh = run_conformance(repo, scenario, timeout, label)
        if coh:
            return None, coh
        rc, findings, tail = run_probe(repo, probe, timeout)
        print(f"[reverted:{label}] {probe} rc={rc} findings={findings} :: {tail}")
        if rc != 0 or findings != [f"FINDING: {vuln}"]:
            if findings == []:
                why = (f"probe printed NO FINDING (crashed/errored, rc={rc}) "
                       f"— distinct from printing the vuln token")
            else:
                why = f"probe printed the wrong token; got {findings}"
            return None, [f"[{label}] BINDING-REJECTED: {probe} does not "
                          f"depend on this anchor — want exactly "
                          f"[FINDING: {vuln}] with the fix reverted; {why} "
                          f"(no record written)"]
    finally:
        for r in reversed(restores):
            r()

    # Arm (c): attribution — single-unit arms always; leave-one-out with
    # --matrix. For a single-unit scenario the single arm IS the full arm.
    units = scenario["units"]
    dep_set: list[str] = []
    single_tokens: dict[str, str] = {}
    if len(units) == 1:
        dep_set = [units[0]["id"]]
        single_tokens[units[0]["id"]] = vuln
    else:
        for u in units:
            solo = dict(scenario, units=[u])
            restores = []
            try:
                try:
                    restores = apply_all(repo, solo)
                except IncoherentRevert as e:
                    return None, [f"[{label}] INCOHERENT-REVERT (single "
                                  f"{u['id']}): {e}"]
                coh = run_conformance(repo, solo, timeout, label)
                if coh:
                    return None, coh
                rc, findings, _ = run_probe(repo, probe, timeout)
                tok = (findings[0][len("FINDING: "):]
                       if rc == 0 and len(findings) == 1 else
                       f"NO-FINDING(rc={rc},{findings})")
                single_tokens[u["id"]] = tok
                print(f"[single:{label}] {u['id']} -> {tok}")
                if rc == 0 and findings == [f"FINDING: {vuln}"]:
                    dep_set.append(u["id"])
            finally:
                for r in reversed(restores):
                    r()
        if not dep_set:
            # Conjunctive: only the joint revert flips. Must be declared.
            dep_set = [u["id"] for u in units]
    loo_tokens: dict[str, str] = {}
    if matrix and len(units) > 1:
        # Necessity is only meaningful for dependency-set members: leaving
        # out a unit the probe never needed proves nothing.
        for u in units:
            if u["id"] not in dep_set:
                print(f"[leave-one-out:{label}] without {u['id']} -> "
                      f"skipped (not in dependency set)")
                continue
            rest = [x for x in units if x["id"] != u["id"]]
            partial = dict(scenario, units=rest)
            restores = []
            try:
                try:
                    restores = apply_all(repo, partial)
                except IncoherentRevert as e:
                    return None, [f"[{label}] INCOHERENT-REVERT (leave-one-out "
                                  f"without {u['id']}): {e}"]
                coh = run_conformance(repo, partial, timeout, label)
                if coh:
                    return None, coh
                rc, findings, _ = run_probe(repo, probe, timeout)
                tok = (findings[0][len("FINDING: "):]
                       if rc == 0 and len(findings) == 1 else
                       f"NO-FINDING(rc={rc},{findings})")
                loo_tokens[u["id"]] = tok
                print(f"[leave-one-out:{label}] without {u['id']} -> {tok}")
                if rc == 0 and findings == [f"FINDING: {vuln}"]:
                    failures.append(
                        f"[{label}] {probe}: still flips without {u['id']} — "
                        f"unit is unnecessary; narrow the anchor or declare it")
            finally:
                for r in reversed(restores):
                    r()
    declared = (scenario.get("declared_dependencies") or {}).get(probe)
    if declared is not None and sorted(declared) != sorted(dep_set):
        return None, [f"[{label}] {probe}: dependency drift — validated "
                      f"{sorted(dep_set)} but declared {sorted(declared)}; "
                      f"re-declare, never trust"]
    if declared is None and len(dep_set) == len(units) and len(units) > 1:
        return None, [f"[{label}] {probe}: conjunctive dependency "
                      f"{sorted(dep_set)} must be declared in "
                      f"declared_dependencies before a record is written"]

    # Arm (d): every other registered scenario with a DISJOINT anchor.
    # A scenario whose units overlap the probe's own anchor (the same
    # impl applied under a sibling label) cannot reveal a wider
    # dependency — the flip is tautological — so it is skipped, not
    # recorded as a cross-flip. Only a flip under disjoint units means
    # the probe depends on more than its anchor.
    def _anchor_key(u: dict) -> str:
        # Function units: the reference impl file. Patch units: the module
        # PLUS the exact anchor strings (two patches in one file are two
        # different anchors — e.g. pre-N1 vs pre-N7 both touch stage8.py).
        if u["kind"] == "function":
            return "impl:" + u["impl"]
        return "patch:" + u["module"] + ":" + repr(u["patches"])
    own_impls = {_anchor_key(u) for u in scenario["units"]}
    cross_flips: list[str] = []
    cross_observed: dict[str, str] = {}
    declared_cross = (scenario.get("declared_cross") or {}).get(probe, [])
    for other in SCENARIOS:
        if other["id"] == label:
            continue
        other_impls = {_anchor_key(u) for u in other["units"]}
        if own_impls & other_impls:
            print(f"[cross-skip:{label}] [{other['id']}] shares anchor units")
            continue
        restores = []
        try:
            try:
                restores = apply_all(repo, other)
            except IncoherentRevert as e:
                return None, [f"[{label}] cross arm [{other['id']}] "
                              f"INCOHERENT-REVERT: {e}"]
            rc, findings, _ = run_probe(repo, probe, timeout)
            tok = (findings[0][len("FINDING: "):]
                   if rc == 0 and len(findings) == 1 else
                   f"NO-FINDING(rc={rc},{findings})")
            cross_observed[other["id"]] = tok
            if rc == 0 and findings == [f"FINDING: {vuln}"]:
                print(f"[cross:{label}] {probe} FLIPS under [{other['id']}]")
                if other["id"] not in declared_cross:
                    failures.append(
                        f"[{label}] {probe}: CROSS-FLIP under "
                        f"[{other['id']}] — probe depends on more than "
                        f"its anchor; declare in declared_cross or rebind "
                        f"(no record written)")
                    break
                cross_flips.append(other["id"])
        finally:
            for r in reversed(restores):
                r()

    # Arm (e): historic.
    hist = historic_token(repo, scenario, probe, timeout)
    print(f"[historic:{label}] {probe} -> {hist}")

    try:
        head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                              capture_output=True, text=True,
                              timeout=60).stdout.strip()
    except Exception:
        head = "unknown"
    hashes = pair_hashes(repo, scenario)
    hashes["probe"] = sha_file(repo / "tests/probes" / probe)
    record = {
        "scenario": label,
        "probe": probe,
        "fixed": {"token": expected, "rc": 0},
        "reverted": {"token": vuln, "rc": 0},
        "dependency_set": sorted(dep_set),
        "matrix": bool(matrix and len(units) > 1) or len(units) == 1,
        "cross_flips": sorted(cross_flips),
        "cross_observed": cross_observed,
        "historic": hist,
        "hashes": hashes,
        "probe_hash": hashes.pop("probe"),
        "validated_at": head,
    }
    if failures:
        return None, failures
    return record, []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Validate probe↔anchor premises.")
    ap.add_argument("--scenario", default=None)
    ap.add_argument("--probe", default=None)
    ap.add_argument("--matrix", action="store_true",
                    help="single-unit and leave-one-out arms per unit")
    ap.add_argument("--timeout", type=int, default=TIMEOUT)
    args = ap.parse_args(argv)

    manifest = json.loads(
        (REPO / "tests/probes/MANIFEST.json").read_text(encoding="utf-8"))
    premise = load_premise(REPO)
    failures: list[str] = []
    validated: set[tuple[str, str]] = set()

    for scenario in SCENARIOS:
        if args.scenario and scenario["id"] != args.scenario:
            continue
        for probe in scenario["probes"]:
            if args.probe and probe != args.probe:
                continue
            if probe not in manifest:
                failures.append(f"[{scenario['id']}] {probe}: not in MANIFEST.json")
                continue
            validated.add((scenario["id"], probe))
            record, errs = validate_pair(REPO, scenario, probe, manifest,
                                         args.matrix, args.timeout)
            failures.extend(errs)
            premise["records"] = [r for r in premise.get("records", [])
                                  if not (r.get("scenario") == scenario["id"]
                                          and r.get("probe") == probe)]
            if record is not None and not errs:
                premise["records"].append(record)

    premise["records"].sort(key=lambda r: (r["scenario"], r["probe"]))
    (REPO / "tests/revert/PREMISE.json").write_text(
        json.dumps(premise, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {REPO / 'tests/revert/PREMISE.json'}: "
          f"{len(premise['records'])} records, {len(failures)} failures")
    for f in failures:
        print("FAIL:", f)
    # Hash-freshness self-check on the records just written.
    stale = []
    for (sid, probe) in sorted(validated):
        from revert.scenarios import by_id
        rec = find_record(premise, sid, probe)
        if rec is not None:
            msg = check_pair(REPO, by_id(sid), probe, rec)
            if msg is not None:
                stale.append(msg)
    for s in stale:
        print("STALE:", s)
    return 1 if (failures or stale) else 0


if __name__ == "__main__":
    raise SystemExit(main())
