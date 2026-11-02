"""Two-tier test runner: routine work costs minutes, certification only when it earns it.

    python scripts/test.py fast    # product tier            (minutes)
    python scripts/test.py check   # premise staleness check (seconds)
    python scripts/test.py full    # certification + product (~2 hours; before a handoff)

The suite holds three populations:

  fast   PRODUCT tier — every tests/test_*.py EXCEPT the certification
         modules below. Answers "does the product work?". Run it on every
         routine change. New tests/test_*.py files join automatically.

  check  STALENESS check — no tests run. Re-hashes every probe/anchor pair
         registered in tests/revert/scenarios.py against its record in
         tests/revert/PREMISE.json (probe file, probelib.py, fixed-unit
         code, reference revert impl) and reports FRESH or STALE, listing
         every drifted pair and component. Exit 0 = fresh (the expensive
         tier is NOT needed for premise reasons); exit 1 = stale or missing
         records (run `full`, and re-validate with
         `python -m tests.revert validate --matrix`). It is the same signal
         test_premise reports as STALE-PREMISE, but it lists every drifted
         component instead of stopping at the first.

  full   EVERYTHING — the certification tier (tests/test_invariants.py,
         tests/test_premise.py, tests/revert/**) plus the product tier, i.e.
         `DDA_TEST_MODE=1 python -m unittest discover -s tests`. Reverts
         product code in sandboxes and re-runs probes (~4 min per probe).
         Answers "can I trust these tests?". Run before a handoff, or when
         `check` says STALE.

Rule of thumb: `fast` on every change; `check` whenever you touched
scripts/ddalib/, tests/probes/, or tests/revert/; `full` before a handoff or
when `check` is STALE.

Extra arguments after the mode are passed to unittest (e.g. `-v`, `-f`,
`-k pattern`) for `fast` and `full`. DDA_TEST_MODE=1 is set automatically.
See docs/TESTING.md.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TESTS = REPO / "tests"

# Certification tier: modules (relative to tests/, discover-style names) and
# whole packages excluded from `fast`.
CERT_MODULES = {"test_invariants", "test_premise"}
CERT_PACKAGES = {"revert"}


def product_modules() -> list[str]:
    """Discover-style module names of the product tier (tests/test_*.py minus
    the certification modules; subpackages such as tests/revert are excluded
    because only top-level files are collected)."""
    mods = sorted(p.stem for p in TESTS.glob("test*.py"))
    return [m for m in mods if m not in CERT_MODULES]


def _env() -> dict:
    env = dict(os.environ)
    env["DDA_TEST_MODE"] = "1"
    return env


def _run_unittest(args: list[str]) -> int:
    # Same import + cwd layout as `discover -s tests` run from the repo root:
    # cwd = repo, tests/ first on sys.path, modules named without a package.
    env = _env()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(TESTS)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    cmd = [sys.executable, "-m", "unittest", *args]
    return subprocess.call(cmd, cwd=str(REPO), env=env)


def cmd_fast(extra: list[str]) -> int:
    mods = product_modules()
    leaked = [m for m in mods if m in CERT_MODULES or m.split(".")[0] in CERT_PACKAGES]
    assert not leaked, f"certification modules leaked into fast tier: {leaked}"
    print(f"[fast] product tier: {len(mods)} modules "
          f"(excluding {', '.join(sorted(CERT_MODULES))}, tests/revert/**)", flush=True)
    t0 = time.monotonic()
    rc = _run_unittest([*extra, *mods])
    print(f"[fast] {'PASS' if rc == 0 else 'FAIL'} in {time.monotonic() - t0:.1f}s", flush=True)
    return rc


def _pair_drift(scenario: dict, probe: str, record: dict | None) -> list[str]:
    """Every drifted component for one probe/anchor pair ([] = fresh)."""
    from revert.premise import pair_hashes, sha_file  # noqa: WPS433

    if record is None:
        return ["NO-RECORD (pair is bound but was never validated)"]
    drift: list[str] = []
    probe_path = REPO / "tests/probes" / probe
    if not probe_path.is_file():
        return [f"probe file tests/probes/{probe} is missing"]
    if record.get("probe_hash") != sha_file(probe_path):
        drift.append(f"probe file tests/probes/{probe}")
    try:
        cur = pair_hashes(REPO, scenario)
    except Exception as exc:  # anchor function vanished / renamed / duplicated
        return drift + [f"anchor unreadable: {exc}"]
    rec_h = record.get("hashes", {})
    if rec_h.get("probelib") != cur["probelib"]:
        drift.append("tests/probes/probelib.py")
    units = {u["id"]: u for u in scenario["units"]}
    for uid, h in cur["fixed_units"].items():
        if rec_h.get("fixed_units", {}).get(uid) != h:
            u = units[uid]
            where = (f"{u['module']}::{u['func']}" if u["kind"] == "function"
                     else f"{u['module']} (patch target)")
            drift.append(f"target unit {uid} [{where}]")
    for uid, h in cur["revert_units"].items():
        if rec_h.get("revert_units", {}).get(uid) != h:
            u = units[uid]
            where = u.get("impl") or "patch anchor strings"
            drift.append(f"reference revert {uid} [{where}]")
    return drift


def cmd_check(_extra: list[str]) -> int:
    t0 = time.monotonic()
    sys.path.insert(0, str(TESTS))
    from revert.premise import find_record, load_premise
    from revert.scenarios import SCENARIOS

    premise = load_premise(REPO)
    manifest = json.loads((TESTS / "probes/MANIFEST.json").read_text(encoding="utf-8"))
    total = 0
    stale: list[tuple[str, str, list[str]]] = []
    for scenario in SCENARIOS:
        for probe in scenario["probes"]:
            total += 1
            if probe not in manifest:
                stale.append((scenario["id"], probe, ["bound but not in MANIFEST.json"]))
                continue
            drift = _pair_drift(scenario, probe, find_record(premise, scenario["id"], probe))
            if drift:
                stale.append((scenario["id"], probe, drift))

    bound = {p for s in SCENARIOS for p in s["probes"]}
    orphans = [name for name, entry in sorted(manifest.items())
               if name.startswith("n_") and name not in bound
               and not (entry.get("binding") == "none" and entry.get("reason"))]

    elapsed = time.monotonic() - t0
    print(f"[check] premise staleness: {total} probe/anchor pairs across "
          f"{len(SCENARIOS)} scenarios ({elapsed:.2f}s)")
    if not stale and not orphans:
        print("[check] FRESH — every pair matches its PREMISE.json record.")
        print("[check] Expensive tier NOT needed for premise reasons; "
              "`fast` is enough for routine changes (run `full` before a handoff).")
        return 0
    print(f"[check] STALE — {len(stale)} of {total} pairs drifted"
          + (f", {len(orphans)} orphan probe(s)" if orphans else "") + ":")
    for sid, probe, drift in stale:
        print(f"  - [{sid}] :: {probe}")
        for d in drift:
            print(f"      changed: {d}")
    for name in orphans:
        print(f"  - ORPHAN {name}: bound to no scenario and not marked binding:none")
    print("[check] Expensive tier IS needed: these certifications no longer describe "
          "the current code.")
    print("        Re-certify: python -m tests.revert validate --matrix")
    print("        Then run:   python scripts/test.py full")
    return 1


def cmd_full(extra: list[str]) -> int:
    print("[full] certification + product tiers "
          "(DDA_TEST_MODE=1 python -m unittest discover -s tests); expect ~2h", flush=True)
    t0 = time.monotonic()
    rc = subprocess.call([sys.executable, "-m", "unittest", "discover", "-s", "tests", *extra],
                         cwd=str(REPO), env=_env())
    print(f"[full] {'PASS' if rc == 0 else 'FAIL'} in {time.monotonic() - t0:.1f}s", flush=True)
    return rc


MODES = {"fast": cmd_fast, "check": cmd_check, "full": cmd_full}


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in MODES:
        print(__doc__)
        print(f"usage: python scripts/test.py {{{'|'.join(MODES)}}} [unittest args]")
        return 2
    return MODES[argv[0]](argv[1:])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
