"""I14 premise records: every bound probe↔anchor pair must have a fresh
validation record, and every bound probe's verdict must come from the
refusal reason (SPEC-504ed55 §2).

  test_premise_records_complete — every registry pair has a PREMISE.json
    record whose hashes match the current tree; every n_* probe is either
    bound or marked binding:none with a reason (n_prefix_g3.py is the
    deliberate unbound case); anything else is ORPHAN / NO-RECORD.
  test_probe_oracles_refusal_reason — the oracle audit (I13): no bare
    exit-code verdicts, no disjunctive (A or B) oracles on bound probes.

Run: DDA_TEST_MODE=1 python -m unittest tests.test_premise
"""
import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

import sys

sys.path.insert(0, str(REPO / "tests"))

from revert.premise import audit_oracle, check_pair, find_record, load_premise  # noqa: E402
from revert.scenarios import SCENARIOS  # noqa: E402


class TestPremiseRecords(unittest.TestCase):
    def test_premise_records_complete(self):
        premise = load_premise(REPO)
        manifest = json.loads(
            (REPO / "tests/probes/MANIFEST.json").read_text(encoding="utf-8"))
        failures = []
        for scenario in SCENARIOS:
            for probe in scenario["probes"]:
                if probe not in manifest:
                    failures.append(f"{probe}: bound but not in MANIFEST.json")
                    continue
                rec = find_record(premise, scenario["id"], probe)
                msg = check_pair(REPO, scenario, probe, rec)
                if msg is not None:
                    failures.append(msg)
        # Every n_* probe is bound or deliberately unbound with a reason.
        bound = {p for s in SCENARIOS for p in s["probes"]}
        for name, entry in sorted(manifest.items()):
            if not name.startswith("n_"):
                continue  # positive controls are unbound by design
            if name in bound:
                continue
            if entry.get("binding") == "none" and entry.get("reason"):
                continue
            failures.append(
                f"ORPHAN: {name} is bound to no scenario and not marked "
                f"binding:none with a reason — bind it or declare it")
        if failures:
            self.fail("premise records incomplete:\n  - " + "\n  - ".join(failures))

    def test_probe_oracles_refusal_reason(self):
        manifest = json.loads(
            (REPO / "tests/probes/MANIFEST.json").read_text(encoding="utf-8"))
        bound = {p for s in SCENARIOS for p in s["probes"]}
        errors = []
        for probe in sorted(bound):
            errors.extend(
                audit_oracle(REPO / "tests/probes" / probe,
                             manifest[probe]["expected"]))
        if errors:
            self.fail("refusal-reason oracle violations:\n  - " + "\n  - ".join(errors))


if __name__ == "__main__":
    unittest.main()
