"""Single source of truth for revert scenarios (SPEC-504ed55 §2, I14).

Each scenario binds one or more negative probes to the exact product-code
anchor(s) whose revert must flip the probe from its expected FINDING to its
vuln FINDING. ``tests/test_invariants.py`` derives its SCENARIOS /
FUNC_SCENARIOS tuples from this registry; ``tests/revert/validate.py`` runs
the full arm matrix and writes ``tests/revert/PREMISE.json``.

Scenario dict:
  id:                   human label, stable (used as PREMISE key).
  kind:                 "function" (AST whole-function revert via apply_unit)
                        or "patch" (legacy string substitution).
  fix_commit:           commit whose PARENT exhibits the vuln (historic arm);
                        None when no single fix commit is recorded.
  units:                [{"id", "kind", "module", "func", "impl"}] for
                        function units, or [{"id", "kind":"patch", "module",
                        "patches": [(old, new), ...]}] for patch units.
  probes:               bound probe filenames.
  declared_dependencies:{probe: [unit ids]} for conjunctive cases — the
                        minimal unit set whose joint revert flips the probe.
                        Omit when every probe flips under a single unit.
  declared_cross:       {probe: [scenario ids]} — other scenarios the probe
                        is KNOWN to also flip under. Undeclared cross-flips
                        fail validation until re-declared here.
"""
from __future__ import annotations

SCENARIOS = [
    {
        "id": "pre-N1 early return",
        "kind": "patch",
        "fix_commit": "d135783",
        "units": [
            {
                "id": "stage8.no-N1-early-return",
                "kind": "patch",
                "module": "scripts/ddalib/stage8.py",
                "patches": [
                    ('    base = wd.root / "evals" / "corrections"\n',
                     '    base = wd.root / "evals" / "corrections"\n'
                     '    if not base.is_dir():  # REVERT-TEST pre-N1 early return\n'
                     '        return []\n'),
                ],
            },
        ],
        "probes": ["n_rm_corrections_evals.py"],
        "declared_dependencies": {
            "n_rm_corrections_evals.py": ["stage8.no-N1-early-return"],
        },
    },
    {
        "id": "pre-N7 no index fallback",
        "kind": "patch",
        "fix_commit": "2391db5",
        "units": [
            {
                "id": "stage8.no-N7-index-fallback",
                "kind": "patch",
                "module": "scripts/ddalib/stage8.py",
                "patches": [
                    ('    for entry in _approvals.index_approvals(wd, "correction"):',
                     '    for entry in []:  # REVERT-TEST pre-N7 no index fallback'),
                ],
            },
        ],
        "probes": [
            "n_gitamend_evals.py",
            "n_gitrebase_evals.py",
            "n_gitreset_evals.py",
            "n_gitupdate_evals.py",
            "n_filterbranch_evals.py",
            "n_prefix_evals.py",
        ],
    },
    {
        "id": "pre-N10 no git-op verdict",
        "kind": "patch",
        "fix_commit": "b8d8a3c",
        "units": [
            {
                "id": "hooks.no-N10-gitop-verdict",
                "kind": "patch",
                "module": "scripts/ddalib/hooks.py",
                "patches": [
                    ('    gv = _git_op_verdict(code) if code else None',
                     '    gv = None  # REVERT-TEST pre-N10 no git-op verdict'),
                ],
            },
        ],
        "probes": ["n_hook_gitops.py"],
        "declared_dependencies": {
            "n_hook_gitops.py": ["hooks.no-N10-gitop-verdict"],
        },
    },
    {
        "id": "pre-I6/N6/M7 no fail-closed append",
        "kind": "function",
        "fix_commit": "2391db5",
        "units": [
            {
                "id": "chain._append_locked::historic",
                "kind": "function",
                "module": "scripts/ddalib/chain.py",
                "func": "_append_locked",
                "impl": "tests/revert/impl/chain_append_locked_historic_d135783.py",
            },
        ],
        "probes": ["n_gitstash_chain.py", "n_gitclean_chain.py"],
    },
    {
        "id": "pre-I12 no broken-chain pin",
        "kind": "function",
        "fix_commit": "ea94356",
        "units": [
            {
                "id": "lineage.lineage::no-pin",
                "kind": "function",
                "module": "scripts/ddalib/lineage.py",
                "func": "lineage",
                "impl": "tests/revert/impl/lineage_lineage_no_pin.py",
            },
        ],
        "probes": ["n_prefix_sticky.py"],
    },
    {
        "id": "pre-N2 no lineage backstop",
        "kind": "function",
        "fix_commit": "d135783",
        "units": [
            {
                "id": "review.existing_calls::preN2",
                "kind": "function",
                "module": "scripts/ddalib/review.py",
                "func": "existing_calls",
                "impl": "tests/revert/impl/review_existing_calls_preN2.py",
            },
        ],
        "probes": ["n_rm_reviews_g3.py", "n_gitclean_g3.py"],
    },
    {
        "id": "pre-I6 no anchored append",
        "kind": "function",
        "fix_commit": "2391db5",
        "units": [
            {
                "id": "chain._append_locked::historic",
                "kind": "function",
                "module": "scripts/ddalib/chain.py",
                "func": "_append_locked",
                "impl": "tests/revert/impl/chain_append_locked_historic_d135783.py",
            },
        ],
        "probes": ["n_prefix_rerun_chain.py"],
    },
    {
        "id": "pre-M7 no committed checkpoints",
        "kind": "function",
        "fix_commit": "c4ede99",
        "units": [
            {
                "id": "chain._append_locked::no-M7",
                "kind": "function",
                "module": "scripts/ddalib/chain.py",
                "func": "_append_locked",
                "impl": "tests/revert/impl/chain_append_locked_no_M7.py",
            },
            {
                "id": "ledger._checkpoint_problems::none",
                "kind": "function",
                "module": "scripts/ddalib/ledger.py",
                "func": "_checkpoint_problems",
                "impl": "tests/revert/impl/ledger_checkpoint_problems_none.py",
            },
        ],
        "probes": ["n_prefix_m7_chain.py", "n_prefix_mirror_rollback.py"],
        "declared_dependencies": {
            # Matrix-determined: each probe pins a different half of the M7
            # fix. m7_chain is refused by the in-append checkpoint floor
            # (chain unit alone flips it); mirror_rollback's oracle needs
            # verify_all to report the gap (ledger unit alone flips it).
            "n_prefix_m7_chain.py": ["chain._append_locked::no-M7"],
            "n_prefix_mirror_rollback.py": ["ledger._checkpoint_problems::none"],
        },
        "declared_cross": {
            # m7_chain also flips under the wholly historic append (no
            # checkpoint floor there either); mirror_rollback needs the I12
            # lineage pin to DETECT, so blinding the pin flips it too.
            "n_prefix_m7_chain.py": ["pre-I6/N6/M7 no fail-closed append", "pre-I6 no anchored append"],
            "n_prefix_mirror_rollback.py": ["pre-I12 no broken-chain pin"],
        },
    },
]


def by_id(scenario_id: str) -> dict:
    for s in SCENARIOS:
        if s["id"] == scenario_id:
            return s
    raise KeyError(f"unknown revert scenario: {scenario_id!r}")


def bound_probes() -> dict[str, str]:
    """probe filename -> scenario id, for every bound probe."""
    out = {}
    for s in SCENARIOS:
        for p in s["probes"]:
            if p in out:
                raise AssertionError(f"probe {p} bound to two scenarios")
            out[p] = s["id"]
    return out
