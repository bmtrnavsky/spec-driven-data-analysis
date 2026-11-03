# Hardening note (engineers)

What the SDDA pipeline guarantees, what it does not, and the suite that
proves each claim. For the product overview, see [README.md](../README.md).
The design, the full gate table, and the reasoning behind each rule live in
[SPEC.md](../SPEC.md).

## Build state

Current build: `0.9.1-phase9` (`python scripts/dda.py version`). All ten
build phases (SPEC §14) are implemented; anything else fails closed.

| Phase | Scope | State |
|-------|-------|-------|
| 0 | Red-team harness (`redteam/run.py`; GREEN = every prevention held) | built |
| 1 | Templates, config, `init` / `start` / `release`, hook entry | built |
| 2 | `lock`, chained evidence logs, `runlog`, `lockguard` / `evidenceguard` | built |
| 3 | Kernel runner, `meta` / `variant` / `run`, gate G6 | built |
| 4 | Approvals (`approve` / `approved`), `doctor`, gate G4 | built |
| 5 | `footercheck`, `footer --check`, `report`, `gitcheck`; gates G0, G8, G9 | built |
| 6 | `definitions`, `defguard`, content-hashed pins; gate G1 | built |
| 7 | Goldfish packet, `review run`, gate G3 | built |
| 8 | `profile` / `verify`, gates G2, G5, G7 | built |
| 9 | `correct`, `evals` | built |

Last verification (commit `ebe5274`, 2026-11-02): fast tier 322 tests
green, premise check FRESH, `redteam/run.py` GREEN (94 prevented, 30
detected, 1 documented environmental miss: no hermes-agent checkout on
this host), `dda verify-chain` reports `chains: ok`.

## Test tiers

```bash
python scripts/test.py fast    # routine product tier (~40 min)
python scripts/test.py check   # premise-staleness gate (seconds): FRESH means fast is enough
python scripts/test.py full    # certification + product (~2 hours; before a handoff)
```

See [docs/TESTING.md](TESTING.md) for what each tier answers and when to
run it. Quick reference of the older commands:

```bash
python redteam/run.py [--json out.json]                # red-team; exit 0 = GREEN
python -m tests.revert validate --matrix               # certify probe/anchor bindings
python -m tests.revert selfcheck                       # repair a tree left by a killed run
```

`tests/probes/` holds adversarial probes, and `tests/revert/` certifies
each one by reverting the fix it is bound to and requiring the probe to
flip. A probe that would pass either way fails certification instead of
quietly proving nothing. Reverts run on a temporary copy under a lock,
never on your checkout.

The red-team harness never touches a live Hermes profile. It points
`DDA_HOME` and `HERMES_HOME` at a scratch directory and drives Hermes's
own `agent.shell_hooks.run_once`. GREEN means every expected prevention
held, no unbound-session false positive, and every miss is a documented
caveat in [redteam/threat-model.md](../redteam/threat-model.md).

## Hook behavior worth knowing

After lock, data reads go through `dda run` (the locked-down kernel, `dda
variant` ids, freeze-on-first-run) and declared connector tools. `dda meta`
is the only metadata peek. Config approval at G4 is built and fails closed
at DECIDE and PUBLISH without an approval for the exact config hash.

Hooks fail open when the interpreter is missing, and the missing-interpreter
case can only be detected, not blocked — except where `dda install` emits
`fail_closed: true` on a blocking hook (verified by `dda doctor`). A live
profile whose block was hand-edited after install is out of scope:
reinstall from `dda install` to restore it.

## Accepted risks (not fixed, with revisit dates)

As of commit `ebe5274` (2026-11-02); each entry below is a documented
caveat in [redteam/threat-model.md](../redteam/threat-model.md):

- Shell-level obfuscation still gets through the argv parser (variable
  indirection, runtime-built commands, `python -c` hiding the release in
  a string) — accepted as evasion rather than a slip; revisit 2026-12-01.
- In-process API calls (`binding.release(...)`, `ddalib.cli.main(...)`)
  are a code-review finding, not a hook finding: there is no `dda` argv
  to parse — accepted; revisit 2026-12-01.
- The word-token backstop runs for `execute_code` only; a `terminal`
  command embedding a second `dda release` inside a non-argv word is
  missed — accepted as evasion; revisit 2026-12-01.
- Blocked-fallback heuristics and deleted-workdir exposure reads are
  heuristic by nature; destroying evidence is a human action outside the
  hook threat model — accepted; revisit 2026-12-01.
- Subagent binding: a bound session's `delegate_task` child is unbound
  (Hermes strips `parent_session_id`), so the child is never blocked —
  narrowed by the runlog unbound-access log plus the lock-time and G4
  exposure scans, which label the workdir post-data; revisit when a future
  Hermes forwards parent lineage on `pre_tool_call`.
- Runtime latency: hook p95 ~600 ms on the Windows host vs the 300 ms
  design target (SPEC §6.9; a target, not a gate) — a performance caveat,
  not a bypass; revisit 2026-12-01.
- Environmental miss at last verification: no hermes-agent checkout on
  this host, so one harness case could not run — documented, not a product
  gap; re-run where a checkout exists.
