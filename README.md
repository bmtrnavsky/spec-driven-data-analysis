# disciplined-data-analysis

Spec-first data analysis for Hermes: lock the plan before the data, block
the shortcuts with hooks, re-check every hook rule at a gate. The design is
in [SPEC.md](SPEC.md). This tree contains build phases 0 and 1 (SPEC §14).

## Status

| Phase | What | State |
|---|---|---|
| 0 | Red-team harness (`redteam/`) | built; GREEN on this install |
| 1 | Workdir layout, `dda` CLI skeleton, lock hashing, hook entry point, session binding | built |
| 2+ | lock/chain, real gate logic, kernel, approvals, footer, definitions, goldfish, verify, evals | not built; commands fail closed (exit 3) |

## Use

```
python scripts/dda.py init <workdir>          # layout + templates
python scripts/dda.py hash <workdir> [--json] # lock hash of the current spec (no side effects)
python scripts/dda.py start <workdir> --session <id>   # bind a session (default: $HERMES_SESSION_ID)
python scripts/dda.py status
python scripts/dda.py release <workdir>
python scripts/dda.py install [--venv]        # print the Hermes hooks block
```

`scripts/dda.cmd` wraps the same on Windows. Everything is stdlib-only
Python ≥ 3.11; `config.yaml` is read by a strict YAML subset parser that
rejects anything it doesn't understand.

## Tests

```
python -m unittest discover -s tests      # phase-1 unit tests
python redteam/run.py [--json out.json]   # phase-0 red-team; exit 0 = GREEN
```

The red-team harness never touches the live Hermes profile: it points
`DDA_HOME` and `HERMES_HOME` at a scratch directory and drives Hermes's own
`agent.shell_hooks.run_once` from the hermes-agent venv. GREEN means every
expected prevention held, no unbound-session false positive, and every miss
is a documented caveat in [redteam/threat-model.md](redteam/threat-model.md).

## Hooks are not installed

Phase 1's blocking hooks are fail-closed stubs: in a bound session they
block every tool call except a clean `dda` command. Don't add the
`dda install` block to a live profile until phase 2 replaces the stubs, or
any bound session can do nothing but run `dda`.
