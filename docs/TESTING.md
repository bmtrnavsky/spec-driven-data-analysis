# Testing

The suite has two tiers, a fast product tier and a slow certification tier,
plus a staleness check that says when the slow tier is actually needed. One runner drives all three:

```bash
python scripts/test.py fast    # product tier: does the product work?      (minutes)
python scripts/test.py check   # is any probe certification stale?          (seconds)
python scripts/test.py full    # certification + product: can I trust them? (~2 hours)
```

| Mode    | Runs | Answers | When |
|---------|------|---------|------|
| `fast`  | every `tests/test_*.py` except `test_invariants.py`, `test_premise.py`, and `tests/revert/**` | Does the product work? | Every routine change |
| `check` | no tests; re-hashes each probe/anchor pair against `tests/revert/PREMISE.json` | Is the expensive tier needed? | After touching `scripts/ddalib/`, `tests/probes/`, or `tests/revert/` |
| `full`  | `DDA_TEST_MODE=1 python -m unittest discover -s tests` (everything) | Can I trust these tests? | Before a handoff, or when `check` says STALE |

## `check`

Every bound probe is certified against the exact code it guards. PREMISE.json
records hashes of the probe file, `tests/probes/probelib.py`, each target
unit (the fixed function's AST, or the patched file), and each reference revert
implementation. `check` recomputes those hashes against the working tree:

- **FRESH** (exit 0): every pair matches. The certification tier would re-prove
  what is already recorded, so `fast` is enough until the handoff.
- **STALE** (exit 1): lists every drifted `[scenario] :: probe` pair and which
  component changed. Re-certify with `python -m tests.revert validate --matrix`,
  then run `full`.

This is the same signal `test_premise` reports as `STALE-PREMISE`, but it lists
every drifted component instead of stopping at the first one.

## Notes

- `DDA_TEST_MODE=1` is set automatically. Extra arguments after `fast`/`full` go
  to unittest (`-v`, `-f`, `-k pattern`).
- `fast` runs one module per process, in parallel (default 4 jobs — measured
  sweet spot on a 12-CPU box; `DDA_TEST_JOBS=N` overrides). Modules share
  nothing (own temp workdir and `DDA_HOME`), so parallelism changes timing
  only. Biggest modules start first so the tail does not stretch the wall.
- New `tests/test_*.py` files join the `fast` tier automatically. To make a new
  module certification-only, add it to `CERT_MODULES` in `scripts/test.py`.
- `check` covers probe/anchor drift only. A `fast` pass plus a FRESH `check` does
  not replace `full` before a handoff, because `full` also runs the metamorphic
  invariant harness and the probe regression runs.
