# Hostile re-review — invariant harness + product @ working tree (2026-11-19)

Reviewer: turing. Tree: `35c0bfd` + uncommitted harness/gate fixes (see §Diff).
Method: independent attack scripts against the CLI and the library, not the builder's
own probes. Every claim below was run; raw output is quoted.

**VERDICT: PASS**, with named tail (§3). The harness is sound (§1); the two product
holes found in this pass are fixed and regression-tested, including the one that let a
session fabricate a passing goldfish review (H1). No HIGH remains open. Residual risks
that are accepted or deferred are listed by name, not hidden.

---

## 1. Harness: PASS

Deterministic enumeration, three fixtures × 16 mutations, each on a fresh fork.

| Run (post-fix) | Result |
|---|---|
| `TestInvEvalBinding` (17 tests) | **17/17 OK**, 977.8s — N1 delete caught: `001 [bound]: fail -- outputs/summary.csv sha256 0636be05dd88 != expected 0000...` |
| `TestInvGoldfishHistory` + `TestInvStickyExposure` (34 tests) | **34/34 OK**, 1255.0s |
| `TestDdaprobeRegression` | **2/2 OK**, 20 probes, 376.4s — manifest both-directions, exactly one `FINDING:` line, non-zero probe rc fails |
| `TestProbeRevertSensitivity` | **NOT RUN this cycle** (certification tier, ~4 min/probe). Run before Brad's hand test. |
| `fast` product tier | **348 tests PASS in 585.0s** (post-fix) |

Mutation classes, all enumerated from one `MUTATIONS` list and asserted per fixture:
cosmetic amend, re-profile, re-run, rename artifact, **delete artifact**, touch mtimes,
unset key, sibling variant, edit-after-signoff, plus 7 git ops (clean, stash -u,
reset --hard, rebase, commit --amend, filter-branch, update-ref).

Monotonicity asserted on every mutation: fail→pass flip, sticky-flag disappearance,
approval `invalid→passing` recovery, G0–G9 DAG. Targeted: spec amend must report
**STALE**, report edit after sign-off must report **STALE**, delete must be **caught**
(`check_delete_caught`).

The 2026-11-08 harness findings are closed:

| Finding | Status | Evidence |
|---|---|---|
| H6 self-referential expectation | CLOSED | `tests/probes/MANIFEST.json` is external; probe count matches both ways |
| H7 substring pass predicate | CLOSED | `findings != [f"FINDING: {expected}"]` — exactly one line, prefix collisions fail |
| H9 filter-branch escape token | CLOSED | no escape tokens in MANIFEST; probe really rewrites: `approval add still in history: False` |
| H10 count-not-identity | CLOSED | both-direction name check |
| H11 mutations without git ops | CLOSED | `MUTATIONS` now holds 7 git ops |
| H12 probes written to the fix | CLOSED | 6 non-empty-prefix probes (`n_prefix_*`), all passing |
| H8 attack-ran unproven | PARTIAL | probe rc must be 0 and internal asserts guard each step; nothing proves ordering explicitly |

One fix landed during this review: `mut_git_reset_hard` never asserted HEAD moved, so a
no-op mutation counted as green. It now asserts (`tests/test_invariants.py`).

## 2. Findings, worst first

### H1 — HIGH — passing goldfish rounds fabricable with two env vars (FIXED)
The stub transport was gated only by `DDA_TEST_MODE=1` / `PYTEST_CURRENT_TEST`
(`review.py:52`) — ordinary environment variables any session can export, and no hook
blocks them. Proven with the same CLI a user runs:

```
control (no test flag) rc: 1 :: no provider key reachable (DDA_GOLDFISH_API_KEY is unset ...)
attack  (2 env vars)   rc: 0 :: goldfish teardown: round 1: pass; round 3: pass
  recorded teardown-r1-001.json: verdict=pass request=stub-0001 model=default
  recorded teardown-r3-002.json: verdict=pass request=stub-0002 model=default
```

`DDA_TEST_MODE=1 DDA_GOLDFISH_STUB=pass dda review run teardown` wrote real review
records and real `runs.log` chain entries, and nothing outside `review.py` mentioned
`stub-`, so `gate_g3` counted every `existing_calls` entry without a provider check.
SPEC §4.5 claims "production runs ignore it and fail closed on the missing provider
key" — a production run *is* the caller setting the variable.

Fixed at the verification boundary, not the writer's:
- records now carry `provider: "stub"` and `model: "stub"` (`review.py`);
- `goldfish_calls_gate` refuses a stub call outside a test run (`gates7.py`), which covers
  G3 and G7 (G7 calls the same function);
- `tests/test_stub_reviews.py` proves both halves.

After the fix, same attack, clean verifier:

```
attack rc: 0 :: goldfish teardown: round 1: pass; round 3: pass
  teardown-r1-001.json: verdict=pass provider=stub model=stub request=stub-0001
verifier gate G3 (no test flag) rc: 1 :: G3 fail: round 1: call stub-0001 is the test stub,
  not an independent review — it cannot satisfy a goldfish round (§5.0); round 3: ...
```

Residual (named, not hidden): a verifier who exports `DDA_TEST_MODE=1` in the same shell
as `dda gate` re-opens it. The fabricated record still self-identifies (`provider=stub`,
`model=stub`), and the footer requires naming the request id, so the lie is visible even
then. Closing that last step needs a trust anchor the agent cannot set (a signed verifier
identity) — a design decision, not a code patch.

### G9-1 / G9-3 — HIGH — data files under `outputs/` and `derived/` passed gitcheck (FIXED)
SPEC §11: gitcheck "fails if any staged file is under a data root, `derived/`, or
`outputs/`". The check was extension-based, so text data slipped:

```
before: outputs/orders.txt -> None      after: 'file under a data-output dir'
        outputs/orders.yaml -> None             'file under a data-output dir'
        derived/rows.log -> None                'file under a data-output dir'
```

`git add -f outputs/orders.txt` reached git and passed G9. Fixed in
`ledger._classify_git_path`; two regression tests in
`tests/test_phase5_round5.py::TestDataOutputDirsNeverCommitted` (both pass).

### N10 — MED — `bash -c 'git clean -fdx'` bypassed evidenceguard (FIXED)
The parser split words but kept a quoted wrapper as one token, so the git op was never
seen. `git clean -fdx`, `-- .analysis`, `stash -u`, `stash apply`, `reset --hard`,
`sudo git …` all blocked; the wrapper was `ALLOW`. Fixed by re-parsing tokens that still
hold a whole command line (`hooks._git_invocations`). Regression added to
`test_phase2::test_evidenceguard_table`. Still ALLOW by design/threat model:
`x=git; $x clean -fdx` (runtime-built command).

### N8 residual — LOW (defence in depth) — forged heads mirror plus short prefix (OPEN)
Anchored append now refuses short prefixes and DDA_HOME redirects:

```
C1 short prefix, mirror intact         -> refused: "1 line(s) but the heads mirror records seq 3"
C2 redirected DDA_HOME                 -> refused: "current DDA_HOME ... differs from the one recorded at lock"
C3 prefix + forged mirror (out-of-band)-> ACCEPTED
```

C3 requires writing the mirror inside `DDA_HOME`, which evidenceguard blocks in a bound
session, and committed `Dda-Chain-Head` trailers catch it when the chain has ever been
committed. Not exploitable through the tool boundary today; no probe covers it.

## 3. Tail — named, not worth fixing now

- `.analysis/reviews/goldfish/rows.txt` with row-level values still passes gitcheck
  (governance text exemption is deliberate: reviews must be committable). Data quoted
  into a review is the leak path; the footer/report hashing does not scan it.
- N4 junction read bypass: untested this cycle (`mklink /J` fixture). Long-standing.
- N9 `evals run` returning 0 while `verify-chain` is non-zero: not retested; gates still
  fail through the G2 cascade, so the CLI verdict is wrong, not the gate.
- G0-1/G1/G2 language-triage gaps (deferred in SPEC): unchanged, accepted risk.
- Revert-sensitivity certification and G9 allowlist manifest drift: run in `full` before
  Brad's hand test.

## 4. Diff (working tree, no commit)

```
 scripts/ddalib/gates7.py           | 10 +++++++    goldfish gate refuses stub calls
 scripts/ddalib/hooks.py            |  5 +++++    shell-wrapper re-parse (N10)
 scripts/ddalib/ledger.py           |  4 ++++    derived/ and outputs/ never committed
 scripts/ddalib/review.py           | 23 +++++++++-   stub calls marked provider/model=stub
 tests/test_invariants.py           |  3 +++     reset-hard mutation must move HEAD
 tests/test_phase2.py               |  6 +++++   bash -c / sudo cases
 tests/test_phase5_round5.py        | 17 +++++++++  2 gitcheck regression tests
 tests/test_phase7.py               |  5 +++-    stub record contract
 tests/test_stub_reviews.py         | new, 2 tests  H1 both halves
```

Suite numbers, post-fix: `fast` **348 tests PASS in 585.0s**; harness **17/17, 34/34**;
probes **20/20** in 376.4s. Revert sensitivity not run (certification tier).

Brad's hand test: **stays open** (per card). Run `python scripts/test.py full` for
revert sensitivity before it.
