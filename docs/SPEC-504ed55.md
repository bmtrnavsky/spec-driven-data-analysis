# SPEC-504ed55: revert-sensitivity redesign

Base: HEAD `504ed55`, tree clean, 359 tests, 1 failing:
`TestProbeRevertSensitivity.test_reverts_flip_probes`, scenario `pre-I6/N6/M7 no fail-closed chains`,
4 probes (n_gitclean_g3, n_rm_reviews_g3, n_prefix_g3, n_prefix_sticky).

All evidence below was reproduced in a scratch clone of 504ed55. No repo code was changed. The
reproduction scripts lived in `~/.hermes-home/cache/scratch/rs504_tools/`. That directory is pruned
after 24h, so every mutant this spec relies on is written out inline.

## Headline verdict

1. **The scenario is a design flaw, not 4 local bugs.** `pre-I6/N6/M7` is not a revert. It is 9
   branch-disablings applied to the *fixed* module. The result is a program that never existed:
   - Two of the 9 substitutions (verify truncation, verify deletion) disable code that **predates
     the fix**. Both checks exist verbatim at `c5ef92b` (Phase 2) and `d135783`.
   - Two substitutions leave dangling code. One is P8's `IndexError`. The other is a new one found
     here: `AttributeError` at chain.py:310 `mirror_hash = heads.get("hash")` once the mirror-required
     raise is disabled and the mirror is absent.
2. **Category A: none of the 3 probes depends on the chain fix.** n_gitclean_g3 and
   n_rm_reviews_g3 are governed by the **N2 lineage backstop** in `review.existing_calls`. Reverting
   N2 flips both. n_prefix_g3's G3 outcome is not chain-dependent under any revert tried, because
   its oracle cannot see what the chain layer does.
3. **Category B: the fix is to stop reverting `verify()`.** The verify checks that P8 targets were
   never part of I6/N6/M7. Once they are correctly left in place, **n_prefix_sticky does not depend
   on the chain fix either.** Its real guard is the ea94356 sticky pin. It needs to be rebound with a
   non-disjunctive oracle.
4. **M7 is NOT closed (a new product finding).** A true N8 attack restores the older prefix
   *together with its older heads mirror*. Against that attack, `verify_all` returns `[]` and
   `lineage()` reports `results_seen_before_profile: False`. Three checkpoint commits exist, and
   `_checkpoint_problems` *would* report the rollback, but `verify_all` only consults it when some
   chain lacks a usable mirror. A rolled-back mirror is usable. No probe has ever been shown to
   depend on M7.
5. **N6 append-side is CLOSED and now properly attributed. N7 is unchanged.** Details are in §5.

---

## Evidence (reproduced at 504ed55)

### E1: chain revert, per-probe (original 9 subs; P8 swapped for a coherent form where needed)
| Probe | HEAD | Chain reverted | What actually decided |
|---|---|---|---|
| n_gitclean_g3 | rc 1 `round 1 already ran twice in this lineage` | **identical** rc 1, same message | `review.existing_calls` N2 backstop (lineage + runs.log). `verify_all` is `[]` both before and after the deletion, so the chain is never involved. |
| n_rm_reviews_g3 | same | **identical** | same |
| n_prefix_g3 | rc 1 `runs.log: file is missing or empty but the heads mirror records seq 4` (chain refusal) | rc 1 `goldfish teardown recorded (round 1: fail; round 3: fail)` (**append accepted**) | The chain *did* change behaviour. The probe re-runs with `stub="fail"` and reads `rc`/G3, so it cannot observe the change. |
| n_prefix_sticky | STICKY-HELD | `IndexError` at chain.py:460 (P8 `elif False:` falls through to `hashes[hs-1]`) | n/a: the reverted module is incoherent |

### E2: N2 mutant (review.py) → both deletion probes flip
`    for ev in _lineage_and_chain_calls(wd, stage):` → `    for ev in []:`
- n_gitclean_g3: `run after clean rc: 0` → `FINDING: G3-LAUNDERED-VULNERABLE`
- n_rm_reviews_g3: `run after deletion rc: 0` → `FINDING: G3-LAUNDERED-VULNERABLE`

### E3: dependency matrix for the 9 chain subs (sub7 = coherent P8)
Subs: 0 N6 restart raise · 1 M7 checkpoint raise · 2 I6 mirror-required · 3 anchored append ·
4 mirror-hash · 5 CAS `assert seq == mirror_seq + 1` · 6 CAS `assert prev == heads["hash"]` ·
7 verify truncation · 8 verify deletion.

- **Single-sub reverts:** no probe flips on any single sub. Reverting sub0 or sub8 alone makes the
  chain probes print `CHAIN-ERROR-UNEXPECTED`. With sub0 alone, the restart is caught by the CAS
  `assert` instead.
- **Leave-one-out** (revert all except sub *k*):

| kept sub | n_gitclean_chain / n_gitstash_chain | n_prefix_sticky |
|---|---|---|
| 0, 5, 6 | ERROR-UNEXPECTED (still blocked) | FLIP |
| 1, 2, 3, 4 | FLIP | FLIP |
| 7, 8 | FLIP | **HOLD** |

Reading the table:
- The chain probes need the N6 raise **and** the CAS asserts. The CAS asserts are a second,
  accidental fail-closed path. They are `assert` statements, so they are stripped under `python -O`.
- Sub1 (M7) is never deciding.
- n_prefix_sticky needs both verify subs 7 and 8 reverted. Those are Phase-2 code, not the fix.

### E4: n_prefix_sticky depends on Phase-2 verify ∨ the ea94356 pin, not on the chain fix
- **Pin mutant** (lineage.py `broken = bool(chain.verify(...))` → `broken = False`): `flag after
  restore: False | verify problems: 6` → STICKY-HELD. The oracle `contained = bool(problems) or
  bool(flag)` is a **disjunction**, so the flag can be laundered while the probe still passes.
- **Full chain revert** with coherent P8: `flag False | verify problems: 0 | G7: FAIL` → FLIPPED.
  G7 fails in *every* arm, so the VULN token is a proxy. It does not mean the attack outcome happened.

### E5: M7 rollback hole (true N8: prefix **and** T0 mirrors restored)
```
chain.verify(lineage): []
verify_all: []
checkpoint commits: 3
_checkpoint_problems (if consulted): ['.analysis/runs.log: file missing but commit 8389bc2… checkpoints seq 3 …', …]
lineage() results_seen_before_profile: False
G7: blocked: G2 fails: lock is not valid (tampered: spec.lock changed outside `dda lock`)
```
- The checkpoint check is skipped because `ledger.verify_all` only calls it when
  `missing_mirror` is true. Its own comment names "a rolled-back … mirror" as the threat, which is
  the case the trigger condition excludes.
- The append side has the same gap. `_committed_checkpoint_seq` is consulted only in the
  `not data` branch (chain.py:290). This is from reading the code. It was not executed separately.
- In this fixture, G7 was saved by an unrelated lock-tamper check. Gate safety under mirror
  rollback is **unproven**. It is not shown broken.

### E6: M7-isolated variant (mirrors deleted, prefix restored)
- At HEAD: `PREFIX-REFUSED-BY-CHECKPOINT` (runs.log missing, no mirror, checkpoint seq 4).
- Sub1-only revert: blocked by sub2 (`lineage.jsonl: 1 line(s) but no heads mirror records this
  chain`). Isolation is incomplete because the restored non-empty lineage hits I6 first.
- All 9 reverted: `AttributeError: 'NoneType' object has no attribute 'get'`, which is the second
  incoherent-revert site.

---

## 1. Category A: probes whose scenario does not govern them

### Root cause
The binding of probe to scenario was asserted and never measured. Each probe was listed under
`pre-I6/N6/M7` because its story mentions deletion or prefix restore. Nobody ran it against the
reverted code: the scenario could not compile until 504ed55, so the premise was untestable. When
it finally ran, it showed the bindings were wrong.

### Per-probe decision

**n_rm_reviews_g3: REBIND to new scenario `pre-N2 no lineage backstop`.**
- The attack deletes the untracked goldfish call files. The committed lineage and runs.log chains
  are never touched (`verify_all == []` throughout). The chain fix is irrelevant by construction.
- The guard that actually holds is the N2 backstop, and E2 proves it flips. This is also the first
  real teeth-proof for the REREVIEW claim "N2 closed for call-file deletion".
- New scenario: `scripts/ddalib/review.py`, function-level revert of `existing_calls` to its pre-N2
  body (glob the call files only). See §3 for the mechanism. The E2 line substitution is the interim
  form.

**n_gitclean_g3: REBIND to `pre-N2 no lineage backstop`. Keep it as a separate probe.**
- `git clean -fdx -- .analysis/reviews` is path-scoped, so the chains survive. It is the same
  guard as n_rm_reviews_g3 with a different deletion vector. The vector is worth keeping because
  git deletion and `rm` reach the files differently.
- Whole-tree `git clean` *is* chain-dependent, and n_gitclean_chain already covers it.
- Update the docstring to say it does not exercise the chain.

**n_prefix_g3: REMOVE from the chain scenario. Do not rebind it as written. Replace its coverage
with two new probes.**
- Its premise is false twice:
  1. The re-run uses `stub="fail"`, so even an accepted append records failing rounds. The probe
     can never print `G3-LAUNDERED-VULNERABLE` under any revert.
  2. G3 is independently held by approval binding. Even with `stub="pass"` and the chain reverted,
     G3 fails: the restore deletes the committed approval file, and the re-approve is rejected by
     §4.5 purity (`approval commit … touches more than …`). It printed `G3-FAILED-OTHER-GUARD` in
     the scratch rewrite.
- Plainly: **the G3 verdict on a prefix restore was never chain-dependent**, because approval
  binding contains it as defence in depth. The chain fix governs one *intermediate step*, whether
  the review re-run append is accepted. E1 shows that step flips: at HEAD the chain refuses, under
  revert the append is accepted.
- Replacement probes. Each has an attributing oracle on the step the guard actually owns:
  - **n_prefix_rerun_chain** (`pre-I6 append`):
    - Steps: restore the T0 prefix with mirrors intact, then `review run --stub pass`.
    - Oracle: the refusal text contains `older prefix` or `heads mirror records` → `PREFIX-REFUSED`.
      rc 0 → `PREFIX-ACCEPTED-VULNERABLE`. Any other nonzero exit → `PREFIX-BLOCKED-OTHER-GUARD`,
      which is never the expected token.
  - **n_prefix_m7_chain** (`pre-M7 checkpoint`):
    - Steps: make every chain the operation appends to missing or empty, and delete its mirror, so
      that I6 and N6 have nothing to anchor on. Then append.
    - Oracle: the refusal text contains `committed checkpoint`.
    - E6 shows the naïve version (restored non-empty lineage) is blocked by I6 first. Isolation
      requires that *no* touched chain is non-empty and mirrorless.
- Optionally, keep n_prefix_g3 as an **unbound** end-to-end regression probe (manifest
  `binding: none`, see §2), with its stub corrected to `pass`. It then documents that G3 survives a
  prefix restore and claims nothing about which guard is responsible.

### Required invariant
**I14a:** every probe in `SCENARIOS` has a premise record (§2) showing that it flips under that
scenario and holds without it. A probe with no such record is not bound to any anchor.

### Acceptance tests
1. Under `pre-N2`, n_rm_reviews_g3 and n_gitclean_g3 print `G3-LAUNDERED-VULNERABLE` with rc 0. At
   HEAD they print `G3-STILL-FAILING`.
2. Under the chain scenario, neither probe is listed.
3. n_prefix_rerun_chain: `PREFIX-REFUSED` at HEAD and `PREFIX-ACCEPTED-VULNERABLE` under
   `pre-I6 append`.
4. n_prefix_m7_chain: `PREFIX-REFUSED-BY-CHECKPOINT` at HEAD and `PREFIX-ACCEPTED-VULNERABLE` under
   `pre-M7`, with **only** the M7 unit reverted.
5. n_prefix_g3 is no longer in `SCENARIOS`. If kept, MANIFEST marks it `binding: none`.

**Classification: TEST-DESIGN FLAW**, fixed by rebinding and rewriting probes. No product guard
is shown broken by Category A.

---

## 2. Meta-rule: premise validation before an anchor is trusted

### Root cause
`test_reverts_flip_probes` checks the flip, but only after a human has *asserted* the binding.
Nothing establishes, or records, that a probe depends on the fix before it is listed. Bindings
were added on narrative grounds while the scenario could not even run. The suite therefore
carried 4 unproven claims for multiple commits. Removing the N6 raise also showed that a
dependency can be **conjunctive** (the CAS assert also blocks), which neither the binding nor the
flip check would reveal.

### Required invariant
**I14 (premise before anchor):** a (scenario, probe) pair counts as teeth only if a recorded
validation shows all of the following:
- **(a) Fixed:** the expected token, rc 0.
- **(b) Reverted:** the VULN token, rc 0. A crash, timeout or wrong token is a failure, never a pass.
- **(c) Coherent revert:** the reverted unit passes its pre-fix conformance tests (§3).
- **(d) Attribution:**
  - The flip is caused by the declared unit. For multi-unit scenarios, record the minimal
    dependency set from single-unit and leave-one-out runs, as in E3.
  - The probe does **not** flip under any other registered scenario, unless that dependency is
    declared.
- **(e) Historic premise, where feasible:** the probe also prints its VULN token on a worktree at
  `fix_commit^`. If probelib API drift makes this infeasible, record `historic: infeasible` with
  a reason. It is never silently skipped.

### Harness design
**Registry.** Move `SCENARIOS` out of test_invariants.py into `tests/revert/scenarios.py`. Each
scenario declares:
- `id`
- `fix_commits` (e.g. `["2391db5"]`)
- `units`: named, function-level reverts (§3)
- `probes`
- `declared_dependencies`: for conjunctive cases

**Validator.** `python -m tests.revert validate [--scenario ID] [--probe NAME] [--matrix]` runs:
1. Arm (a) on the clean tree.
2. Arm (b) with all units reverted.
3. With `--matrix`, single-unit and leave-one-out arms per unit.
4. A cross-scenario arm: the probe under every other scenario.
5. Optionally, arm (e) in a `git worktree` at `fix_commit^`, with the current probe and probelib
   copied in.

It writes `tests/revert/PREMISE.json`, one record per pair:
```json
{"scenario": "pre-N2 no lineage backstop", "probe": "n_rm_reviews_g3.py",
 "fixed": {"token": "G3-STILL-FAILING", "rc": 0},
 "reverted": {"token": "G3-LAUNDERED-VULNERABLE", "rc": 0},
 "dependency_set": ["existing_calls"], "cross_flips": [],
 "historic": {"commit": "<fix>^", "token": "G3-LAUNDERED-VULNERABLE"} ,
 "hashes": {"probe": "<sha256>", "probelib": "<sha256>",
            "fixed_units": {"review.existing_calls": "<sha256 of AST-normalised body>"},
            "revert_units": {"review.existing_calls": "<sha256>"}},
 "validated_at": "<HEAD sha>"}
```
Write PREMISE.json in the same commit as the binding. It is reviewed as gate code, like the
MANIFEST.

**When it runs.**
- **Creation (manual):** binding a probe without a PREMISE record is rejected by the meta-test below.
- **Every suite run** (`test_reverts_flip_probes`, fast path): re-run arms (a) and (b). Then check
  the hashes. If the probe, probelib, a fixed unit, or a revert unit changed since validation, the
  pair is reported as `STALE-PREMISE: re-run validate`. It fails rather than being trusted.
- **New meta-test `test_premise_records_complete`:**
  - every pair in `SCENARIOS` has a PREMISE record with matching hashes;
  - every `n_*` probe is either bound, or marked `binding: none` in the MANIFEST with a reason;
  - the result is reported as ORPHAN otherwise.
- **CI / pre-merge (slow path):** `validate --matrix` on any change touching `scripts/ddalib/`,
  `tests/probes/` or `tests/revert/`. A newly appearing cross-flip or dependency change fails until
  it is re-declared. This would have caught N9 silently re-attributing n_gitreset_evals
  (SPEC-b8d8a3c cluster 3).

**Oracle rule** (makes I13 enforceable):
- A probe's FINDING must be decided by the **refusal reason** of the step its guard owns: message
  text and exit code class.
- `rc != 0` alone is never containment.
- Disjunctive oracles (`A or B`) are banned in bound probes. If both layers matter, split the probe
  into one per layer.

### Acceptance tests
1. `test_premise_records_complete` fails on 504ed55 for all 6 chain pairs (no records). It passes
   after the §1/§3 rebinds plus `validate`.
2. Mutation: edit one byte in a bound probe → `STALE-PREMISE` failure naming the probe.
3. Bind n_gitclean_g3 back to the chain scenario. `validate` must reject it, because arm (b) prints
   the expected token instead of the VULN token, and must write no record.
4. `validate --matrix` on the chain-append scenario reproduces E3's dependency sets:
   `{N6-raise, CAS}` for the chain probes, and never `{M7}`.

**Classification: DESIGN FLAW** (harness). The suite trusted bindings it never established.

---

## 3. Category B: coherent reverts (P8 and the substitution mechanism)

### Root cause
Reverting by string substitution inside the fixed function body produces fixed control flow with
holes cut out. That is not a pre-fix implementation:
- **P8:** `elif hs > len(hashes):` → `elif False:` removes the guard that protects the next arm,
  so `hashes[hs-1]` raises `IndexError`.
- **Sub2** (found here): disabling `if heads is None: raise` leaves `mirror_hash = heads.get(...)`
  live, which raises `AttributeError` when the mirror is absent (E6).
- **Subs 7 and 8 revert nothing.** `verify()`'s truncation and deletion checks are byte-identical at
  `c5ef92b`/`d135783` and at HEAD. The pre-I6/N6/M7 `verify()` *is* the current `verify()`; M7's
  verify-side addition lives in `ledger.verify_all` / `_checkpoint_problems`, not in `chain.verify`.
  Neutering them simulates a weaker product that never shipped. Probes that "flip" on that tell us
  nothing about the fix.

A one-line patch (`elif …: pass`) does compile and was verified to make n_prefix_sticky flip. It
should still be rejected as the fix, for two reasons: it keeps reverting non-fix code, and it
leaves the sub2 class of crash in place.

### Redesign: function-level reference reverts
1. **Unit = a whole function**, located by AST (`ast.FunctionDef` name → `lineno..end_lineno`).
   It is replaced by a reference implementation from `tests/revert/impl/<module>_<unit>.py`. No
   line anchors, and no `if False:` bodies.
2. **The reference implementation is historic where one exists.**
   - `chain._append_locked` pre-I6/N6/M7 is `d135783:scripts/ddalib/chain.py`'s `_append_locked`
     verbatim: `_last_line` → seq/prev, append, write the mirror. It has no mirror read, no anchor,
     no CAS and no checkpoint, and it is coherent by construction.
   - Signature drift is the only edit allowed, and it is listed in the impl file's header.
3. **Granular units for attribution.** One historic function cannot separate N6 from M7, so add
   *derived* units. Each is the fixed function with exactly one rule removed **and its dependents
   adjusted**:
   - `append.no_N6`: the `mirror_seq > 0` raise is removed, the restart uses fresh genesis, and the
     CAS is skipped when restarting (`mirror_seq = 0`).
   - `append.no_M7`: the `ckpt` lookup and raise are removed.
   - `append.no_I6`: the historic body.

   Each derived unit is a complete function file. It is not a substitution.
4. **`verify()` is not part of the chain scenario.** Delete subs 7 and 8. If a "verify blind to
   truncation" *mutant* is ever wanted, register it as a **mutation**, not a revert. It must keep
   every predicate and drop only the `problems.append` (`elif hs > len(hashes): pass`), and it
   carries `historic: n/a`.
5. **Coherence check (premise arm c).** Each reference unit ships its pre-fix conformance tests in
   `tests/revert/conformance/`, run against the reverted module before any probe:
   - `_append_locked` (pre-I6): append to an empty file gives seq 1; append to an N-line file gives
     seq N+1; a missing file gives genesis.
   - `verify` mutant: no exception for any `hs` in `0..len+2`; the mirror can be None or present.

   Any exception other than the asserted DdaError fails the scenario as `INCOHERENT-REVERT`, kept
   distinct from `NO-FINDING` and wrong-token.

### Consequence for n_prefix_sticky (rebind)
- Under a coherent revert, `verify()` is unchanged, so the probe prints STICKY-HELD (E3: keeping
  sub7 or sub8 holds). **It does not depend on the chain fix.**
- Its real guard is the ea94356 verified-read pin (I12).
- Rebind it to a new scenario `pre-I12 no sticky pin`: function-level `lineage.lineage` without the
  `broken` pin.
- Change the oracle to the attack outcome alone: `flag True` → STICKY-HELD, `flag False` →
  STICKY-FLIPPED-VULNERABLE. E4 confirms the flag reads False under the pin mutant.
- Keep `verify problems > 0` as a printed diagnostic, never as a disjunct.

### Acceptance tests
1. Revert test logs show no `if False:  # REVERT-TEST` text for chain.py. Scenario application is
   by AST function replacement only, and the applied module imports cleanly.
2. Under `pre-I6/N6/M7` (historic `_append_locked`): n_gitclean_chain and n_gitstash_chain print
   CHAIN-RESTARTED-VULNERABLE, rc 0. No IndexError or AttributeError appears in any arm, including
   the E6 mirrorless case.
3. Under `append.no_N6` alone, both chain probes flip. Fix the CAS-assert duplication first,
   otherwise this records the declared conjunction `{no_N6, CAS}`. Replace the `assert`s with
   `DdaError` raises, because asserts are stripped under `-O`.
4. Under `pre-I12 no sticky pin`, n_prefix_sticky prints STICKY-FLIPPED-VULNERABLE. At HEAD it
   prints STICKY-HELD with `flag True`.
5. Conformance: each `tests/revert/conformance/` case passes on its reference unit and raises no
   non-DdaError exception.

**Classification: DESIGN FLAW** (the revert mechanism). The P8 one-liner is a LOCAL PATCH. It is
acceptable only as a registered mutation, not as a revert.

---

## 4. New product finding: M7 rollback hole (blocks M7 closure)

**Root cause.**
- `ledger.verify_all` gates `_checkpoint_problems` on `missing_mirror`.
- `chain._append_locked` consults `_committed_checkpoint_seq` only when the file is missing or empty.
- An attacker who restores an older prefix **and** the matching older mirror from `dda_home()/heads/`
  passes both checks. The chain then verifies, `lineage()` unreads the exposure, and appends
  silently extend the older prefix.
- This is the exact N8 case named in chain.py:283 and ledger.py's comment.

**Required invariant I7″.** When a workdir chain is verified, or appended to on any CLI path that
can change a gate verdict, its live seq must be ≥ the highest committed checkpoint seq for that
chain, whether or not a mirror is present.
- To keep the hot path fast, cache the checkpoint scan keyed on `git rev-parse HEAD` plus the reflog
  tip. Do not skip it.

**Acceptance tests.**
1. The E5 script becomes probe `n_prefix_mirror_rollback.py`. Expected tokens:
   `ROLLBACK-DETECTED` (`verify_all` non-empty and `lineage()` flag True) vs
   `ROLLBACK-LAUNDERED-VULNERABLE`. It prints VULNERABLE at 504ed55.
2. After the fix, the same probe is bound to the `append.no_M7` + `verify_all.no_M7` units, with a
   PREMISE record.
3. The hot-path cost of `dda verify-chain` stays within 20% of 504ed55 on the p9 fixture.

**Classification: PRODUCT DESIGN FLAW.** The trigger condition contradicts the threat it documents.

---

## 5. Verdict on N6 / N7 / M7

| Finding | Before | After this analysis |
|---|---|---|
| **N6 append-side** (clean/stash restart) | Claimed closed; revert proof broken until 504ed55 | **CLOSED and attributed.** n_gitclean_chain and n_gitstash_chain flip only when the N6 raise *and* the CAS asserts are reverted (E3). Caveat: the second guard is an `assert`. |
| **N6-read / I12** (sticky flags) | "Proven" by n_prefix_sticky | **Implemented, not yet proven.** The old proof was a disjunction (E4) that never isolated the pin. Proven after the §3 rebind passes. Also incomplete against mirror rollback (§4). |
| **N2** (call-file deletion) | Closed, no revert proof | **CLOSED and now attributed** (E2), pending the `pre-N2` scenario and its PREMISE record. |
| **N7** | Separate scenario `pre-N7 no index fallback`, not among the failures | **No change.** This analysis does not touch its anchor or probes. SPEC-b8d8a3c's I13 status stands. |
| **M7** | Open per SPEC-b8d8a3c, trailer redesign landed in 18c4ca9 | **NOT closed.** (a) No probe depends on M7: sub1 never decides (E3), and the isolated variant was pre-empted by I6 (E6). (b) The rollback hole lets an older prefix plus older mirror pass both `verify_all` and `lineage()` (E5). Re-close only under I7″, with n_prefix_m7_chain and n_prefix_mirror_rollback validated per I14. |

## Implementation order
1. **§3 mechanism.** Add the AST unit replacer, the historic `_append_locked` impl and the
   conformance tests. Drop verify subs 7 and 8. Replace the CAS `assert`s with `DdaError`.
2. **§2 registry, validator, PREMISE.json and `test_premise_records_complete`.**
3. **§1 rebinds.** Add the `pre-N2` scenario and attach n_rm_reviews_g3 and n_gitclean_g3 to it.
   Remove n_prefix_g3 from the chain scenario. Add n_prefix_rerun_chain and n_prefix_m7_chain.
   Rebind n_prefix_sticky to `pre-I12` with the flag-only oracle.
4. **§4 product fix (I7″),** then n_prefix_mirror_rollback, then validate.
5. **Full suite:** 0 failures, `validate --matrix` clean, and every bound pair has a fresh PREMISE
   record. Only then mark N6-read, N2 and M7 closed.
