# SPEC-b8d8a3c: resolving the 14 failures at b8d8a3c

Extends docs/SPEC-2391db5.md. Scope: the 14 suite failures at HEAD b8d8a3c (359 tests).
This document makes no code changes. Every claim below comes from reading the code at b8d8a3c
or from a reproduction run in a scratch fork or scratch clone.

## Headline verdict

**Status: NOT SHIPPABLE. Two of the three clusters are design flaws, one is a test-design flaw, and
cluster 2's working diagnosis is wrong.**

- **Cluster 1 (10 failures).** This is a real contradiction inside SPEC-2391db5. M7 puts a new committed
  `.json` file into git but never amends M5/§11 (the G9 allowlist and the safety scan).
  - Resolution: **redesign the M7 container.** Move the checkpoint into a commit-message trailer, not a
    tree file.
  - Do not add a path exemption.
- **Cluster 2 (3 failures).** The hook does **not** block the harness's `git stash -u`. The harness calls
  git through `subprocess`, which never passes through the agent hook. The stash runs (rc 0) and
  surfaces a real read-side fail-open:
  - `lineage()` and `verify_approval()` compute clean-looking values from a workdir whose chains do
    not verify.
  - One sub-failure (TestInvStickyExposure) is also a harness target bug.
  - The mutation is **not obsolete**. Keep it.
- **Cluster 3 (1 failure).** The `n_gitreset_evals.py` probe passes for the wrong reason. After
  `reset --hard`, the N9 chain check (rc 4) blocks first, so the N7 index fallback is never the deciding
  guard. The probe's oracle (`rc != 0`) cannot tell the two apart.
- **Earlier closures.** N6 was over-closed: gates were checked, but sticky labels and approval states
  were not. N7's reset coverage was valid at 2391db5, but its regression evidence is void since N9
  landed. M7 must not be recorded as closed.

---

## Cluster 1: `.analysis/chain-heads.json` vs G9 / gitcheck (10 failures)

Affected: Phase5Setup.test_gitcheck_clean, TestG9CommittedData.test_g9_fails_on_committed_data,
TestGitcheckHardened, TestEvidencePrefixes, TestOversizeContent, TestExtensionEvasion,
TestLockSidecarCleanup, TestExtensionlessDataSniff, TestSecretValueShapes,
TestGovernanceJsonCommittable.

### Verified mechanism
- `ledger.snapshot_chain_heads()` (ledger.py:356) writes `.analysis/chain-heads.json`.
  - `approvals.py:473-487` and `ledger.py:954` commit it with every dda-made commit.
- The safety scan's exemption set `_git_safety_evidence()` (ledger.py:593-630) does not list it.
- Neither does `_git_safety_known()` (ledger.py:569-590).
- So `_classify_git_path` (ledger.py:748) hits `.json ∈ GIT_SAFETY_EXTS`, which yields "data/secret format".
- Reproduced: TestGovernanceJsonCommittable → `G9 fail: data/secret files in git: .analysis/chain-heads.json (data/secret format)`.
- The M5 allowlist `_g9_governance_patterns()` (gates5.py:195-231) does not list the path either.
  - Once the scan is fixed, G9 fails a second time with "committed file not allowlisted".
- A second, quieter widening already shipped. `_only_added_file()` (approvals.py:505-530) lets an
  approval commit also modify `chain-heads.json` with **arbitrary content**. The "approval commit adds
  exactly one approval file" rule (§4.5) is therefore no longer exact.

### Root cause (design)
SPEC-2391db5 M7 added a new committed governance artifact. It did not apply the rules every
committed dda file must satisfy:
- M5: allowlist by exact path, sha256 on the G9 manifest.
- §11: classification by the data/secret scan.
- §4.5: approval-commit purity.

M7 and M5 were each specified correctly on their own. Their composition was never specified.

### Options considered
| Option | Fixes G9? | Integrity effect | Verdict |
|---|---|---|---|
| A. Exact-path exemption in `_git_safety_evidence` + allowlist | Yes | M7 anchor unchanged. **Opens a G9 data-smuggling channel**: any bytes named `chain-heads.json` skip the extension, tabular and binary checks (only the secret regexes still run). Combined with `_only_added_file`, an approval commit can carry them. This is the same weakness `profile.json`'s path-only exemption already has. | Reject as specified. Acceptable only as A′ below. |
| A′. Exemption **gated on strict schema**: `{rel: {seq:int≥1, hash:64-hex}}`, `rel ∈ workdir_chains(wd)`, ≤ 64 KiB, no other keys. Anything else is classified as data. | Yes | Closes the smuggling channel. Keeps the `_only_added_file` special case and the extra committed path. | Fallback only. |
| B. Move it out of `.analysis/` | No | The extension check applies everywhere. | Reject. |
| C. Hash, encrypt or rename (e.g. drop `.json`) | Dodges the check | Readers need plaintext `seq`/`hash`, so hashing destroys the function. Renaming to evade the extension check is the exact pattern TestExtensionEvasion exists to catch: the gate would be defeating itself. | Reject. |
| D. Derive checkpoints purely from tracked content | No | The vulnerable chains (runs.log, lineage.jsonl, approvals.index.jsonl, audit.log) are **untracked by design**. Git holds nothing to derive their heads from, so some datum must be written into git. | Impossible for untracked chains. |
| **E. Commit-message trailer** `Dda-Chain-Head: <rel> <seq> <hash>` (one per chain) on every dda-made commit | Yes: no tree file exists | Same anchoring strength as the file. The trailer is part of the commit object, so it is covered by `-S` signatures and survives in the reflog exactly as the tree file does. It is parsed strictly (no free-form payload), so it is not a data channel. It restores exact §4.5 purity (`_only_added_file` loses its exception). | **Adopt.** |

### Does any option reopen the hole M7 closes?
The hole M7 closes (N8) is a non-empty older chain prefix restored without its mirror. The defence
is "the chain must extend the highest checkpoint seq recorded in any commit on any ref or in the
reflog" (`_committed_checkpoint_seq`, max semantics).
- **A forged checkpoint cannot lower the bar.** Max semantics means a low forged value is ignored.
  A high or mismatched forged value only makes the chain fail closed (DoS, not bypass). This holds
  for A, A′ and E.
- **The real reopening risk in A is to G9/M5, not to M7.** A path-only exemption turns the
  checkpoint's path into an unscanned channel for committing data.
- **The residual risk is shared, not introduced.** `git reflog expire --expire=now --all && git gc
  --prune=now` defeats tree-file and trailer checkpoints alike, and the N7 git-object fallback too.
  It stays out of scope here. It is a single identifiable act that N10 blocks in the hook. Record it in
  `redteam/threat-model.md`.

### Required invariant
**I7′:** every dda-made commit (lock, amend, approve, signoff, the `ledger.py:954` path) carries one
`Dda-Chain-Head:` trailer per non-empty workdir chain, with values taken from the heads mirrors.
- `chain_checkpoints(root)` enumerates `git log --all` ∪ `git log -g` and parses trailers only.
  - The cap and max-seq semantics are unchanged.
- `.analysis/chain-heads.json` no longer exists.
- The G9 safety scan and the M5 allowlist gain **no** new exemption.
- `_only_added_file` returns to "exactly one `A` line and nothing else".

**I11 (composition rule, new):** any future SPEC item that adds a committed dda artifact must state:
- its §11 classification;
- its M5 allowlist entry;
- its effect on §4.5 approval-commit purity.

If it cannot, it is not specified.

### Acceptance tests
1. All 10 listed tests pass unchanged. No test edits are allowed for cluster 1.
2. `test_m7_trailer_present`: after lock, approve and signoff, each commit's trailers list every
   non-empty chain with seq = mirror seq.
3. `test_m7_no_tree_file`: `git ls-files` never lists `chain-heads.json`, and `dda gitcheck` exits 0
   on a clean fixture.
4. The existing M7/N8 probes still print their manifest tokens: n_prefix_g3 → G3-STILL-FAILING,
   n_prefix_evals → EVALS-STILL-BLOCKED, n_prefix_sticky → STICKY-HELD. The checkpoint must also
   be found via the reflog after `reset --hard`.
5. `test_m7_forged_trailer_cannot_lower`: a hand-made commit with a lower `Dda-Chain-Head` seq
   leaves the chain bar unchanged. One with a mismatched hash makes verify fail closed.
6. `test_approval_commit_purity_exact`: an approval commit that also modifies any other path, of
   any name, is rejected.
7. Revert sensitivity: add a scenario that turns trailer emission into a no-op. n_prefix_* must
   then flip.

**Classification: DESIGN FLAW** (a spec composition error between M7 and M5/§11/§4.5). A local
patch (option A) would leave the suite green but add an unscanned channel for committing data.

---

## Cluster 2: `test_mutation_git_stash_u` × 3 fixtures

### The working diagnosis is wrong
The claim was that "N10 blocks stash, so the mutation cannot run". That is not what happens:
- `mut_git_stash_u` (test_invariants.py:309-314) runs `git` through `subprocess` (`_git`, :286).
- The evidenceguard hook (`hooks._git_op_verdict`, hooks.py:273) only judges **agent tool calls**
  (`pre_tool_call`). Nothing in the harness path invokes it.
- Reproduced in a scratch fork: `stash rc 0 — Saved working directory and index state On master: inv`
  for all three fixtures.

### What actually fails (reproduced)
| Fixture | Failing assertion | Observed |
|---|---|---|
| TestInvEvalBinding | :380 approvals monotone | `signoff recovered stale->unverified`. Stash reverted tracked edits (spec.md, spec.lock, config.yaml, definitions) to committed bytes while 6 chains failed verify_all (runs.log, audit.log, ledger.md truncated, specs-tried, approvals.index, lineage). |
| TestInvGoldfishHistory | :373 sticky flag | `goldfish_mode` True → False. `lineage.jsonl` was stashed, and `verify_all` reports "file missing but heads mirror records seq 5". |
| TestInvStickyExposure | :313 target removed | `delete_target()` = `derived/snapshots` is **gitignored** (`.gitignore:2:derived/`), and `stash -u` does not touch ignored files: a harness bug. Underneath it, `results_seen_before_profile` also went True → False for the same `lineage.jsonl` reason. |

### Root cause
1. **Product (design): derived views are not verified views.**
   - `lineage.lineage()` (lineage.py:139) builds the sticky flags from `chain.read_records()`, which
     parses without verifying. A missing file yields `[]`, so the flags read False.
   - `approvals.verify_approval()` can report a passing state (`unverified`) while the chain set
     fails to verify.
   - The gates are safe because `gates8._preamble` (gates8.py:35) calls `verify_all` first. Every
     other consumer of these APIs (the harness snapshot, `review` round accounting through `events()`,
     footers and reports, any future caller) gets laundered values.
   - The N6 fix made **append** and **verify** fail closed. It did not touch **read**.
2. **Harness (local):** the StickyExposure stash mutation asserts on a gitignored target. That proves
   nothing about `stash -u`, whose attack surface is untracked, non-ignored chains.

### Bypass deliberately, or obsolete?
**Neither. Keep the mutation as is.** It already sits outside the hook by construction, and that is
the correct threat model:
- The hook is a cooperative-agent guard. N10 is labelled defense-in-depth in REREVIEW-2391db5.
- A human can run `git stash -u`, and so can another shell, an IDE git panel, or a variant script
  executed by `kernel.do_run` that calls `subprocess.run(["git","stash","-u"])`. None of those pass
  through `pre_tool_call`.
- The attack is therefore not impossible. Calling the mutation obsolete would delete the only
  coverage of the out-of-hook path.
- N10 keeps its own coverage in `n_hook_gitops.py`, which drives the hook directly.

A "test-only bypass path" is not needed and must not be added: the product must not grow a hook
switch.

### Required invariants
- **I12 (verified reads):** `lineage()`, `events()`-derived accounting, `verify_approval()`, and
  `stage8.match_evals()` either:
  - (a) run on a verified chain set, or
  - (b) return a poisoned result: `lineage()` raises `DdaError(EXIT_CHAIN)`, or returns
    `{"unverifiable": True}` with every sticky flag held **True**; `verify_approval()` returns state
    `chain_broken ∈ INVALID_STATES`.

  Pick one contract and apply it to all four APIs. The recommended contract is raising, which
  matches `evals.do_run` N9.
- **I12a:** sticky flags are monotone across any workdir operation: absence of evidence is never
  evidence of absence.
- **Harness:** each fixture's stash mutation must assert that at least one **untracked,
  non-ignored chain** was removed (e.g. `.analysis/lineage.jsonl`) instead of using `delete_target()`.
  Alternatively, add `stash_target()` with that contract. Do not switch to `stash -a`. That would
  make the test stash `derived/` and pass for the wrong reason.

### Acceptance tests
1. The three `test_mutation_git_stash_u` tests pass with the mutation still run through raw
   `subprocess` git. No hook involvement is allowed.
2. `test_lineage_fails_closed_on_missing_chain`: delete `lineage.jsonl` while its mirror is at seq > 0.
   Then `lineage()` either raises EXIT_CHAIN or holds every sticky flag True. Never False.
3. `test_approval_not_passing_on_broken_chains`: with any chain failing `verify_all`, no
   `verify_approval()` result is in PASSING_STATES.
4. Revert-sensitivity scenario "pre-I12 raw lineage read". Revert the guard in `lineage()`, and the
   new probe `n_gitstash_sticky.py` (manifest token STICKY-HELD) must flip.
5. `test_stash_target_is_untracked_chain`: a meta-test that the stash target of every fixture is
   neither tracked nor ignored.

**Classification:**
- Read-side fail-open: **DESIGN FLAW**. The verified-read contract was never specified.
- Gitignored stash target: **LOCAL PATCH** (harness).

---

## Cluster 3: TestProbeRevertSensitivity, `[pre-N7 no index fallback] n_gitreset_evals.py`

### Verified mechanism
Reproduced in a scratch clone: with `stage8.py:598` reverted to `for entry in []:`, `n_gitreset_evals.py`
prints `evals run after reset --hard rc: 4 … ledger.md: 1 lines but heads mirror records seq 3
(truncated)` and then `FINDING: EVALS-STILL-BLOCKED`. The control run `n_gitamend_evals.py` under the
same revert prints `EVALS-UNBOUND-VULNERABLE`, as it should.

- `reset --hard HEAD~1` also rolls the **tracked** `ledger.md` chain back to an older prefix.
- The N9 guard (`evals.do_run` → `verify_all`, evals.py:185) therefore exits 4 before matching runs.
- The probe's oracle is `rc != 0` (n_gitreset_evals.py:14), which counts the chain block as
  "EVALS-STILL-BLOCKED".
- The N7 fallback is never the deciding guard, so reverting it changes nothing.
- At 2391db5 this probe *was* N7-sensitive, because N9 did not exist yet (REREVIEW: "a_n1_git
  reset -> evals run rc: 1"). Landing N9 silently re-attributed the result.

### What makes a revert anchor genuinely sensitive
A revert anchor is only sensitive if the probe's outcome is attributable to exactly one guard. That
needs three things:
1. **Isolation.** The probe defeats every other layer a real attacker could also defeat, so the target
   guard is the last line. For reset, a real attacker also restores the tracked chain from the
   reflog (`git show <dropped>:.analysis/ledger.md > .analysis/ledger.md`). After that, `verify_all` is
   clean, and only N7's index fallback still binds the case. The probe must perform that step and
   assert `verify_all(wd) == []` as a **precondition** before `evals run`.
2. **Attributing oracle.** The FINDING token encodes *why* evals blocked: rc 1 **and** case `001` in
   `failed_bound` → EVALS-STILL-BLOCKED. rc 4 (EXIT_CHAIN) → EVALS-BLOCKED-BY-CHAIN, which is not the
   manifest token. Any nonzero exit is not a pass.
3. **Specific flip.** Under revert, `TestProbeRevertSensitivity` must see the probe's **VULN token**
   (`EVALS-UNBOUND-VULNERABLE`). "Anything except the expected token" is not enough. A probe that
   crashes under revert currently counts as sensitive, and that is the same false-pass shape in the
   other direction.

### Required invariant
**I13 (attribution):** for every scenario in `SCENARIOS`, each listed probe:
- prints its manifest token with all guards intact;
- prints its declared VULN token with only that scenario reverted;
- exits 0 in both cases.

The VULN token is recorded in MANIFEST.json as `{"expect": ..., "vuln": ...}`. That is an
intentional schema change to M8 and is reviewed as gate code. A probe that blocks through a
different guard's exit code fails I13.

### Acceptance tests
1. `n_gitreset_evals.py` (rewritten per Isolation + Attributing oracle) prints EVALS-STILL-BLOCKED
   at HEAD and EVALS-UNBOUND-VULNERABLE with N7 reverted.
2. `test_reverts_flip_probes` requires `findings == [f"FINDING: {manifest[name]['vuln']}"]` and
   `rc == 0` under revert.
3. Audit sweep: every other `n_*` probe gets the same three-part check. Any probe whose block can
   come from a guard other than the one its scenario reverts must gain an isolation step. Candidates
   to check first are n_gitrebase_evals and n_gitupdate_evals, which may also roll `ledger.md`
   depending on the fixture.

**Classification: TEST-DESIGN FLAW, fixed by local patches.** The product guard (N7) is not shown
broken. Its proof was invalidated. The fix needs probe edits and a harness rule, not product code.

---

## Earlier findings that were wrongly closed

| Finding | Status in REREVIEW-2391db5 | Correct status after this analysis |
|---|---|---|
| **N6** (clean/stash deletes untracked chains) | "missing/empty: CLOSED" (evidence: verify-chain 4, gates `PPffffffff`) | **Over-closed.** Only the gates and verify were checked. After a stash, `lineage()` drops sticky flags and `verify_approval()` reports passing states. The harness ran no git mutations until b8d8a3c (the 2391db5 `MUTATIONS` list held only the 9 cosmetic classes), so invariants 2 and 3 were never exercised against N6. Reopen as N6-read under I12. |
| **N7, reset sub-case** | "CLOSED for reset/…" | **Closure valid at 2391db5; evidence now void.** N9 masks it. Status: unproven until I13 test 1 passes. Not known broken. |
| **M7** | Implemented and committed in b8d8a3c with commit message "verified probes" | **Not closed.** It ships a G9 regression (10 failures) and a §4.5 purity exception. Re-close only under I7′. |
| **N10** | Defense-in-depth (correctly labelled) | Not wrongly closed. Cluster 2's framing over-read it as making stash impossible. It does not, and must not be relied on as a primary control. |
| **N2 / G7-2** (sticky) | Closed for call-file deletion | The same read-side fail-open applies under stash. Re-verify under I12 acceptance test 4. |

## Implementation order
1. I12 (verified reads). It changes what every harness snapshot sees, so land it first and re-run the
   suite.
2. I7′ (trailer checkpoints), plus removal of the `_only_added_file` exception.
3. I13 (probe attribution) and the MANIFEST `vuln` schema, then the per-probe isolation edits.
4. Harness stash target fix.
5. Full suite: 359+ tests, 0 failures, and `TestProbeRevertSensitivity` green with the stricter flip
   check, before any finding is marked closed.
