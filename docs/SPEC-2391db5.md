# DDA @ 2391db5: fix spec (follows DESIGN-FIX-SPEC.md shape)

Author: claude-opus-5-5 · Basis: REREVIEW-2391db5.md (attack scripts ../rr-2391/atk/, outputs ../rr-2391/out/).
Read-only review. No repo or gate-layer edits were made.

## 0. Diagnosis

Two root causes account for every new finding:

| # | Root cause | Findings |
|---|---|---|
| R6 | **Trust-on-append.** The untracked evidence chains (runs.log, lineage.jsonl, approvals.index.jsonl) have one anchor: the heads mirror. Their own appender advances that mirror without first checking that the file still ends at the anchored head. The N6 patch special-cased "file missing/empty", which is one symptom of R6. A restored shorter prefix is the general case. N7's fix moved binding into approvals.index.jsonl, so it inherits R6. | N8 (G3, evals, sticky), N6-partial, N7-partial, G3-1/G7-2/EV-1 reopened |
| R7 | **The harness's oracle is the thing under test.** The expected outcome is parsed from the probe file. The pass check is a substring search. The probe set is a count, not a list. An escape token allows "pass without running". So the harness verifies that probes agree with themselves, not with ground truth. | H6, H7, H8, H9, H10, H12 (and H11 doc/claim drift) |

Local issues (not root causes): N9 (evals CLI ignores chain status) and N10 (hook git-op parsing).

Threat-model note, as in DESIGN-FIX-SPEC §0. N8 needs only `git stash` plus `git stash apply stash@{n}`,
which a cooperative agent uses routinely ("let me stash, try something, restore"). It is reachable
by the convenient path, so it is a **DESIGN** flaw and must be impossible by construction.

---

## 1. Finding-by-finding classification

| ID | Sev | Class | Root | Fix mechanism |
|---|---|---|---|---|
| N8 | HIGH | **DESIGN** | R6 | M6 anchored append (compare-and-swap on head) + M7 git-committed checkpoints |
| N6 | HIGH | **DESIGN** (residual of N8) | R6 | Subsumed by M6; remove the special case |
| N7 | HIGH | **DESIGN** (dependency) | R6 | Keep the index fallback; it becomes sound once M6/M7 hold |
| N9 | MED | local | — | `evals run` (and every gate-adjacent CLI verdict) fails closed when `ledger.verify_all` reports problems |
| N10 | MED | local (defense-in-depth) | R5 | evidenceguard parses git subcommands, not pathspec strings |
| H6 | HIGH | **DESIGN** (harness) | R7 | M8 external manifest |
| H7 | HIGH | **DESIGN** (harness) | R7 | M8 exact-line, exactly-one, closed-vocabulary check |
| H8 | MED | **DESIGN** (harness) | R7 | M9 mutation-kill validation for every negative probe |
| H9 | HIGH | local | R7 | Drop the escape token; run filter-branch via Git-for-Windows bash; otherwise `skipTest`, never pass |
| H10 | MED | local | R7 | Probe set == manifest keys (equality, not `>=`) |
| H11 | MED | local | — | Add git ops to `MUTATIONS` or correct the docstring/commit claim. Recommended: add them |
| H12 | HIGH | local | R7 | Add N8 probes (three prefix-restore probes) and a hook-routed git-op probe |
| G3-1, G7-2, EV-1, N2 | — | reopened by N8 | R6 | Re-close via M6/M7; no separate work |
| G9-1/2/3, G0-1, G1-Metrics, G2-1/2/4, EV-2, EV-3, N3, N4, N5 | — | carried | R4/R5 | Unchanged; see DESIGN-FIX-SPEC §2 (M4, M5). Not re-specified here |

---

## 2. Mechanisms

### M6. Anchored append: the appender never advances a head it cannot extend (fixes N8, N6; secures N7)
Root cause in code: chain.py `_append_locked` (lines ~203-237). It reads the last line, sets `seq = last+1`,
writes, then `_write_json_atomic(heads_path, {seq, hash})` with no comparison to the old mirror.

Required invariant **I6**: an append to chain C succeeds only if, before writing,
`len(lines(C)) == mirror.seq` and `line_hash(lines(C)[mirror.seq-1]) == mirror.hash`. If there is no mirror,
C must be empty AND the workdir must have no other evidence of prior appends (see M7). Otherwise raise
`DdaError` (§3.2 case 8). The mirror update is a compare-and-swap: new.seq == old.seq+1 and new.prev == old.hash.
- This replaces the N6 special case: missing, empty, shorter, forked, and longer all fail the same check.
- `verify()` and append use the same function, so "verify says truncated" can never be followed by
  "append silently accepts".
- The mirror path must be derived from a value the agent cannot redirect per command. Record the
  resolved DDA_HOME (or a workdir-id → mirror-path binding) in the lock record. On every append and
  verify, refuse when the current DDA_HOME differs from the recorded one.

### M7. Git-committed chain checkpoints (fixes N8 even if the mirror is lost or reset)
Required invariant **I7**: every dda-made commit (lock, amend, approve, signoff) includes
`.analysis/chain-heads.json` = {chain: {seq, hash}} for every chain at that moment. G2's chain check
requires, for the newest checkpoint reachable from HEAD *and* the newest one in reflog/`approvals.index`:
`lines(C)[seq-1]` hashes to the checkpointed value. A restored prefix shorter than any checkpoint fails.
That covers the a_prefix_g3 and a_prefix_evals shapes: an approval commit always lands after the failed
round or the correction record. Design note: this is the "anchor in a store the agent cannot cheaply roll back" principle (DESIGN-FIX-SPEC M1/M2) applied to the chains themselves.

### M8. External oracle for probes (fixes H6, H7, H10)
Required invariant **I8**: the expected outcome of probe P is defined outside P.
- `tests/probes/MANIFEST.json`: `{"n_gitclean_g3.py": "G3-STILL-FAILING", ...}`. Exactly one token per probe; no tuples.
  The manifest change must be reviewed like gate code (CODEOWNERS or a signed approval, kind `probe-manifest`).
- `set(glob("tests/probes/*.py")) - {"probelib.py"} == set(MANIFEST)`. Equality: any unlisted or missing file fails.
- Parse stdout lines with `^FINDING: ([A-Z0-9-]+)$`. Require exactly one such line, require it to be the last
  non-empty stdout line, and require it to equal the manifest token. Any line containing `VULNERABLE` fails, whatever the token.
- Token vocabulary is closed (`SAFE_TOKENS`, `VULN_TOKENS` in the harness), and no token may be a prefix of another
  (assert at collection time).

### M9. Mutation-kill validation (fixes H8, and makes M8 trustworthy)
Required invariant **I9**: every negative probe is proven able to fail. For each `n_*` probe the manifest names
a *revert* (a patch or `git checkout <sha> -- <files>` spec under `tests/probes/reverts/`). A slow test
(`DDA_SLOW=1`, run before every handoff) clones the repo to scratch, applies the revert, runs the probe, and
requires its VULNERABLE token. A probe that short-circuits (`print; exit`) cannot pass this. Precedent: the orchestrator's manual N6 revert, and this review's N7 revert (rr-2391/clone: all four evals probes → `EVALS-UNBOUND-VULNERABLE`).

---

## 3. Acceptance tests (each must FAIL at 2391db5 and PASS after the fix)

| AT | Covers | Test |
|---|---|---|
| AT-1 | N8/G3 | Port a_prefix_g3.py to `tests/probes/n_prefix_g3.py`: fail round 1, approve, `git stash push -u` + `stash apply`, fail round 2, `stash push -u` + `stash apply stash@{1}`, pass re-run + answers. Expect G3 fail OR any append raises, and `verify-chain` != 0. Today: `G3 pass`, `chains: ok` |
| AT-2 | N8/evals, N7 | Port a_prefix_evals.py → `n_prefix_evals.py`. Expect `evals run` rc 1 (case bound) or a refused append. Today: `matched: []`, rc 0, `chains: ok` |
| AT-3 | N8/G7-2 | Port a_prefix_sticky.py → `n_prefix_sticky.py`. Expect sticky True or `dda profile` refused. Today: sticky False, `chains: ok` |
| AT-4 | M6 unit | In-process: append 3, copy file, append 2, restore copy, append → `DdaError`; same for a forked line, an appended-outside line, and a mismatched DDA_HOME |
| AT-5 | M7 | Prefix restore below the last approval commit with the mirror deleted (fresh DDA_HOME) → G2 fails with "below committed checkpoint" |
| AT-6 | N9 | `git clean -fdx -- .analysis` + `reset --hard HEAD~1` → `dda evals run` rc != 0 with the chain problem in the output. Today rc 0 |
| AT-7 | N10 | Hook verdicts in a bound session: BLOCK for `git clean -fdx`, `git clean -fdx -- .`, `git stash -u`, `git stash apply/pop`, `git reset --hard`, `git checkout <rev> -- .analysis`. Rewrite ops (rebase, amend, update-ref, filter-branch) at least WARN plus a lineage event |
| AT-8 | H6/H7 | Harness self-test: the synthetic probes A-G and J from a_harness.py are each reported RED |
| AT-9 | H9 | n_filterbranch has one expected token, `EVALS-STILL-BLOCKED`, and runs via Git-for-Windows bash (or `skipTest` with the reason). a_filterbranch.py shows it passes today when it actually runs |
| AT-10 | H10 | Deleting any probe, or adding an unlisted one, fails collection |
| AT-11 | H8/M9 | Revert-kill: for each n_* probe, its revert makes it print its VULN token (N6: chain.py@d135783; N7: stage8.py+approvals.py@d135783; N8: the pre-M6 chain.py) |
| AT-12 | H11 | `MUTATIONS` contains git_stash_u, git_stash_apply_prefix, git_reset_hard, git_rebase, git_commit_amend, git_update_ref; each runs against all three fixtures through `run_mutation` |

---

## 4. Design flaws vs local patches
- **Design (must be by construction):** M6 (I6) and M7 (I7) for R6; M8 (I8) and M9 (I9) for R7.
  Without M6/M7, every "history lives in an untracked chain" fix (N2, N7, G7-2 sticky, G3 cap) can be
  undone with `git stash`. Without M8/M9, a green harness proves only that the probes agree with themselves.
- **Local:** N9, N10, H9, H10, H11, H12. Small edits, but H12 (AT-1..3) must land first. AT-1..3 are the
  regression oracle for M6/M7.
- **Order:** AT-1..3 (fail at HEAD) → M8 manifest + exact-line check → M6 → M7 → N9/N10 → M9 slow revert test → H9/H11.

## 5. Out of scope / carried
G9-1/2/3, N3 (M5 commit allowlist), G0-1, G1 metrics, G2-1/2/4 (M4 structured declarations),
EV-2, EV-3, N4 (realpath on write targets), N5 (lineage id in spec/tier digest; signoff breadth): per DESIGN-FIX-SPEC §2/§5.
