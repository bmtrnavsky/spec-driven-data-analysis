# Hostile re-review @ 2391db5 (read-only). Reviewer: claude-opus-5-5
Attack scripts: ../rr-2391/atk/. Raw outputs: ../rr-2391/out/ (old-probe retests in out/old/).

VERDICT: NOT CLEAN. N6 is only half-fixed. Restoring a NON-EMPTY older prefix of the untracked chains
(`git stash push -u` then `git stash apply stash@{1}`, both hook-ALLOWed) launders three gates, and in
each case `verify-chain` reports `chains: ok` (N8, HIGH, proven 3/3 with controls). The harness is
better than at d135783 and does catch reverts of N6 and N7. But its expected outcome is
self-referential, its pass predicate is a substring match, the filter-branch probe passes through an
escape token whose premise is false, and it has no probe for N8. Fix spec: SPEC-2391db5.md.

## Positive results (verified)
- TestDdaprobeRegression at HEAD: 2/2 OK, 13 probes. Each one prints its declared finding (out/probes_head.txt).
- The harness catches an N7 revert. In a scratch clone with stage8.py and approvals.py checked out from
  d135783, n_gitreset, n_gitupdate, n_gitamend, and n_gitrebase all print `EVALS-UNBOUND-VULNERABLE`, so the suite would fail.
- Negative probes block for the RIGHT reason (a_reason.py). After reset, update-ref, amend, or rebase,
  case `161eb5785d3d2bc9` is still bound via the "correction approval recorded in approvals.index.jsonl"
  path, and `evals run` rc=1 "bound correction eval(s) failed". n_rm_reviews/n_gitclean_g3:
  "latest call stub-0003 is fail".
- Real `git filter-branch` works on this host through Git-for-Windows bash (`C:/Program Files/Git/bin/bash.exe`).
  a_filterbranch.py on a real fixture: rewrite rc 0, `evals run` rc 1, EVALS-STILL-BLOCKED. N7 holds for filter-branch.

## Findings retest
| ID | Verdict | Raw (HEAD) |
|---|---|---|
| G8-1 | CLOSED | p_g8b: `G8 fail: PUBLISH needs a verified human sign-off ... no committed signoff approval covers 550875ad...` |
| G9-1 | STILL OPEN | n_g9: outputs/orders.txt/.yaml, reports/appendix.md, derived/rows.log, .analysis/notes/b64.txt -> gitcheck=pass allowlist=pass |
| G9-2 | STILL OPEN | `.analysis/packets/zz/orders.csv`, `.analysis/reviews/goldfish/rows.txt`: pass/pass |
| G9-3 | STILL OPEN | `outputs/e.dat PAR1` pass; `outputs/c.py split AKIA` pass |
| G0-1 | STILL OPEN (deferred) | p_g0: U+2753, bullet list, and-joined, abbrev smuggle, decision N/A/TBD/none -> PASS |
| G1 prose | ACCEPTED (claim downgrade) | p_g1: every arm PASS (BLOCK=0) |
| G1 Metrics | PARTIAL | `metrics U+2215`, `metrics U+2254`, `metrics frac` -> PASS |
| G3-1 | PARTIAL | p_g3 amend shopping -> `G3 fail` (closed); reopened by N8 (a_prefix_g3 -> G3 pass) |
| G3-2 | CLOSED | p_g3 degrade -> `G3 fail` |
| G2-1 | PARTIAL | p_g2: only `'patients'` BLOCKs; n_g2 "Topics none + ICU mortality" -> PASS at EXPLORE |
| G2-2 | STILL OPEN | n_g2b: "Topics: none + 'health' only in Population" -> PASS |
| G2-3 | CLOSED | p_g2b: all 9 audiences BLOCK |
| G2-4 | PARTIAL | Destination wordpress BLOCKs; `Destination blank` -> PASS |
| G7-1 | CLOSED | p_g7 control/other_variant/amend: `DdaError: no profile for the current lock` (still no positive control in p_g7; p_g7_ok now covers it) |
| G7-2 | PARTIAL | amend path closed; sticky flag erasable via N8 (a_prefix_sticky: True -> False, verify-chain ok) |
| EV-1 | PARTIAL | p_ev: trigger tamper rc 1, delete check rc 1; binding droppable via N8 (a_prefix_evals) |
| EV-2 | STILL OPEN (harmless for edits) | p_hook: `ALLOW write case.md`; `BLOCK terminal sed case.md` |
| EV-3 | PARTIAL | n_ev3_tags: empty or `join: no` Pattern tags -> matched=[] evals_run_rc=0, G1 pass |
| N1 | CLOSED | n_ev_rmdir: rm evals/corrections -> rc 1, `001 bound`; n_rm_corrections_evals EVALS-STILL-BLOCKED |
| N2 | CLOSED for call-file deletion; BYPASSED by N8 | n_g3_clean: re-run refused "round 1 already ran twice in this lineage", G3 fail |
| N3 | STILL OPEN | same as G9-1 |
| N4 | STILL OPEN | n_hook2: `ALLOW write_file via real junction outputs/j/ledger.md`, `.../approvals.index.jsonl` |
| N5 | STILL OPEN | no change (diff touches approvals.py, chain.py, stage8.py, tests only) |
| N6 | PARTIAL | missing/empty: CLOSED (a_n2_launder clean/stash -> `verify-chain 4`, gates PPffffffff; a_sticky_clean -> chains FAILED). Non-empty prefix: OPEN (N8) |
| N7 | CLOSED for reset/rebase/amend/update-ref/filter-branch; BYPASSED by N8 | a_n1_git reset/rebase -> `evals run rc: 1`; the index it relies on is an untracked chain |

## New bypasses
- **N8 HIGH (DESIGN): chain prefix-restore laundering.** `chain._append_locked` (chain.py:203-237) fails
  closed only when the file is missing or empty. A shorter but intact prefix is accepted. The appender
  sets `seq = last+1` and then overwrites the heads mirror unconditionally, so `verify()`'s
  "N lines but heads mirror records seq M (truncated)" check is erased by the next honest append.
  Only hook-allowed ops are needed (a_hook.py: `ALLOW git stash -u && git stash apply`,
  `ALLOW git stash push -u -m T1`, `ALLOW git stash apply stash@{1}`). Proofs, each with a control
  that runs the same flow without the stash ops:
  - a_prefix_g3.py: 2 failed goldfish rounds. Restore the post-round-1 prefix, then one pass re-run and answer files.
    `verify-chain rc 0 chains: ok`, `G3 pass` -> RESULT G3-LAUNDERED-VULNERABLE. Control: `G3 fail ... latest call stub-0003 is fail`.
  - a_prefix_evals.py: bound failing case, then reset --hard plus restore of the index prefix that predates the
    correction record, then `dda approved spec`. `verify-chain rc 0`, `matched: []`,
    `evals run rc: 0 no correction evals matched` -> EVALS-UNBOUND-VULNERABLE. Control: rc 1, chains FLAGGED.
  - a_prefix_sticky.py: run before re-profile, so sticky True. Restore the pre-run lineage prefix, then `dda profile`.
    `verify-chain rc 0`, `sticky after: False` -> STICKY-ERASED-VULNERABLE. Control: sticky True.
  - Untested aggravator: redirecting `DDA_HOME` per command would also hide a missing or short mirror (heads None skips the N6 check).
- **N9 MED (local): `dda evals run` does not fail closed on chain failure.** a_clean_reset_evals.py:
  `git clean -fdx -- .analysis` (run directly) then `reset --hard HEAD~1` gives `evals run rc: 0` "001 [unbound]: fail ...
  unbound (draft)", while `verify-chain rc 4`. Gates still fail through the G2 cascade; the CLI verdict is wrong.
- **N10 MED (local, defense-in-depth): evidenceguard git coverage is a pathspec string match.** a_hook.py:
  `BLOCK git clean -fdx -- .analysis`, but `ALLOW git clean -fdx` (no pathspec), `ALLOW git clean -fdx -- .`,
  and ALLOW for stash -u/apply/pop, reset --hard, rebase, commit --amend, and update-ref. The d135783 "block or flag
  git clean/stash/reset" fix item was only partly done.

## Harness attack (tests/test_invariants.py:455-504, tests/probes/)
Synthetic probes run through the harness's own `_expected()` and its exact pass predicate (a_harness.py):
| Case | Result |
|---|---|
| A: edit the probe's EXPECTED to the vulnerable token | GREEN |
| B: docstring line `EXPECTED = "…VULNERABLE"` above the real one (first `^EXPECTED` match wins) | GREEN, expected=('EVALS-UNBOUND-VULNERABLE',) |
| C: probe prints both the VULNERABLE and the SAFE finding | GREEN |
| D: finding echoed mid-line in other output, then a VULNERABLE line | GREEN |
| E: prefix collision, `EVALS-OK` vs printed `EVALS-OK-BUT-UNBOUND` | GREEN |
| F: `print(FINDING); sys.exit(0)` before the attack | GREEN |
| G: tuple EXPECTED with an always-reachable escape token | GREEN |
| J: `EXPECTED = ""` | GREEN (matches any FINDING) |
| H/I: re-declaration inside a function / trailing comment | correctly ignored / handled (not a hole) |
- **H6 HIGH: the expected outcome is self-referential.** The ground truth is the file under test. Editing one
  line (A), or adding a docstring or comment line at column 0 above it (B), flips the expectation and the suite stays green. There is no external manifest.
- **H7 HIGH: the pass predicate is `f"FINDING: {e}" in stdout`.** That is a substring match anywhere. Nothing
  requires exactly one FINDING line, nothing fails on a VULNERABLE token, and prefix collisions pass (C, D, E). There is no actual collision among
  the 13 current tokens; this is latent.
- **H8 MED: probe completeness is not enforced (F).** Nothing proves the attack ran before the finding printed.
- **H9 HIGH: n_filterbranch_evals's escape token rests on a false premise.** `EXPECTED = ("EVALS-STILL-BLOCKED",
  "FILTER-BRANCH-TOOLCHAIN-BROKEN")`. The self-test uses PATH `git` = `/mingw64/bin/git` (MSYS2). Git-for-Windows
  bash runs filter-branch fine (rr-2391/fb: "Ref 'refs/heads/master' was rewritten"). The suite therefore always takes the
  escape path, the real attack never runs, and any future filter-branch regression would stay green permanently.
- **H10 MED: `>= 13` pins a count, not identities.** Deleting n_gitclean_g3.py and adding a trivial p_x.py
  stays green. Renaming a probe away from `p_*`/`n_*` silently drops it. The floor went from 15 to 13 in this commit.
- **H11 MED: claim (c) is false.** `MUTATIONS` (test_invariants.py:57) still holds the 9 in-process mutations.
  Only the module docstring lists git_clean/git_stash_u/..., so the fixture-by-mutation monotonic matrix has no git op.
- **H12 HIGH: the probes were written to the fix.** n_gitclean_chain and n_gitstash_chain test only "file missing", which is exactly
  the case the N6 patch handles. No probe covers a non-empty prefix (N8). n_gitclean_chain also uses
  `git clean -- .analysis`, which the hook BLOCKS, while the hook-allowed stash-apply route is untested.
- H3 (masked monotonicity) and H5 (snapshot swallows exceptions): no fixture change in this diff, so STILL OPEN.
  H5 is partly mitigated: `evals_ok` is now asserted in TestInvEvalBinding.check_delete_caught.

## Positive probes
Genuine, not trivial. Each runs the honest flow through the CLI and asserts the gate rc == 0, so an
"always fail" regression would be caught. Weaknesses:
- p_g7_ok is EXPLORE tier, and its self re-reads are "No objection" text (gates check only presence).
- p_g3_pass is a single pass-stub with no prior history.
- None shares a fixture with its negative twin, so a negative could block for an unrelated reason. a_reason.py
  confirmed that is not happening today, but nothing in the harness asserts the reason.

## Process
- No repo files modified. The N7-revert check used a throwaway clone (rr-2391/clone).
- Full 337+ suite not re-run; only TestDdaprobeRegression and targeted attacks.
