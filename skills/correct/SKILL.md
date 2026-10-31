# correct

Capture a human correction as a binding eval, then prove it replays.
Matching is mechanical — the agent cannot drop a matched case.

## When to use

A human corrected an analysis (wrong join grain, misread definition,
timezone error, wrong denominator, or anything else where the agent's
reasoning failed and a person had to fix it). Run this skill before the
next lock, so the correction binds to future specs instead of living in
chat history.

## Procedure

1. **Draft the case.** Run `dda evals new` with the correction:
   - `--title`: one sentence naming the analysis and the mistake.
   - `--triggers`: source aliases, definition names, and pattern tags
     from the closed vocabulary below (comma-separated, at least one).
   - `--what-wrong` / `--correct-behavior`: what failed and the right
     behavior. `--what-happened` for the step-by-step if it matters.
   - A deterministic check (`--check-file` under `outputs/` or
     `derived/` plus `--check-sha256`) and/or `--review-question` for
     the goldfish. At least one of the two makes it an eval; a case
     with neither stays a draft.
   - `--source`: date (UTC) and who reported the correction.
2. **Check the match.** Run `dda evals match`. Every binding case whose
   trigger keys intersect the spec's aliases, pins, and declared
   pattern tags is listed. If this correction does not match the spec
   it was written for, fix the trigger keys — never hand-filter the
   match list.
3. **Bind it.** Commit a signed `correction` approval for the case
   directory (`dda approve correction NNN`, then `dda approved
   correction NNN`). A case becomes binding only with a verified
   `correction` approval (§4.5). Below PUBLISH an unverified approval
   still binds (the G3 rule); at PUBLISH only a verified one does.
4. **Run the checks.** Run `dda evals run` (the same checks `dda
   verify` runs). A bound case with a failing check is stop-and-ask
   case 5 at DECIDE+: stop and park, do not re-lock around it. At
   EXPLORE, record the failure in the report and proceed once the fix
   or an amendment is locked.
5. **Verify end to end.** Re-run `dda verify`, then the gate. A changed
   case file or a changed match since verify fails G7 — re-verify.

## Closed pattern-tag vocabulary

`join`, `grain`, `denominator`, `timezone`, `window`, `filter`,
`definition`, `metric`, `label`, `cohort`, `population`,
`time-window`, `threshold`, `exclusion`, `outlier`, `nulls`,
`duplicates`, `rounding`, `currency`, `sampling`, `attribution`,
`seasonality`, `survivorship`, `confounder`, `simpson`,
`base-rate`, `selection-bias`, `leakage`, `bias`,
`multiple-comparisons`, `hypothesis`.

Trigger keys that name a locked alias, pin, or definition do not need
to be in this list. A tag outside both the vocabulary and the
spec is refused by `dda evals new` — declare the spec's own tags under
`## Pattern tags` first.

## Key rule

Matching is mechanical (`dda evals match` selects every intersecting
binding case). Review questions flow to the goldfish packet (§5.1) and
are never counted as deterministic tests. Only deterministic checks
form the plugin's own regression suite, so the suite stays
reproducible.
