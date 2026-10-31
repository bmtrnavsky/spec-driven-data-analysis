# Correction case NNN — drafted by the `correct` skill, bound by approval

Fill every section. Trigger keys name locked source aliases, definition
names, and pattern tags from the closed vocabulary in
`skills/correct/SKILL.md` (e.g. `join`, `timezone`, `denominator`).
Matching is mechanical (`dda evals match`): every binding case whose
trigger keys intersect the spec's aliases, pins, and declared pattern
tags is selected, and the agent cannot drop a matched case.

# TITLE

One sentence: what analysis this correction came from.

## Trigger keys

Trigger keys: alias-or-definition, pattern-tag

Comma- or semicolon-separated. At least one key is required.

## What the agent did

What the agent did, step by step.

## What was wrong

What was wrong and why it mattered for the decision.

## Correct behavior

The correct behavior, so the next analysis gets it right the first time.

## Deterministic check

Optional, but a case without either a check or a review question is a
draft, not an eval. Exactly one of the two blocks below; delete the
other. Paths are confined to `outputs/` and `derived/` — anything else
is refused.

file: outputs/summary.csv
sha256: <64 lowercase hex digits of the expected file>

## Review question

Optional. One question for the goldfish, appended to the round list of
every matched packet (§5.1). Not counted as a deterministic test.

Review question: <one question>

## Source correction

Source correction: <date (UTC), who reported it>
