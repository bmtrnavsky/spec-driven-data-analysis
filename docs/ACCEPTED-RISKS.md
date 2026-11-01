# Accepted Risks — status as of 2026-11-01

This document records what is **open, known, and deliberately not fixed** in DDA, so that
nobody later mistakes an accepted risk for an untested one. It is dated because the
acceptance decision belongs to a moment: if you are reading this a year from now, re-check
it rather than assuming it still holds.

**Acceptance criterion in force:** the pipeline must *enforce the process* and be
*difficult to break*, not impossible. It is not a cage and does not claim to be one.
Bypasses that require deliberate, informed, adversarial effort against the evidence store
are accepted, provided they are countable and attributable.

---

## What is enforced today (verified, with raw proof)

These are the behaviors the pipeline exists to guarantee. All were reproduced with a
control showing the gate blocks when it should:

- The agent cannot skip a tier unnoticed.
- The agent cannot self-authorize a **DECIDE → EXPLORE** step-down — the cheat that skips
  both the reviewer and the human.
- An approval cannot be reused after the content underneath it changed; it reports
  **STALE**.
- Evals cannot be reported as passing when the bound case failed.
- Failing review rounds cannot be quietly re-run until they look green.
- The lineage log is readable and inspectable by the human.

The full suite is **369 tests, OK**. The premise validator proves that each probe actually
depends on the fix it claims to test, and fails loudly (`STALE-PREMISE`) when code changes
under a recorded anchor.

---

## Closed with proof (2026-10-31 → 2026-11-01)

For the record, so these are not re-opened by mistake:

| ID | Hole | Proof |
|---|---|---|
| N1 | Deleting `evals/corrections/` dropped bound cases | `rc=1`, bound case survives |
| N2 | Deleting review records reset the re-run cap and laundered failed rounds | re-run refused from lineage history |
| N6 | A missing chain file let the chain restart from zero and overwrite its own mirror | append fails closed |
| N7 | History rewrite could unbind a correction case | binding survives reset/rebase/amend/update-ref |
| N8/M7 | Restoring an older prefix **plus its mirror** sailed through | `ROLLBACK-DETECTED` vs `ROLLBACK-LAUNDERED-VULNERABLE` pre-fix |
| N9 | `dda evals run` reported success while chains failed to verify | verify consulted first |
| N10 | Hook matched path text, not the git operation | `_git_op_verdict` judges the operation |
| NEW-5 | Reverts edited live product code in place; a killed run left it stripped | temp copy + OS lock + startup self-check repairs it |
| NEW-6 | Premise hashes pinned raw bytes, so records only validated on a CRLF checkout | LF/CRLF hash identically; validates on a clean clone |

---

## Open, accepted (not fixed)

Everything below requires deliberate adversarial effort. None of it is reachable by an
agent that is simply trying to do the work and cutting corners — which is the actual
threat model.

### Integrity hardening (checkpoint floor)

| ID | Sev | What an adversary can do | Why accepted for now |
|---|---|---|---|
| NEW-1 | HIGH | Trailers are written only on `dda`'s own commits, so failed rounds landing *after* the last commit are not pinned. Two failed rounds can be rolled back and G3 flips fail→pass with `verify` clean. | Needs an agent that understands the commit-trailer scheme and times its rollback after the last `dda approve`. |
| NEW-2 | HIGH | The checkpoint scan stops after 200 commits, so ~201 `git commit --allow-empty` calls walk the floor out of range. `git reflog expire` + `git gc --prune=now` also clears it. | Requires hundreds of deliberate commits into your own repo, or a reflog wipe. Extremely visible in the log. |
| NEW-3 | MED | The checkpoint cache is trusted without verification; an empty cache entry makes G3 pass. | Writes are blocked directly; reachable only through NEW-4. |

### Write-target confinement

| ID | Sev | What an adversary can do | Why accepted for now |
|---|---|---|---|
| NEW-4 | HIGH | Write targets are canonicalized lexically, not with realpath, and link creation is not blocked. A junction to `.analysis` or `DDA_HOME` lets an agent write the ledger, approvals index, heads mirror, and checkpoint cache. | Building a directory junction (or `mklink /J`) is a deliberate act with no innocent explanation. |

### Gate scope and coverage

| ID | Sev | What an adversary can do | Why accepted for now |
|---|---|---|---|
| G9-1 / N3 | MED | G9 skips checks on any agent-writable path, so "allowed to write" is treated as "allowed to commit". Data rows committed as `outputs/*.txt`, `derived/*.log`, `evals/*.html` pass. | These are visible artifacts in your own repo, committed deliberately. |
| G9-2 | MED | The `packets/[^/]+/.+` exemption lets `.analysis/packets/zz/orders.csv` pass. | Narrow, and the file is still visible. |
| N5 | MED | The signoff digest covers `answer.md` and `reports/**/*.md` only, so an edit to `outputs/headline.csv` or `reports/deck.html` does not invalidate signoff. | Matters only if a downstream consumer trusts signoff as full-artifact coverage; do not rely on it for that today. |
| G2-2 | MED | The sensitive-topic scan covers only 3 spec sections, so health terms in Population/Method/Hypotheses pass at EXPLORE. | The human reads the spec at tier approval. |
| EV-3 | MED | A spec with an empty `## Pattern tags` section, or `join: no`, yields `matched=[]` and `run_ok=True`. | No bound case is silently dropped today; the gap is in surfacing declines. |
| NEW-7 | MED | The premise hash covers the anchored function but not the helpers it calls, so helper drift does not invalidate a record. | Affects harness confidence, not product behavior. |
| G0-1 | LOW | Placeholder and list-markup Decisions pass; U+2753 not in the terminator set. | Hygiene gate; human reviews the spec. |
| G1 prose | LOW | Free text after a Metrics pin (`∕`, `≔`, `\frac`) is accepted as a warning, not a failure. | Documented downgrade; the pin itself is still required. |

---

## Accepted by design (documented, will not be fixed)

- **G0-1 compound questions** ("and"-joined, `vs.`-smuggled) — not mechanically decidable.
  Covered by human tier approval.
- **G9-3 split secrets in source code** — detecting these needs execution; defer to platform
  secret scanning.
- **EV-2** — writes to `evals/corrections/**` cannot change binding, because bound cases are
  read from the committed approval payload. The spec wording was corrected instead: edits
  there are drafts until re-approved.
- **NEW-8 oracle soundness** — probes are authored by the same trusted party as the fix.
  A lint is the right level, not a data-flow analyser.
- **NEW-9 forged trailers** — an unauthenticated trailer can permanently wedge a workdir.
  Fail-closed only; a human-only recovery command is the remedy.

---

## If work resumes — order of attack

1. **NEW-7** — widen certification scope (helper kind), so the M7 work below is actually certified.
2. **NEW-1, NEW-2, NEW-3** together — the checkpoint floor redesign: pin store, uncapped scan, no cache. M7 stays open until all three probes are green and certified.
3. **N4** — realpath plus link-creation block. Without it, the agent can still roll back mirrors.
4. **NEW-4** — default-deny git.
5. **G9-1/N3, G9-2, N5, EV-3, G2-2** — product gates.
6. **G9-3 magic sniff, G0-1 placeholders, NEW-8 record checks.** EV-2 and NEW-9: documentation only.

Full detail, per-finding root cause, required invariant, acceptance test, and the exact
reproduction for each is in [`SPEC-34478d1.md`](SPEC-34478d1.md), with the hostile review at
that commit.

---

## Honest summary

The gates enforce the process, and that holds. What remains open is a set of ways for a
*determined adversary with write access to the evidence store* to defeat the audit trail.
That adversary is not the agent doing your analysis. Every one of the items above is
documented, dated, reproducible, and — where it matters — covered by a probe that will go
red the moment someone closes it and breaks something else.
