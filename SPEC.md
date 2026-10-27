---
name: disciplined-data-analysis
status: spec draft (no code yet)
version: 0.1.0-spec
date: 2026-10-27
sibling: C:\Users\bmtrn\disciplined-vibe-coding (v0.2.0)
sources: Turing pipeline structure (disciplined-vibe-coding), Elephant-Goldfish Model (Google, Apache 2.0), ponytail economy (DietrichGebert/ponytail, MIT), gap survey deleg_6fc04e39
---

# Disciplined Data Analysis — plugin spec

Question → locked spec → data → answer, with every fork disclosed.
The sibling plugin keeps code honest. This one keeps conclusions honest.

This document is the spec only: stages, gates, hooks, skills, review rounds,
and enforcement. It contains no code. Build order is in §12.

## 0. What this plugin must prevent

Ranked gaps from the survey, each mapped to the mechanism that closes it:

| # | Gap | Closed by |
|---|---|---|
| 1 | Spec written (or rewritten) after seeing data | Lock stage + spec hash + `lockguard` hook (§3, §6.1) |
| 2 | Silent forking paths: only the winning cut is reported | Specs-tried ledger + footer count (§4.3, §8) |
| 3 | Reviewer shares the analyst's context and blind spots | Goldfish review, pre-data and post-result (§5) |
| 4 | No checkpoint between stages | Per-stage gates G0–G9 (§3) |
| 5 | Report cannot be traced back to its inputs | Mandatory provenance footer + `footercheck` hook (§8, §6.5) |
| 6 | Agent quietly redefines "active user", "revenue", etc. | Human-owned definitions registry + `defguard` hook (§7) |
| 7 | Same review depth for a glance and a board deck | Risk tiers set review depth (§2.2, §5.3) |
| 8 | Human corrections are forgotten next session | Correction evals, replayed at Verify (§9) |
| 9 | Analysis can mutate raw data, phone home, or leak rows | Safe kernel (§10) |

## 1. Cast and principles

- **Elephant** — the analyst (you plus the agent with full conversation
  context). Drafts the spec, runs the analysis.
- **Goldfish** — sees only the artifacts: spec, lock, definitions,
  specs-tried ledger, outputs, provenance. Never the chat. Catches
  unstated assumptions and story-fitting.
- **Human** — owns definitions, approves the spec at DECIDE+, signs off at
  PUBLISH, and is the only source of corrections.

Principles carried over from the sibling plugin, unchanged:

- **Friction contract.** Every gate is a fast check plus a one-line
  reason. Small work gets less ceremony, never more. A gate that slows the
  analyst gets bypassed.
- **Wayfinder rides along.** One status line plus gate result per stage
  exit in `.analysis/wayfinder.md`. Any session resumes cold.

Principle added here:

- **Ponytail economy.** The smallest analysis that answers the question.
  No cuts nobody asked for, no chart that does not carry a claim, no new
  dependency where SQL or the standard library already does it. Every
  extra cut is also an extra fork (§4.3) — economy and honesty point the
  same way.
- **Prevent, detect, disclose.** Hooks prevent where Hermes allows it.
  Gates detect what hooks miss (hooks fail open — §6.0). The provenance
  footer discloses whatever remains. No rule relies on only one layer.

## 2. Sizing: economy rung and risk tier

Two independent dials, both declared in one sentence each in the spec.

### 2.1 Economy rung (how much ceremony)

| Rung | When | Ceremony |
|---|---|---|
| glance | one source, one query or table, answer fits in chat | 3-line spec (question, source, definition refs); auto-lock; chat answer with short footer |
| quick-cut | one or two sources, a few queries, no modeling | short spec; lock; profile; report file with full footer |
| full analysis | multiple sources, joins, modeling, or statistical inference | full spec template; all stages; plan file |
| study | multiple sessions, milestones | spec per milestone; roadmap; Wayfinder mandatory |

Overrides: PII or regulated data steps up one rung. PUBLISH tier is never
glance. When in doubt, pick the lower rung; step up mid-run if needed (a
step-up is logged as a spec amendment).

### 2.2 Risk tier (how much review)

| Tier | Meaning | Examples |
|---|---|---|
| EXPLORE | curiosity, internal, nobody acts on it | "roughly how many posts per month?" |
| DECIDE | informs a decision Brad or a client will act on | pricing change, feature cut, tool choice |
| PUBLISH | leaves the building, or touches money/health | blog post stat, client deliverable, trading, health data |

Tier sets review depth (§5.3), evals required (§9), and sign-off. Rung
and tier are independent: a glance can be DECIDE; a study can be EXPLORE.

## 3. Pipeline: stages and gates

```text
Intake -> Define -> Economy+Tier -> Teardown -> LOCK -> Profile -> Analyze -> Verify -> Report -> Archive
          ^ no data touched before LOCK ^           (amendments loop back to Define, re-lock, logged)
Wayfinder rides along every stage.
```

Each gate writes `G<n>: pass|fail — <one-line reason>` to Wayfinder.
"Who checks" = A (agent self-check), G (goldfish), H (human), K (hook).

| # | Stage | Skill | Artifact | Gate (pass condition) | Who |
|---|---|---|---|---|---|
| 0 | Intake | `intake` | intake block | G0: question stated as one sentence; decision it informs named (or "none — EXPLORE") | A |
| 1 | Define | `define`, `definitions` | `.analysis/spec.md` | G1: every metric in the spec resolves to a registry definition `name@version`; data sources named; hypotheses and "what would change the answer" stated; exclusions stated | A, K |
| 2 | Economy+Tier | `define` | two sentences in spec | G2: rung and tier declared; overrides applied | A |
| 3 | Teardown (pre-data) | `goldfish-review` | `.analysis/reviews/teardown.md` | G3: tier-scaled rounds pass (§5.1); at DECIDE+ human approves spec | G, H |
| 4 | Lock | `lock` | `.analysis/spec.lock`, ledger entry | G4: lock written; hash recomputes; definitions versions pinned | A, K |
| 5 | Profile (first data contact) | `profile` | `.analysis/profile.md` | G5: snapshot recorded (source id, as-of, row count, content hash); schema and ranges match spec expectations or mismatch filed as amendment | A |
| 6 | Analyze | `analyze` | outputs, `runs.log`, `specs-tried.jsonl` | G6: every run logged; every variant beyond the locked spec has a ledger entry with a reason | K, A |
| 7 | Verify | `verify`, `goldfish-review`, `correct` | `.analysis/verify.md` | G7: clean-kernel reproduction matches; drift recorded; correction evals pass; post-result goldfish rounds pass (§5.2) | A, G |
| 8 | Report | `report` | `reports/<slug>.md` | G8: provenance footer complete; exploratory results labelled; at PUBLISH human sign-off recorded | K, H |
| 9 | Archive | `report` | ledger closed, commit | G9: spec, lock, ledger, verify, report committed together; Wayfinder closed | A |

### 3.1 Amendments (the honest loop back)

Data contact often reveals that the spec was wrong (column missing, grain
different, population smaller than assumed). That is allowed. Silently
editing the spec is not.

- Amendment = new spec version (`specs/v2.md`), a one-line reason, and a
  re-lock. The ledger marks it **post-data**.
- At EXPLORE: agent amends and continues.
- At DECIDE: amendment re-runs teardown round 3 (design critique) only.
- At PUBLISH: amendment needs human approval before re-lock.
- The report states the amendment count and lists post-data amendments
  in the footer. Results under a post-data spec are not "confirmatory".

### 3.2 Stop-and-ask cases (the only ones)

1. A metric has no registry definition (§7).
2. Post-data amendment at PUBLISH tier.
3. A hook blocked a tool call and the cause is not an obvious slip.
4. Reproduction fails at Verify and the cause is not found in one debug pass.

Everything else proceeds with stated assumptions, recorded in the spec.

## 4. Artifacts and ledgers

Workdir layout (all human-readable, all committed):

```text
.analysis/
  spec.md              current spec (working copy)
  specs/vN.md          every locked version, immutable once locked
  spec.lock            current lock: version, hash, timestamp, definition pins, tier, rung
  ledger.md            lock history: one line per lock/amendment (pre-data | post-data)
  specs-tried.jsonl    every analytic variant actually run
  runs.log             every kernel execution (written by hook + kernel)
  profile.md           data snapshot facts
  reviews/             teardown.md, results.md (goldfish round notes)
  verify.md            reproduction evidence, drift, eval results
  wayfinder.md         stage + gate lines
  config.yaml          data roots, kernel policy, tier, registry location
reports/<slug>.md      final report with provenance footer
definitions/           human-owned registry (or pointer to shared registry)
evals/corrections/     correction eval cases (§9)
```

### 4.1 Spec template sections

Question; decision it informs; tier; rung; population and time window;
data sources (by id, not contents); metrics (`name@version` only — no
inline formulas); hypotheses with direction; planned comparisons and
cuts (closed list); method; exclusion and outlier rules; thresholds that
would change the decision; known risks (confounders, selection, leakage);
assumptions; out of scope.

### 4.2 Lock hash

- SHA-256 over the normalized spec body (whitespace-normalized, sections
  in template order) plus the sorted list of `definition@version` pins
  plus data source ids. Data contents are not in the lock hash — the
  snapshot hash is taken at Profile and recorded separately, so "what we
  planned" and "what we got" stay distinguishable.
- The lock records the timestamp and the state of `runs.log`: it must be
  empty of data-root reads (§6.1). A lock taken after data reads is
  recorded as post-data, never as pre-registration.

### 4.3 Specs-tried ledger

One entry per distinct analytic variant actually executed: id, parent id,
what changed (filter, cut, model, outlier rule, definition), why,
`locked | exploratory`, output pointer, run ids. Re-running the same
variant is not a new entry; changing anything that could move the answer
is. Reports must state "N variants tried, K reported, locked variant is
X". A result not from a locked variant is labelled **exploratory**
wherever it appears.

## 5. Review rounds (elephant / goldfish)

The goldfish packet is fixed and contains only files: spec, lock,
definitions excerpts, plus (post-result) profile, specs-tried ledger,
outputs, draft report, provenance footer. No conversation. Run as a
second session or delegated subagent; at EXPLORE a cold self re-read is
acceptable.

### 5.1 Pre-data teardown (stage 3) — reviews the plan, not results

1. **Zoom-out** — does the question match the decision? Would any answer
   change anything?
2. **Comprehension** — could a stranger run this from the spec alone?
   Every metric resolves; every source named.
3. **Design critique** — confounders, selection bias, leakage, base rates,
   multiple comparisons, grain mismatches in joins, survivorship, time
   window effects.
4. **Intermediate zoom-out** — after critique, is this still the
   smallest analysis that answers it (ponytail)? Cut unneeded cuts now,
   before they become forks.
5. **Lockability** — are thresholds and planned comparisons concrete
   enough that "we changed the plan" would be detectable?

### 5.2 Post-result review (stage 7) — reviews claims against artifacts

1. **Claim-to-evidence** — every claim in the draft maps to a logged
   output and run id.
2. **Forking paths** — reported variant is the locked one, or labelled
   exploratory; N tried is disclosed.
3. **Alternative explanations** — could a confounder, Simpson's paradox,
   selection effect, or data-quality artifact produce the same result?
4. **Definitions conformance** — computed metrics match registry
   definitions (grain, filters, time basis).
5. **Lean** — every table and chart carries a claim; delete the rest.

### 5.3 Depth by tier

| Tier | Pre-data | Post-result | Sign-off |
|---|---|---|---|
| EXPLORE | 2 passes: consequence + alternatives (self, cold re-read) | rounds 1–2 (self) | none |
| DECIDE | all 5 rounds, goldfish session | all 5 rounds, goldfish session | human approves spec before lock |
| PUBLISH | all 5, goldfish session + independent second goldfish on round 3 | all 5, two independent goldfish sessions | human approves spec and signs report |

Round failure: fix the spec (pre-data) or the report/analysis
(post-result), re-run only the failed round, max one re-run per round;
a second failure escalates to the human. Each round leaves one line in
`reviews/`.

## 6. Hooks

### 6.0 Hermes hook constraints that shape this design

(Same facts as the sibling `HOOKS.md`.) Shell hooks get a JSON payload on
stdin and must print JSON on stdout. Only `pre_llm_call` can inject
context. `pre_tool_call` can block or approve and sees `tool_input`.
`post_tool_call` cannot inject or alter, but the script may write files
as a side effect. Hooks fail open: malformed output, nonzero exit, or
timeout is logged and ignored. Non-interactive contexts need
`hooks_auto_accept`. Therefore: **every hook rule is re-checked by a
gate**, and a gate failure for a rule a hook should have blocked is
reported as a hook fault.

Unlike the sibling (nudge-only by choice), this plugin uses blocking
`pre_tool_call` hooks for a small number of rules where a false negative
corrupts the conclusion. Each blocking hook is scoped narrowly by
`.analysis/config.yaml` to keep false positives rare, and every block
message says exactly how to unblock.

### 6.1 `lockguard` — pre_tool_call, BLOCKS

- Matcher: `terminal`, `execute_code`, `read_file`. Browser tools are
  out of scope (not a data path).
- Fires when tool input references a declared data root (path or
  connection id from config).
- Blocks if `spec.lock` is missing, or the current `spec.md` hash differs
  from the lock and no amendment is pending.
- Unblock message: "Lock the spec first (lock skill), or file an
  amendment." Gate G4/G5 re-check `runs.log` for pre-lock data reads.

### 6.2 `rawguard` — pre_tool_call, BLOCKS

- Blocks writes, moves, or deletes targeting raw data roots, and
  in-place overwrites of snapshot files. Derived data goes to `derived/`.

### 6.3 `defguard` — pre_tool_call, BLOCKS

- Blocks agent `write_file`/`patch`/terminal writes into `definitions/`
  (except `definitions/proposals/`). The registry is human-edited only.

### 6.4 `runlog` — post_tool_call, side effect only

- Appends to `.analysis/runs.log`: timestamp, tool, hash of the
  code/command, data roots referenced, session id. Never blocks. This is
  the evidence base for G4, G6, and the footer's run ids.

### 6.5 `footercheck` — pre_tool_call, BLOCKS

- Matcher: writes to `reports/`. Blocks when the content lacks a
  provenance footer marker or any required footer field (§8) is empty.

### 6.6 `driftnudge` — pre_llm_call, advisory

- Injects one line when: spec.md hash ≠ lock with no amendment; more
  than N (default 5) exploratory ledger entries since last review; or
  `runs.log` shows data-root executions with no matching specs-tried
  entry. Emits `{}` otherwise.

### 6.7 Installation and approval

Hooks are declared in profile `config.yaml` like the sibling. Install
docs must state: blocking hooks need first-use approval; gateway/cron
need auto-accept; `hermes hooks doctor` flags edits. All hooks are
dependency-free shell (no jq), and every exit path prints valid JSON.

## 7. Human-owned definitions

- Registry entry: name, plain-English meaning, formula, grain, filters,
  time basis (event vs. processed, timezone), owner, version, approved
  date, known traps.
- Location: per-project `definitions/` or a shared registry path in
  config (candidate: vault note per metric). Decision open (§13).
- The agent may read and cite; it may only **propose** new or changed
  definitions in `definitions/proposals/`. A human merges and bumps
  version.
- Specs cite `name@version`; inline formulas in a spec fail G1.
- Unknown metric = stop and ask (§3.2). The agent may suggest a
  proposal text but must not proceed on it at DECIDE+; at EXPLORE it may
  proceed with the proposal labelled **provisional definition** in the
  footer.

## 8. Provenance footer (mandatory on every report)

Fields, all required (empty = G8 fail, `footercheck` block):

- Question (one line) and tier/rung
- Spec version and lock hash (short), lock timestamp
- Amendments: count, how many post-data
- Variants: N tried, K reported, locked variant id; exploratory labels present
- Definitions: list of `name@version` (provisional flagged)
- Data: source id, as-of, row count, snapshot hash per source
- Kernel: environment lock hash, seed, network policy
- Reproduce: one command or skill invocation that regenerates outputs
- Review: rounds run, by whom (self / goldfish session ids / human)
- Correction evals: count run, count passed
- Caveats: known limits in one or two lines
- Generated date

Glance rung: short footer in chat (spec hash, sources, definitions, N
tried). Everything else: full footer.

## 9. Correction evals

When a human corrects an analysis (wrong join grain, misread definition,
timezone error, wrong denominator), the `correct` skill captures it as a
case in `evals/corrections/NNN`:

- trigger context (dataset, definition, or pattern it applies to)
- what the agent did, what was wrong, the correct behavior
- a check that would catch it (expected value, invariant, or
  review question)
- source correction (date, who)

Use:

- **Verify (G7):** replay every case whose trigger matches this
  analysis's datasets or definitions. DECIDE+ requires all applicable
  cases pass; EXPLORE reports failures but proceeds.
- **Plugin regression:** the full case set doubles as the plugin's own
  test suite when skills change.
- Cases are human-approved before they become binding; the agent drafts.

## 10. Safe kernel

The execution environment for Profile, Analyze, and Verify. Policy
spec, not implementation:

- Raw data roots mounted or treated read-only (`rawguard` + kernel
  policy); derived outputs only to `derived/`.
- Network off by default; allowlist per config (e.g. the warehouse host).
- Pinned environment (uv lockfile); its hash goes in the footer.
- Seeded randomness; seed in footer.
- Every execution logged to `runs.log` with code hash.
- Output caps: no more than a configured number of raw rows echoed into
  chat; PII columns (declared in config) masked in printed output.
- Clean-run reproduction: Verify re-runs the locked variant from a fresh
  kernel and diffs outputs. Mismatch = G7 fail.
- Credentials via the Hermes vault/env, never in spec, code, or logs.

Implementation choice (subprocess runner vs. Jupyter kernel vs. DuckDB
sandbox) is deferred to the build plan (§13).

## 11. Skills

Namespaced `disciplined-data-analysis:<skill>`, plus an orchestrator
`disciplined-data-analysis` that holds the stage map (mirrors sibling
layout: `skills/*/SKILL.md`, `plugins/disciplined-data-analysis/SKILL.md`,
`references/`, `templates/`).

| Skill | Owns | Key rule |
|---|---|---|
| `disciplined-data-analysis` (orchestrator) | stage map, gates, friction contract | no data before lock |
| `intake` | stage 0 | question + decision in one sentence each |
| `define` | stages 1–2, spec template, rung/tier | metrics by reference only |
| `definitions` | registry lookup and proposals | agent never edits the registry |
| `goldfish-review` | stages 3 and 7 review rounds, packet assembly | packet is files only, never chat |
| `lock` | stage 4, hash, ledger, amendments | post-data locks are labelled post-data |
| `profile` | stage 5, snapshot facts | mismatch becomes amendment, not silent fix |
| `analyze` | stage 6, safe kernel use, specs-tried logging, ponytail economy | every variant logged with a reason |
| `verify` | stage 7, clean reproduction, drift | fresh evidence or it did not happen |
| `correct` | correction capture and eval replay | corrections become cases, cases become checks |
| `report` | stages 8–9, footer, archive | exploratory labelled at point of claim |

Reused from the sibling instead of duplicated (ponytail): `research`
(doc reading and read.log), `debug` (reproduction failures), `version`
(commit conventions). Referenced, not required — the plugin works
standalone with a short fallback paragraph in each skill.

Templates: `spec.md`, `spec.glance.md`, `wayfinder.md`, `footer.md`,
`definition.md`, `correction-case.md`, `goldfish-packet.md`.
References: `economy-tier-ladder.md`, `review-rounds.md`,
`enforcement-matrix.md`, `kernel-policy.md`.

## 12. Enforcement matrix (prevent / detect / disclose)

| Rule | Prevent (hook) | Detect (gate) | Disclose (footer) |
|---|---|---|---|
| No data before lock | `lockguard` | G4/G5 scan `runs.log` | lock timestamp, post-data flags |
| Spec edits after lock are amendments | `lockguard`, `driftnudge` | G4 hash recompute, G7 drift | amendment counts |
| All variants logged | `runlog` + `driftnudge` | G6 runs↔ledger match | N tried / K reported |
| Definitions human-owned | `defguard` | G1 refs resolve; G7 round 4 | `name@version`, provisional flag |
| Raw data immutable | `rawguard`, kernel policy | G7 snapshot hash re-check | snapshot hashes |
| Reports carry provenance | `footercheck` | G8 field check | the footer itself |
| Review depth matches risk | — | G3/G7 round lines vs tier table | review field |
| Corrections not repeated | — | G7 eval replay | eval counts |
| Reproducible | kernel pinning | G7 clean rerun diff | env hash, seed, reproduce command |

Bypass handling: any gate that passes only because a hook was disabled or
failed open is recorded in Wayfinder as `pass (hook fault: <name>)` and
the footer caveat says so. 1.0 bar: three real analyses (one per tier)
through the full pipeline with zero unrecorded bypasses and zero hook
false-positive blocks left unfixed.

Build order (when code starts): orchestrator + templates → `lock` +
`runlog` + `lockguard` (gap 1 first) → specs-tried ledger → `footercheck`
+ `report` → `definitions` + `defguard` → `goldfish-review` → `verify` +
safe kernel → `correct` + evals.

## 13. Open decisions (need Brad)

1. **Repo location.** Proposed: `C:\Users\bmtrn\disciplined-data-analysis`
   (this folder), sibling to `disciplined-vibe-coding`, same layout and
   update contract (shipped read-only, `user/` overlay). Not yet `git init`.
2. **Definitions registry home:** per-project folder vs. shared vault
   notes (shared wins if metrics recur across projects).
3. **Blocking hooks:** accept three blocking `pre_tool_call` hooks
   (`lockguard`, `rawguard`, `defguard`) plus `footercheck`, departing from
   the sibling's nudge-only stance? Alternative: ship all as advisory and
   rely on gates — weaker on gap 1.
4. **Kernel implementation:** subprocess + uv venv (simplest), Jupyter
   kernel (richer), or DuckDB-only sandbox (safest for tabular work).
5. **Glance-rung lock:** keep auto-lock even for glances (proposed — it is
   one line and keeps gap 1 closed everywhere), or exempt glances?
6. **Goldfish execution:** delegated subagent (default) vs. second
   profile (stronger isolation, more setup).
