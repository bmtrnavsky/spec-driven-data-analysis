---
name: disciplined-data-analysis
status: spec draft, reshaped after blind review (no code yet)
version: 0.2.0-spec
date: 2026-10-27
sibling: C:\Users\bmtrn\disciplined-vibe-coding (v0.2.0)
sources: Turing pipeline structure (disciplined-vibe-coding), Elephant-Goldfish Model (Google, Apache 2.0), ponytail economy (DietrichGebert/ponytail, MIT), gap survey deleg_6fc04e39, blind review deleg_1df92e5a (22 findings, all addressed — see Appendix A)
---

# Disciplined Data Analysis — plugin spec

Question → locked spec → data → answer, with every fork disclosed.
The sibling plugin keeps code honest. This one keeps conclusions honest.

This document is the spec only: stages, gates, hooks, skills, review rounds,
and enforcement. It contains no code. Build order is in §14.

## 0. What this plugin must prevent

Ranked gaps from the survey, each mapped to the mechanism that closes it:

| # | Gap | Closed by |
|---|---|---|
| 1 | Spec written (or rewritten) after seeing data | Lock + spec hash + `lockguard` + kernel audit hook + prior-exposure declaration (§3, §4.1, §6.1, §10) |
| 2 | Silent forking paths: only the winning cut is reported | Variant scripts + specs-tried ledger + orphan-run check + footer counts (§4.3, §8) |
| 3 | Reviewer shares the analyst's context and blind spots | Goldfish review with read-only packet tools and a templated brief (§5) |
| 4 | No checkpoint between stages | Per-stage gates G0–G9, computed by script where possible (§3) |
| 5 | Report cannot be traced back to its inputs | Provenance footer whose values are recomputed, not just present (§8, §6.5) |
| 6 | Agent quietly redefines "active user", "revenue", etc. | Human-owned registry, content-hashed pins, `defguard` (§7) |
| 7 | Same review depth for a glance and a board deck | Risk tiers, with mechanical triggers and human confirmation (§2.2, §5.3) |
| 8 | Human corrections are forgotten next session | Correction evals, matched mechanically and replayed at Verify (§9) |
| 9 | Analysis can mutate raw data, phone home, or leak rows | Kernel as the only post-lock data path, audit hook, display masking, no data in git (§10, §11) |

### 0.1 Threat model (what "prevent" means here)

The agent is treated as **cooperative but fallible**: it slips,
rationalizes, and takes the convenient path, but it is not actively trying
to defeat the plugin.

- Hooks string-match tool inputs. They **prevent slips**, not determined
  evasion (variables, `os.environ`, `cd` plus relative paths, symlinks).
- Evasion is made **detectable**: the kernel audit hook logs real file
  opens and socket connects regardless of tool-input text (§10.1), evidence
  files are hash-chained (§4.4), and locks are git commits (§4.2).
- Whatever is neither prevented nor detected is **disclosed** in the footer
  as a caveat. The spec never claims prevention where only detection exists.
- Phase 0 of the build (§14) is a red-team test that measures which of
  these claims hold on this Hermes install before any gate is trusted.

## 1. Cast and principles

- **Elephant** — the analyst (you plus the agent with full conversation
  context). Drafts the spec, runs the analysis.
- **Goldfish** — sees only the packet files: spec, lock, definitions,
  specs-tried ledger, outputs, provenance. Never the chat, memory, RAG, or
  data. Catches unstated assumptions and story-fitting.
- **Human** — owns definitions and `config.yaml`, confirms tier at DECIDE+,
  approves the spec at DECIDE+, signs off at PUBLISH, and is the only
  source of corrections. Human acts are recorded as artifacts the agent
  cannot produce (§4.5).
- **`dda` CLI** — the plugin's deterministic scripts. Besides the hooks,
  it is the only writer of evidence files under `.analysis/`.

Principles carried over from the sibling plugin:

- **Friction contract.** Every gate is a fast check plus a one-line
  reason. Small work gets less ceremony, never more. A gate that slows the
  analyst gets bypassed.
- **Wayfinder rides along.** One status line plus gate result per stage
  exit in `.analysis/wayfinder.md`. Any session resumes cold.

Principles added in this plugin:

- **Ponytail economy.** The smallest analysis that answers the question.
  No cuts nobody asked for, no chart that does not carry a claim, no new
  dependency where SQL or the standard library already does it. Every
  extra cut is also an extra fork (§4.3) — economy and honesty point the
  same way.
- **Prevent, detect, disclose.** Hooks prevent where Hermes allows it.
  Gates detect what hooks miss (hooks fail open — §6.0). The provenance
  footer discloses whatever remains. No rule relies on only one layer.
- **Scripts check; agents don't grade themselves.** A gate that can be
  computed from files is computed by `dda gate Gn`, not asserted by the
  agent.

## 2. Sizing: economy rung and risk tier

Two independent dials, both declared in one sentence each in the spec.
The spec is the only place either is stored; `config.yaml` holds only a
project default tier, used as the starting proposal.

### 2.1 Economy rung (how much ceremony)

| Rung | When | Ceremony |
|---|---|---|
| glance | one source, one query or table, answer fits in chat | 3-line spec (question, source, definition pins) + prior-exposure line; lock; answer in chat and in `.analysis/answer.md` with short footer |
| quick-cut | one or two sources, a few queries, no modeling | short spec; lock; profile; report file with full footer |
| full analysis | multiple sources, joins, modeling, or statistical inference | full spec template; all stages; plan file |
| study | multiple sessions, milestones | one milestone directory per milestone (§4, §12); roadmap; Wayfinder mandatory |

Overrides: PII or regulated data steps up one rung. PUBLISH tier is never
glance. When in doubt, pick the lower rung; step up mid-run if needed (a
step-up is logged as an amendment).

### 2.2 Risk tier (how much review)

| Tier | Meaning | Examples |
|---|---|---|
| EXPLORE | curiosity, internal, nobody acts on it | "roughly how many posts per month?" |
| DECIDE | informs a decision Brad or a client will act on | pricing change, feature cut, tool choice |
| PUBLISH | leaves the building, or touches money/health | blog post stat, client deliverable, trading, health data |

Tier sets review depth (§5.3), evals required (§9), and sign-off. Rung
and tier are independent: a glance can be DECIDE; a study can be EXPLORE.

**Tier confirmation (G2).** The agent proposes; rules decide who confirms.

- `dda gate G2` forces at least DECIDE if any trigger fires: G0 names a
  decision; the audience is external; a source is flagged PII/regulated in
  config; or the topic tags include money, health, or trading. The agent
  cannot declare EXPLORE when a trigger fires.
- PUBLISH is forced when the audience is external or a publish channel
  (§6.5) is the destination.
- EXPLORE with no trigger: agent-confirmed, and the footer says so.
- DECIDE or PUBLISH: the human confirms the tier together with the spec
  approval (§4.5).
- **Raising** the tier mid-run: the agent may do it at any time (it only
  adds review). It is logged as an amendment, and the missing reviews for
  the new tier run before Report.
- **Lowering** the tier mid-run: human approval only, logged as an
  amendment.

## 3. Pipeline: stages and gates

```text
Intake -> Define -> Economy+Tier -> Teardown -> LOCK -> Profile -> Analyze -> Verify -> Report -> Archive
          ^ metadata only before LOCK (§3.3) ^      (amendments loop back to Define, re-lock, logged)
Wayfinder rides along every stage.
```

Each gate writes `G<n>: pass|fail — <one-line reason>` to Wayfinder via
`dda gate`. "Who checks" = S (`dda` script, deterministic), A (agent
judgment), G (goldfish), H (human artifact, §4.5), K (hook).

| # | Stage | Skill | Artifact | Gate (pass condition) | Who |
|---|---|---|---|---|---|
| 0 | Intake | `intake` | intake block | G0: question stated as one sentence; decision it informs named (or "none — EXPLORE") | A |
| 1 | Define | `define`, `definitions` | `.analysis/spec.md` | G1: every metric resolves to a registry pin `name@version#hash` and the hash recomputes; sources named by config alias; hypotheses, "what would change the answer", exclusions, and prior exposure stated; no inline formulas | S, K |
| 2 | Economy+Tier | `define` | two sentences in spec | G2: rung and tier declared; overrides and tier triggers applied (§2.2); human tier confirmation present when required | S, H |
| 3 | Teardown (pre-data) | `goldfish-review` | `.analysis/reviews/teardown.md` | G3: tier-scaled rounds recorded from real goldfish sessions (§5); at DECIDE+, a verified human spec approval for this spec hash | S, G, H |
| 4 | Lock | `lock` | `specs/vN.md`, `spec.lock`, ledger entry, git commit | G4: lock hash recomputes (spec + definition pins + config hash + source aliases); evidence chains verify; `runs.log` and the audit log show no non-metadata data reads before this lock, otherwise the lock is labelled post-data | S, K |
| 5 | Profile (first data contact) | `profile` | `.analysis/profile.md` | G5: snapshot or fingerprint recorded per source (§10.3); schema compared with declared expectations; mismatch filed as amendment | S, A |
| 6 | Analyze | `analyze` | variant scripts, outputs, `runs.log`, `specs-tried.jsonl` | G6: every data-touching run maps to a variant id (no orphan runs); every variant beyond the locked one has a ledger entry with a reason; hook heartbeat complete (§6.8) | S, K |
| 7 | Verify | `verify`, `goldfish-review`, `correct` | `.analysis/verify.md` | G7: locked variant reproduces from its saved script in a fresh kernel within declared tolerance against the snapshot; source drift recorded separately (§10.3); matched correction evals pass; post-result goldfish rounds recorded (§5.2) | S, G |
| 8 | Report | `report` | `reports/<slug>.md` or `.analysis/answer.md` | G8: footer values recompute from lock, ledgers, runs, profile, reviews, approvals (§8); `exploratory` and `post-data-locked` labels present at point of claim; at PUBLISH, verified human sign-off for this report hash | S, K, H |
| 9 | Archive | `report` | ledger closed, commit, push | G9: spec, lock, ledger, verify, report committed together; `dda gitcheck` finds no data or secrets staged (§11); evidence chains verify; Wayfinder closed | S |

### 3.1 Amendments (the honest loop back)

Data contact often reveals that the spec was wrong (column missing, grain
different, population smaller than assumed). That is allowed. Silently
editing the spec is not.

- An amendment is a new spec version (`specs/v2.md`), a one-line reason,
  and a re-lock (`dda lock --amend "<reason>"`). The ledger marks it
  **post-data** when any non-metadata data read precedes it.
- **No "amendment pending" state unlocks data.** Data reads require
  `hash(spec.md) == lock hash` and a matching config hash, always. Edit
  the spec, re-lock, then read. (This closes the open-an-amendment,
  read-the-data, then-write-the-spec loophole.)
- Results computed under a post-data lock carry the label
  **`post-data-locked`**, never `locked`. They are not confirmatory and
  the report must say so where the claim appears.
- Review of a post-data amendment:
  - EXPLORE: the agent amends and continues.
  - DECIDE: goldfish rounds 1 (zoom-out) and 3 (design critique), plus
    a verified human approval of the new version.
  - PUBLISH: same as DECIDE, plus the second goldfish on round 3.
- Amendment cap: a third post-data amendment at DECIDE+ triggers a full
  teardown re-run, and the footer flags "spec moved after data N times".
- Every spec version counts toward "N variants tried" in the footer, so
  forking cannot move from the variants ledger into spec versions.
- Tier and rung changes are amendments (§2).

### 3.2 Stop-and-ask cases (complete list)

1. A metric has no registry definition (§7) at DECIDE+.
2. A human tier confirmation or spec approval is required (G2, G3, or a
   post-data amendment at DECIDE+).
3. PUBLISH sign-off before release (G8).
4. A goldfish round fails twice (§5.3).
5. A matched correction eval fails at DECIDE+ (§9).
6. A hook blocked a tool call and the cause is not an obvious slip.
7. Reproduction fails at Verify and the cause is not found in one debug
   pass.
8. An evidence chain fails to verify (§4.4) or a hook fault is detected
   (§6.8).

Everything else proceeds with stated assumptions, recorded in the spec.

**No-human contexts** (cron, gateway with Brad absent, subagents):
stop-and-ask becomes **stop-and-park**. Wayfinder records
`awaiting-human: <case>`, nothing proceeds past that gate, and nothing is
auto-approved.

### 3.3 Pre-lock metadata allowance

Before lock, `dda meta <alias>` is the only allowed data-root access. It
returns, and logs to `runs.log` as `kind: meta`:

- **Allowed:** file list, file sizes and mtimes, table list, column names
  and types, row count.
- **Never:** values, headers with rows, samples, min/max, distinct
  values, histograms, null rates.

`lockguard` lets `dda meta` through and blocks every other data read.
Range and value expectations in the spec come from domain knowledge or
declared prior exposure, never from observation. A `meta` read does not
make a lock post-data.

## 4. Artifacts and ledgers

Workdir layout. `C` = committed, `X` = never committed (§11).

```text
.analysis/                    guarded: agent writes blocked except spec.md and wayfinder.md (§6.2)
  config.yaml          C  data-root aliases, kernel policy, PII columns, default tier, publish channels, approver keys (human-owned)
  spec.md              C  current spec (working copy, agent-editable)
  specs/vN.md          C  every locked version, written only by `dda lock`
  spec.lock            C  version, lock hash, timestamp, definition pins, config hash, tier, rung, label
  ledger.md            C  lock/amendment history, hash-chained
  specs-tried.jsonl    C  every analytic variant run, hash-chained
  runs.log             C  every tool call and kernel execution, append-only, hash-chained, no data values
  runs/blobs/<hash>    C  exact code/query text of each run, secrets scrubbed
  variants/<id>.py|sql C  runnable script per variant (what Verify replays)
  approvals/           C  human approval records (§4.5)
  profile.md           C  aggregate snapshot facts only — no rows, no samples
  reviews/             C  goldfish outputs, recorded by `dda review record`
  verify.md            C  reproduction evidence, drift, eval results
  answer.md            C  glance answer plus short footer
  wayfinder.md         C  stage + gate lines
  milestones/<m>/      C  study rung only: its own spec.md, specs/, spec.lock, ledger
derived/               X  derived data and snapshots
outputs/               X  row-level tables; aggregates are promoted into the report
reports/<slug>.md      C  final report with provenance footer
definitions/           C  human-owned registry; agent writes only to definitions/proposals/
evals/corrections/     C  correction eval cases (§9)
```

### 4.1 Spec template sections

Question; decision it informs; tier; rung; audience; population and time
window; data sources (config alias only, not contents or paths); metrics
(`name@version#hash` only — no inline formulas); hypotheses with
direction; planned comparisons and cuts (closed list); method; exclusion
and outlier rules; reproduction tolerance (exact, or a numeric tolerance
per output); thresholds that would change the decision; known risks
(confounders, selection, leakage); **prior exposure**; assumptions; out of
scope.

**Prior exposure** (required, one line minimum). Has the analyst, the
agent, or Brad already seen results from these sources — earlier reports,
`derived/` files, dashboards, memory or RAG recall, Brad's own knowledge
of the numbers? Answer "none known" or list them. Any entry labels the
lock **pre-data (prior exposure)** in the ledger and footer, and
confirmatory language is not allowed. Before lock, `lockguard` treats
`derived/` and earlier reports built from the same source aliases as data
roots.

### 4.2 Lock

- `dda lock` computes SHA-256 over: the normalized spec body
  (whitespace-normalized, sections in template order) + sorted definition
  pins `name@version#contenthash` + the `config.yaml` hash + sorted source
  aliases. Data contents are not in the lock hash; the snapshot is
  recorded at Profile, so "what we planned" and "what we got" stay
  distinguishable.
- It reads `runs.log` and the kernel audit log. Any non-`meta` data-root
  access before now labels the lock **post-data**, never pre-registration.
- It writes `specs/vN.md`, `spec.lock`, and a ledger line, then commits
  those files to git. Rewriting a lock then means rewriting git history,
  which becomes visible on the remote after G9's push.
- A `config.yaml` change after lock changes the expected lock hash. Data
  reads block until re-lock, and the re-lock is an amendment.

### 4.3 Specs-tried ledger and variants

- A **variant** is a runnable script in `variants/<id>` with a structured
  header: population/window, filters, cuts, model, outlier rule,
  definition pins. Its **variant key** is a hash of that header. A new key
  is a new variant — a mechanical rule, not a judgment call.
- Not a new variant: formatting, chart styling, renaming, or re-running
  the same key. A change to any header field is a new variant.
- A `specs-tried.jsonl` entry holds: id, parent id, variant key, header
  diff, why, label (`locked | post-data-locked | exploratory`), output
  pointer, run ids. It is written by `dda variant`, which `analyze` calls.
- Every `runs.log` entry that touches a data root must carry a variant id.
  A run without one is an **orphan run**, and orphans fail G6.
- After lock, the kernel and declared connector tools are the only data
  paths (§6.1). SQL run through MCP connector tools is logged with full
  query text and must carry a variant id like any other run.
- Numbers read off dashboards or other browser views are labelled
  **observed, not reproduced** and cannot be the reported locked result.
- Reports state "N variants tried (including M spec versions), K
  reported, locked variant is X". A result not from the locked variant is
  labelled at the point of claim.

### 4.4 Evidence integrity

- `runs.log`, `ledger.md`, `specs-tried.jsonl`, and `approvals/` are
  append-only JSON lines. Each line carries `prev`, the SHA-256 of the
  previous line. `dda verify-chain` checks every chain.
- On each append, the chain heads are mirrored to
  `~/.hermes-home/dda/heads/<workdir-id>.json`, which is also guarded. A
  truncated or edited log fails verification against the mirror.
- `evidenceguard` (§6.2) blocks agent writes to all of the above. Hooks
  and `dda` are the only writers.
- A chain failure is a stop-and-ask case (§3.2) and a footer caveat.

### 4.5 Human approval artifacts

An approval must be something the agent cannot produce.

- An approval is a git commit, made by an approver, that adds
  `.analysis/approvals/<kind>-<artifact-hash>.json` and is **signed** with
  an SSH or GPG key listed in `config.yaml` under `approvers`. Kinds:
  `tier`, `spec`, `amendment`, `signoff`, `definition`, `correction`,
  `config`.
- The signing key must need a passphrase on each use, or must not be
  loaded in any agent reachable from the Hermes shell. `dda doctor` warns
  if `ssh-agent` or `gpg-agent` holds an approver key.
- `dda approved <kind> <artifact>` checks the signature
  (`git verify-commit`), the signer fingerprint against config, and that
  the artifact hash matches the current artifact. An approval of spec v2
  does not cover v3.
- `lockguard` blocks agent runs of `git commit -S`, `git tag -s`, and
  `dda approve`, and `evidenceguard` blocks agent writes to `approvals/`.
- Fallback if Brad has no signing key set up: the approval is recorded as
  **unverified**, and the footer says so. It never counts as verified.

## 5. Review rounds (elephant / goldfish)

### 5.0 Goldfish isolation

- **Packet.** `dda packet <stage>` copies a fixed file set into a packet
  directory under the scratch dir: spec, lock, definition excerpts, plus
  (post-result) profile, specs-tried ledger, aggregate outputs, draft
  report, and footer. No data files, no `derived/`, no raw rows. The
  packet hash is recorded.
- **Toolset.** The goldfish subagent gets read-only packet tools only:
  `read_file` and `search_files`, scoped to the packet directory. No
  terminal, code execution, web, memory, `chat_history_lookup`, RAG, or
  `tool_call`. `lockguard` also applies to subagent sessions (verified in
  phase 0, §14).
- **Brief.** The brief is the `goldfish-packet.md` template. `dda packet`
  fills in only the packet path, the stage, and the round list. The
  elephant cannot add prose. The brief hash is recorded.
- **Recording.** `dda review record <delegation-id>` pulls the goldfish's
  final output from Hermes session state, not from the elephant, and
  writes it to `reviews/` with the session id, packet hash, brief hash,
  and model.
- **Independence.** The two goldfish at PUBLISH are two sessions on
  **different models** when available (config `goldfish_models`). With
  only one model, the footer says "second goldfish: same model —
  correlated blind spots possible".

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
5. **Lockability** — are thresholds, comparisons, and tolerance concrete
   enough that "we changed the plan" would be detectable?

`dda packet` appends the review question of every matched correction
eval (§9) to the round list.

### 5.2 Post-result review (stage 7) — reviews claims against artifacts

1. **Claim-to-evidence** — every claim in the draft maps to a logged
   output, variant id, and run id.
2. **Forking paths** — the reported variant is the locked one, or it is
   labelled `post-data-locked` or `exploratory`; N tried is disclosed.
3. **Alternative explanations** — could a confounder, Simpson's paradox,
   selection effect, or data-quality artifact produce the same result?
4. **Definitions conformance** — computed metrics match registry
   definitions (grain, filters, time basis).
5. **Lean** — every table and chart carries a claim; delete the rest.

### 5.3 Depth by tier and rung

| Tier | Rung | Pre-data | Post-result | Human |
|---|---|---|---|---|
| EXPLORE | any | rounds 1 and 3, self cold re-read | rounds 1 and 2, self | none |
| DECIDE | glance | rounds 1 and 3, one goldfish session | rounds 1 and 2, one goldfish session | tier + spec approval (one signed commit) |
| DECIDE | quick-cut and up | all 5 rounds, goldfish session | all 5 rounds, goldfish session | tier + spec approval before lock |
| PUBLISH | quick-cut and up | all 5, goldfish + second goldfish on round 3 | all 5, two goldfish sessions | tier + spec approval; signed report sign-off |

Self re-reads are written to `reviews/` by the agent and labelled `self`
in the footer.

Round failure: fix the spec (pre-data) or the report/analysis
(post-result), and re-run only the failed round, at most once per round.
A second failure is a stop-and-ask case. Each round leaves one line in
`reviews/`.

## 6. Hooks

### 6.0 Hermes hook constraints that shape this design

(Same facts as the sibling `HOOKS.md`.) Shell hooks get a JSON payload on
stdin (`tool_name`, `tool_input`, `session_id`, `cwd`, `extra`) and must
print JSON on stdout. Only `pre_llm_call` can inject context.
`pre_tool_call` can block or approve. `post_tool_call` cannot inject or
alter output, but the script may write files as a side effect. Hooks fail
open: malformed output, nonzero exit, or timeout is logged and ignored.
Non-interactive contexts need `hooks_auto_accept`. Therefore **every hook
rule is re-checked by a gate**, and hook faults are detected by heartbeat
(§6.8), not assumed.

Unlike the sibling (nudge-only by choice), this plugin uses blocking
`pre_tool_call` hooks where a false negative corrupts the conclusion.
Each is scoped by `.analysis/config.yaml` to keep false positives rare,
and every block message says exactly how to unblock.

**Scope and concurrency.** Hooks never infer the workdir from `cwd`.
`dda start <workdir> [--milestone <m>]` binds a session id to one workdir
(and, for studies, one active milestone) in
`~/.hermes-home/dda/sessions/<session-id>.json`. A data read by session S
is judged only against the lock of S's bound workdir, and only for roots
that lock lists. Two workdirs may analyze the same root; workdir A's lock
never unlocks reads for B. A session with no binding that touches a root
declared by any registered workdir is blocked with "run `dda start`".

### 6.1 `lockguard` — pre_tool_call, BLOCKS

- Matcher: **all tools**. It inspects `terminal`, `execute_code`,
  `read_file`, `search_files`, `web_extract`, browser navigation, and
  `tool_call` (the inner tool name and arguments).
- Data-root aliases in config map to any of: paths, connection hosts, URL
  prefixes (dashboards, GA, WordPress stats), and deferred-tool name
  patterns (e.g. D1 or R2 query tools). A tool input matching any of them
  is a data read.
- Before lock: block every data read except `dda meta` (§3.3), and treat
  `derived/` and earlier reports for the same aliases as data roots
  (§4.1).
- After lock: allow data reads only through the kernel runner
  (`dda run`) and declared connector tools, and only when
  `hash(spec.md)` and the config hash match the lock. Direct
  `read_file`/`search_files` on data roots stays blocked after lock,
  because that output would bypass masking (§10.2).
- Also blocks agent `git commit -S`, `git tag -s`, and `dda approve`.
- The block message names the fix: "Lock the spec (`dda lock`)",
  "Re-lock after your spec edit", "Use `dda run`", or "Run `dda start`".

### 6.2 `evidenceguard` — pre_tool_call, BLOCKS

- Blocks agent writes, moves, deletes, and in-place edits (through
  `write_file`, `patch`, `terminal`, or `execute_code`) under
  `.analysis/**` except `spec.md` and `wayfinder.md`, and under
  `~/.hermes-home/dda/**`. This covers `config.yaml`, `runs.log`,
  `spec.lock`, `specs/`, ledgers, and `approvals/`.
- `dda` subcommands pass through; they enforce their own rules.
- Detection backstop: chain verification (§4.4) and lock commits (§4.2).

### 6.3 `rawguard` — pre_tool_call, BLOCKS

- Blocks writes, moves, or deletes targeting raw data roots, and
  in-place overwrites of snapshot files in `derived/snapshots/`. Derived
  data goes to `derived/`.

### 6.4 `defguard` — pre_tool_call, BLOCKS

- Blocks agent writes into `definitions/` except `definitions/proposals/`,
  including `mv`/`cp` out of proposals and `git checkout`/`git restore` of
  definition files. The registry is human-edited only. Content-hashed pins
  (§7) catch any write that slips through.

### 6.5 `footercheck` — pre_tool_call, BLOCKS

- Matcher: writes to `reports/` and `.analysis/answer.md`, plus every
  **publish channel** declared in config (vault note writes,
  `bt-post-publisher` and WordPress tool calls, Drive publishing).
- Blocks when the footer is missing, a field is empty, or a recomputable
  field is wrong: lock hash, spec version, lock label, N/K counts,
  definition pins, snapshot hashes, approval status. It calls
  `dda footer --check`, which recomputes these from the evidence files.
- Chat cannot be checked by a hook. A chat answer is disclosure only; the
  checked copy is `answer.md` (glance) or the report.

### 6.6 `runlog` — pre_tool_call + post_tool_call, side effect only

- Pre: appends a `seen` line (sequence number, session id, tool name) for
  every tool call. Post: appends the matching `done` line with timestamp,
  tool, code/query hash, blob pointer, data-root **aliases** referenced,
  variant id if any, and kind (`meta | data | other`).
- Records aliases, never paths containing credentials or connection
  strings; blobs are scrubbed of secrets (§10.4). Never blocks.

### 6.7 `driftnudge` — pre_llm_call, advisory

- Injects one line when: the spec.md hash differs from the lock; more
  than N (default 5) exploratory variants exist since the last review;
  orphan runs exist; or a chain fails to verify. Emits `{}` otherwise.

### 6.8 Hook-fault detection (heartbeat)

- Every hook appends to a per-session heartbeat with a sequence counter.
- `dda gate` compares, per session, Hermes's recorded tool-call count
  (from session state) with `runlog`'s `seen` lines, `done` lines, and
  `lockguard` decisions. Any gap is a **hook fault** naming the hook and
  the tool calls it missed.
- The kernel audit log (§10.1) is an independent second source: a file
  open on a data root with no matching `runs.log` entry is reported as a
  hook fault or an evasion.
- A gate that passes despite a hook fault is recorded as
  `pass (hook fault: <name>)` and appears as a footer caveat.

### 6.9 Installation and approval

Hooks are declared in the profile `config.yaml` like the sibling's.
Install docs state: blocking hooks need first-use approval; gateway and
cron need auto-accept; `hermes hooks doctor` flags edits. All hooks are
dependency-free shell (no jq), and every exit path prints valid JSON.
`dda doctor` checks hook registration, approver key setup, and that the
heartbeat is live.

## 7. Human-owned definitions

- Location: **per-project `definitions/`** (decided, §15). Shared only
  when a second lane needs the same definitions.
- Registry entry: name, plain-English meaning, formula, grain, filters,
  time basis (event vs. processed, timezone), owner, version, approved
  date, known traps.
- Pins are `name@version#contenthash`, where the hash is a short SHA-256
  of the normalized entry. G1, G4, and G8 recompute it; an entry that
  changed without a version bump fails.
- The agent may read and cite, and may only **propose** new or changed
  definitions in `definitions/proposals/`. A human merges, bumps the
  version, and records a signed `definition` approval (§4.5).
- Specs cite pins only; inline formulas in a spec fail G1.
- Unknown metric at DECIDE+: stop and ask (§3.2). At EXPLORE the agent
  may proceed on its proposal, labelled **provisional definition** in the
  footer.

## 8. Provenance footer (mandatory on every report)

All fields are required and **value-checked** by `dda footer --check`.
An empty or wrong field fails G8 and is blocked by `footercheck`.

| Field | Checked against |
|---|---|
| Question and tier/rung; tier confirmed by (agent / human-verified / human-unverified) | spec, approvals |
| Spec version, lock hash (short), lock timestamp, lock label (pre-data / pre-data prior exposure / post-data) | `spec.lock`, ledger |
| Amendments: count, post-data count | ledger |
| Variants: N tried (incl. spec versions), K reported, locked variant id; labels present | specs-tried, report text |
| Definitions: pins `name@version#hash`, provisional flagged | registry |
| Data: source alias, as-of, row count, snapshot hash or fingerprint per source; drift since snapshot | profile, verify |
| Kernel: environment lock hash, seed, network policy, audit-hook status | kernel record |
| Reproduce: one `dda` command that regenerates outputs from the locked variant | variants/ |
| Review: rounds run, by whom (self / goldfish session ids and models / human) | reviews/ |
| Approvals: kinds present, verified or unverified | approvals/ |
| Correction evals: matched, run, passed | verify.md |
| Hook faults and chain status | heartbeat, verify-chain |
| Caveats: known limits in one or two lines | not checked (human-readable) |
| Generated date | not checked |

Glance rung: a short footer (lock hash, lock label, sources, pins, N
tried, review) in chat and in `answer.md`. Only `answer.md` is checked.

## 9. Correction evals

When a human corrects an analysis (wrong join grain, misread definition,
timezone error, wrong denominator), the `correct` skill drafts a case in
`evals/corrections/NNN`:

- **trigger keys**: source aliases, definition names, and pattern tags
  from a closed vocabulary (e.g. `join`, `timezone`, `denominator`)
- what the agent did, what was wrong, the correct behavior
- a **deterministic check** (expected value or invariant over outputs)
  and/or a **review question** for the goldfish
- source correction (date, who)

Rules:

- A case becomes binding only with a signed `correction` approval (§4.5).
- **Matching is mechanical.** `dda evals match` selects every binding
  case whose trigger keys intersect the spec's aliases, pins, and declared
  pattern tags. The agent cannot drop a matched case.
- Deterministic checks run at Verify (G7). DECIDE+ requires all to pass
  (a failure is stop-and-ask); EXPLORE reports failures and proceeds.
- Review questions are added to the goldfish rounds (§5.1) and are not
  counted as deterministic tests.
- **Plugin regression:** only the deterministic checks form the plugin's
  own test suite, so the suite stays reproducible.

## 10. Safe kernel

The execution environment for Profile, Analyze, and Verify. Decision 4
(Jupyter) stands, but "full tool access" is narrowed to "full Python
inside the kernel": the kernel is the only post-lock data path (§6.1).
The narrowing is about data access paths, not tools: the kernel's
isolated environment always carries the full data stack (§10.1a).

### 10.1 Kernel policy

- Launched only by `dda run`, bound to the session's workdir.
- A Python **audit hook** (`sys.addaudithook`) is installed at kernel
  start. It:
  - logs every `open` on a data-root path and every `socket.connect` to
    `runs.log` as `kind: audit`, regardless of tool-input text;
  - refuses `open` on data roots when the lock is invalid, and refuses
    write-mode `open` on raw roots and snapshots;
  - refuses `socket.connect` to hosts not on the config allowlist;
  - logs subprocess spawns. Native extensions and subprocesses can
    bypass Python audit hooks; this limit is disclosed, and spawns are at
    least visible.
- On Windows this design has no OS-level read-only mount or firewall.
  Read-only and network-off are enforced by the audit hook and `rawguard`,
  and the footer reports `network policy: audit-enforced`.
- Pinned environment (uv lockfile); its hash goes in the footer.
- Seeded randomness; the seed goes in the footer.

### 10.1a Kernel environment: full data stack, always

The kernel runs in an **isolated** Python environment (its own uv-managed
venv, separate from Hermes's and the user's interpreters). Isolation is
about *where* the tools run, never about *which* tools are available.
The isolated environment MUST ship the full data-analysis stack; a
trimmed, minimal, or "just what this analysis needs" subset is
non-conformant.

- **Required baseline (always installed, pinned in the lockfile):**
  - data handling: `pandas`, `numpy`, `pyarrow`, `polars`, `duckdb`;
  - statistics and modelling: `scipy`, `statsmodels`, `scikit-learn`;
  - plotting: `matplotlib`, `seaborn`;
  - file formats: `openpyxl`, `xlrd` (Excel), plus the parquet and CSV
    support that comes with the above;
  - kernel: `ipykernel`, `ipython`, `jupyter_client`.
- **Never trimmed.** `dda` must not drop baseline packages to save
  install time, disk, or startup cost, and must not build per-analysis
  minimal environments. If a baseline package fails to install, the
  kernel does not start: `dda run` stops and reports the failure. It
  never silently falls back to a reduced stack.
- **Additions, not substitutions.** Projects may add packages (connector
  drivers, domain libraries) via `config.yaml`; additions go through the
  lockfile and change the environment hash. Baseline packages can be
  version-bumped but not removed.
- **Startup check.** At kernel start `dda run` imports every baseline
  package and records the resolved versions in the kernel record. A
  missing or unimportable baseline package fails the start; it is not a
  warning.
- **Footer.** The environment hash already covers the full package set;
  the kernel record lists baseline versions so a reader can see the
  stack was complete.
- **Security is unchanged.** The full stack runs under the same audit
  hook, data-root guards, network allowlist, and display masking
  (§10.1, §10.2). Network-capable libraries in the stack do not widen
  network access; the allowlist still governs every `socket.connect`.

### 10.2 Output and PII

- An IPython display formatter caps raw rows echoed to chat (config
  `max_rows_echo`) and masks declared PII columns in printed output.
- Because `read_file` and `search_files` on data roots stay blocked after
  lock (§6.1), direct file reads cannot bypass the formatter.
- `profile.md`, `runs.log`, and blobs contain no data values. `profile`
  writes aggregates only.

### 10.3 Snapshots, reproduction, and drift

Two separate checks that are never conflated:

- **Snapshot** at Profile, by source type:
  - files: content hash of the file set;
  - warehouse tables small enough to copy: materialize to
    `derived/snapshots/<alias>@<asof>` and hash;
  - tables too large to copy: a **fingerprint** = row count +
    order-independent checksum over declared key columns + max update
    timestamp, plus the exact as-of query. The footer says
    "fingerprint, not full snapshot".
- **Reproduction (G7 pass/fail):** Verify runs the locked variant's saved
  script (`variants/<id>`) in a fresh kernel against the snapshot and
  diffs outputs within the spec's declared tolerance (default exact).
  Notebook state is never the replay source; Analyze exports the locked
  variant to a script before Verify. A mismatch beyond tolerance fails G7.
- **Drift (recorded, not a failure):** Verify recomputes the live
  source's hash or fingerprint and records any change since the snapshot.
  When no snapshot could be materialized, reproduction runs against live
  data. A mismatch is then reported as "irreproducible: live source
  drifted", which fails G7 at PUBLISH and is a caveat below PUBLISH.

### 10.4 Credentials

- Connection strings and keys live in the Hermes vault or env and are
  referenced by name in config (`conn: env:WAREHOUSE_URL`). They never
  appear in the spec, code, config values, logs, or blobs.
- `runlog` records data-root **aliases** only. Blobs pass through a
  scrubber that replaces known secret env values and URL credentials with
  `<redacted:NAME>`. `dda gitcheck` rejects blobs that match a secret
  pattern.

## 11. Data hygiene and git

- Committed: everything marked `C` in §4 — specs, locks, ledgers, logs
  without data values, code blobs, variant scripts, aggregate profile,
  reviews, verify, reports, definitions, evals.
- Never committed: raw data, `derived/`, row-level `outputs/`, snapshots,
  and notebook outputs (stripped before commit).
- The plugin ships a `.gitignore` template. `dda gitcheck` runs at G9 and
  before every `dda lock` commit. It fails if any staged file is under a
  data root, `derived/`, or `outputs/`; contains values under a declared
  PII column name; or matches a secret pattern.
- Reports carry aggregates only. Row-level excerpts need PUBLISH sign-off
  and PII masking.

## 12. Skills

Namespaced `disciplined-data-analysis:<skill>`, plus an orchestrator
`disciplined-data-analysis` that holds the stage map. Layout mirrors the
sibling: `skills/*/SKILL.md`, `plugins/disciplined-data-analysis/SKILL.md`,
`references/`, `templates/`, and `scripts/dda`.

| Skill | Owns | Key rule |
|---|---|---|
| `disciplined-data-analysis` (orchestrator) | stage map, gates, friction contract, `dda start` | no data before lock; scripts check, agents don't grade themselves |
| `intake` | stage 0 | question + decision in one sentence each |
| `define` | stages 1–2, spec template, rung/tier, prior exposure | metrics by pin only; tier triggers apply |
| `definitions` | registry lookup and proposals | agent never edits the registry |
| `goldfish-review` | stages 3 and 7, packet, brief, recording | packet files only, read-only tools, templated brief |
| `lock` | stage 4, hash, ledger, amendments, `dda meta` | post-data locks are labelled post-data |
| `profile` | stage 5, snapshot or fingerprint | aggregates only; mismatch becomes amendment |
| `analyze` | stage 6, kernel use, variant scripts, ledger, ponytail economy | every data run carries a variant id |
| `verify` | stage 7, clean reproduction, drift, chain check | replay the saved script, never notebook state |
| `correct` | correction capture, eval matching and replay | matching is mechanical |
| `report` | stages 8–9, footer, archive, gitcheck | labels at point of claim; no data in git |

Study rung: each milestone is `.analysis/milestones/<m>/` with its own
spec, lock, and ledger. `dda start --milestone <m>` selects which lock
governs the session, one active milestone per session.

Reused from the sibling instead of duplicated (ponytail): `research`
(doc reading and read.log), `debug` (reproduction failures), `version`
(commit conventions). Referenced, not required — the plugin works
standalone with a short fallback paragraph in each skill.

Templates: `spec.md`, `spec.glance.md`, `wayfinder.md`, `footer.md`,
`definition.md`, `correction-case.md`, `goldfish-packet.md`, `variant.py`,
`variant.sql`, `config.yaml`, `gitignore`.
References: `economy-tier-ladder.md`, `review-rounds.md`,
`enforcement-matrix.md`, `kernel-policy.md`, `threat-model.md`.

## 13. Enforcement matrix (prevent / detect / disclose)

| Rule | Prevent (hook/kernel) | Detect (gate; S unless noted) | Disclose (footer) |
|---|---|---|---|
| No data before lock | `lockguard` (all tools), kernel audit hook | G4 scan of `runs.log` and audit log | lock label, prior exposure |
| Spec edits after lock are amendments | `lockguard` hash match, `driftnudge` | G4 recompute, lock commits | amendment and post-data counts |
| Evidence not edited | `evidenceguard` | chain verify against mirrored heads | chain status |
| Config not edited to dodge rules | `evidenceguard` | config hash in lock | via lock hash |
| All variants logged | `runlog`, kernel-only data path | G6 orphan-run check | N tried / K reported |
| Definitions human-owned | `defguard` | content-hash pins at G1/G4/G8; G7 round 4 (G) | pins, provisional flag |
| Raw data immutable | `rawguard`, audit hook | G7 snapshot re-check | snapshot hashes |
| Approvals genuine | `lockguard` and `evidenceguard` on signing and `approvals/` | `dda approved` signature check | verified / unverified |
| Tier honest | G2 triggers | human tier approval (H) | tier confirmed by |
| Goldfish isolated | read-only packet tools, templated brief | recorded from session state with packet and brief hashes | goldfish session ids, models |
| Reports carry true provenance | `footercheck` (reports, `answer.md`, publish channels) | G8 value recompute | the footer itself |
| Review depth matches risk | — | G3/G7 round records vs tier table | review field |
| Corrections not repeated | — | mechanical match + G7 replay | eval counts |
| Reproducible | kernel pinning, saved variant scripts | G7 fresh-kernel replay within tolerance | env hash, seed, reproduce command, drift |
| No data or secrets in git | `.gitignore`, blob scrubber | `dda gitcheck` at lock and G9 | — |
| Hooks actually ran | — | heartbeat vs session tool-call count; audit-log cross-check | hook faults |

Bypass handling: any gate that passes despite a detected hook fault is
recorded `pass (hook fault: <name>)` and appears as a footer caveat. An
**unrecorded bypass** is now falsifiable: a tool call or kernel file open
that the session state, heartbeat, or audit log shows, but that no gate
flagged.

**1.0 bar:** the phase-0 red-team suite (§14) passes or every miss is a
documented caveat; then three real analyses (one per tier) run through the
full pipeline with zero unrecorded bypasses, zero chain failures, and zero
hook false-positive blocks left unfixed.

## 14. Build order

0. **Red-team harness first.** Before any gate is trusted, a script tries
   these on this Hermes install: a data read before lock through
   `terminal`, `execute_code`, `read_file`, `search_files`, `web_extract`,
   `tool_call`, the browser, a kernel variable path, and a `config.yaml`
   edit; editing `runs.log` and `spec.lock`; forging an approval file and
   an unsigned approval commit; a goldfish subagent reaching chat history
   or data. It also checks whether hooks fire in subagent sessions and
   whether `tool_call` exposes the inner tool name to hooks. Each outcome
   is recorded as prevented, detected, or missed. Every miss gets a
   mechanism or becomes a documented caveat in `threat-model.md`.
1. Orchestrator, templates, config, and `dda start` (session binding).
2. `lock`, `runlog` with heartbeat, `lockguard`, `evidenceguard`, and
   hash chains (gap 1 first).
3. Kernel runner with audit hook, `dda meta`, variants, specs-tried
   ledger, and the orphan check.
4. Approvals (`dda approve` / `dda approved`, signing setup in
   `dda doctor`).
5. `footercheck`, `dda footer --check`, `report`, and `dda gitcheck`.
6. `definitions`, `defguard`, and content-hashed pins.
7. `goldfish-review` (packet, toolset, recording).
8. `verify` (snapshots, fingerprints, replay, drift).
9. `correct` and evals.

## 15. Decisions

1. **Repo location: DECIDED 2026-10-27** —
   `C:\Users\bmtrn\disciplined-data-analysis`, git initialized, remote
   `bmtrnavsky/spec-driven-data-analysis`. Same layout and update contract
   as the sibling (shipped read-only, `user/` overlay).
2. **Definitions registry home: DECIDED 2026-10-27 — per-project.**
   Shared only when a second lane needs the same definitions.
3. **Blocking hooks: DECIDED 2026-10-27 — blocking.** This departs from
   the sibling's nudge-only stance. After review the blocking set is five:
   `lockguard`, `evidenceguard`, `rawguard`, `defguard`, `footercheck`.
4. **Kernel: DECIDED 2026-10-27 — Jupyter.** Revised after review: "full
   tool access" now means full Python inside an audit-hooked kernel that
   is the only post-lock data path (§10). The kernel's isolated
   environment ships the full data stack (pandas, numpy, scipy,
   scikit-learn, matplotlib, etc.), never a trimmed subset (§10.1a),
   per Brad 2026-10-27. **Needs Brad's confirmation of the rest of the
   revision.**
5. **Glance-rung lock: DECIDED 2026-10-27 — always lock, even glances.**
   To offset the friction, a DECIDE glance uses the reduced review row
   (§5.3).
6. **Goldfish execution: DECIDED 2026-10-27 — temp subagent.** Revised
   after review: read-only packet tools, templated brief, output recorded
   from session state (§5.0), instead of full tool access. **Needs Brad's
   confirmation of the revision.**
7. **Approval mechanism: OPEN.** Proposed: signed git commits with a key
   that needs a passphrase on each use (§4.5). Brad either sets up a key
   or accepts that approvals are recorded as unverified.
8. **Second-goldfish model: OPEN.** Which second model or provider gives
   PUBLISH-tier independence (§5.0).

## Appendix A. Blind review (deleg_1df92e5a) → changes

| # | Finding | Resolution |
|---|---|---|
| 1 | Evidence and config unguarded; gates self-attested | `evidenceguard` (§6.2); hash chains with mirrored heads (§4.4); config hash in lock (§4.2); script-checked gates (§3) |
| 2 | Jupyter with full tool access contradicts §10 | Threat model (§0.1); kernel-only data path, audit hook, display masking (§10); decision 4 revised |
| 3 | `lockguard` matcher incomplete | All tools incl. `search_files`, `web_extract`, `tool_call`, browser; URL and tool-pattern roots (§6.1) |
| 4 | Goldfish isolation broken | Read-only packet tools, templated brief, output recorded from session state, different models (§5.0); decision 6 revised |
| 5 | Approvals forgeable; no-human contexts undefined | Signed approval commits (§4.5); stop-and-park (§3.2) |
| 6 | Post-data amendment launders exploratory results | `post-data-locked` label; rounds 1+3 plus human at DECIDE+; cap; spec versions count as variants (§3.1) |
| 7 | Agent sets its own tier | Mechanical triggers, human confirmation, raise/lower rules; tier stored only in spec (§2.2) |
| 8 | Pre-lock boundary undefined | Metadata-only allowance via `dda meta` (§3.3) |
| 9 | Prior exposure not covered | Required declaration, lock label, pre-lock block on derived data and earlier reports (§4.1) |
| 10 | "Amendment pending" loophole | Removed; reads need an exact hash match (§3.1, §6.1) |
| 11 | Definition pins lack a content hash | `name@version#hash`, recomputed at G1/G4/G8 (§7) |
| 12 | G7 contradicts itself; live sources | Reproduction vs drift split, fingerprints, declared tolerance (§10.3) |
| 13 | Nothing to replay | Code blobs and variant scripts; replay the script, not notebook state (§4, §10.3) |
| 14 | Hook-fault detection impossible | Heartbeat vs session tool-call count, audit-log cross-check (§6.8) |
| 15 | Footer checks presence, not truth; other channels | Value recompute (§8); publish-channel matcher; checked `answer.md` (§6.5) |
| 16 | Stop-and-ask list incomplete | Complete list (§3.2) |
| 17 | DECIDE glance too heavy | Reduced DECIDE-glance row (§5.3) |
| 18 | Variant definition left to judgment | Variant key from structured header; orphan runs; connector SQL logged; dashboard numbers labelled (§4.3) |
| 19 | Eval matching by agent; suite not deterministic | Mechanical trigger matching; review questions kept separate (§9) |
| 20 | "All committed" commits data | Committed/never lists, `.gitignore`, `dda gitcheck` (§11) |
| 21 | Concurrency and scope undefined | Session binding, per-workdir locks, milestone directories (§6.0, §12) |
| 22 | Credentials in logs | Aliases only, scrubbed blobs, vault/env references (§10.4) |
| Low | Stale text | Decision 1 marked decided; stale §7/§10 cross-references removed; decision 3 cleaned up; EXPLORE rounds named; principle headings fixed |
