---
name: disciplined-data-analysis
status: spec draft, second reshape after blind re-review; build phases 0–5 implemented (see README)
version: 0.3.0-spec
date: 2026-10-27
sibling: C:\Users\bmtrn\disciplined-vibe-coding (v0.2.0)
sources: Turing pipeline structure (disciplined-vibe-coding), Elephant-Goldfish Model (Google, Apache 2.0), ponytail economy (DietrichGebert/ponytail, MIT), gap survey deleg_6fc04e39, blind review deleg_1df92e5a (22 findings, all addressed — see Appendix A), blind re-review deleg_37619031 (8 blockers, all addressed — see Appendix B)
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
| 3 | Reviewer shares the analyst's context and blind spots | Goldfish review as a one-shot, no-tools model call on an inlined packet and a templated brief (§5) |
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
- Evasion is made **detectable**: the kernel audit hook and reader
  wrappers log real file opens and socket connects regardless of tool-input
  text (§10.1), evidence files are hash-chained under a file lock (§4.4),
  and locks are git commits (§4.2).
- Native code that is neither wrapped nor locked down (§10.1b) is outside
  both prevention and detection, and the footer says so.
- Hooks bite only sessions bound to a workdir with `dda start` (§6.0).
  Everything else Brad does in Hermes is untouched; reads of a project's
  roots from unbound sessions are logged and labelled, not blocked.
- Whatever is neither prevented nor detected is **disclosed** in the footer
  as a caveat. The spec never claims prevention where only detection exists.
- Phase 0 of the build (§14) is a red-team test that measures which of
  these claims hold on this Hermes install before any gate is trusted.

## 1. Cast and principles

- **Elephant** — the analyst (you plus the agent with full conversation
  context). Drafts the spec, runs the analysis.
- **Goldfish** — a one-shot model call with no tools, made by `dda`. It
  sees only the packet, inlined into the prompt: spec, lock, definitions,
  specs-tried ledger, outputs, provenance. Never the chat, memory, RAG, or
  data, because nothing else is in the request. Catches unstated
  assumptions and story-fitting.
- **Human** — owns definitions and `config.yaml`, confirms tier at DECIDE+,
  approves the spec and the config at DECIDE+, signs off at PUBLISH, and
  is the only source of corrections. Human acts are recorded as artifacts the agent
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
| 3 | Teardown (pre-data) | `goldfish-review` | `.analysis/reviews/goldfish/teardown.md` | G3: tier-scaled rounds recorded from `dda review run` calls (§5.0); at DECIDE, a human spec approval for this spec hash (verified, or unverified and disclosed); at PUBLISH, verified only (§4.5) | S, G, H |
| 4 | Lock | `lock` | `specs/vN.md`, `spec.lock`, ledger entry, git commit | G4: lock hash recomputes (spec + definition pins + config hash + source aliases); a `config` approval exists for this config hash, signed through the approver chain (§4.5; verified required at DECIDE+, unapproved config disclosed at EXPLORE); evidence chains verify; `runs.log`, the audit log, and the unbound-access log (§6.0) show no non-metadata reads of these aliases before this lock, otherwise the lock is labelled post-data | S, K, H |
| 5 | Profile (first data contact) | `profile` | `.analysis/profile.md` | G5: snapshot or fingerprint recorded per source (§10.3); schema compared with declared expectations; mismatch filed as amendment | S, A |
| 6 | Analyze | `analyze` | variant scripts, outputs, `runs.log`, `specs-tried.jsonl` | G6: every data-touching run maps to a variant id (no orphan runs); every kernel record is IPC-imported with a policy hash bound to the run's lock hash and pairs with a parent-appended `kernel-start`; every variant beyond the locked one has a ledger entry with a reason; hook heartbeat complete (§6.8) | S, K |
| 7 | Verify | `verify`, `goldfish-review`, `correct` | `.analysis/verify.md` | G7: locked variant reproduces from its saved script in a fresh kernel within declared tolerance against the snapshot; source drift recorded separately (§10.3); matched correction evals pass; post-result goldfish rounds recorded (§5.2) | S, G |
| 8 | Report | `report` | `reports/<slug>.md` or `.analysis/answer.md` | G8: footer values recompute from lock, ledgers, runs, profile, reviews, approvals (§8); `exploratory` and `post-data-locked` labels present at point of claim; at PUBLISH, verified human sign-off for this report hash | S, K, H |
| 9 | Archive | `report` | ledger closed, commit, push | G9: spec, lock, ledger, verify, report committed together; `dda gitcheck` finds no data or secrets staged (§11); evidence chains verify; Wayfinder closed; `dda release` unbinds every session and deregisters the workdir's roots (§6.0) | S |

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
9. A PUBLISH gate (G3 or G8) has only an unverified approval (§4.5).
10. The approver chain fails to verify, or `dda doctor` downgrades
    approvals because a signing key is reachable from the agent (§4.5).

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
.analysis/                    guarded: agent writes allowed only on the paths marked `agent` in §6.2
  config.yaml          C  data-root aliases, kernel policy, PII columns, default tier, publish channels, approver keys (human-owned)
  spec.md              C  current spec (working copy, agent-editable)
  specs/vN.md          C  every locked version, written only by `dda lock`
  spec.lock            C  version, lock hash, timestamp, definition pins, config hash, tier, rung, label
  ledger.md            C  lock/amendment history, hash-chained
  specs-tried.jsonl    C  every analytic variant run, hash-chained
  runs.log             C  every tool call and kernel execution, append-only, hash-chained, no data values
  runs/blobs/<hash>    C  exact code/query text of each run, secrets scrubbed
  variants/<id>.py|sql C  runnable script per variant (what Verify replays)
  audit.log            C  kernel audit and reader-wrapper events, hash-chained, aliases only (§10.1)
  approvals/           C  one signed file per human approval, committed by the human (§4.5)
  approvals.index.jsonl C verified-approval index written by `dda approved`, hash-chained
  profile.md           C  aggregate snapshot facts only, written by `dda profile` — no rows, no samples
  reviews/goldfish/    C  goldfish outputs, written by `dda review run`
  reviews/self/        C  EXPLORE self re-reads, written by the agent, labelled `self`
  notes/               C  agent prose: profile and verify interpretation, scratch reasoning
  verify.md            C  reproduction evidence, drift, eval results, written by `dda verify`
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
- **Freeze on first run.** The agent writes `variants/<id>.py|sql`.
  The first `dda run` under that id records the script's body hash in
  `specs-tried.jsonl`, and from then on `evidenceguard` blocks edits to
  that file. A changed script is a new variant id. `dda gate G6` fails
  any run whose script body hash differs from the frozen one.
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

- `runs.log`, `audit.log`, `ledger.md`, `specs-tried.jsonl`, and
  `approvals.index.jsonl` are append-only JSON lines. Each line carries
  `seq` and `prev`, the SHA-256 of the previous line. `dda verify-chain`
  checks every chain. (`approvals/` itself is not a chain: it holds one
  human-committed file per approval, §4.5.)
- **One appender, one lock.** Hermes runs batched tool calls
  concurrently, so several hooks and the kernel can append at the same
  moment. Every writer (hooks, `dda`, the kernel audit hook) appends
  through the same function, `dda.chain.append(file, record)`, which:
  1. takes an exclusive OS lock on `<file>.lock` (`msvcrt.locking` on
     Windows, `fcntl.flock` elsewhere), waiting at most 2 seconds;
  2. reads the last line, sets `seq = last.seq + 1` and
     `prev = sha256(last line)`;
  3. writes the line with one `write` call, flushes, fsyncs;
  4. updates the heads mirror while still holding the lock, then
     releases it.
- Lock timeout: a `pre_tool_call` hook that cannot get the lock blocks
  the call with "evidence log busy, retry" (fail closed for bound
  sessions). A `post_tool_call` hook writes the record to
  `<file>.spill/<pid>-<n>.json` instead. `dda` merges spill files into the
  chain under the lock on its next run and logs the merge. A spill file
  that is still unmerged at a gate is a hook fault (§6.8).
- The kernel never appends to a chain: it writes audit events to its IPC
  event file outside the workdir, and the `dda run` parent imports them
  into `audit.log` (plus `kernel-launch`/`kernel-start`/`kernel-stop`)
  through the locked appender after the subprocess exits. Kernel traffic
  therefore never contends for a chain lock, and a kernel that crashes
  mid-run leaves its already-written events for the parent to import.
- Kernel audit traffic lands in `audit.log` (via the parent's IPC
  import), not `runs.log`, so hook traffic and kernel traffic do not
  contend for one lock.
- On each append, the chain heads are mirrored to
  `~/.hermes-home/dda/heads/<workdir-id>.json`, which is also guarded. A
  truncated or edited log fails verification against the mirror. The
  mirror sits in the same trust domain as the logs, so it catches slips,
  not a deliberate rewrite of both; the pushed git history (G9) is the
  stronger backstop.
- `evidenceguard` (§6.2) blocks agent writes to all of the above. Hooks
  and `dda` are the only writers.
- A chain failure is a stop-and-ask case (§3.2) and a footer caveat.

### 4.5 Human approval artifacts

An approval must be something the agent cannot produce.

- **Format.** An approval is a git commit, made by an approver in their
  own terminal with `dda approve <kind> <artifact>`, that adds exactly one
  file, `.analysis/approvals/<kind>-<artifact-hash>.json`, and is
  **signed**. Kinds: `tier`, `spec`, `amendment`, `signoff`,
  `definition`, `correction`, `config`. These files are not a hash chain.
  When `dda approved` verifies one, it appends the commit sha, signer
  fingerprint, kind, and artifact hash to the chained
  `approvals.index.jsonl` (§4.4), so a later deletion is visible.
- **Approver chain (root of trust).** Approver keys live in
  `config.yaml` under `approvers`, which only a string-match hook guards,
  so the key list is never trusted on its own:
  - The first `config` approval is trust-on-first-use. `dda init` prints
    the approver fingerprints, Brad confirms them, and he signs that
    first config approval himself. The fingerprints also go in every
    footer, so a foreign key shows up where Brad reads.
  - Every later config whose `approvers` block differs must be approved
    by a key from the **previous** approved set. `dda approved` walks the
    chain from the first config approval to the current config hash; a
    key added without a signature from an earlier key fails the walk.
  - G4 requires a `config` approval for the exact config hash being
    locked (§3). A slipped config edit changes the hash, so data reads
    block until a human approves the new config.
  - Kernel package additions (§10.1a) live in `kernel.yaml`, outside the
    config hash, so adding a library needs neither a config approval nor
    a re-lock. The kernel environment hash still goes in the footer.
- **Keys the agent cannot use.** A verified approval needs a signing key
  that the agent cannot drive. Preferred: an SSH `ed25519-sk` (FIDO2)
  key that needs a physical touch for every signature. Otherwise a GPG
  key with a passphrase and no cache. `dda doctor` checks this and,
  where it fails, **downgrades every approval to unverified** (a fail,
  not a warning) until fixed:
  - `gpg-agent`: the effective config (`gpgconf --list-options
    gpg-agent`) must have `ignore-cache-for-signing`, or
    `default-cache-ttl 0` and `max-cache-ttl 0`. The default 600-second
    cache fails.
  - `ssh-agent`: `ssh-add -l` (fingerprints, with `-L` as fallback) must
    not list a non-`-sk` approver key — matched exact-only against the
    approver fingerprints — on any agent the Hermes shell can reach: `SSH_AUTH_SOCK`, the Windows
    OpenSSH agent service (`\\.\pipe\openssh-ssh-agent`), Pageant, and
    1Password's agent. A running Windows `ssh-agent` service holding the
    key fails.
  - Git signing config: `commit.gpgsign` and `tag.gpgSign` must be
    false (or unset) in every scope that applies to the workdir, and
    `user.signingkey` must not name an approver key in those scopes.
    Auto-signing would sign agent commits without `-S`, which `lockguard`
    cannot see. `dda approve` passes `-S` and the key explicitly, so the
    human loses nothing.
- **`dda`'s own commits** (`dda lock`, G9) always run as
  `git -c commit.gpgsign=false -c tag.gpgSign=false commit …`, so they
  never prompt, never hang under cron, and never borrow an approver key.
- `dda approved <kind> <artifact>` checks: the signature
  (`git verify-commit`); the signer against the approver chain; that the
  commit adds only that one approval file; that it is reachable from the
  current branch; that the artifact hash matches the current artifact
  (an approval of spec v2 does not cover v3); and that `dda doctor`'s
  key checks pass now.
- `lockguard` blocks agent runs of `git commit -S`, `git tag -s`,
  `git -c commit.gpgsign=true`, and `dda approve`, and `evidenceguard`
  blocks agent writes to `approvals/` and `approvals.index.jsonl`.
- **Unverified approvals.** With no key, or after a doctor downgrade,
  an approval file can be committed unsigned. It is recorded as
  **unverified** and the footer says "human approval unverified (agent
  could have produced it)". Unverified satisfies G3 and G4 at DECIDE,
  with that disclosure. It **never** satisfies any gate at PUBLISH: a
  PUBLISH analysis with only unverified approvals parks (§3.2, case 9).

## 5. Review rounds (elephant / goldfish)

### 5.0 Goldfish isolation

Hermes's `delegate_task` cannot restrict a subagent's tools: children
inherit the parent's toolsets minus a short fixed list, so a delegated
goldfish would have terminal, code execution, web, `tool_call`,
`chat_history_lookup`, and RAG. The goldfish is therefore **not a Hermes
subagent**. It is a single model request made by `dda`, with no tools in
the request at all. Isolation comes from what is in the request, not from
policing what a session does.

- **Packet.** `dda packet <stage>` assembles a fixed file set: spec, lock,
  definition excerpts, plus (post-result) profile, specs-tried ledger,
  aggregate outputs, draft report, and footer. No data files, no
  `derived/`, no raw rows. The packet is stored under
  `.analysis/packets/<packet-hash>/` (committed, so it outlives scratch
  pruning) and its hash is recorded. A packet over the size cap (config
  `goldfish_max_tokens`, default 150k tokens) fails with the file list
  and sizes; the agent trims outputs or splits rounds, it never drops
  the spec or lock.
- **Call.** `dda review run <stage> [--model <id>]` sends one request to
  the provider API directly (not through the Hermes agent loop):
  system prompt = the `goldfish-packet.md` template, user message = the
  packet inlined as delimited files, `tools` empty, no memory, no
  context files, no hooks, no prior turns. The API key comes from the
  Hermes vault or env by name (§10.4). There is nothing for the goldfish
  to call, so there is nothing to scope.
- **Brief.** `dda` fills the template with only the stage and the round
  list (including matched correction-eval questions, §5.1). The elephant
  cannot add prose. Because `dda` builds the request, the recorded
  brief hash is the hash of the bytes actually sent.
- **Recording.** `dda review run` writes the full request hash, response,
  model id, provider request id, packet hash, brief hash, and token
  counts to `reviews/goldfish/` and appends a `review` line to
  `runs.log`. **Every** call is recorded, including failed or
  unfavourable ones. G3 and G7 count every call for the packet and
  stage, so the elephant cannot re-roll until it gets a pass ("goldfish
  shopping"): a round passes only if the latest call passes and every
  earlier call's objections are answered in the review file.
- **Independence.** The two goldfish at PUBLISH are two calls to
  **different models** when available (config `goldfish_models`). With
  only one model, the footer says "second goldfish: same model —
  correlated blind spots possible".
- **Fallback.** If no provider key is reachable from `dda`, goldfish
  rounds cannot run. Below PUBLISH they degrade to `self` re-reads with a
  footer caveat; at PUBLISH the analysis parks.

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
| DECIDE | glance | rounds 1 and 3, one goldfish call | rounds 1 and 2, one goldfish call | tier + spec approval (one signed commit) |
| DECIDE | quick-cut and up | all 5 rounds, goldfish call | all 5 rounds, goldfish call | tier + spec + config approval before lock |
| PUBLISH | quick-cut and up | all 5, goldfish + second goldfish on round 3 | all 5, two goldfish calls | tier + spec + config approval; signed report sign-off (all verified) |

Self re-reads are written to `reviews/self/` by the agent (the one
`reviews/` path `evidenceguard` allows) and labelled `self` in the footer.
Goldfish rows in this table mean `dda review run` calls (§5.0), not
sessions.

Round failure: fix the spec (pre-data) or the report/analysis
(post-result), and re-run only the failed round, at most once per round.
A second failure is a stop-and-ask case. Each round leaves one line in
`reviews/goldfish/` or `reviews/self/`.

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
Each fires only in bound sessions and is scoped by
`.analysis/config.yaml` to keep false positives rare, and every block
message says exactly how to unblock.

**Scope: hooks bite only bound sessions.** Hermes hooks are
profile-wide, so they see every session Brad runs: morning-brief,
`bt-post-publisher`, GA and WordPress stats, ordinary vault notes. The
plugin must not block any of that.

- **Binding.** Hooks never infer the workdir from `cwd`.
  `dda start <workdir> [--milestone <m>]` binds a session id to one
  workdir (and, for studies, one active milestone) in
  `~/.hermes-home/dda/sessions/<session-id>.json`. One binding per
  session; rebinding a session that has data reads needs `dda start
  --rebind`, which is logged in both workdirs' ledgers. If Hermes exposes
  the post-compression session lineage in the hook payload (phase 0
  checks), the binding follows it; otherwise the new session id must run
  `dda start` again.
- **Subagents inherit the parent binding.** Subagents are allowed. A
  child session whose parent session id is visible to `dda` (hook
  payload, or session lineage; phase 0 checks which) inherits the
  parent's binding unchanged: same workdir, same milestone, same lock
  hash, same ledger. The child gets no lock, ledger, or binding of its
  own and cannot rebind; every hook judges it exactly as it judges the
  parent, and its runs land in the parent workdir's `runs.log` with the
  child session id and `parent: <session-id>`. `dda start` from a child
  is refused.
- **Unbound children stay unbound.** A child that cannot be linked to a
  bound parent is treated as any unbound session: hooks do not block it,
  and `runlog` records its root matches in the unbound-access log. There
  is no late binding. The gate flags its output post-data: G4 labels the
  lock **post-data (unbound access)** if the child read a locked alias,
  and G6/G8 label any result, variant, or report claim that draws on an
  unbound child's output **post-data (unbound child)**, naming the child
  session in the footer.
- **Unbound sessions are never blocked.** For a session with no binding,
  every blocking hook returns `{}`. `runlog` alone still runs: if the
  tool input matches a root declared by an **active** workdir, it appends
  a line (session id, tool, alias, time) to
  `~/.hermes-home/dda/unbound-access.log`. It never blocks.
- **Detection instead.** G4 reads the unbound-access log. A read of one
  of the lock's aliases after the workdir was registered labels the lock
  **post-data (unbound access)**, and the footer names the sessions. The
  lock stores the log head as the `unbound` watermark
  (`heads/global.unbound-access.log.json`); G4 carries it, so lines the
  lock already judged are not re-reported and only newer lines count.
  This also catches workdir hopping: G4 checks the bound session's history
  and the logs of other active workdirs, with no shared-locator
  requirement — a session with data reads in two workdirs' `runs.log`
  files (a rootless hop), and any `rebind` ledger line for a session that
  read data anywhere, labels the lock **post-data (unbound access)** and
  names the session. A rebind with no data reads anywhere stays clean.
- **Bound sessions.** A data read by bound session S is judged only
  against the lock of S's workdir, and only for roots that lock lists.
  Two workdirs may analyze the same root; workdir A's lock never unlocks
  reads for B.
- **Release.** `dda release` (run by G9, or `dda abandon` for dropped
  work) unbinds every session bound to the workdir and marks it
  inactive. Both are **human-only**: every blocking hook refuses them
  from agent tool calls, because a release launders later reads (the
  roots leave the active set, so a re-lock afterwards looks clean). The
  release itself is ledgered — one `release` / `abandon` line naming the
  unbound sessions — so the laundering step stays in the chain.
  Inactive workdirs' roots are no longer matched by hooks, but the
  released workdir stays listed (registry `released` section) and its
  runs.log plus its release lines stay in the exposure/G4 scan: a
  finished analysis still counts as prior exposure for later sessions.
  `dda status`
  lists active workdirs and bound sessions; `dda doctor` warns about
  workdirs active for more than 14 days with no runs.
- **Fast exit.** The first thing every hook does is check
  `sessions/<session-id>.json` and the active-roots cache. An unbound
  session with no root match returns in well under the time budget
  (§6.9).

### 6.1 `lockguard` — pre_tool_call, BLOCKS

- Matcher: **all tools**. It inspects `terminal`, `execute_code`,
  `read_file`, `search_files`, `web_extract`, browser navigation, and
  `tool_call` (the inner tool name and arguments).
- Data-root aliases in config map to any of: paths, connection hosts, URL
  prefixes (dashboards, GA, WordPress stats), and deferred-tool name
  patterns (e.g. D1 or R2 query tools). A tool input matching any of them
  is a data read. Naming a root's direct parent directory counts too:
  listing the parent exposes the root, so `mentions_path` matches the
  parent one level up (deeper ancestors do not match, so `ls C:/Users`
  stays allowed).
- Before lock: block every data read except `dda meta` (§3.3), and treat
  `derived/` and earlier reports for the same aliases as data roots
  (§4.1).
- After lock: allow data reads only through the kernel runner
  (`dda run`) and declared connector tools, and only when
  `hash(spec.md)` and the config hash match the lock. Direct
  `read_file`/`search_files` on data roots stays blocked after lock,
  because that output would bypass masking (§10.2).
- Also blocks agent `git commit -S`, `git tag -s`,
  `git -c commit.gpgsign=true`, `dda approve` (§4.5), and
  `dda release` / `dda abandon` (§6.0, human-only).
- Applies to bound sessions only (§6.0). It never computes the lock hash
  on the hot path; it reads the cached lock state (§6.9).
- The block message names the fix: "Lock the spec (`dda lock`)",
  "Re-lock after your spec edit", "Use `dda run`", or "Approve the
  config (`dda approve config`)".

### 6.2 `evidenceguard` — pre_tool_call, BLOCKS

- Blocks agent writes, moves, deletes, and in-place edits (through
  `write_file`, `patch`, `terminal`, or `execute_code`) under
  `.analysis/**` and `~/.hermes-home/dda/**`, except the paths marked
  `agent` below. Every other file has exactly one named writer.

| Path | Writer | Check |
|---|---|---|
| `spec.md` | agent | lock hash (§4.2) |
| `wayfinder.md` (status prose) | agent | gate lines are recomputed by `dda gate`, never trusted (G9 reruns every gate) |
| `variants/<id>.py\|sql` | agent, until first run | frozen after first run (§4.3) |
| `answer.md` | agent | `footercheck` (§6.5) |
| `reviews/self/` | agent | labelled `self` in the footer |
| `notes/` | agent | not evidence; never cited by a gate |
| `profile.md` | `dda profile` | G5 |
| `verify.md` | `dda verify` | G7 |
| `reviews/goldfish/`, `packets/` | `dda review run`, `dda packet` | packet and brief hashes (§5.0) |
| `runs.log`, `runs/blobs/` | `runlog` hook, `dda` | chain (§4.4) |
| `audit.log` | `dda run` (parent, importing the kernel's IPC events) | chain (§4.4) |
| `spec.lock`, `specs/`, `ledger.md` | `dda lock` | lock commit, chain |
| `specs-tried.jsonl` | `dda variant`, `dda run` | chain |
| `approvals/` | human, via `dda approve` in their own terminal | signature (§4.5) |
| `approvals.index.jsonl` | `dda approved` | chain |
| `config.yaml` | human | config approval chain (§4.5) |
| `kernel.yaml` | agent or human | env hash in footer; outside the lock hash |
| `~/.hermes-home/dda/**` | `dda`, hooks | heads mirror, session bindings |

- `dda` subcommands pass through; they enforce their own rules.
- Applies to bound sessions only (§6.0); an unbound session writing into
  an active workdir's `.analysis/` is logged to the unbound-access log
  and fails the next chain or gate check.
- Detection backstop: chain verification (§4.4), lock commits (§4.2), and
  the config approval chain (§4.5).

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
- Scope: bound sessions only (§6.0). Within a bound session, a
  publish-channel call is checked only when its content or source path
  contains a report or answer from the bound workdir (matched by report
  slug, lock hash, or file path). An ordinary vault note in an unbound
  session, or an unrelated note in a bound one, is never touched.
- In a bound session, a publish-channel call carrying the workdir's
  report is also blocked when the tier is below PUBLISH or the verified
  sign-off is missing ("raise the tier and get sign-off first").
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
  variant id if any, and kind (`meta | data | other | blocked`). A post
  that carries a sibling hook's block signal — on the wire
  `extra.status: "blocked"` with the JSON-string result `{"error": msg}`
  (older/synthetic payloads: `blocked: true`, `decision/action: block`, or
  a block error) — is logged `blocked` with
  empty aliases: a blocked attempt never executed, so it must never count
  as exposure.
- Records aliases, never paths containing credentials or connection
  strings; blobs are scrubbed of secrets (§10.4). Never blocks.

### 6.7 `driftnudge` — pre_llm_call, advisory

- Injects one line when: the spec.md hash differs from the lock; more
  than N (default 5) exploratory variants exist since the last review;
  orphan runs exist; or a chain fails to verify. Emits `{}` otherwise.

### 6.8 Hook-fault detection (heartbeat)

- Every hook appends to a per-session heartbeat with a sequence counter,
  through the locked appender (§4.4).
- `dda gate` compares, per session, Hermes's recorded tool-call count
  (from session state) with `runlog`'s `seen` lines, `done` lines, and
  `lockguard` decisions. Any gap is a **hook fault** naming the hook and
  the tool calls it missed.
- The kernel audit log (§10.1, including reader-wrapper events, §10.1b) is an independent second source: a file
  open on a data root with no matching `runs.log` entry is reported as a
  hook fault or an evasion. Kernel events reach `audit.log` only through
  the parent's IPC import, so the pairing also proves the import ran:
  a `run` entry whose kernel record lacks the IPC marker, whose policy
  hash does not match the run's lock hash, or with no parent-appended
  `kernel-start` for its run id is a fabricated run and fails G6.
- A gate that passes despite a hook fault is recorded as
  `pass (hook fault: <name>)` and appears as a footer caveat.

### 6.9 Installation and approval

Hooks are declared in the profile `config.yaml` like the sibling's.
Install docs state: blocking hooks need first-use approval; gateway and
cron need auto-accept; `hermes hooks doctor` flags edits.

**Runtime and interpreter.** The hooks are not shell. `lockguard` needs
the lock state (normalized spec, definition content hashes, YAML config)
and `footercheck` calls `dda`, so all hooks are **Python**, in one entry
point `hooks/dda_hook.py <hook-name>` that shares code with `dda`.

- **Interpreter.** `dda install` creates the plugin's own uv venv
  (`<plugin>/.venv`, Python ≥ 3.11, PyYAML pinned; separate from the
  kernel venv in §10.1a) and writes each hook command with the
  **absolute** interpreter path, e.g.
  `C:/…/disciplined-data-analysis/.venv/Scripts/python.exe
  C:/…/hooks/dda_hook.py lockguard`. Nothing relies on `python3` or
  `python` on PATH (on this host `python3` does not exist, and a hook
  whose interpreter is missing fails open).
- **Fail closed inside, detect outside.** The entry point wraps every
  hook in a catch-all. For a bound session, an internal error in a
  blocking hook returns `block` with "dda hook error: <class>; run
  `dda doctor`"; for an unbound session it returns `{}`. Every exit path
  prints valid JSON. What the script cannot catch (interpreter missing,
  Hermes timeout) fails open in Hermes; the heartbeat (§6.8) detects it,
  and `dda doctor` verifies the interpreter path, the venv imports, and a
  dry-run of each hook.
- **Time budget.** Hook timeout is 5 seconds (as in the sibling). Target
  under 300 ms per call, measured in phase 0. Hooks never hash the spec,
  config, or definitions on the hot path. `dda` keeps a lock-state cache
  at `~/.hermes-home/dda/state/<workdir-id>.json`: lock hash, expected
  file hashes, and the mtime and size of `spec.md`, `config.yaml`, and
  every pinned definition. A hook recomputes a hash only for a file
  whose mtime or size changed, then updates the cache under the chain
  lock. An unbound session with no root match exits after two small file
  reads (§6.0).

`dda doctor` checks hook registration, the interpreter path, approver
key setup (§4.5), the active-workdir list, and that the heartbeat is
live.

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
| Kernel: environment lock hash, seed, network policy (enforced or detect-only, per library), audit-hook and wrapper status | kernel record |
| Reproduce: one `dda` command that regenerates outputs from the locked variant | variants/ |
| Review: rounds run, by whom (self / goldfish request ids and models / human), approver fingerprints, config approval status | reviews/, approvals.index.jsonl |
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

- Launched only by `dda run`, bound to the session's workdir, as a
  **separate locked subprocess**: its own process, started `-I -P` with a
  clean environment, carrying a frozen **policy snapshot** (aliases, roots,
  hosts, allowed dirs, lock hash, variant, run id, session, entry-script
  path) that the parent writes to a policy file **outside** the workdir and
  passes by path. The kernel never reads `spec.lock`, the ledger, or any
  other `.analysis` file to learn policy; the snapshot is frozen at spawn
  (a re-lock mid-run does not change the running kernel — the parent
  records the spawn-time lock hash on the run entry and G6 compares it).
- **Narrow IPC door, no ledger access.** The kernel holds no `.analysis`
  handle and appends to no chain. Its only outputs are (1) derived files
  under `derived/` or `outputs/`, (2) stdout/stderr tails captured by the
  parent, (3) a status file, and (4) an audit-event file — the last two
  written to a parent-owned IPC directory **outside** the workdir. The
  parent imports the event file into `audit.log` through the locked
  appender (§4.4) and writes the kernel record. The audit hook refuses
  every `open` under `.analysis` from inside the kernel except a
  read-only open of the entry script itself.
- A Python **audit hook** (`sys.addaudithook`) is installed at kernel
  start. It:
  - logs every `open` on a data-root path and every `socket.connect` to
    its IPC event file (imported by the parent into `runs.log` as
    `kind: audit` — never written directly), regardless of tool-input text;
  - refuses `open` on data roots when the lock is invalid, and refuses
    write-mode `open` on raw roots and snapshots;
  - refuses `socket.connect` to hosts not on the config allowlist;
  - logs subprocess spawns. Native extensions and subprocesses can
    bypass Python audit hooks; spawns are at least visible.
- The audit hook alone does **not** cover the mandated data stack:
  duckdb, polars, and pyarrow open files and sockets in native code that
  `sys.addaudithook` never sees. Those libraries are the main data path,
  so they get their own controls (§10.1b).
- On Windows this design has no OS-level read-only mount or firewall.
  Read-only and network-off are enforced by the audit hook, the native
  lockdown and wrappers (§10.1b), and `rawguard`. The footer reports
  `network policy: audit+wrapper-enforced` only when phase 0 and the
  kernel start check both pass; otherwise it reports `network policy:
  detect-only (runs.log/audit.log)` and names the unenforced path.
- Pinned environment (uv lockfile); its hash goes in the footer.
- Seeded randomness; the seed goes in the footer.

### 10.1b Native data libraries: lockdown and reader wrappers

The kernel bootstrap (`dda`'s kernel startup file, run before any user
code in the locked subprocess) reads only the parent-supplied policy
file — never the workdir's `.analysis` — applies these, and records each
one in the IPC status file for the parent to copy into the kernel
record. A step that fails stops the kernel, like a missing baseline
package (§10.1a).

- **duckdb.** The bootstrap replaces `duckdb.connect`, `duckdb.sql`,
  `duckdb.query`, `duckdb.read_*`, and `duckdb.default_connection` with
  versions that return a connection configured, in this order:
  1. `SET allowed_directories = [<bound workdir's raw roots>, derived/,
     outputs/]` (only when the lock is valid; otherwise only `derived/`
     and `outputs/` of this workdir);
  2. `SET autoinstall_known_extensions = false`,
     `SET autoload_known_extensions = false` (no `httpfs`, no `INSTALL`);
  3. `SET enable_external_access = false` (no other files, no network);
  4. `SET lock_configuration = true` (user code cannot undo 1–3).

  The wrapper also logs each statement's referenced paths to its IPC
  event file (parent-imported into `audit.log`) as aliases, and refuses `COPY … TO`, `EXPORT DATABASE`, and
  `ATTACH` whose target resolves under a raw root or snapshot (duckdb
  cannot make one allowed directory read-only). Raw-root mutation that
  slips past this is caught by the G7 snapshot re-check.
- **polars and pyarrow.** The bootstrap wraps the readers and writers
  that do their own I/O: `pl.read_*`, `pl.scan_*`, `DataFrame.write_*`,
  `LazyFrame.sink_*`; `pyarrow.parquet.read_table`/`ParquetFile`/
  `write_table`, `pyarrow.dataset.dataset`/`write_dataset`,
  `pyarrow.csv.read_csv`/`open_csv`, `pyarrow.feather.*`, and the
  `pyarrow.fs` remote filesystem constructors. Each wrapper resolves the
  path, checks lock validity and root membership exactly like the audit
  hook, logs to its IPC event file (imported by the parent into
  `audit.log`), refuses writes onto raw roots and snapshots,
  and refuses remote URLs (`s3://`, `gs://`, `http(s)://`, `az://`)
  whose host is not on the allowlist. pandas readers that route through
  pyarrow (`read_parquet`, `read_feather`, `engine="pyarrow"`) are
  covered by the same wrappers.
- **Belt.** The kernel process starts with `HTTP_PROXY`/`HTTPS_PROXY`
  pointing at a closed local port and `NO_PROXY` set to the allowlist,
  which many native HTTP clients honour. This is defence in depth, not a
  claim.
- **Limits, disclosed.** A cooperative agent uses these paths; a
  determined one can reach native I/O another way (ctypes, an unwrapped
  library, a subprocess). Those paths are detect-only at best and are
  listed in `threat-model.md`. Phase 0 tests every path named here; any
  that escapes downgrades the footer to `detect-only` for that library.

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
  drivers, domain libraries) via `.analysis/kernel.yaml`; additions go
  through the lockfile and change the environment hash, not the config
  hash (§4.5), so they never force a re-lock. A new library that does
  native I/O is detect-only until it has a wrapper (§10.1b). Baseline packages can be
  version-bumped but not removed.
- **Startup check.** At kernel start `dda run` imports every baseline
  package and records the resolved versions in the kernel record. A
  missing or unimportable baseline package fails the start; it is not a
  warning.
- **Footer.** The environment hash already covers the full package set;
  the kernel record lists baseline versions so a reader can see the
  stack was complete.
- **Security.** The full stack runs under the same audit hook,
  data-root guards, network allowlist, and display masking (§10.1,
  §10.2), plus the native lockdown and wrappers (§10.1b), which exist
  because the audit hook cannot see native I/O.

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
| `disciplined-data-analysis` (orchestrator) | stage map, gates, friction contract, `dda start` / `dda release` | no data before lock; scripts check, agents don't grade themselves; hooks bite only bound sessions |
| `intake` | stage 0 | question + decision in one sentence each |
| `define` | stages 1–2, spec template, rung/tier, prior exposure | metrics by pin only; tier triggers apply |
| `definitions` | registry lookup and proposals | agent never edits the registry |
| `goldfish-review` | stages 3 and 7, packet, `dda review run`, recording | one-shot no-tools call, packet inlined, templated brief, every call recorded |
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
| No data before lock | `lockguard` (all tools, bound sessions), kernel audit hook, native lockdown and wrappers (§10.1b) | G4 scan of `runs.log`, `audit.log`, unbound-access log | lock label, prior exposure |
| Spec edits after lock are amendments | `lockguard` hash match, `driftnudge` | G4 recompute, lock commits | amendment and post-data counts |
| Evidence not edited | `evidenceguard` | chain verify against mirrored heads | chain status |
| Config not edited to dodge rules | `evidenceguard` | config hash in lock; G4 config approval through the approver chain | config approval status, approver fingerprints |
| All variants logged | `runlog`, kernel-only data path | G6 orphan-run check | N tried / K reported |
| Definitions human-owned | `defguard` | content-hash pins at G1/G4/G8; G7 round 4 (G) | pins, provisional flag |
| Raw data immutable | `rawguard`, audit hook, duckdb/polars/pyarrow write refusals | G7 snapshot re-check | snapshot hashes |
| Approvals genuine | `lockguard` and `evidenceguard` on signing and `approvals/`; `dda doctor` key checks downgrade on failure | `dda approved` signature, approver chain, reachability | verified / unverified |
| Tier honest | G2 triggers | human tier approval (H) | tier confirmed by |
| Goldfish isolated | one-shot call with no tools, packet inlined, templated brief built by `dda` | every call recorded with request, packet, and brief hashes; G3/G7 count all calls | goldfish request ids, models |
| Reports carry true provenance | `footercheck` (reports, `answer.md`, publish channels) | G8 value recompute | the footer itself |
| Review depth matches risk | — | G3/G7 round records vs tier table | review field |
| Corrections not repeated | — | mechanical match + G7 replay | eval counts |
| Reproducible | kernel pinning, saved variant scripts | G7 fresh-kernel replay within tolerance | env hash, seed, reproduce command, drift |
| No data or secrets in git | `.gitignore`, blob scrubber | `dda gitcheck` at lock and G9 | — |
| Hooks actually ran | absolute-path interpreter, fail-closed entry point | heartbeat vs session tool-call count; audit-log cross-check; unmerged spill files | hook faults |
| Evidence chains intact under concurrency | locked appender (§4.4) | `dda verify-chain` | chain status |
| Brad's other sessions unaffected | hooks no-op for unbound sessions; `dda release` at G9 | unbound-access log feeds G4 | post-data (unbound access) label |

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
   an unsigned approval commit; an approval signed through a cached
   `gpg-agent` passphrase, a loaded `ssh-agent` key, and global
   `commit.gpgsign=true`; a config edit that adds an approver key. It
   also checks whether hooks fire in subagent sessions, whether
   `tool_call` exposes the inner tool name to hooks, and whether the
   payload carries parent-session or compression lineage. Added for
   v0.3:
   - **Native I/O:** `pd.read_parquet`, `pl.read_csv`, `pl.scan_parquet`,
     `pyarrow.dataset`, `duckdb.sql("select * from 'raw.csv'")`, duckdb
     `COPY TO` onto a raw root, duckdb `INSTALL httpfs` and a remote read,
     each before and after lock (§10.1b).
   - **Concurrency:** 50 batched tool calls plus a kernel writing
     `audit.log` at the same time; `dda verify-chain` must pass with no
     forked `prev`, no duplicate `seq`, and no lost spill file (§4.4).
   - **Hook runtime:** hook latency per call (target < 300 ms), a missing
     interpreter path, and an exception inside a blocking hook (§6.9).
   - **Scope:** an unbound session reading GA/WordPress stats, writing a
     vault note, and running `bt-post-publisher` while a workdir is
     active: zero blocks, unbound-access lines written; the same after
     `dda release`: zero lines (§6.0).
   - **Goldfish:** `dda review run` request has an empty tool list and
     no context beyond the packet; re-roll attempts are all counted.
   Each outcome is recorded as prevented, detected, or missed. Every miss gets a
   mechanism or becomes a documented caveat in `threat-model.md`.
1. Orchestrator, templates, config, `dda install` (plugin venv, absolute
   hook paths), the Python hook entry point, `dda start` / `dda release`
   (session binding and scoping).
2. `lock`, the locked chain appender, `runlog` with heartbeat,
   `lockguard`, `evidenceguard` with its writer table, and the lock-state
   cache (gap 1 first).
3. Kernel runner with audit hook, native lockdown and reader wrappers,
   `dda meta`, variants with freeze-on-first-run, specs-tried ledger, and
   the orphan check.
4. Approvals (`dda approve` / `dda approved`, approver chain, config
   approval at G4, key checks in `dda doctor`).
5. `footercheck`, `dda footer --check`, `report`, and `dda gitcheck`.
6. `definitions`, `defguard`, and content-hashed pins.
7. `goldfish-review` (packet, `dda review run` one-shot call, recording).
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
6. **Goldfish execution: REVISED 2026-10-27 — one-shot no-tools call.**
   The temp-subagent decision cannot be built: `delegate_task` gives
   children the parent's tools (re-review deleg_37619031, blocker 1).
   The goldfish is now a single provider request made by `dda`, with the
   packet inlined and no tools (§5.0). It keeps the intent of the
   original decision (a fresh, context-free reviewer) without the tool
   surface. **Needs Brad's confirmation.**
7. **Approval mechanism: OPEN.** Proposed: signed git commits through an
   approver chain, with an `ed25519-sk` touch key (preferred) or a GPG
   key with signing cache disabled (§4.5). Without a key, DECIDE runs
   with disclosed unverified approvals and PUBLISH parks.
8. **Second-goldfish model: OPEN.** Which second model or provider gives
   PUBLISH-tier independence (§5.0).
9. **Subagents: DECIDED 2026-10-27 — allowed, inherit the parent
   binding.** A linked child shares the parent's lock hash and ledger and
   is hooked as the parent. An unbound child stays unbound, and the gate
   labels its output post-data (§6.0).

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

## Appendix B. Blind re-review (deleg_37619031) → changes

The re-review found 8 blockers. All are addressed below. Its partial-fix
and smaller items are not all addressed in v0.3; the ones folded in are
noted.

| # | Blocker | Resolution |
|---|---|---|
| 1 | `delegate_task` cannot restrict subagent tools, so the goldfish inherits terminal, web, `tool_call`, chat history, RAG; packet scoping and brief hash unenforced | Goldfish is a one-shot provider call by `dda review run` with no tools and the packet inlined; brief hash is of the bytes sent; every call recorded and counted (closes "goldfish shopping"); packets committed, not in scratch (§1, §5.0, decision 6) |
| 2 | duckdb, polars, pyarrow do native I/O the audit hook never sees; `audit-enforced` footer would be false | Kernel bootstrap: duckdb `allowed_directories`, extension autoinstall/autoload off, `enable_external_access=false`, `lock_configuration=true`, COPY/EXPORT/ATTACH refusals; polars/pyarrow reader and writer wrappers; footer downgrades to `detect-only` for any path that escapes phase 0 (§10.1, §10.1b, §14) |
| 3 | `evidenceguard` blocks variants, `answer.md`, `profile.md`, `verify.md`, self reviews | Writer table: every `.analysis/` path has one named writer; agent paths are `spec.md`, `wayfinder.md`, variants until first run, `answer.md`, `reviews/self/`, `notes/`; `profile.md`/`verify.md` written by `dda` (§4, §4.3, §6.2) |
| 4 | Approver keys and config hash sit in a hook-guarded file; no gate needs a config approval | G4 needs a `config` approval for the exact config hash; approver chain (TOFU root, later key changes signed by a previous key); fingerprints in every footer; kernel packages moved to `kernel.yaml` outside the config hash (§3, §4.5, §10.1a) |
| 5 | `gpg-agent` cache, Windows `ssh-agent`, global `commit.gpgsign`, contradictory approvals format, unverified at PUBLISH unspecified | Doctor key checks downgrade approvals (fail, not warn); `ed25519-sk` preferred; `dda` commits with signing forced off; `lockguard` blocks `-c commit.gpgsign=true`; per-approval files plus a chained index; unverified ok at DECIDE with disclosure, never at PUBLISH (§4.4, §4.5, §3.2) |
| 6 | Hooks can't be dependency-free shell; interpreter unnamed; `python3` missing here; 5 s timeout | Python hooks in one entry point, absolute interpreter path into the plugin's own uv venv, fail-closed catch-all for bound sessions, lock-state cache keyed on mtime/size, 300 ms target (§6.9) |
| 7 | Concurrent hooks fork the hash chain (the kernel never appends: the parent imports its IPC events after exit) | One locked appender (`msvcrt.locking`/`flock`), `seq` assigned under the lock, spill files on timeout merged by `dda`, kernel traffic via parent IPC import; phase 0 concurrency test (§4.4, §14) |
| 8 | Profile-wide hooks block Brad's everyday sessions; no workdir release; vault matcher too broad | Hooks no-op for unbound sessions; unbound reads of active roots logged and labelled post-data at G4 (also catches workdir hopping); `dda release` at G9; `footercheck` matches publish calls only when they carry the bound workdir's report; rebinding logged (§6.0, §6.5, §3) |

Folded in from the partial/smaller lists: goldfish shopping (#4),
workdir hopping and rebinding (#6/9), publish-channel tier check (#7),
variant body-hash freeze (#18), stop-and-ask additions for unverified
PUBLISH approvals (#16), config-hash churn from kernel packages, heads
mirror overclaim, wayfinder gate lines recomputed, packet pruning.
Still open from the re-review: definition pins tied to signed approval
hashes (#11), as-of-bounded replay and float/row-order tolerance (#12),
connector `tool_call` variant ids and masking (#15, #18), PII scrubbing
of blobs, history-rewrite blocking before push, tier triggers that rely
on agent-written fields (#7), `dda meta` for URL roots, and the §3.1
hash wording.
