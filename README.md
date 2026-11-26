# A data analyst that shows its work

![Spec Driven Data Analysis](docs/social-preview.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Hermes Plugin](https://img.shields.io/badge/Hermes-Plugin-teal.svg)](https://hermes-agent.nousresearch.com/docs)
[![Version](https://img.shields.io/badge/version-0.9.6-orange.svg)](docs/CHANGELOG.md)

## What it does

Spec Driven Data Analysis makes an AI's data work checkable.

Ask an AI for a number and you get one, stated with confidence. You cannot see
which question it answered, which rows it dropped, or whether the method was
chosen before or after the first result looked good. This pack changes the
order of events. You write the question down, and the way it will be answered,
before the data is opened. The work then runs through one controlled path, and
a reviewer with no memory of the build checks it before the number reaches you.

The ordering is the point. A locked plan does not make a model honest. It makes
a convenient choice visible afterwards. So the question being checked is not
whether the model is clever. It is whether the answer was chosen before or
after the number appeared.

The pack is for anyone who has to hand a number to another person and defend
it, without being a data engineer. Strict checklists for analysis exist, but
they are written for engineers: gate codes, file trees, a pipeline you have to
operate yourself. This one is written for the person who stands behind the
result.

It is a plugin: built for Hermes, portable to any agent that can load skill
files.

## How it works

One loop per question, or per milestone of a larger analysis:

    Intake -> Define -> Economy+Tier -> Teardown -> LOCK -> Profile -> Analyze -> Verify -> Report -> Archive

In plain words:

**Before the lock** you and the agent work in the open. Research, read
documentation, shape the question. Nothing is frozen and nothing is at risk.

**The lock is the hinge.** The spec — the question, the definitions, the
sources, and the plan for answering it — is fingerprinted and committed to
git. A fingerprint is a short code computed from the text, so any later edit
produces a different one. From that moment the question is fixed, and so is the
evidence about it.

**After the lock the runner is closed.** Data reads go through a single
controlled path. Every run gets an id. Each version of the analysis script (one
version is called a variant) freezes the first time it runs. Research access is
gone, because the point is that you can no longer go looking for a friendlier
answer.

**The reviewer has no memory of the build.** The project calls it the goldfish.
At teardown, and again after results, a separate context reads a packet of
evidence and reports what it sees. It cannot edit the spec, cannot run
anything, and cannot approve its own work. Forgetting is the point.

**The evidence is append-only.** It lives in `.analysis/`. Each entry records
its position in the list and the fingerprint of the entry before it. Entries
can be added, never edited. Change something in the middle and the chain says
so.

What the loop refuses: no changing the question after seeing the answer, no
number that cannot be re-run, no self-grading by the builder, no dropped failed
approaches. It also refuses re-running until something looks green, an approval
without a recorded yes, data reads around the runner, and any chart without a
path back to a locked spec and a recorded yes.

Each refusal is tested, not asserted: `python scripts/test.py fast` (product
tier), `python scripts/test.py full` (425 tests), `python redteam/run.py`
(GREEN means every prevention held), `python -m tests.revert validate --matrix`
(probe certifications). Full pipeline, checkpoint table, and the reasoning
behind each rule: [SPEC.md](SPEC.md).

## Stakes-aware, not one-size-fits-all

Every job gets a tier. **EXPLORE** means looking around, nothing at risk.
**DECIDE** means a choice gets made on this answer. **PUBLISH** means it goes to
someone else. The tier sets how much review is required, whether you have to
say yes first, and how much evidence has to exist. A glance gets one line of
plan. A decision that costs real money gets the full chain and an independent
second opinion.

The agent cannot lower its own tier to skip the reviewer. Setting the tier too
low is the cheat that matters most, so it is the one the checks watch hardest.

## How to use it

**Install.** Paste this to your agent:

> Install the spec-driven-data-analysis plugin, then use it for my next
> analysis. Write the question down first, and do not open the data until I say
> the spec is right.

Or install it yourself with `hermes plugins install spec-driven-data-analysis`.
Update with `hermes plugins update spec-driven-data-analysis`. Never copy a
folder over an install: that moves you off the reviewed version.

**Ask your question.** Say what number you need and who it is for, in one
sentence. The agent runs the loop and stops wherever a person has to be on the
hook: the spec, the tier, the setup, the report. It does not pass one of those
on its own say-so.

**Say yes.** When the run stops for you, the agent shows one command and waits.
You run that command in your own terminal, quoting the words you said:

```bash
python scripts/dda.py approve spec --yes "yes, lock it"
```

What gets recorded is the exact wording, who said it, when, and the fingerprint
of the exact thing approved. That record is the approval. There is no password
and no signing key. The trade is deliberate and written down in
[SPEC.md](SPEC.md) §4.5: a record cannot prove who typed it, but a deleted
record shows up in the chain. Until you say yes the run parks, and it resumes
from the point where it stopped. The agent never approves its own work.

**What good output looks like.** `dda verify-chain` reports `chains: ok`. `dda
verify` re-runs the locked script against the snapshot (the frozen copy of the
data taken at lock time) and compares the results. `dda approved` reads your
recorded yes back and prints the verdict for the exact thing you approved.

Every command and every gate: [SPEC.md](SPEC.md). Engineers: gates, build
phases, and accepted risks live in [docs/HARDENING.md](docs/HARDENING.md).

Sibling project:
[disciplined-vibe-coding](https://github.com/bmtrnavsky/disciplined-vibe-coding)
applies the same discipline to code: define before building, test before
shipping, verify before claiming done.

## Layout

Python 3.11 or newer, standard library only. A workdir (the folder holding one
analysis) must live inside a git repo, because that is where the lock is
committed.

    SPEC.md               the design, the checkpoint table, and the reasoning behind each rule
    __init__.py           plugin entry point: registers every skills/*/SKILL.md
    scripts/dda.py        the command line tool; Python 3.11+, standard library only
    scripts/dda.cmd       the same commands on Windows
    scripts/ddalib/       gates, evidence chains, the runner, reviews, approvals
    templates/            spec, config, review packet, wayfinder, correction case
    skills/correct/       the correction skill used by evals
    hooks/                optional Hermes hook wiring
    tests/                product tiers, adversarial probes, probe certifications
    redteam/              prevention harness; GREEN means every prevention held
    docs/TESTING.md       what each test tier answers and when to run it

## License

MIT. See [LICENSE](LICENSE).
