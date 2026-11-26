# Changelog

## 0.9.6 - 2026-11-26

Every version number now says the same thing.

- The plugin manifest, the CLI version string, the README badge, this changelog,
  and the git tag all read 0.9.6. Before this, the manifest and the CLI still
  said 0.9.4 after the 0.9.5 license fix shipped, so anyone who read the version
  from the manifest, or from a pin taken off it, named a release that was no
  longer current.
- No behavior changed. Nothing in the analysis path moved.

## 0.9.5 - 2026-11-26

The license is plain MIT again.

- `LICENSE` is the standard MIT text with one copyright line. Earlier drafts
  pointed at attribution files that were never in the repo, which made the
  license unreadable on its own. Nothing else changed.

## 0.9.4 - 2026-11-26

Approval got simpler by owner decision, and three ways around the checks were
closed.

- **An approval is now your yes in chat, recorded word for word.** The record
  holds the words, who said them, when, and a fingerprint of the exact thing
  approved. Passwords, signing keys, passphrases, Telegram message ids, and the
  approver chain are gone, along with `scripts/dda_relay.py`, the script that
  used to carry a Telegram confirmation in. Old signed records are refused as
  legacy; they are never read as a yes. The trade (a record cannot prove who
  typed it) is written down in SPEC section 4.5. Owner order, 2026-11-25.
- **A fake review can no longer pass.** Reviews produced by the test stub were
  noted and then counted. Now the gate refuses the stub call itself, however the
  session set its environment.
- **A shell wrapper can no longer hide a git command.** A command line passed
  through `bash -c "…"` used to slip past the git guard as one opaque token. It
  is now re-parsed, and name matching ignores case, path, `.exe`, and empty shell
  quotes, so `g""it clean -fdx` is still git.
- **README in plain language.** What it does comes first, jargon is defined where
  it appears, and the approval section matches the new model.
- **The correction skill now loads.** The pack shipped `skills/correct/` but had
  no entry point, so the host never registered it. A 15-line root `__init__.py`
  registers every `skills/*/SKILL.md`, and the plugin is loadable for catalog
  admission.
- Tests: 425 green on the full run, redteam GREEN, probe certifications
  re-minted.

## 0.9.3 - 2026-11-08

Approval relay hardened against the Opus review findings, plus a second approval channel.

- Digest pinning: an approval records the artifact digest it was granted against, so a
  changed artifact no longer reads as CONFIRMED.
- Replay gate: a reused message id or a replayed record reads as a bad signature, and a
  stale confirmation names no channel in the footer.
- Planted trailers are refused: the artifact must be the only file the record adds.
- Lockguard coverage extended across the relay paths.
- Chat channel: approvals confirm via Telegram or regular chat; signing keys stay
  reserved for the reviewer identity (SPEC section 15, decision 7 redirect).
- Reviewer independence wired: the approving identity cannot be the builder.
- Tests: approval relay and phase 2 suites extended for each finding.

## 0.9.2 - 2026-11-02

Product release. All ten build phases (SPEC section 14) complete and green:
full suite 386 tests OK, redteam GREEN, verify-chain ok.

- Sales README: product page up top, hardening detail in docs/HARDENING.md.
- Manifest: plugin.yaml so the repo installs and registers.
- Phases 0-9 built across the weekend plus three rework sessions and the
  redteam GREEN repairs; closeout at 70f13cb.

Pending final gates (not blocking use): a genuine Opus review and Brad's
hands-on test.
