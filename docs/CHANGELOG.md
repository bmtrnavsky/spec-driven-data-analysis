# Changelog

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
