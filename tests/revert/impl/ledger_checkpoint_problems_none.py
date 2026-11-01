"""Derived reference impl: ledger._checkpoint_problems that sees no checkpoints.

The M7 read side neutered: no history is consulted, so a rolled-back
prefix verifies cleanly. Paired with chain_append_locked_no_M7 for the
pre-M7 scenario.
"""


def _checkpoint_problems(wd: Workdir) -> list[str]:
    return []
