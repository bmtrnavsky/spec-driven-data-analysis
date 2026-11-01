"""Conformance for the neutered _checkpoint_problems reference impl.

Runs WHILE the revert is applied. The M7 read side is gone: no history
is consulted, so the function reports no problems unconditionally.
"""
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO))
os.environ.setdefault("DDA_TEST_MODE", "1")
tmp = Path(tempfile.mkdtemp(prefix="dda-conf-ckptnone-"))
os.environ["DDA_HOME"] = str(tmp / "home")

from ddalib import ledger as _ledger  # noqa: E402
from ddalib.layout import Workdir  # noqa: E402

wd = Workdir.at(tmp / "wd")
assert _ledger._checkpoint_problems(wd) == [], "neutered scan must return []"
print("CONFORMANCE-OK: neutered _checkpoint_problems returns []")
