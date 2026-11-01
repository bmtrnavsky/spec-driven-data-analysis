"""Conformance for the no-pin lineage reference impl.

Runs WHILE the revert is applied. A lineage chain that fails verification
(1 live line against a mirror recording seq 5) must be read as computed
— results_seen_before_profile False with no runs on record — instead of
pinning True the way the fixed function does.
"""
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO))
os.environ.setdefault("DDA_TEST_MODE", "1")
tmp = Path(tempfile.mkdtemp(prefix="dda-conf-nopin-"))
os.environ["DDA_HOME"] = str(tmp / "home")

from ddalib import chain as _chain  # noqa: E402
from ddalib import lineage as _lin  # noqa: E402
from ddalib.layout import Workdir  # noqa: E402

wd = Workdir.at(tmp / "wd")
lp = _lin.lineage_log(wd)
lp.parent.mkdir(parents=True, exist_ok=True)
_chain.append(lp, {"type": "lock", "lineage_id": "t", "lock_hash": "t", "lock_epoch": 1})
assert not _chain.verify(lp), "control: 1 live line must verify before forging the mirror"
_chain._write_json_atomic(_chain.heads_path(lp),
                          {"seq": 5, "hash": "0" * 64, "file": _chain.canonical_path(lp)})
assert _chain.verify(lp), "control: forged-ahead mirror must break verification"
view = _lin.lineage(wd)
assert view["events"] == 1, view
assert view["results_seen_before_profile"] is False, (
    f"no-pin lineage must read the broken prefix as computed, got {view}")
print("CONFORMANCE-OK: no-pin lineage reads the broken chain unpinned")
