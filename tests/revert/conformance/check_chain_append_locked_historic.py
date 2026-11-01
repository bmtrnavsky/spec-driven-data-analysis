"""Conformance for the historic (pre-I6/N6/M7) _append_locked reference impl.

Runs WHILE the revert is applied. Pre-fix semantics: chaining extends
with correct seq/prev, and a deleted chain restarts from genesis without
raising (no mirror anchoring, no checkpoint floor).
"""
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO))
os.environ.setdefault("DDA_TEST_MODE", "1")
tmp = Path(tempfile.mkdtemp(prefix="dda-conf-hist-"))
os.environ["DDA_HOME"] = str(tmp / "home")

from ddalib import chain as _chain  # noqa: E402

p = tmp / ".analysis" / "c.jsonl"
r1 = _chain.append(p, {"type": "note", "x": 1})
assert r1["seq"] == 1 and r1["prev"] == _chain.GENESIS, r1
r2 = _chain.append(p, {"type": "note", "x": 2})
assert r2["seq"] == 2, r2
lines = p.read_bytes().splitlines()
assert len(lines) == 2, lines
import json as _json
assert _json.loads(lines[1])["prev"] == _chain.line_hash(lines[0]), "prev must chain"
p.unlink()
r3 = _chain.append(p, {"type": "note", "x": 3})
assert r3["seq"] == 1, f"historic append must restart from genesis, got {r3}"
print("CONFORMANCE-OK: historic _append_locked chains and restarts")
