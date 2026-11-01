"""Conformance for the derived no-M7 _append_locked reference impl.

Runs WHILE the revert is applied. Mirror anchoring (I6/N6) must be
intact — only the git-history floor is gone:
(a) missing file + live mirror -> N6 refusal naming the heads mirror;
(b) live prefix matching its mirror -> extends normally;
(c) missing file + no mirror + a committed checkpoint recording a longer
    chain -> restarts from genesis (the M7 floor is absent).
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO))
os.environ.setdefault("DDA_TEST_MODE", "1")
tmp = Path(tempfile.mkdtemp(prefix="dda-conf-nom7-"))
os.environ["DDA_HOME"] = str(tmp / "home")

from ddalib import chain as _chain  # noqa: E402
from ddalib.layout import DdaError  # noqa: E402

# (a) N6 intact.
pa = tmp / ".analysis" / "a.jsonl"
_chain.append(pa, {"type": "note"})
pa.unlink()
try:
    _chain.append(pa, {"type": "note"})
    raise SystemExit("FAIL: no_M7 must still refuse when the mirror survives (N6)")
except DdaError as e:
    assert "heads mirror" in str(e), str(e)[:200]

# (b) Normal anchored extension intact.
pb = tmp / ".analysis" / "b.jsonl"
_chain.append(pb, {"type": "note"})
r = _chain.append(pb, {"type": "note"})
assert r["seq"] == 2, r

# (c) Checkpoint floor absent: tmp git repo with a trailer seq 5, chain
# file + mirror both gone -> genesis restart instead of refusal.
root = tmp / "wd"
(root / ".analysis").mkdir(parents=True)
pc = root / ".analysis" / "c.jsonl"
_chain.append(pc, {"type": "note"})
_chain.heads_path(pc).unlink()
pc.unlink()
g = lambda *a: subprocess.run(["git", "-C", str(root), *a],
                              capture_output=True, text=True, check=True)
g("init", "-q")
g("config", "user.email", "t@t.t")
g("config", "user.name", "t")
(root / "x.txt").write_text("x")
g("add", "-A")
g("commit", "-q", "-m", "probe\n\nDda-Chain-Head: .analysis/c.jsonl 5 " + "0" * 64)
r = _chain.append(pc, {"type": "note"})
assert r["seq"] == 1 and r["prev"] == _chain.GENESIS, f"no_M7 must restart, got {r}"
print("CONFORMANCE-OK: no_M7 keeps mirror anchoring, drops the checkpoint floor")
