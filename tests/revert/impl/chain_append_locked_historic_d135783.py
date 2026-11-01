"""Reference impl: chain._append_locked as of d135783 (pre-I6/N6/M7).

Verbatim body from commit d135783 — the appender before the anchored,
mirror-checked, checkpoint-pinned rewrite. A revert to this impl restarts
any chain from whatever prefix is live: no mirror anchoring, no
fail-closed restart, no checkpoint floor.
"""


def _append_locked(path: Path, record: dict) -> dict:
    last = _last_line(path)
    if last is None:
        seq, prev = 1, GENESIS
    else:
        if not last.endswith(b"\n"):
            raise DdaError(f"{path}: last line is incomplete (torn write); run `dda verify-chain`")
        try:
            seq = int(json.loads(last)["seq"]) + 1
        except Exception:
            raise DdaError(f"{path}: last line is not a chain record; run `dda verify-chain`") from None
        prev = line_hash(last)
    rec = dict(record)
    rec.pop("seq", None)
    rec.pop("prev", None)
    rec.setdefault("t", now_iso())
    rec.setdefault("ts", round(time.time(), 3))
    rec["seq"], rec["prev"] = seq, prev
    line = canonical_line(rec)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "ab") as fh:
        fh.write(line)
        fh.flush()
        os.fsync(fh.fileno())
    _write_json_atomic(heads_path(path), {"seq": seq, "hash": line_hash(line), "file": canonical_path(path)})
    return rec
