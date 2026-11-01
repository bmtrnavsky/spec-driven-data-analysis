"""Derived reference impl: chain._append_locked without the M7 checkpoint floor.

The fixed body with both committed-checkpoint lookups/raises removed
(missing/empty branch and live-prefix branch). Mirror anchoring (I6/N6)
is intact: only the git-history floor (M7) is gone, so the M7 rollback
attack (older prefix + older mirror) restarts from genesis here.
"""


def _append_locked(path: Path, record: dict) -> dict:
    # Anchored append (invariant I6): a chain file may only be extended
    # exactly at its mirrored head. Restoring an older prefix — with or
    # without the mirror — fails closed instead of silently restarting.
    _check_dda_home_binding(path)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except FileNotFoundError:
        data = None
    heads = _read_heads(path)
    mirror_seq = heads.get("seq") if isinstance(heads, dict) else None
    if not isinstance(mirror_seq, int) or mirror_seq < 1:
        heads, mirror_seq = None, 0
    if not data:
        # Missing or empty file: a fresh chain starts only from genesis.
        # A non-empty mirror means evidence was deleted (N6: `git clean
        # -fdx` / `git stash -u` remove the file but not the mirror).
        # DERIVED no_M7: the committed-checkpoint raise is removed.
        if mirror_seq > 0:
            raise DdaError(
                f"{path}: file is missing or empty but the heads mirror records "
                f"seq {mirror_seq} (evidence was deleted, e.g. by `git clean -fdx` "
                f"or `git stash -u`); restore it before appending (§3.2 case 8)")
        seq, prev = 1, GENESIS
    else:
        if not data.endswith(b"\n"):
            raise DdaError(f"{path}: last line is incomplete (torn write); run `dda verify-chain`")
        lines = data.split(b"\n")
        lines.pop()  # trailing newline
        n = len(lines)
        last = lines[-1]
        # DERIVED no_M7: the live-prefix checkpoint raise is removed.
        if not isinstance(heads, dict):
            raise DdaError(
                f"{path}: {n} line(s) but no heads mirror records this chain "
                f"(file was not written by the appender, or the mirror was "
                f"deleted); restore the mirror before appending (§3.2 case 8)")
        mirror_hash = heads.get("hash")
        if n != mirror_seq:
            if n < mirror_seq:
                raise DdaError(
                    f"{path}: {n} line(s) but the heads mirror records seq "
                    f"{mirror_seq} — the chain was replaced by an older prefix; "
                    f"restore it before appending (§3.2 case 8)")
            raise DdaError(
                f"{path}: {n} line(s) but the heads mirror records seq "
                f"{mirror_seq} — line(s) after the heads mirror (appended "
                f"outside the appender); run `dda verify-chain` (§3.2 case 8)")
        if line_hash(last) != mirror_hash:
            raise DdaError(
                f"{path}: last line does not match the heads mirror "
                f"(rewritten or forked); restore it before appending (§3.2 case 8)")
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
    # CAS on the mirror: the new entry extends exactly the head we anchored
    # on (new.seq == old.seq+1, new.prev == old.hash). The file lock held
    # across read and write makes this atomic against other appenders.
    assert seq == mirror_seq + 1, (seq, mirror_seq)
    if mirror_seq > 0:
        assert prev == heads.get("hash"), "mirror moved under the file lock"
    _write_json_atomic(heads_path(path), {"seq": seq, "hash": line_hash(line), "file": canonical_path(path)})
    return rec
