"""Reference impl: review.existing_calls before the N2 backstop (pre-N2).

Verbatim body from the parent of d135783: only the untracked call files
`.analysis/reviews/goldfish/<stage>-r*.json` are read. The lineage-log and
runs.log backstop (which survives `git clean -fdx` / `git stash -u` /
`git reset --hard` deletion of the call files) is absent, so deleting the
call files resets the re-run cap and launders failed rounds.
"""


def existing_calls(wd: Workdir, stage: str) -> list[dict]:
    out = []
    base = reviews_dir(wd)
    if not base.is_dir():
        return out
    for p in sorted(base.glob(f"{stage}-r*.json")):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if rec.get("format") == FORMAT_CALL and rec.get("stage") == stage:
            out.append(rec)
    return out
