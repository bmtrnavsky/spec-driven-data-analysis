"""`python -m tests.revert validate [...]` / `python -m tests.revert selfcheck`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))

from revert.apply import run_selfcheck_cli  # noqa: E402
from revert.validate import main  # noqa: E402

if __name__ == "__main__":
    argv = sys.argv[1:]
    # `selfcheck`: detect + repair a tree left stripped by an earlier run
    # (I16 startup self-check), refreshing any premise record it invalidated.
    if argv[:1] == ["selfcheck"]:
        raise SystemExit(run_selfcheck_cli(argv[1:]))
    # Accept the spec form `python -m tests.revert validate [...]`: the
    # package invocation receives "validate" as its first argument.
    if argv[:1] == ["validate"]:
        argv = argv[1:]
    raise SystemExit(main(argv))
