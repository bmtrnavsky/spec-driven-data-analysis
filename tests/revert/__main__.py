"""`python -m tests.revert validate [...]` entry point."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))

from revert.validate import main

if __name__ == "__main__":
    argv = sys.argv[1:]
    # Accept the spec form `python -m tests.revert validate [...]`: the
    # package invocation receives "validate" as its first argument.
    if argv[:1] == ["validate"]:
        argv = argv[1:]
    raise SystemExit(main(argv))
