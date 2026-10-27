#!/usr/bin/env python
"""`dda` entry point. Run as `python scripts/dda.py <command>` or via scripts/dda.cmd."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ddalib.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
