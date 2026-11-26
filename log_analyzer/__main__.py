"""Entry point for running the package via `python -m log_analyzer`."""

import sys

from log_analyzer.cli import main

if __name__ == "__main__":
    sys.exit(main())
