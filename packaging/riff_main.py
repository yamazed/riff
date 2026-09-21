"""PyInstaller entry point — a plain script, because a frozen build cannot
use `python -m riff`."""

import multiprocessing
import sys

from riff.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
