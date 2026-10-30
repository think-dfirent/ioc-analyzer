"""Backward-compatible entry point. The CLI lives in cli.py."""

import sys

from ioc_analyzer.cli import main

__all__ = ["main"]

if __name__ == "__main__":
    sys.exit(main())
