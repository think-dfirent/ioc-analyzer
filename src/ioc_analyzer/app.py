"""Deprecated entry point: use the `ioc-analyzer` command or `python -m ioc_analyzer`.

Kept for one more phase so existing scripts keep working; removed in Phase 9.
"""

import sys

from ioc_analyzer.cli import main

__all__ = ["main"]

DEPRECATION_NOTICE = (
    "warning: `python -m ioc_analyzer.app` is deprecated and will be removed; "
    "use `ioc-analyzer` or `python -m ioc_analyzer`"
)

if __name__ == "__main__":
    print(DEPRECATION_NOTICE, file=sys.stderr)  # stderr: --json output stays clean
    sys.exit(main())
