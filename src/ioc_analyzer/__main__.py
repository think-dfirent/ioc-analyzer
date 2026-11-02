"""`python -m ioc_analyzer` runs the CLI, exactly like the `ioc-analyzer` command."""

import sys

from ioc_analyzer.cli import main

if __name__ == "__main__":
    sys.exit(main())
