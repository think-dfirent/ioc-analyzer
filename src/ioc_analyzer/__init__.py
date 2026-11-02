"""IOC extraction and enrichment for SOC analysts."""

from importlib.metadata import PackageNotFoundError, version

try:
    # pyproject.toml is the only place the version is written (CLAUDE.md Decisions).
    __version__ = version("ioc-analyzer")
except PackageNotFoundError:  # a source tree that was never pip-installed
    __version__ = "0+unknown"
