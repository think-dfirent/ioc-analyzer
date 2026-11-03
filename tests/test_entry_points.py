"""Run the real entry points in a separate Python process, the way users do."""

import subprocess
import sys

from ioc_analyzer import __version__


def run_module(module: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", module, *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_python_dash_m_package_runs_the_cli():
    result = run_module("ioc_analyzer", "--version")
    assert result.returncode == 0
    assert result.stdout == f"ioc-analyzer {__version__}\n"
    assert result.stderr == ""


def test_exit_codes_reach_the_shell():
    result = run_module("ioc_analyzer", "--no-such-flag")
    assert result.returncode == 2
