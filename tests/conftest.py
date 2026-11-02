import time

import pytest


class FakeClock:
    """Time that only moves when someone sleeps; every wait is recorded."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    """Every test gets a fake clock, and nothing in a test can really sleep.
    Like "tests never touch the network": a retry that waits 3 real seconds would make the suite
    slow without anyone noticing why"""

    fake = FakeClock()
    monkeypatch.setattr(time, "sleep", fake.sleep)
    monkeypatch.setattr(time, "monotonic", fake.monotonic)
    return fake


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch, tmp_path):
    """No test reads the developer's real settings file or real keys.

    The settings file location is pointed at an empty temp folder, and our
    variables are removed from the environment; a test sets what it needs.
    """
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    for name in ("VIRUSTOTAL_API", "ABUSEIPDB_API", "VIRUSTOTAL_RATE_PER_MIN"):
        monkeypatch.delenv(name, raising=False)
