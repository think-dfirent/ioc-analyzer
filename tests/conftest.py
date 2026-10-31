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


@pytest.fixture
def clock(monkeypatch):
    """Every tests gets a fake clock, and nothing in a test can really sleep.
    Like "tests never tounch the network": a retry that waits 3 real seconds would make the suite
    slow without anyone noticing why"""

    fake = FakeClock()
    monkeypatch.setattr(time, "sleep", fake.sleep)
    return fake
