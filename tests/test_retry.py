import pytest

from ioc_analyzer.clients.errors import (
    ProviderError,
    ProviderTransientError,
    ProviderUnavailableError,
)
from ioc_analyzer.clients.retry import call_with_retries


def answers(*outcomes):
    """A fake call that returns or raises the given outcomes, one per try."""
    remaining = list(outcomes)
    tries = []

    def call():
        tries.append(1)
        outcome = remaining.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    call.tries = tries
    return call


def test_success_needs_no_retry(clock):
    call = answers("data")
    assert call_with_retries(call, sleep=clock.sleep) == "data"
    assert clock.sleeps == []


def test_transient_failure_then_success(clock):
    call = answers(ProviderTransientError("HTTP 503"), "data")
    assert call_with_retries(call, sleep=clock.sleep) == "data"
    assert clock.sleeps == [1.0]


def test_gives_up_after_two_retries_with_growing_waits(clock):
    call = answers(*[ProviderTransientError("HTTP 503")] * 3)
    with pytest.raises(ProviderTransientError):
        call_with_retries(call, sleep=clock.sleep)
    assert len(call.tries) == 3
    assert clock.sleeps == [1.0, 2.0]


@pytest.mark.parametrize(
    "error",
    [ProviderError("HTTP 400"), ProviderUnavailableError("HTTP 401"), TypeError("bug")],
)
def test_other_errors_are_not_retried(clock, error):
    call = answers(error)
    with pytest.raises(type(error)):
        call_with_retries(call, sleep=clock.sleep)
    assert len(call.tries) == 1
    assert clock.sleeps == []


def test_each_retry_is_logged_as_a_warning(clock, caplog):
    call = answers(ProviderTransientError("VirusTotal returned HTTP 503"), "data")
    call_with_retries(call, sleep=clock.sleep)
    [record] = caplog.records
    assert record.levelname == "WARNING"
    assert record.getMessage() == "VirusTotal returned HTTP 503; retry 1/2 in 1 s"
