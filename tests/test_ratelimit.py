import pytest

from ioc_analyzer.clients.ratelimit import RateLimiter


def limiter(clock, limit=4):
    return RateLimiter("VT", limit, clock=clock.monotonic, sleep=clock.sleep)


def test_first_calls_up_to_the_limit_do_not_wait(clock):
    vt = limiter(clock)
    for _ in range(4):
        vt.wait()
    assert clock.sleeps == []


def test_next_call_waits_until_the_oldest_leaves_the_window(clock):
    vt = limiter(clock)
    for _ in range(4):
        vt.wait()
    clock.now = 20.0  # 20 s later, the window is still full

    vt.wait()

    assert clock.sleeps == [40.0]  # the call from t=0 expires at t=60


def test_calls_older_than_the_window_stop_counting(clock):
    vt = limiter(clock)
    for _ in range(4):
        vt.wait()
    clock.now = 60.0

    vt.wait()

    assert clock.sleeps == []


def test_ten_calls_at_four_per_minute_take_two_minutes(clock):
    vt = limiter(clock)
    for _ in range(10):
        vt.wait()
    # Calls 5 and 9 wait; then 5-8 and 9-10 go out together.
    assert clock.sleeps == [60.0, 60.0]
    assert clock.now == 120.0


def test_limit_zero_never_waits(clock):
    vt = limiter(clock, limit=0)
    for _ in range(100):
        vt.wait()
    assert clock.sleeps == []


def test_negative_limit_is_rejected(clock):
    with pytest.raises(ValueError, match="0 or more"):
        limiter(clock, limit=-1)


def test_wait_is_logged_at_info(clock, caplog):
    vt = limiter(clock, limit=1)
    vt.wait()
    vt.wait()
    [record] = caplog.records
    assert record.levelname == "INFO"
    assert record.getMessage() == "waiting 60 s for the VT rate limit (1 per 60 s)"
