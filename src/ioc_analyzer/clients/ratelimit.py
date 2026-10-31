"""Client-side rate limiting: at most N calls in any rolling time window."""

import logging
from collections import deque
from collections.abc import Callable

logger = logging.getLogger(__name__)


class RateLimiter:
    """Make callers wait so that at most `limit` calls start in any `window` seconds.
    Rolling window, not fixed spacing: with 4 per 60 s, the first 4 calls go out
    at once and the 5th waits until 60 s after the first. Small alerts never wait.
    limit=0 turns the limiter off (for keys without a per-minute limit)
    """

    def __init__(
        self,
        name: str,
        limit: int,
        window: float = 60.0,
        *,
        clock: Callable[[], float],
        sleep: Callable[[float], None],
    ) -> None:
        if limit < 0:
            raise ValueError(f"{name} rate limit must be 0 or more, got {limit}")
        self._name = name
        self._limit = limit
        self._window = window
        self._clock = clock
        self._sleep = sleep
        # Start times of recent calls, older first
        self._starts: deque[float] = deque()

    def wait(self) -> None:
        """Block until one more call is allowed, then record it."""
        if self._limit == 0:
            return
        now = self._clock()
        while self._starts and now - self._starts[0] >= self._window:
            self._starts.popleft()  # older than the window: no longer counts
        if len(self._starts) >= self._limit:
            delay = self._window - (now - self._starts.popleft())
            logger.info(
                "waiting %.0f s for the %s rate limit (%d per %.0f s)",
                delay,
                self._name,
                self._limit,
                self._window,
            )
            self._sleep(delay)
            now = self._clock()
        self._starts.append(now)
