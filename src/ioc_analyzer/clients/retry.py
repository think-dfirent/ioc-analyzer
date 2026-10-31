"""Retry transient provider failures, waiting longer each time (backoff)"""

import logging
from collections.abc import Callable, Sequence
from typing import TypeVar

from ioc_analyzer.clients.errors import ProviderTransientError

logger = logging.getLogger(__name__)

T = TypeVar("T")

# One wait per retry: 2 retries, 1s then 2s
DEFAULT_DELAYS: tuple[float, ...] = (1.0, 2.0)


def call_with_retries(
    call: Callable[[], T],
    *,
    sleep: Callable[[float], None],
    delays: Sequence[float] = DEFAULT_DELAYS,
) -> T:
    """Run call(); after a ProviderTransientError, wait and try again, once per delay.
    The error from the last try is re-raised. Every other exception (401/429, a bad body, a bug in our code)
    passes straight through on the first try, because trying again would give the same answer.
    Only use this for requests that are safe to repeat (GET)
    """
    for attempt, delay in enumerate(delays, start=1):
        try:
            return call()
        except ProviderTransientError as exc:
            logger.warning("%s; retry %d/%d in %g s", exc, attempt, len(delays), delay)
            sleep(delay)
    return call()
