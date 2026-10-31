"""Retry provider failures that may clear on their own: transient errors and 429."""

import logging
from collections.abc import Callable, Sequence
from typing import TypeVar

from ioc_analyzer.clients.errors import (
    ProviderRateLimitedError,
    ProviderTransientError,
    ProviderUnavailableError,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")

# One wait per retry: 2 retries, 1s then 2s
DEFAULT_DELAYS: tuple[float, ...] = (1.0, 2.0)
RATE_LIMIT_WAIT = 60.0


def call_with_retries(
    call: Callable[[], T],
    *,
    sleep: Callable[[float], None],
    delays: Sequence[float] = DEFAULT_DELAYS,
    rate_limit_wait: float = RATE_LIMIT_WAIT,
) -> T:
    """Run call(), retrying the failures that may clear on their own.

    - ProviderTransientError (timeout, connection, 5xx): retry once per delay,
    then re-raise the last error
    - ProviderRateLimitError (429): wait rate_limit_wait once and try again;
    Every other exception (401, a bad body, a bug in our code) passes straight through on the first try,
    because trying again would give the same answer. Only use this for requests that are
    safe to repeat (GET lookups).
    """
    retries = 0
    rate_limited = False
    while True:
        try:
            return call()
        except ProviderRateLimitedError as exc:
            if rate_limited:
                raise ProviderUnavailableError(
                    f"{exc} again after waiting {rate_limit_wait:g} s; the quota is probably used up"
                ) from exc
            rate_limited = True
            logger.warning(
                "%s; waiting %g s, then trying once more", exc, rate_limit_wait
            )
            sleep(rate_limit_wait)
        except ProviderTransientError as exc:
            if retries == len(delays):
                raise
            delay = delays[retries]
            retries += 1
            logger.warning("%s; retry %d/%d in %g s", exc, retries, len(delays), delay)
            sleep(delay)
