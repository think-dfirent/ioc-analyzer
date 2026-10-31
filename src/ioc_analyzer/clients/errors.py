"""Exception shared by all TI provider clients"""


class ProviderError(Exception):
    """A lookup for one indicator failed
    The caller should mark this indicator as failed and continue with the next one
    """


class ProviderUnavailableError(ProviderError):
    """The provider cannot serve any more lookups in this run
    Raised for problems that will repeat for every indicator, such as a rejected API key (HTTP 401)
    or an exhausted quota (HTTP 429), the caller should stop sending requests to this provider.
    """


class ProviderTransientError(ProviderError):
    """A failure that may not happen on the next try: timeout, dropped connection, 5xx
    Clients retry these a few times (see retry.py). If every try fails, the caller treats it like any other ProviderError:
    this indicator failed, carry on.
    """


class ProviderRateLimitedError(ProviderError):
    """HTTP 429: too many requests
    Either we went too fast (clears once the rate window passes) or the daily/monthly quota is used up
    (does not clear today). The status code can't tell which, so retry.py waits once and tries again; a second 429 means the
    quota is gone.
    """
