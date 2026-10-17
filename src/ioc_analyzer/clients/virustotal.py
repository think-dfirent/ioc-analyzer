BASE_URL = "https://virustotal.com/api/v3"
DEFAULT_TIMEOUT_SECONDS = 10


class VirusToTalClient:
    def __init__(self, api_key: float | None, timeout=DEFAULT_TIMEOUT_SECONDS) -> None:
        if not api_key:
            raise ValueError(
                "VirusTotal API key is missing. Set VIRUSTOTAL_API in your .env file."
            )
        self._api_key = api_key
        self._timeout = timeout
