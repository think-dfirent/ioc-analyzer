from typing import Literal
from urllib.parse import quote

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


ArtifactKind = Literal["ip", "domain", "file"]
_ENDPOINTS: dict[str, str] = {
    "ip": "ip_addresses",
    "domain": "domains",
    "file": "files",
}


def build_url(artifact: str, kind=ArtifactKind) -> str:
    endpoint = _ENDPOINTS.get(kind)
    if endpoint is None:
        raise ValueError(f"Unsupported artifact type: {kind!r}")
    return f"{BASE_URL}/{endpoint}/{quote(artifact, safe="")}"
