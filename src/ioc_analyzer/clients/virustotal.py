from typing import Any, Literal
from urllib.parse import quote
import requests
from ioc_analyzer.clients.errors import ProviderError, ProviderUnavailableError

BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT_SECONDS = 10

ArtifactKind = Literal["ip", "domain", "file"]
_ENDPOINTS: dict[str, str] = {
    "ip": "ip_addresses",
    "domain": "domains",
    "file": "files",
}


def build_url(artifact: str, kind: ArtifactKind) -> str:
    endpoint = _ENDPOINTS.get(kind)
    if endpoint is None:
        raise ValueError(f"Unsupported artifact type: {kind!r}")
    return f"{BASE_URL}/{endpoint}/{quote(artifact, safe="")}"


class VirusTotalClient:
    def __init__(self, api_key: str | None, timeout=DEFAULT_TIMEOUT_SECONDS) -> None:
        if not api_key:
            raise ValueError(
                "VirusTotal API key is missing. Set VIRUSTOTAL_API in your .env file."
            )
        self._api_key = api_key
        self._timeout = timeout

    def lookup(self, artifact: str, kind=ArtifactKind) -> dict[str, Any] | None:
        url = build_url(artifact, kind)
        try:
            response = requests.get(
                url, headers={"x-apikey": self._api_key}, timeout=self._timeout
            )
        except requests.RequestException as exc:
            raise ProviderError("VirusTotal unreachable")

        status = response.status_code
        if status == 404:
            return None
        if status == 401:
            raise ProviderUnavailableError("VirusTotal reject the API key (401)")
        if status == 429:
            raise ProviderUnavailableError("VirusTotal quota exceeded (429)")
        if not response.ok:
            raise ProviderError(f"VirusTotal returned HTTP {status}")

        try:
            return response.json()
        except ValueError as exc:
            raise ProviderError(
                "VirusTotal returned a response that is not JSON"
            ) from exc
