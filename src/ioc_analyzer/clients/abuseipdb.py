from typing import Any

import requests

from ioc_analyzer.clients.errors import ProviderError, ProviderUnavailableError

BASE_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_MAX_AGE_DAYS = 90


def parse_abuse(response):
    data = response.get("data")
    result = {
        "artifact": data.get("ipAddress"),
        "source": "AbuseIPDB",
        "abuse_confidence": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "distinct_reporters": data.get("numDistinctUsers"),
        "last_reported_at": data.get("lastReportedAt"),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "usage_type": data.get("usageType"),
        "domain": data.get("domain"),
        "hostnames": data.get("hostnames"),
        "is_tor": data.get("isTor"),
    }
    return result


class AbuseIPDBClient:
    def __init__(
        self,
        api_key: str | None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    ) -> None:
        if not api_key:
            raise ValueError(
                "AbuseIPDB is missing. Set ABUSEIPDB_API in your .env file"
            )
        if not 1 <= max_age_days <= 365:
            raise ValueError(
                f"max_age_days must be between 1 and 365, got {max_age_days}"
            )
        self._api_key = api_key
        self._timeout = timeout
        self._max_age_days = max_age_days

    def lookup(self, artifact):
        url = f"{BASE_URL}/{artifact}"
        payload = self._fetch(url, artifact)
        try:
            return parse_abuse(payload)
        except KeyError as exc:
            raise ProviderError(f"AbuseIPDB response is missing field {exc}") from exc

    def _fetch(self, url, artifact) -> dict[str, Any] | None:
        headers = {"Key": self._api_key, "Accept": "application/json"}
        params = {"ipAddress": artifact, "maxAgeInDays": self._max_age_days}
        try:
            response = requests.get(
                url, headers=headers, params=params, timeout=self._timeout
            )
        except requests.RequestException as exc:
            raise ProviderError(f"AbuseIPDB unreachable: {exc}") from exc
        status = response.status_code
        if status == 404:
            return None
        if status == 401:
            raise ProviderUnavailableError(f"AbuseIPDB rejected the API key {status}")
        if status == 429:
            raise ProviderUnavailableError(
                f"AbuseIPDB Daily rate limit of 1000 requests exceeded for this endpoint. See headers for additional details {status}"
            )
        if not response.ok:
            raise ProviderError(f"AbuseIPDB returned HTTP {status}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise ProviderError(
                f"AbuseIPDB returned a response that is not JSON: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise ProviderError("AbuseIPDB returned JSON with an unexpected shape")
        return payload
