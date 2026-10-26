from typing import Any

import requests

from ioc_analyzer.clients.errors import ProviderError, ProviderUnavailableError

BASE_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_MAX_AGE_DAYS = 90


def parse_abuse(data: dict[str, Any]) -> dict[str, Any]:
    """Turn "data" object to a flat dict"""
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


def _error_detail(payload: dict[str, Any]) -> str:
    errors = payload.get("errors") or []
    if errors and isinstance(errors[0], dict):
        return errors[0].get("detail") or "no error detail given"
    return "no data and no error details in response"


class AbuseIPDBClient:
    def __init__(
        self,
        api_key: str | None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    ) -> None:
        if not api_key:
            raise ValueError(
                "AbuseIPDB API key is missing. Set ABUSEIPDB_API in your .env file"
            )
        if not 1 <= max_age_days <= 365:
            raise ValueError(
                f"max_age_days must be between 1 and 365, got {max_age_days}"
            )
        self._api_key = api_key
        self._timeout = timeout
        self._max_age_days = max_age_days

    def lookup(self, artifact: str) -> dict[str, Any]:
        payload = self._fetch(artifact)
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ProviderError(f"AbuseIPDB returned no data {_error_detail(payload)}")
        return parse_abuse(data)

    def _fetch(self, artifact: str) -> dict[str, Any]:
        headers = {"Key": self._api_key, "Accept": "application/json"}
        params = {"ipAddress": artifact, "maxAgeInDays": self._max_age_days}
        try:
            response = requests.get(
                BASE_URL, headers=headers, params=params, timeout=self._timeout
            )
        except requests.RequestException as exc:
            raise ProviderError(f"AbuseIPDB unreachable: {exc}") from exc
        status = response.status_code
        if status == 401:
            raise ProviderUnavailableError(f"AbuseIPDB rejected the API key {status}")
        if status == 429:
            raise ProviderUnavailableError(f"AbuseIPDB quota exceeded {status}")
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
