import time
from collections.abc import Callable
from functools import partial
from typing import Any, Literal
from urllib.parse import quote

import requests

from ioc_analyzer.clients.errors import (
    ProviderError,
    ProviderTransientError,
    ProviderUnavailableError,
)
from ioc_analyzer.clients.ratelimit import RateLimiter
from ioc_analyzer.clients.retry import call_with_retries

BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_RATE_PER_MIN = 4  # free tier VT API
# attack kind dict
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


def parse_vt_ip(response):
    attributes = response["data"]["attributes"]

    result = {
        "artifact": response["data"]["id"],
        "network": attributes.get("network"),
        "asn": attributes.get("asn"),
        "as_owner": attributes.get("as_owner"),
        "country": attributes.get("country"),
        "reputation": attributes.get("reputation"),
        "analysis_stats": attributes.get("last_analysis_stats"),
    }
    return result


def parse_vt_domain(response):
    data = response["data"]
    attributes = data["attributes"]

    stats = attributes.get("last_analysis_stats")
    return {
        "artifact": data["id"],
        "type": "domain",
        "analysis_stats": stats,
        "reputation": attributes.get("reputation"),
        "total_votes": attributes.get("total_votes"),
        "categories": attributes.get("categories"),
        "registrar": attributes.get("registrar"),
        "tld": attributes.get("tld"),
        "creation_date": attributes.get("creation_date"),
        "expiration_date": attributes.get("expiration_date"),
        "first_seen_date": attributes.get("first_seen_date"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "dns_records": attributes.get("last_dns_records"),
        "dns_records_date": attributes.get("last_dns_records_date"),
        "tags": attributes.get("tags"),
    }


def parse_vt_file(response):
    data = response["data"]
    attributes = data["attributes"]

    return {
        "artifact": data["id"],
        "type": "file",
        "analysis_stats": attributes.get("last_analysis_stats"),
        "reputation": attributes.get("reputation"),
        "meaningful_name": attributes.get("meaningful_name"),
        "names": attributes.get("names"),
        "type_description": attributes.get("type_description"),
        "type_extension": attributes.get("type_extension"),
        "size": attributes.get("size"),
        "md5": attributes.get("md5"),
        "sha1": attributes.get("sha1"),
        "sha256": attributes.get("sha256"),
        "first_submission_date": attributes.get("first_submission_date"),
        "last_submission_date": attributes.get("last_submission_date"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "tags": attributes.get("tags"),
        "threat_classification": attributes.get("popular_threat_classification"),
        "sandbox_verdicts": attributes.get("sandbox_verdicts"),
    }


_PARSER = {
    "ip": parse_vt_ip,
    "domain": parse_vt_domain,
    "file": parse_vt_file,
}


class VirusTotalClient:
    def __init__(
        self,
        api_key: str | None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        sleep: Callable[[float], None] | None = None,
        rate_per_min: int = DEFAULT_RATE_PER_MIN,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not api_key:
            raise ValueError(
                "VirusTotal API key is missing. Set VIRUSTOTAL_API in your .env file."
            )
        self._api_key = api_key
        self._timeout = timeout
        # looked up now, not as a default argument, so tests that replace
        # time.sleep before building the client get the fake
        self._sleep = time.sleep if sleep is None else sleep
        self._limiter = RateLimiter(
            "VirusTotal",
            rate_per_min,
            clock=time.monotonic if clock is None else clock,
            sleep=self._sleep,
        )

    def lookup(self, artifact: str, kind: ArtifactKind) -> dict[str, Any] | None:
        url = build_url(artifact, kind)
        parser = _PARSER[kind]
        payload = call_with_retries(partial(self._fetch, url), sleep=self._sleep)
        if payload is None:
            return None
        try:
            return parser(payload)
        except KeyError as exc:
            raise ProviderError(f"VirusTotal response is missing field {exc}") from exc

    def _fetch(self, url: str) -> dict[str, Any] | None:
        """Send the GET request and return the JSON body, or None on 404."""
        self._limiter.wait()  # every attempt counts against the quota, retries too
        try:
            response = requests.get(
                url, headers={"x-apikey": self._api_key}, timeout=self._timeout
            )
        except (requests.Timeout, requests.ConnectionError) as exc:
            raise ProviderTransientError(f"VirusTotal unreachable: {exc}") from exc
        except requests.RequestException as exc:
            raise ProviderError(f"VirusTotal request failed: {exc}") from exc

        status = response.status_code
        if status == 404:
            return None
        if status == 401:
            raise ProviderUnavailableError(
                f"VirusTotal rejected the API key ({status})"
            )
        if status == 429:
            raise ProviderUnavailableError(f"VirusTotal quota exceeded ({status})")
        if status >= 500:
            raise ProviderTransientError(f"VirusTotal returned HTTP {status}")
        if not response.ok:
            raise ProviderError(f"VirusTotal returned HTTP {status}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise ProviderError(
                "VirusTotal returned a response that is not JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise ProviderError("VirusTotal returned JSON with an unexpected shape")
        return payload
