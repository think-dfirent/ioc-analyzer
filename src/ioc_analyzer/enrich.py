"""Enrichment: send indicators to providers and collect the results.
Nothing here prints or exits. Problems come back as data in EnrichmentResult.errors,
and the caller decides how to show them.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from functools import partial
from typing import Any, Literal, Protocol

from ioc_analyzer.clients.errors import ProviderError, ProviderUnavailableError
from ioc_analyzer.normalization import (
    normalize_domain_result,
    normalize_file_result,
    normalize_ip_result,
)

Kind = Literal["ip", "domain", "file"]

"""What happened when we asked one provider about one indicator:
ok: it answered with data
not_found: not record (404) - not a failure
unavailable: no API key, disabled earlier by 401/429
error: we asked and the request failed (5xx, timeout, bad response)
"""
Status = Literal["ok", "not_found", "unavailable", "error"]


@dataclass(frozen=True)
class EnrichmentResult:
    """Outcome of enriching one indicator.

    vt_status:    what happened with VirusTotal (see Status).
    abuse_status: same for AbuseIPDB, or None when it does not apply (not an IP).
    report:       normalized data for report.print_analysis, or None when VirusTotal
                  failed or has no record (an IP always gets a report, built from AbuseIPDB).
    errors:       one ready-to-show message per provider problem,
                  e.g. "8.8.8.8: AbuseIPDB failed: AbuseIPDB returned HTTP 500".
    """

    indicator: str
    kind: Kind
    vt_status: Status
    abuse_status: Status | None = None
    report: dict[str, Any] | None = None
    errors: tuple[str, ...] = ()

    @property
    def failed(self) -> bool:
        return bool(self.errors)

    @property
    def not_found(self) -> bool:
        return self.vt_status == "not_found"


class VTLookup(Protocol):
    def lookup(self, artifact: str, kind: Kind) -> dict[str, Any] | None: ...


class IPLookup(Protocol):
    def lookup(self, artifact: str) -> dict[str, Any] | None: ...


def _query(
    provider: str, lookup: Callable[[], dict[str, Any] | None], artifact: str
) -> tuple[dict[str, Any] | None, str | None]:
    """Run one lookup. Return (data, None) on an answer, (None, message) on failure.

    ProviderUnavailableError is re-raised: the caller must stop using that provider.
    Any other exception is a bug in our code and crashes on purpose.
    """
    try:
        return lookup(), None
    except ProviderUnavailableError:
        raise
    except ProviderError as exc:
        return None, f"{artifact}: {provider} failed: {exc}"


def _status(data: dict[str, Any] | None, error: str | None) -> Status:
    """Turn the outcome of one _query call into Status"""
    if error is not None:
        return "error"
    return "not_found" if data is None else "ok"


def enrich(
    indicators: Iterable[tuple[str, Kind]],
    vt_client: VTLookup,
    abuse_client: IPLookup | None = None,
) -> list[EnrichmentResult]:
    """Look up each unique indicator and return one result per indicator, in order.

    A provider that raises ProviderUnavailableError (401/429) is not called again
    for the rest of this run. abuse_client=None means AbuseIPDB is not configured.
    """
    results: list[EnrichmentResult] = []
    vt_enabled = True
    abuse_enabled = abuse_client is not None

    for artifact, kind in dict.fromkeys(indicators):
        errors: list[str] = []

        vt = None
        vt_status: Status = "unavailable"
        if vt_enabled:
            try:
                vt, error = _query(
                    "VirusTotal", partial(vt_client.lookup, artifact, kind), artifact
                )
            except ProviderUnavailableError as exc:
                errors.append(f"VirusTotal disabled for the rest of this run: {exc}")
                vt_enabled = False
            else:
                vt_status = _status(vt, error)
                if error:
                    errors.append(error)

        report: dict[str, Any] | None = None
        abuse_status: Status | None = None
        if kind == "ip":
            abuse = None
            abuse_status = "unavailable"
            if abuse_enabled and abuse_client is not None:
                try:
                    abuse, error = _query(
                        "AbuseIPDB", partial(abuse_client.lookup, artifact), artifact
                    )
                except ProviderUnavailableError as exc:
                    errors.append(f"AbuseIPDB disabled for the rest of this run: {exc}")
                    abuse_enabled = False
                else:
                    abuse_status = _status(abuse, error)
                    if error:
                        errors.append(error)
            report = normalize_ip_result(vt, abuse, artifact, vt_status=vt_status)
        elif vt is not None:
            if kind == "domain":
                report = normalize_domain_result(vt)
            else:
                report = normalize_file_result(vt)

        results.append(
            EnrichmentResult(
                indicator=artifact,
                kind=kind,
                report=report,
                vt_status=vt_status,
                abuse_status=abuse_status,
                errors=tuple(errors),
            )
        )
    return results
