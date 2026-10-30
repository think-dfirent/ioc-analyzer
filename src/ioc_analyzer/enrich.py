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


@dataclass(frozen=True)
class EnrichmentResult:
    """Outcome of enriching one indicator.

    report:    normalized data for report.print_analysis, or None when VirusTotal
               failed or has no record (an IP always gets a report, built from AbuseIPDB).
    not_found: True when VirusTotal answered 404, a valid "no record" answer, not a failure.
    errors:    one ready-to-show message per provider problem,
               e.g. "8.8.8.8: AbuseIPDB failed: AbuseIPDB returned HTTP 500".
    """

    indicator: str
    kind: Kind
    report: dict[str, Any] | None = None
    not_found: bool = False
    errors: tuple[str, ...] = ()

    @property
    def failed(self) -> bool:
        return bool(self.errors)


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

        vt_ok, vt = False, None
        if vt_enabled:
            try:
                vt, error = _query(
                    "VirusTotal", partial(vt_client.lookup, artifact, kind), artifact
                )
            except ProviderUnavailableError as exc:
                errors.append(f"VirusTotal disabled for the rest of this run: {exc}")
                vt_enabled = False
            else:
                vt_ok = error is None
                if error:
                    errors.append(error)
        not_found = vt_ok and vt is None

        report: dict[str, Any] | None = None
        if kind == "ip":
            abuse = None
            if abuse_enabled and abuse_client is not None:
                try:
                    abuse, error = _query(
                        "AbuseIPDB", partial(abuse_client.lookup, artifact), artifact
                    )
                except ProviderUnavailableError as exc:
                    errors.append(f"AbuseIPDB disabled for the rest of this run: {exc}")
                    abuse_enabled = False
                else:
                    if error:
                        errors.append(error)
            vt_status = "not_found" if not_found else None
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
                not_found=not_found,
                errors=tuple(errors),
            )
        )
    return results
