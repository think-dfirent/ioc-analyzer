"""Enrichment: send indicators to providers and collect the results.

Nothing here prints or exits. Problems come back as data in EnrichmentResult.errors,
and the caller decides how to show them.
"""

from dataclasses import dataclass
from typing import Any, Literal

Kind = Literal["ip", "domain", "file"]


@dataclass(frozen=True)
class EnrichmentResult:
    """Outcome of enriching one indicator
    report: normalized data for report.print_analysis, or None when there is fail| no record
    not_found: 404
    errors:    one message per provider failure, e.g. "AbuseIPDB failed: HTTP 500".
    """

    indicator: str
    kind: Kind
    report: dict[str, Any] | None = None
    not_found: bool = False
    errors: tuple[str, ...] = ()

    @property
    def failed(self) -> bool:
        return bool(self.errors)
