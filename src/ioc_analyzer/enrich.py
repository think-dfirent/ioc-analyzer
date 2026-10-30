"""Send indicators to providers and collect the results
Problem come back as data in EnrichmentResult.errors, and the caller decides how to show them
"""

from dataclasses import dataclass
from typing import Any, Literal

Kind = Literal["ip", "domain", "file"]


@dataclass(frozen=True)  # immutable - read-only
class EnrichmentResult:
    """Outcome of enriching one indicator
    report: normalized data for report.print_analysis, or None when there is fail| no record
    not_found: 404
    """

    indicator: str
    kind: Kind
    report: dict[str, Any] | None = None
    """
    with "=None" (optional): EnrichmentResult(indicator="8.8.8.8", kind="ip", not_found=True)
    without "=None" (required): EnrichmentResult(indicator="8.8.8.8", kind="ip", report=None, not_found=True)
    """
    not_found: bool = False
    errors: tuple[str, ...] = ()  # tuple for immutable

    @property
    def failed(self) -> bool:
        return bool(self.errors)  # an empty tuple.failed == True and vice-versa
