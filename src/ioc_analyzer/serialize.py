"""Machine-readable output: EnrichmentResult -> JSON for SOAR playbooks and scripts

Missing values stay null here; "Unknonw" is display-only and lives in report.py.
The field names below are public contract: renaming one breaks every consumer.
"""

import json
from collections.abc import Iterable
from typing import Any

from ioc_analyzer.enrich import EnrichmentResult


def result_to_dict(result: EnrichmentResult) -> dict[str, Any]:
    """One indicator as plain JSON-ready data."""
    providers: dict[str, dict[str, str]] = {"virustotal": {"status": result.vt_status}}
    if result.abuse_status is not None:
        providers["abuseipdb"] = {"status": result.abuse_status}
    return {
        "indicator": result.indicator,
        "type": result.kind,
        "providers": providers,
        "report": result.report,
        "errors": list(result.errors),
    }


def to_json(results: Iterable[EnrichmentResult]) -> str:
    """The whole run as one JSON document: {"results": [...]}."""
    return json.dumps({"results": [result_to_dict(r) for r in results]}, indent=2)
