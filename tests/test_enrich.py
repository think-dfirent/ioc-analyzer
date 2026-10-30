from ioc_analyzer.enrich import EnrichmentResult


def test_result_without_errors_is_not_failed():
    result = EnrichmentResult(indicator="8.8.8.8", kind="ip")
    assert result.failed is False


def test_result_with_errors_is_failed():
    result = EnrichmentResult(
        indicator="8.8.8.8", kind="ip", errors=("AbuseIPDB failed: HTTP 500")
    )
    assert result.failed is True
