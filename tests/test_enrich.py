import pytest

from ioc_analyzer.clients.errors import ProviderError, ProviderUnavailableError
from ioc_analyzer.enrich import EnrichmentResult, enrich

HASH = "a" * 64


class FakeClient:
    """Stands in for a provider client: answers from a dict, records every call.

    An answer that is an exception is raised instead of returned.
    """

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def lookup(self, artifact, kind=None):
        self.calls.append(artifact)
        answer = self.answers.get(artifact)
        if isinstance(answer, Exception):
            raise answer
        return answer


VT_IP = {"artifact": "8.8.8.8", "analysis_stats": {"malicious": 0, "harmless": 70}}
ABUSE_IP = {"artifact": "8.8.8.8", "abuse_confidence": 0, "total_reports": 3}


def test_result_without_errors_is_not_failed():
    result = EnrichmentResult(indicator="8.8.8.8", kind="ip")
    assert result.failed is False


def test_result_with_errors_is_failed():
    result = EnrichmentResult(
        indicator="8.8.8.8", kind="ip", errors=("AbuseIPDB failed: HTTP 500")
    )
    assert result.failed is True


def test_enrich_prints_nothing(capsys):
    vt = FakeClient({"8.8.8.8": ProviderError("HTTP 500")})
    enrich([("8.8.8.8", "ip"), (HASH, "file")], vt, FakeClient({}))
    assert capsys.readouterr() == ("", "")


def test_both_providers_answer():
    [result] = enrich(
        [("8.8.8.8", "ip")],
        FakeClient({"8.8.8.8": VT_IP}),
        FakeClient({"8.8.8.8": ABUSE_IP}),
    )
    assert result.failed is False
    assert result.report["abuseipdb"]["confidence"] == 0


def test_ip_with_failed_vt_still_has_report_from_abuseipdb():
    [result] = enrich(
        [("8.8.8.8", "ip")],
        FakeClient({"8.8.8.8": ProviderError("HTTP 500")}),
        FakeClient({"8.8.8.8": ABUSE_IP}),
    )
    assert result.report["virustotal"] is None
    assert result.report["abuseipdb"]["total_reports"] == 3
    assert result.not_found is False
    assert result.errors == ("8.8.8.8: VirusTotal failed: HTTP 500",)


def test_hash_unknown_to_vt_is_not_found_not_failed():
    [result] = enrich([(HASH, "file")], FakeClient({}))
    assert result.report is None
    assert result.not_found is True
    assert result.failed is False


def test_hash_with_failed_vt_has_no_report():
    [result] = enrich([(HASH, "file")], FakeClient({HASH: ProviderError("HTTP 500")}))
    assert result.report is None
    assert result.not_found is False
    assert result.failed is True


def test_unavailable_vt_is_not_called_again():
    vt = FakeClient({HASH: ProviderUnavailableError("HTTP 401")})
    results = enrich([(HASH, "file"), ("b" * 64, "file")], vt)
    assert vt.calls == [HASH]
    assert results[0].errors == (
        "VirusTotal disabled for the rest of this run: HTTP 401",
    )


def test_without_abuseipdb_client_ip_still_enriched_by_vt():
    [result] = enrich([("8.8.8.8", "ip")], FakeClient({"8.8.8.8": VT_IP}), None)
    assert result.report["abuseipdb"] is None
    assert result.failed is False


def test_duplicate_indicators_are_looked_up_once():
    vt = FakeClient({})
    results = enrich([(HASH, "file"), (HASH, "file")], vt)
    assert vt.calls == [HASH]
    assert len(results) == 1


def test_programming_errors_crash():
    with pytest.raises(TypeError):
        enrich([(HASH, "file")], FakeClient({HASH: TypeError("bug in our code")}))
