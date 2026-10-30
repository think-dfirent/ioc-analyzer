import json

from ioc_analyzer.enrich import EnrichmentResult
from ioc_analyzer.normalization import normalize_domain_result
from ioc_analyzer.serialize import to_json


def test_missing_values_are_null_not_unknown():
    report = normalize_domain_result({"artifact": "example.com"})
    result = EnrichmentResult("example.com", "domain", vt_status="ok", report=report)

    text = to_json([result])

    assert json.loads(text)["results"][0]["report"]["virustotal"]["malicious"] is None
    assert "Unknown" not in text


def test_each_provider_reports_its_status():
    ip = EnrichmentResult("8.8.8.8", "ip", vt_status="ok", abuse_status="unavailable")
    file = EnrichmentResult("a" * 64, "file", vt_status="not_found")

    ip_out, file_out = json.loads(to_json([ip, file]))["results"]

    assert ip_out["providers"] == {
        "virustotal": {"status": "ok"},
        "abuseipdb": {"status": "unavailable"},
    }
    assert file_out["providers"] == {"virustotal": {"status": "not_found"}}
    assert file_out["report"] is None


def test_errors_become_a_list():
    result = EnrichmentResult(
        "8.8.8.8", "ip", vt_status="error", errors=("8.8.8.8: VirusTotal failed",)
    )
    [out] = json.loads(to_json([result]))["results"]
    assert out["errors"] == ["8.8.8.8: VirusTotal failed"]


def test_no_results_is_still_a_document():
    assert json.loads(to_json([])) == {"results": []}
