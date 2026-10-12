from ioc_analyzer import app
from ioc_analyzer.app import query_abuse, ProviderError
import pytest


@pytest.fixture
def abuse_response():
    return {
        "data": {
            "ipAddress": "1.2.3.4",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidenceScore": 87,
            "countryCode": "RU",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Example Hosting LLC",
            "domain": "example-hosting.ru",
            "hostnames": ["host1.example-hosting.ru"],
            "isTor": False,
            "totalReports": 152,
            "numDistinctUsers": 41,
            "lastReportedAt": "2026-10-01T12:34:56+00:00",
        }
    }


""" The tests wil be:
A full response test
Test_query_abuse: test full the response
test_query_abuse_missing_api
test_query_abuse_missing_confidence
"""


@pytest.fixture
def fake_get_json(monkeypatch, abuse_response):
    calls = []  # to track the response(s)

    def fake(url, headers, params):
        calls.append({"url": url, "headers": headers, "params": params})
        return abuse_response

    monkeypatch.setenv("ABUSEIPDB_API", "key")
    monkeypatch.setattr(
        app, "get_json", fake, raising=True
    )  # temporarily set the get_json function in ioc-analyzer.app as "fake"
    return calls


def test_query_abuse_maps_response_fields(fake_get_json):
    result = query_abuse("1.2.3.4")
    assert result["artifact"] == "1.2.3.4"
    assert result["source"] == "AbuseIPDB"
    assert result["abuse_confidence"] == 87
    assert result["total_reports"] == 152
    assert result["distinct_reporters"] == 41
    assert result["last_reported_at"] == "2026-10-01T12:34:56+00:00"
    assert result["country"] == "RU"
    assert result["isp"] == "Example Hosting LLC"
    assert result["usage_type"] == "Data Center/Web Hosting/Transit"
    assert result["domain"] == "example-hosting.ru"
    assert result["hostnames"] == ["host1.example-hosting.ru"]
    assert result["is_tor"] is False


def test_query_abuse_missing_api(monkeypatch, fake_get_json):
    monkeypatch.delenv("ABUSEIPDB_API")
    with pytest.raises(ValueError, match="AbuseIPDB"):
        query_abuse("1.2.3.4")
    assert fake_get_json == []


def test_query_abuse_missing_confidence(fake_get_json, abuse_response):
    del abuse_response["data"]["abuseConfidenceScore"]
    result = query_abuse("1.2.3.4")
    assert result["abuse_confidence"] is None


def test_query_abuse_confidence_is_zero(fake_get_json, abuse_response):
    abuse_response["data"]["abuseConfidenceScore"] = 0
    result = query_abuse("1.2.3.4")
    assert result["abuse_confidence"] == 0


def test_query_abuse_no_data(fake_get_json, abuse_response):
    abuse_response.clear()
    abuse_response["errors"] = [
        {
            "detail": "The ip address must be a valid IPv4 or IPv6",
            "status": 422,
        }
    ]
    with pytest.raises(ProviderError, match="valid IPv4"):
        query_abuse("1.2.3.4")
