import pytest
import requests
from ioc_analyzer.clients.errors import ProviderError, ProviderUnavailableError
from ioc_analyzer.clients import abuseipdb
from ioc_analyzer.clients.abuseipdb import AbuseIPDBClient, BASE_URL


@pytest.mark.parametrize("api_key", ["", None])
def test_abuseipdb_client_missing_api_key(api_key):
    with pytest.raises(ValueError, match="ABUSEIPDB_API"):
        AbuseIPDBClient(api_key=api_key)


def test_abuseipdb_client_with_api_key():
    client = AbuseIPDBClient(api_key="test_key")
    assert client is not None


class FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload

    # the fetch fuction only care about status code and the json payload
    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        if self._payload is None:
            raise ValueError("not JSON")
        return self._payload


@pytest.fixture
def fake_get(monkeypatch):
    calls = []

    def install(response=None, error=None):
        def fake(url, **kw):
            calls.append({"url": url, **kw})
            if error is not None:
                raise error
            return response

        monkeypatch.setattr(
            abuseipdb.requests, "get", fake
        )  # abuseipdb.requests.get = fake
        return calls

    return install


@pytest.fixture
def client():
    return AbuseIPDBClient(api_key="test_key", timeout=5, max_age_days=90)


@pytest.fixture
def abuse_payload():
    return {
        "data": {
            "ipAddress": "118.25.6.39",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidenceScore": 100,
            "countryCode": "CN",
            "countryName": "China",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Tencent Cloud Computing (Beijing) Co. Ltd",
            "domain": "tencent.com",
            "hostnames": [],
            "isTor": False,
            "totalReports": 1,
            "numDistinctUsers": 1,
            "lastReportedAt": "2018-12-20T20:55:14+00:00",
            "reports": [
                {
                    "reportedAt": "2018-12-20T20:55:14+00:00",
                    "comment": "Dec 20 20:55:14 srv206 sshd[13937]: Invalid user oracle from 118.25.6.39",
                    "categories": [18, 22],
                    "reporterId": 1,
                    "reporterCountryCode": "US",
                    "reporterCountryName": "United States",
                }
            ],
        }
    }


def test_lookup_sends_key_ip_and_settings(client, fake_get, abuse_payload):
    calls = fake_get(FakeResponse(200, abuse_payload))
    client.lookup("118.25.6.39")
    assert len(calls) == 1
    assert calls[0]["url"] == BASE_URL
    assert calls[0]["headers"] == {"Key": "test_key", "Accept": "application/json"}
    assert calls[0]["timeout"] == 5
    assert calls[0]["params"]["maxAgeInDays"] == 90
    assert calls[0]["params"]["ipAddress"] == "118.25.6.39"


def test_lookup_returns_parsed_result(client, fake_get, abuse_payload):
    fake_get(FakeResponse(200, abuse_payload))
    result = client.lookup("118.25.6.39")
    assert result["artifact"] == "118.25.6.39"
    assert result["abuse_confidence"] == 100
    assert result["total_reports"] == 1


@pytest.mark.parametrize("status_code", [401, 429])
def test_abuse_ipdb_returned_provider_unavailable(fake_get, client, status_code):
    fake_get(FakeResponse(status_code))
    with pytest.raises(ProviderUnavailableError, match=f"{status_code}"):
        client.lookup("8.8.8.8")


def test_abuse_ipdb_return_server_error(fake_get, client):
    fake_get(FakeResponse(500))
    with pytest.raises(ProviderError, match="500"):
        client.lookup("8.8.8.8")


def test_abuse_ipdb_network_error(fake_get, client):
    fake_get(error=requests.ConnectionError("Network connection error"))
    with pytest.raises(ProviderError, match="Network"):
        client.lookup("1.2.3.4")


def test_abuse_ipdb_returned_non_json_body(fake_get, client):
    fake_get(response=FakeResponse(200, None))
    with pytest.raises(
        ProviderError, match="AbuseIPDB returned a response that is not JSON"
    ):
        client.lookup("8.8.8.8")


def test_abuse_ipdb_returned_an_unexpected_shape_json(fake_get, client):
    fake_get(response=FakeResponse(200, ""))
    with pytest.raises(
        ProviderError, match="AbuseIPDB returned JSON with an unexpected shape"
    ):
        client.lookup("8.8.8.8")


def test_lookup_without_data_reports_abuseipdb_error(client, fake_get):
    payload = {
        "errors": [{"detail": "The ip address must be a valid IPv4 or IPv6 address."}]
    }
    fake_get(FakeResponse(200, payload))
    with pytest.raises(ProviderError, match="valid IPv4"):
        client.lookup("not-an-ip")


def test_lookup_without_data_or_errors_is_provider_error(client, fake_get):
    fake_get(FakeResponse(200, {}))
    with pytest.raises(ProviderError, match="no data"):
        client.lookup("8.8.8.8")


def test_lookup_404_is_provider_error_not_crash(client, fake_get):
    fake_get(FakeResponse(404))
    with pytest.raises(ProviderError, match="404") as info:
        client.lookup("8.8.8.8")
    assert type(info.value) is ProviderError
