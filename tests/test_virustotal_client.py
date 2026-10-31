import pytest
import requests

from ioc_analyzer.clients import virustotal
from ioc_analyzer.clients.errors import ProviderError, ProviderUnavailableError
from ioc_analyzer.clients.virustotal import BASE_URL, VirusTotalClient, build_url


@pytest.mark.parametrize("api_key", ["", None])
def test_virustotal_client_missing_api_key(api_key):
    with pytest.raises(ValueError, match="VIRUSTOTAL_API"):
        VirusTotalClient(api_key=api_key)


def test_virustotal_accepts_api_key():
    client = VirusTotalClient(api_key="test_key")
    assert client is not None


@pytest.mark.parametrize(
    ("kind", "endpoint"),
    [("ip", "ip_addresses"), ("domain", "domains"), ("file", "files")],
)
def test_build_url_uses_endpoint_for_kind(kind, endpoint):
    assert build_url("abc", kind) == f"{BASE_URL}/{endpoint}/abc"


def test_build_url_rejects_unknown_kind():
    with pytest.raises(ValueError, match="hash"):
        build_url("abc", "hash")


def test_build_url_encodes_path_characters():
    url = build_url("8.8.8.8/../users", "ip")
    assert url == f"{BASE_URL}/ip_addresses/8.8.8.8%2F..%2Fusers"


def test_build_url_uses_real_virustotal_host():
    assert (
        build_url("8.8.8.8", "ip")
        == "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
    )


class FakeResponse:
    """Stands in for the request.Response with only what lookup() uses"""

    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload

    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        if self._payload is None:
            raise ValueError("not JSON")
        return self._payload


@pytest.fixture
def fake_get(monkeypatch):
    """Replace requests.get with a fake. Returns a list of recorded calls."""
    calls = []

    def install(response=None, error=None):
        def fake(url, **kwargs):
            calls.append({"url": url, **kwargs})
            if error is not None:
                raise error
            return response

        monkeypatch.setattr(virustotal.requests, "get", fake)
        return calls

    return install


@pytest.fixture
def client(clock):
    return VirusTotalClient(api_key="test-key", timeout=5, sleep=clock.sleep)


def vt_ip_payload():
    return {"data": {"id": "8.8.8.8", "type": "ip_address", "attributes": {}}}


def test_lookup_returns_parsed_report_when_found(client, fake_get):
    fake_get(FakeResponse(200, vt_ip_payload()))
    result = client.lookup("8.8.8.8", "ip")
    assert result["artifact"] == "8.8.8.8"
    assert result["analysis_stats"] is None


def test_lookup_sends_key_header_and_timeout(client, fake_get):
    calls = fake_get(FakeResponse(200, vt_ip_payload()))
    client.lookup("8.8.8.8", "ip")
    assert calls[0]["headers"] == {"x-apikey": "test-key"}
    assert calls[0]["timeout"] == 5


def test_lookup_returns_none_when_not_found(client, fake_get):
    fake_get(FakeResponse(404))
    assert client.lookup("8.8.8.8", "ip") is None


def test_lookup_stops_provider_on_rejected_key(client, fake_get, clock):
    calls = fake_get(FakeResponse(401))
    with pytest.raises(ProviderUnavailableError, match="API key"):
        client.lookup("8.8.8.8", "ip")
    assert len(calls) == 1
    assert clock.sleeps == []


def test_lookup_429_twice_stops_provider_after_one_wait(client, fake_get, clock):
    calls = fake_get(FakeResponse(429))
    with pytest.raises(ProviderUnavailableError, match="quota"):
        client.lookup("8.8.8.8", "ip")
    assert len(calls) == 2
    assert 60.0 in clock.sleeps


def test_lookup_429_then_answer_succeeds(client, monkeypatch, clock):
    get = Sequence(FakeResponse(429), FakeResponse(200, vt_ip_payload()))
    monkeypatch.setattr(virustotal.requests, "get", get)
    assert client.lookup("8.8.8.8", "ip")["artifact"] == "8.8.8.8"
    assert get.calls == 2


def test_lookup_server_error_skips_only_this_artifact(client, fake_get):
    fake_get(FakeResponse(500))
    with pytest.raises(ProviderError) as info:
        client.lookup("8.8.8.8", "ip")
    assert not isinstance(info.value, ProviderUnavailableError)


def test_lookup_network_failure_is_provider_error(client, fake_get):
    fake_get(error=requests.ConnectionError("down"))
    with pytest.raises(ProviderError, match="unreachable"):
        client.lookup("8.8.8.8", "ip")


def test_lookup_non_json_body_is_provider_error(client, fake_get):
    fake_get(FakeResponse(200, payload=None))
    with pytest.raises(ProviderError, match="not JSON"):
        client.lookup("8.8.8.8", "ip")


def test_lookup_missing_id_is_provider_error(client, fake_get):
    payload = vt_ip_payload()
    del payload["data"]["id"]
    fake_get(FakeResponse(200, payload))
    with pytest.raises(ProviderError, match="missing field 'id'"):
        client.lookup("8.8.8.8", "ip")


def test_lookup_non_object_json_is_provider_error(client, fake_get):
    fake_get(FakeResponse(200, ["not", "a", "dict"]))
    with pytest.raises(ProviderError, match="unexpected shape"):
        client.lookup("8.8.8.8", "ip")


class Sequence:
    """requests.get stand-in that answers with the next response (or error) each call."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def __call__(self, url, **kwargs):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


@pytest.mark.parametrize(
    "first",
    [FakeResponse(503), requests.Timeout("slow"), requests.ConnectionError("reset")],
)
def test_transient_failure_is_retried(client, monkeypatch, clock, first):
    get = Sequence(first, FakeResponse(200, vt_ip_payload()))
    monkeypatch.setattr(virustotal.requests, "get", get)

    assert client.lookup("8.8.8.8", "ip")["artifact"] == "8.8.8.8"
    assert get.calls == 2
    assert clock.sleeps == [1.0]


@pytest.mark.parametrize(
    "response", [FakeResponse(400), FakeResponse(401), FakeResponse(404)]
)
def test_permanent_answers_are_not_retried(client, monkeypatch, clock, response):
    get = Sequence(response)
    monkeypatch.setattr(virustotal.requests, "get", get)

    try:
        client.lookup("8.8.8.8", "ip")
    except ProviderError:
        pass
    assert get.calls == 1
    assert clock.sleeps == []


def test_server_error_on_every_try_fails_after_two_retries(client, fake_get, clock):
    calls = fake_get(FakeResponse(500))
    with pytest.raises(ProviderError, match="HTTP 500"):
        client.lookup("8.8.8.8", "ip")
    assert len(calls) == 3
    assert clock.sleeps == [1.0, 2.0]


def test_client_waits_for_the_rate_limit(monkeypatch, clock):
    get = Sequence(*[FakeResponse(404)] * 3)
    monkeypatch.setattr(virustotal.requests, "get", get)
    client = VirusTotalClient(api_key="k", rate_per_min=2)

    for _ in range(3):
        client.lookup("8.8.8.8", "ip")

    assert get.calls == 3
    assert clock.sleeps == [60.0]


def test_retries_count_against_the_rate_limit(monkeypatch, clock):
    get = Sequence(FakeResponse(503), FakeResponse(404), FakeResponse(404))
    monkeypatch.setattr(virustotal.requests, "get", get)
    client = VirusTotalClient(api_key="k", rate_per_min=2)

    client.lookup("8.8.8.8", "ip")  # t=0 fails, retry at t=1: both use the quota
    client.lookup("1.1.1.1", "ip")  # window full until t=60

    assert clock.sleeps == [1.0, 59.0]
