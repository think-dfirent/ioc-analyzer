"""API keys must never reach stdout, stderr or logs."""

import pytest
import requests
from ioc_analyzer import cli
from ioc_analyzer.clients.abuseipdb import AbuseIPDBClient
from ioc_analyzer.clients.virustotal import VirusTotalClient

VT_KEY = "VT-SECRET-0123456789abcdef"
ABUSE_KEY = "ABUSE-SECRET-fedcba9876543210"


class FakeResponse:
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


OUTCOMES = {
    "timeout": requests.Timeout("read timed out"),
    "connection error": requests.ConnectionError("connection reset by peer"),
    "server error": FakeResponse(500),
    "rejected key": FakeResponse(401),
    "rate limited": FakeResponse(429),
    "not json": FakeResponse(200),
    "not found": FakeResponse(404),
}


@pytest.mark.parametrize("output", [[], ["--json"]], ids=["text", "json"])
@pytest.mark.parametrize("outcome", OUTCOMES.values(), ids=OUTCOMES.keys())
def test_api_keys_never_appear_in_output_or_logs(
    monkeypatch, capsys, caplog, outcome, output
):
    monkeypatch.setattr(cli, "load_dotenv", lambda: None)
    monkeypatch.setenv("VIRUSTOTAL_API", VT_KEY)
    monkeypatch.setenv("ABUSEIPDB_API", ABUSE_KEY)
    monkeypatch.delenv("VIRUSTOTAL_RATE_PER_MIN", raising=False)

    def fake_get(url, **kwargs):
        if isinstance(outcome, Exception):
            # Real requests errors include the URL, so a key in the URL would leak.
            raise type(outcome)(f"{outcome} (url: {url})")
        return outcome

    # Both clients call requests.get on the same requests module.
    monkeypatch.setattr(requests, "get", fake_get)

    # -v: DEBUG messages are where a careless "request headers=..." line would go.
    cli.main(["-v", *output, "8.8.8.8", "evil.example", "a" * 64])

    captured = capsys.readouterr()
    everything = captured.out + captured.err + caplog.text
    assert everything  # something was written, so "key not in it" means something
    assert VT_KEY not in everything
    assert ABUSE_KEY not in everything


def test_client_repr_does_not_show_the_key():
    shown = repr(VirusTotalClient(api_key=VT_KEY)) + repr(
        AbuseIPDBClient(api_key=ABUSE_KEY)
    )
    assert VT_KEY not in shown
    assert ABUSE_KEY not in shown
