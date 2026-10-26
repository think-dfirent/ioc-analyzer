import pytest
from ioc_analyzer import app
from ioc_analyzer.clients import virustotal
from ioc_analyzer.clients.errors import ProviderError

HASH_A = "a" * 64
HASH_B = "b" * 64


class FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code

    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        return {}


@pytest.fixture
def fake_vt(monkeypatch):
    monkeypatch.setattr(app, "load_dotenv", lambda: None)
    monkeypatch.setenv("VIRUSTOTAL_API", "test-key")
    calls = []

    def answer_with(status_code):
        def fake_get(url, **kwargs):
            calls.append(url)
            return FakeResponse(status_code)

        monkeypatch.setattr(virustotal.requests, "get", fake_get)
        return calls

    return answer_with


def test_unknown_hash_is_reported_not_failed(fake_vt, capsys):
    fake_vt(404)
    assert app.main([HASH_A]) == 0
    assert "no VirusTotal record" in capsys.readouterr().out


def test_server_error_makes_run_fail(fake_vt):
    fake_vt(500)
    assert app.main([HASH_A]) == 1


def test_rejected_key_stops_further_vt_calls(fake_vt):
    calls = fake_vt(401)
    assert app.main([HASH_A, HASH_B]) == 1
    assert len(calls) == 1


def test_missing_key_stops_before_any_request(fake_vt, monkeypatch, capsys):
    calls = fake_vt(200)
    monkeypatch.delenv("VIRUSTOTAL_API")
    assert app.main([HASH_A]) == 1
    assert calls == []
    assert "VIRUSTOTAL_API" in capsys.readouterr().err


def test_unknown_ip_shows_no_record(fake_vt, monkeypatch, capsys):
    fake_vt(404)
    monkeypatch.setenv("ABUSEIPDB_API", "test-key")
    monkeypatch.setattr(
        app.AbuseIPDBClient, "lookup", lambda self, artifact: {"artifact": artifact}
    )
    assert app.main(["8.8.8.8"]) == 0
    assert "No VirusTotal record" in capsys.readouterr().out


def test_missing_abuseipdb_key_warns_and_continues(fake_vt, monkeypatch, capsys):
    fake_vt(404)
    monkeypatch.delenv("ABUSEIPDB_API", raising=False)
    assert app.main(["8.8.8.8"]) == 0
    captured = capsys.readouterr()
    assert "Continuing without AbuseIPDB" in captured.err
    assert "No VirusTotal record" in captured.out


def test_query_safely_reports_provider_error(capsys):
    def failing_lookup(artifact):
        raise ProviderError("(server down)")

    assert app.query_safely("VirusTotal", failing_lookup, "8.8.8.8") == (False, None)
    assert "VirusTotal failed (server down)" in capsys.readouterr().err


def test_query_safely_lets_programming_errors_crash():
    def buggy_lookup(artifact):
        raise TypeError("bug in our own code")

    with pytest.raises(TypeError):
        app.query_safely("VirusTotal", buggy_lookup, "8.8.8.8")
