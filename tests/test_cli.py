import pytest
from ioc_analyzer import app, cli
from ioc_analyzer.clients import virustotal, abuseipdb

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
    monkeypatch.setattr(cli, "load_dotenv", lambda: None)
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
    assert cli.main([HASH_A]) == 0
    assert "no VirusTotal record" in capsys.readouterr().out


def test_server_error_makes_run_fail(fake_vt):
    fake_vt(500)
    assert cli.main([HASH_A]) == 1


def test_rejected_key_stops_further_vt_calls(fake_vt):
    calls = fake_vt(401)
    assert cli.main([HASH_A, HASH_B]) == 1
    assert len(calls) == 1


def test_missing_key_stops_before_any_request(fake_vt, monkeypatch, capsys):
    calls = fake_vt(200)
    monkeypatch.delenv("VIRUSTOTAL_API")
    assert cli.main([HASH_A]) == 1
    assert calls == []
    assert "VIRUSTOTAL_API" in capsys.readouterr().err


def test_unknown_ip_shows_no_record(fake_vt, monkeypatch, capsys):
    fake_vt(404)
    monkeypatch.setenv("ABUSEIPDB_API", "test-key")
    monkeypatch.setattr(
        cli.AbuseIPDBClient, "lookup", lambda self, artifact: {"artifact": artifact}
    )
    assert cli.main(["8.8.8.8"]) == 0
    assert "No VirusTotal record" in capsys.readouterr().out


def test_missing_abuseipdb_key_warns_and_continues(fake_vt, monkeypatch, capsys):
    fake_vt(404)
    monkeypatch.delenv("ABUSEIPDB_API", raising=False)
    assert cli.main(["8.8.8.8"]) == 0
    captured = capsys.readouterr()
    assert "Continuing without AbuseIPDB" in captured.err
    assert "No VirusTotal record" in captured.out


@pytest.fixture
def fake_both(monkeypatch):
    """Fake HTTP for providers: VT answers 404, AbuseIPDB answers abuse_status
    Both clients call the same requests.get, so the fake routes on the URL"""

    monkeypatch.setattr(cli, "load_dotenv", lambda: None)
    monkeypatch.setenv("VIRUSTOTAL_API", "test-key")
    monkeypatch.setenv("ABUSEIPDB_API", "test-key")
    abuse_calls = []

    def answer_with(abuse_status):
        def fake_get(url, **kwargs):
            if url == abuseipdb.BASE_URL:
                abuse_calls.append(kwargs["params"]["ipAddress"])
                return FakeResponse(abuse_status)
            return FakeResponse(404)

        monkeypatch.setattr(abuseipdb.requests, "get", fake_get)
        return abuse_calls

    return answer_with


def test_rejected_abuseipdb_key_stops_further_abuseipdb_calls(fake_both):
    abuse_calls = fake_both(401)
    assert cli.main(["8.8.8.8", "1.1.1.1"]) == 1  # overall exit code is 1
    assert abuse_calls == ["8.8.8.8"]  # AbuseIPDB was only called once for 8.8.8.8


def test_abuseipdb_server_error_fails_run_but_keeps_vt_result(fake_both, capsys):
    fake_both(500)
    assert cli.main(["8.8.8.8"]) == 1
    captured = capsys.readouterr()
    assert "No VirusTotal record" in captured.out
    assert "AbuseIPDB failed: AbuseIPDB returned HTTP 500" in captured.err


def test_app_module_is_a_thin_wrapper_around_cli():
    assert app.main is cli.main
