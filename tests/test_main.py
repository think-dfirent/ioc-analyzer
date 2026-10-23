import pytest
from ioc_analyzer import app
from ioc_analyzer.clients import virustotal

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
    monkeypatch.setattr(app, "query_abuse", lambda artifact: {"artifact": artifact})
    assert app.main(["8.8.8.8"]) == 0
    assert "No VirusTotal record" in capsys.readouterr().out
