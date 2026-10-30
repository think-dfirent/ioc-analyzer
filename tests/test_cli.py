import io
import json
import tomllib
from pathlib import Path

import pytest

from ioc_analyzer import __version__, app, cli
from ioc_analyzer.clients import abuseipdb, virustotal

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


def test_help_works_without_api_keys(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_dotenv", lambda: None)
    monkeypatch.delenv("VIRUSTOTAL_API", raising=False)

    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])

    assert exc.value.code == 0
    assert "usage: ioc-analyzer" in capsys.readouterr().out


def test_unknown_option_is_a_usage_error(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_dotenv", lambda: None)
    monkeypatch.delenv("VIRUSTOTAL_API", raising=False)

    with pytest.raises(SystemExit) as exc:
        cli.main(["--bogus"])

    assert exc.value.code == 2
    assert "usage: ioc-analyzer" in capsys.readouterr().err


def test_file_input_is_scanned(fake_vt, tmp_path, capsys):
    fake_vt(404)
    alert = tmp_path / "alert.txt"
    alert.write_text(f"EDR alert, sha256={HASH_A}", encoding="utf-8")

    assert cli.main(["--file", str(alert)]) == 0
    assert "no VirusTotal record" in capsys.readouterr().out


def test_dash_reads_stdin(fake_vt, monkeypatch, capsys):
    fake_vt(404)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"hash {HASH_A}\n"))

    assert cli.main(["-"]) == 0
    assert "no VirusTotal record" in capsys.readouterr().out


def test_text_and_file_together_is_a_usage_error(fake_vt, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([HASH_A, "--file", "alert.txt"])

    assert exc.value.code == 2
    assert "not allowed with" in capsys.readouterr().err


def test_missing_file_exits_2_before_any_lookup(fake_vt, tmp_path, capsys):
    calls = fake_vt(200)

    assert cli.main(["--file", str(tmp_path / "missing.txt")]) == 2
    assert calls == []
    assert "Cannot read" in capsys.readouterr().err


def test_non_utf8_file_exits_2_with_a_hint(fake_vt, tmp_path, capsys):
    fake_vt(200)
    alert = tmp_path / "alert.txt"
    alert.write_text(HASH_A, encoding="utf-16")  # what PowerShell 5.1 '>' produces

    assert cli.main(["--file", str(alert)]) == 2
    assert "not UTF-8" in capsys.readouterr().err


def test_clipboard_failure_exits_2(fake_vt, monkeypatch, capsys):
    fake_vt(200)

    def broken_paste():
        raise cli.pyperclip.PyperclipException("no clipboard mechanism")

    monkeypatch.setattr(cli.pyperclip, "paste", broken_paste)

    assert cli.main([]) == 2
    assert "Cannot read clipboard" in capsys.readouterr().err


def test_version_prints_name_and_version_without_api_keys(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_dotenv", lambda: None)
    monkeypatch.delenv("VIRUSTOTAL_API", raising=False)

    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])

    assert exc.value.code == 0
    assert capsys.readouterr().out == f"ioc-analyzer {__version__}\n"


def test_version_matches_pyproject():
    # Two copies of the version exist until Phase 7; this test stops them drifting apart.
    pyproject = Path(__file__).parents[1] / "pyproject.toml"
    with pyproject.open("rb") as f:
        assert tomllib.load(f)["project"]["version"] == __version__


def test_no_color_flag_turns_color_off_for_that_run_only(fake_vt, monkeypatch):
    fake_vt(404)
    calls = []
    monkeypatch.setattr(cli, "set_color", calls.append)

    cli.main(["--no-color", HASH_A])
    cli.main([HASH_A])

    assert calls == [False, True]


def test_json_stdout_is_one_parseable_document(fake_vt, capsys):
    fake_vt(404)

    assert cli.main(["--json", HASH_A, "8.8.8.8"]) == 0

    captured = capsys.readouterr()
    results = json.loads(captured.out)["results"]  # fails if anything else is on stdout
    assert [r["providers"]["virustotal"]["status"] for r in results] == [
        "not_found",
        "not_found",
    ]
    assert "Continuing without AbuseIPDB" in captured.err  # warning kept off stdout


def test_json_with_no_iocs_prints_an_empty_document(fake_vt, capsys):
    fake_vt(200)
    cli.main(["--json", "nothing to see here"])
    assert json.loads(capsys.readouterr().out) == {"results": []}
