"""Display rules from CLAUDE.md Decisions: missing provider data shows as
"Unknown"/"Unavailable", never as None, and a real 0 stays 0."""

import pytest
from ioc_analyzer.normalization import (
    normalize_domain_result,
    normalize_file_result,
    normalize_ip_result,
)
from ioc_analyzer import report
from ioc_analyzer.report import color_text, print_analysis, set_color, show


def test_show_keeps_zero_and_hides_missing():
    assert show(0) == "0"
    assert show(None) == "Unknown"
    assert show("") == "Unknown"
    assert show(15169, "AS{}") == "AS15169"
    assert show(None, "AS{}") == "Unknown"


def test_ip_with_missing_fields_shows_unknown_but_keeps_zero(capsys):
    vt = {"analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70}}
    abuse = {"abuse_confidence": 0, "total_reports": 0}

    print_analysis(normalize_ip_result(vt, abuse, "203.0.113.7"))

    out = capsys.readouterr().out
    assert "None" not in out
    assert "Reputation     : Unknown" in out
    assert "ASN            : Unknown" in out
    assert "Reports        : 0" in out


def test_domain_with_missing_fields_shows_unknown(capsys):
    print_analysis(normalize_domain_result({"artifact": "example.com"}))

    out = capsys.readouterr().out
    assert "None" not in out
    assert "Registrar      : Unknown" in out


def test_file_with_missing_fields_shows_unknown(capsys):
    vt = {"artifact": "a" * 64, "analysis_stats": {"malicious": 3, "undetected": 60}}

    print_analysis(normalize_file_result(vt))

    out = capsys.readouterr().out
    assert "None" not in out
    assert "Size           : Unknown" in out
    assert "Threat Label   : Unknown" in out


def test_vt_missing_count_shows_unknown(capsys):
    print_analysis(normalize_domain_result({"artifact": "example.com"}))

    out = capsys.readouterr().out
    assert "Malicious     : Unknown" in out
    assert "Unavailable" not in out


class FakeTerminal:
    def isatty(self):
        return True


@pytest.fixture
def terminal(monkeypatch):
    # Test our on/off rule, not Windows console setup, so pretend to be POSIX.
    monkeypatch.setattr(report.os, "name", "posix")
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(report, "_color_enabled", True)  # restored after each test
    return FakeTerminal()


def test_terminal_gets_color_by_default(terminal):
    assert color_text("x", "danger", stream=terminal) == "\033[1;31mx\033[0m"


def test_set_color_false_gives_plain_text(terminal):
    set_color(False)
    assert color_text("x", "danger", stream=terminal) == "x"


def test_no_color_variable_gives_plain_text(terminal, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert color_text("x", "danger", stream=terminal) == "x"
