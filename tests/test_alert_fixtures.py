"""Extraction on realistic (synthetic) alert text. See CLAUDE.md: fixtures are
never copied from real alerts; they use .example/.test domains, EICAR hashes and
an IP already published in public reports."""

from pathlib import Path

import pytest

from ioc_analyzer.extractors import extract_indicators

FIXTURES = Path(__file__).parent / "fixtures"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def extract(name):
    return extract_indicators((FIXTURES / name).read_text(encoding="utf-8"))


def test_edr_alert_finds_the_real_iocs_even_when_defanged():
    found = extract("edr_alert.txt")
    assert {
        ("185.220.101.4", "ip"),  # written as 185.220.101[.]4 and 185[.]220[.]101[.]4
        ("update-check.example", "domain"),  # inside hxxp://...[.]example/a.ps1
        ("cdn-static.test", "domain"),  # written as cdn-static(.)test
        (EICAR_SHA256, "file"),
        (EICAR_MD5, "file"),  # written in upper case
    } <= set(found)


def test_edr_alert_skips_private_ips_files_and_duplicates():
    found = extract("edr_alert.txt")
    values = [value for value, _ in found]
    assert "10.20.30.41" not in values  # internal host
    assert not any(v.endswith((".exe", ".docm")) for v in values)
    assert len(values) == len(set(values))


def test_phishing_headers_find_sender_infrastructure_and_defanged_link():
    found = extract("phishing_headers.txt")
    assert {
        ("185.220.101.4", "ip"),
        ("invoices-portal.example", "domain"),
        ("mail.invoices-portal.example", "domain"),
        ("login-microsoftonline.example", "domain"),  # hxxps[:]//...[.]example
    } <= set(found)
    assert ("10.0.5.17", "ip") not in found


@pytest.mark.parametrize("name", ["edr_alert.txt", "phishing_headers.txt"])
def test_no_false_positive_domains(name):
    # User names (CORP\j.doe, j.doe@...), code (Net.WebClient) and header fields
    # (smtp.mailfrom) look like domains; their "TLDs" don't exist.
    domains = {value for value, kind in extract(name) if kind == "domain"}
    assert not domains & {"j.doe", "net.webclient", "smtp.mailfrom", "header.from"}
