import pytest

from ioc_analyzer.extractors import is_domain, known_tlds


def test_bundled_tld_list_is_complete():
    tlds = known_tlds()
    assert len(tlds) > 1000  # IANA lists ~1,400; a truncated file would show here
    assert {"com", "vn", "xn--p1ai"} <= tlds  # generic, country, punycode (.рф)


@pytest.mark.parametrize("value", ["evil.com", "bank.com.vn", "shop.app", "a.example"])
def test_domains_with_real_or_reserved_tlds_are_accepted(value):
    assert is_domain(value)


@pytest.mark.parametrize(
    "value",
    ["j.doe", "Net.WebClient", "smtp.mailfrom", "header.from", "config.local"],
)
def test_names_with_made_up_tlds_are_rejected(value):
    assert not is_domain(value)


@pytest.mark.parametrize(
    "value", ["detect.py", "script.ps", "invoice.one", "update.cab", "payload.exe"]
)
def test_file_names_are_not_domains(value):
    assert not is_domain(value)


@pytest.mark.parametrize("value", ["microsoft-update.zip", "invoice-scan.mov"])
def test_file_looking_phishing_tlds_are_still_domains(value):
    # Registered on purpose to look like attachments; missing them is the point.
    assert is_domain(value)
