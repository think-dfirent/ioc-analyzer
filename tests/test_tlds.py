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
