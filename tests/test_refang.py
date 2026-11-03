import pytest

from ioc_analyzer.extractors import refang


@pytest.mark.parametrize(
    ("defanged", "expected"),
    [
        ("185.220.101[.]4", "185.220.101.4"),
        ("185[.]220[.]101[.]4", "185.220.101.4"),
        ("evil(.)example", "evil.example"),
        ("evil{.}example", "evil.example"),
        ("evil[dot]example", "evil.example"),
        ("evil(DOT)example", "evil.example"),
        ("hxxp://evil[.]example/a", "http://evil.example/a"),
        ("hxxps://evil[.]example", "https://evil.example"),
        ("hXXps[:]//evil[.]example", "https://evil.example"),
        ("hxxp[://]evil[.]example", "http://evil.example"),
        ("185.220.101.4[:]443", "185.220.101.4:443"),
    ],
)
def test_defanged_forms_are_refanged(defanged, expected):
    assert refang(defanged) == expected


@pytest.mark.parametrize(
    "text",
    [
        "plain text with 8.8.8.8 and https://example.com",
        "meet at the dot com party",  # bare "dot" is English, not a defang
        "evil . example",  # spaces are not a defang marker
        "hxxpfoo is just a word",  # hxxp only counts as a scheme
        "list[0] and f(x) and {key}",  # brackets without a dot inside
    ],
)
def test_text_without_defang_markers_is_unchanged(text):
    assert refang(text) == text


def test_refang_is_idempotent():
    once = refang("hxxps[:]//evil[.]example and 1[.]2[.]3[.]4")
    assert refang(once) == once
