from ioc_analyzer.extractors import (
    ip_extraction,
    domain_extraction,
    is_domain,
    hash_extraction,
)


# ip_extraction
def test_extract_public_ipv4():
    test = "Suspicious connection to 8.8.8.8"
    result = ip_extraction(test)
    assert result == ["8.8.8.8"]


def test_ignore_private_ipv4():
    test = "Host 192.168.1.50 contacted another system"
    result = ip_extraction(test)
    assert result == []


def test_ignore_invalid_ipv4():
    test = "Host 999.999.99.222 connects to local hosts through port 445"
    result = ip_extraction(test)
    assert result == []


def test_extract_multiple_public_ipv4():
    test = "Host 123.123.123.123 connected to host 172.33.32.1"
    result = ip_extraction(test)
    assert result == ["123.123.123.123", "172.33.32.1"]


# is_domain
def test_valid_domain():
    assert is_domain("valid-domain.com") is True


def test_valid_sub_domain():
    assert is_domain("sub.valid-domain.com") is True


def test_invalid_domain():
    assert is_domain("asdfwer-asedfsdf") is False


# domain_extraction
def test_extract_domain():
    test = "Contact example.com"
    assert domain_extraction(test) == ["example.com"]


def test_extract_domain_from_full_url():
    test = "Visit https://example.com/login?id=123"
    assert domain_extraction(test) == ["example.com"]


def test_ignore_duplicate_domain():
    test = "example.com example.com"
    assert domain_extraction(test) == ["example.com"]


# hash_extraction
def test_extract_md5():
    md5 = "a" * 32
    test = f"The malware md5 hash is {md5}"
    assert hash_extraction(test) == [md5]


def test_extract_sha1():
    sha1 = "b" * 40
    test = f"The malware sha1 hash is {sha1}"
    assert hash_extraction(test) == [sha1]


def test_extract_sha256():
    sha256 = "c" * 64
    test = f"The malware sha256 hash is {sha256}"
    assert hash_extraction(test) == [sha256]


def test_ignore_invalid_hash():
    test = "These aren't hashes: 1hlo1l3iyh2, 1ol5o6l7oi, h5o7p23920uh52kljh4j3k3"
    assert hash_extraction(test) == []
