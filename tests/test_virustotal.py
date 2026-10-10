from ioc_analyzer.app import (
    get_vt_url,
    parse_vt_ip,
    parse_vt_domain,
    parse_vt_file,
)
import pytest

VT_BASE = "https://www.virustotal.com/api/v3"


@pytest.mark.parametrize(
    "artifact, expected_path",
    [
        ("8.8.8.8", "ip_addresses"),
        ("a" * 32, "files"),  # MD5
        ("a" * 40, "files"),  # SHA1
        ("a" * 64, "files"),  # SHA256
        ("example.com", "domains"),
    ],
)
def test_get_vt_url(artifact, expected_path):
    assert get_vt_url(artifact) == f"{VT_BASE}/{expected_path}/{artifact}"


@pytest.fixture
def vt_ip_response():
    return {
        "data": {
            "id": "8.8.8.8",
            "type": "ip_address",
            "attributes": {
                "network": "8.8.8.0/24",
                "asn": 15169,
                "as_owner": "GOOGLE",
                "country": "US",
                "reputation": 5,
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 2,
                },
            },
        }
    }


@pytest.fixture
def vt_domain_response():
    return {
        "data": {
            "id": "example.com",
            "type": "domain",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 2,
                    "harmless": 70,
                    "undetected": 20,
                },
                "reputation": -5,
                "total_votes": {
                    "harmless": 10,
                    "malicious": 3,
                },
                "categories": {
                    "BitDefender": "technology",
                    "Forcepoint ThreatSeeker": "information technology",
                },
                "registrar": "Example Registrar Inc.",
                "tld": "com",
                "creation_date": 1609459200,
                "expiration_date": 1893456000,
                "first_seen_date": 1612137600,
                "last_analysis_date": 1756684800,
                "last_dns_records": [
                    {
                        "type": "A",
                        "value": "93.184.216.34",
                    },
                    {
                        "type": "MX",
                        "value": "mail.example.com",
                    },
                    {
                        "type": "NS",
                        "value": "ns1.example.com",
                    },
                ],
                "last_dns_records_date": 1756684800,
                "tags": [
                    "test-domain",
                    "technology",
                ],
            },
        }
    }


@pytest.fixture
def vt_file_response():
    sha256 = "b" * 64
    return {
        "data": {
            "id": sha256,
            "type": "file",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 40,
                    "suspicious": 1,
                    "harmless": 0,
                    "undetected": 30,
                },
                "reputation": -20,
                "meaningful_name": "invoice.exe",
                "names": ["invoice.exe", "payload.bin"],
                "type_description": "Win32 EXE",
                "type_extension": "exe",
                "size": 102400,
                "md5": "c" * 32,
                "sha1": "d" * 40,
                "sha256": sha256,
                "first_submission_date": 1609459200,
                "last_submission_date": 1756684800,
                "last_analysis_date": 1756684800,
                "tags": ["peexe", "signed"],
                "popular_threat_classification": {
                    "suggested_threat_label": "trojan.agent",
                },
                "sandbox_verdicts": {
                    "Zenbox": {"category": "malicious"},
                },
            },
        }
    }


def test_parse_vt_ip(vt_ip_response):
    result = parse_vt_ip(vt_ip_response)
    assert result["artifact"] == "8.8.8.8"
    assert result["network"] == "8.8.8.0/24"
    assert result["asn"] == 15169
    assert result["as_owner"] == "GOOGLE"
    assert result["country"] == "US"
    assert result["reputation"] == 5
    assert result["analysis_stats"] == {"malicious": 1, "suspicious": 2}


def test_parse_vt_ip_missing_id(vt_ip_response):
    del vt_ip_response["data"]["id"]
    with pytest.raises(KeyError, match="id"):
        parse_vt_ip(vt_ip_response)


def test_parse_vt_ip_missing_reputation_is_none(vt_ip_response):
    del vt_ip_response["data"]["attributes"]["reputation"]
    result = parse_vt_ip(vt_ip_response)
    assert result["reputation"] is None


def test_parse_vt_domain(vt_domain_response):
    result = parse_vt_domain(vt_domain_response)
    assert result["artifact"] == "example.com"
    assert result["type"] == "domain"
    assert result["reputation"] == -5
    assert result["registrar"] == "Example Registrar Inc."
    assert result["tld"] == "com"
    # Keys that parse_vt_domain renames from the VT response
    assert result["analysis_stats"]["malicious"] == 1
    assert result["dns_records"][0] == {"type": "A", "value": "93.184.216.34"}
    assert result["dns_records_date"] == 1756684800


def test_parse_vt_domain_missing_id(vt_domain_response):
    del vt_domain_response["data"]["id"]
    with pytest.raises(KeyError, match="id"):
        parse_vt_domain(vt_domain_response)


def test_parse_vt_domain_missing_reputation_is_none(vt_domain_response):
    del vt_domain_response["data"]["attributes"]["reputation"]
    result = parse_vt_domain(vt_domain_response)
    assert result["type"] == "domain"
    assert result["reputation"] is None


def test_parse_vt_file(vt_file_response):
    result = parse_vt_file(vt_file_response)
    assert result["artifact"] == "b" * 64
    assert result["type"] == "file"
    assert result["reputation"] == -20
    assert result["meaningful_name"] == "invoice.exe"
    assert result["md5"] == "c" * 32
    assert result["sha1"] == "d" * 40
    assert result["sha256"] == "b" * 64
    # Keys that parse_vt_file renames from the VT response
    assert result["analysis_stats"]["malicious"] == 40
    assert result["threat_classification"] == {
        "suggested_threat_label": "trojan.agent",
    }


def test_parse_vt_file_missing_id(vt_file_response):
    del vt_file_response["data"]["id"]
    with pytest.raises(KeyError, match="id"):
        parse_vt_file(vt_file_response)
