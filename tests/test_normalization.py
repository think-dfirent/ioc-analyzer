from ioc_analyzer.normalization import (
    normalize_ip_result,
    normalize_domain_result,
    normalize_file_result,
    format_timestamp,
)
from ioc_analyzer.normalization import (
    format_timestamp,
    normalize_file_result,
    normalize_domain_result,
    normalize_ip_result,
)


def test_normalize_ip_result_combines_providers():
    vt_result = {
        "artifact": "8.8.8.8",
        "network": "8.8.8.0/24",
        "asn": 15169,
        "as_owner": "GOOGLE",
        "country": "US",
        "reputation": 10,
        "analysis_stats": {
            "malicious": 2,
            "suspicious": 1,
            "harmless": 50,
            "undetected": 30,
        },
    }

    abuse_result = {
        "artifact": "8.8.8.8",
        "abuse_confidence": 5,
        "total_reports": 10,
        "distinct_reporters": 8,
        "last_reported_at": "2026-10-01T10:00:00Z",
        "country": "US",
        "isp": "Google LLC",
        "usage_type": "Data Center/Web Hosting/Transit",
        "domain": "google.com",
        "is_tor": False,
    }

    result = normalize_ip_result(vt_result, abuse_result)

    assert result["indicator"] == "8.8.8.8"
    assert result["type"] == "ip"

    assert result["virustotal"]["malicious"] == 2
    assert result["virustotal"]["suspicious"] == 1
    assert result["virustotal"]["total"] == 83
    assert result["virustotal"]["reputation"] == 10

    assert result["abuseipdb"]["confidence"] == 5
    assert result["abuseipdb"]["total_reports"] == 10
    assert result["abuseipdb"]["distinct_reporters"] == 8

    assert result["network_context"]["country"] == "US"
    assert result["network_context"]["asn"] == 15169
    assert result["network_context"]["owner"] == "GOOGLE"
    assert result["network_context"]["network"] == "8.8.8.0/24"


def test_normalize_ip_without_virustotal():
    abuse_result = {
        "artifact": "8.8.8.8",
        "abuse_confidence": 5,
        "total_reports": 10,
        "distinct_reporters": 8,
        "last_reported_at": "2026-10-01T10:00:00Z",
        "country": "US",
        "isp": "Google LLC",
        "usage_type": "Data Center",
        "domain": "google.com",
        "is_tor": False,
    }

    result = normalize_ip_result(None, abuse_result)

    assert result["indicator"] == "8.8.8.8"
    assert result["virustotal"] is None
    assert result["abuseipdb"]["confidence"] == 5
    assert result["network_context"]["country"] == "US"
    assert result["network_context"]["owner"] == "Google LLC"


def test_normalize_ip_without_abuseipdb():
    vt_result = {
        "artifact": "8.8.8.8",
        "analysis_stats": {"malicious": 0, "suspicious": 0},
        "reputation": 10,
        "country": "US",
        "asn": 15169,
        "as_owner": "GOOGLE",
        "network": "8.8.8.0/24",
    }

    result = normalize_ip_result(vt_result, None)

    assert result["indicator"] == "8.8.8.8"
    assert result["abuseipdb"] is None
    assert result["virustotal"]["total"] == 0
    assert result["network_context"]["owner"] == "GOOGLE"


def test_normalize_ip_without_provider_results():
    result = normalize_ip_result(None, None, indicator="8.8.8.8")

    assert result["indicator"] == "8.8.8.8"
    assert result["virustotal"] is None
    assert result["abuseipdb"] is None


def test_normalize_ip_explicit_indicator_takes_priority():
    vt_result = {
        "artifact": "1.1.1.1",
        "analysis_stats": {},
    }

    result = normalize_ip_result(
        vt_result,
        None,
        indicator="8.8.8.8",
    )

    assert result["indicator"] == "8.8.8.8"


def test_normalize_domain_result():
    vt_result = {
        "artifact": "example.com",
        "analysis_stats": {
            "malicious": 3,
            "suspicious": 2,
            "harmless": 40,
        },
        "reputation": -5,
        "registrar": "Example Registrar",
        "tld": "com",
        "creation_date": 1609459200,
        "expiration_date": 1893456000,
        "first_seen_date": 1612137600,
        "dns_records": [
            {"type": "A", "value": "93.184.216.34"},
            {"type": "MX", "value": "mail.example.com"},
        ],
        "tags": ["test", "demo"],
    }
    result = normalize_domain_result(vt_result)

    assert result["indicator"] == "example.com"
    assert result["type"] == "domain"
    assert result["virustotal"]["malicious"] == 3
    assert result["virustotal"]["total"] == 45
    assert result["domain_context"]["registrar"] == "Example Registrar"
    assert result["domain_context"]["creation_date"] == format_timestamp(
        vt_result["creation_date"]
    )
    assert result["domain_context"]["expiration_date"] == format_timestamp(
        vt_result["expiration_date"]
    )
    assert result["domain_context"]["first_seen"] == format_timestamp(
        vt_result["first_seen_date"]
    )
    assert result["dns"]["records"][0] == {
        "type": "A",
        "value": "93.184.216.34",
    }
    assert result["tags"] == ["test", "demo"]


def test_normalized_domain_missing_optional_data():
    result = normalize_domain_result(
        {
            "artifact": "example.com",
            "analysis_stats": None,
        }
    )
    assert result["dns"]["records"] == []
    assert result["tags"] == []
    assert result["domain_context"]["creation_date"] is None


def test_normalize_domain_missing_stats_is_unknown():
    result = normalize_domain_result(
        {
            "artifact": "example.com",
            "analysis_stats": None,
        }
    )
    assert result["virustotal"]["malicious"] is None
    assert result["virustotal"]["suspicious"] is None
    assert result["virustotal"]["total"] is None


def test_normalize_domain_real_zero_stays_zero():
    result = normalize_domain_result(
        {
            "artifact": "example.com",
            "analysis_stats": {
                "suspicious": 10,
                "malicious": 9,
            },
        }
    )
    assert result["virustotal"]["malicious"] == 9
    assert result["virustotal"]["suspicious"] == 10
    assert result["virustotal"]["total"] == 19


def test_normalize_file_result():
    vt_result = {
        "artifact": "c" * 64,
        "analysis_stats": {
            "malicious": 20,
            "suspicious": 5,
            "harmless": 10,
        },
        "reputation": -20,
        "meaningful_name": "malware.exe",
        "type_description": "Win32 EXE",
        "type_extension": "exe",
        "size": 123456,
        "md5": "a" * 32,
        "sha1": "b" * 40,
        "sha256": "c" * 64,
        "first_submission_date": 1609459200,
        "last_submission_date": 1612137600,
        "last_analysis_date": 1614556800,
        "tags": ["peexe"],
        "threat_classification": {"suggested_threat_label": "trojan"},
        "sandbox_verdicts": {
            "sandbox-a": {"category": "malicious"},
            "sandbox-b": {"category": "suspicious"},
        },
    }
    result = normalize_file_result(vt_result)
    assert result["indicator"] == "c" * 64
    assert result["type"] == "file"

    assert result["virustotal"]["malicious"] == 20
    assert result["virustotal"]["total"] == 35
    assert result["virustotal"]["threat_label"] == "trojan"

    assert result["file_context"]["name"] == "malware.exe"
    assert result["file_context"]["sha256"] == "c" * 64

    assert result["sandbox"] == {
        "sandbox-a": "malicious",
        "sandbox-b": "suspicious",
    }


def test_normalize_file_with_missing_optional_data():
    result = normalize_file_result(
        {
            "artifact": "c" * 64,
            "analysis_stats": None,
        }
    )

    assert result["virustotal"]["total"] == 0
    assert result["virustotal"]["threat_label"] is None
    assert result["file_context"]["tags"] == []
    assert result["timeline"]["first_submission"] is None
    assert result["sandbox"] == {}


def test_format_timestamp():
    assert format_timestamp(1609459200) == "2021-01-01 00:00 UTC"
    assert format_timestamp(None) is None
