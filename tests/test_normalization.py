from ioc_analyzer.app import (
    normalize_ip_result,
    normalize_domain_result,
    normalize_file_result,
    format_timestamp,
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
