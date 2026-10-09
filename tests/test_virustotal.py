from ioc_analyzer.app import (
    get_vt_url,
    parse_vt_ip,
    parse_vt_domain,
    parse_vt_file,
)


def test_get_vt_url():
    assert (
        get_vt_url("8.8.8.8")
        == f"https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
    )
    artifact = "a" * 40
    assert get_vt_url(artifact) == f"https://www.virustotal.com/api/v3/files/{artifact}"
    artifact = "example.com"
    assert (
        get_vt_url(artifact) == f"https://www.virustotal.com/api/v3/domains/{artifact}"
    )


def test_parse_vt_ip():
    response = {
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
    result = parse_vt_ip(response)
    assert result["artifact"] == "8.8.8.8"
    assert result["network"] == "8.8.8.0/24"
    assert result["asn"] == 15169
    assert result["as_owner"] == "GOOGLE"
    assert result["country"] == "US"
    assert result["reputation"] == 5
    assert result["analysis_stats"] == {"malicious": 1, "suspicious": 2}


def test_parse_vt_domain():
    response = {
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
    result = parse_vt_domain(response)
    assert result["artifact"] == "example.com"
    assert result["type"] == "domain"
    assert result["reputation"] == -5
    assert result["registrar"] == "Example Registrar Inc."
    assert result["tld"] == "com"
    assert result["analysis_stats"]["malicious"] == 1

def test_parse_vt_ip_missing_required_data():
    