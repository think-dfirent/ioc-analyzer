response = {
    "data": {
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
attributes = response["data"]["attributes"]
print(response["data"]["id"])
print(attributes.get("reputation"))
