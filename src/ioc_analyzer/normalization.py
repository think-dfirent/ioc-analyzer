# normalization
from datetime import datetime, timezone


def format_timestamp(timestamp):
    if not timestamp:
        return None

    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )


def normalize_ip_result(vt_result, abuse_result, indicator=None):
    vt_result = vt_result or {}
    abuse_result = abuse_result or {}
    vt_stats = vt_result.get("analysis_stats") or {}

    total = sum(vt_stats.values()) if vt_stats else None
    result = {
        "indicator": indicator
        or vt_result.get("artifact")
        or abuse_result.get("artifact"),
        "type": "ip",
        "virustotal": (
            {
                "malicious": vt_stats.get("malicious"),
                "suspicious": vt_stats.get("suspicious"),
                "total": total,
                "reputation": vt_result.get("reputation"),
            }
            if vt_result
            else None
        ),
        "abuseipdb": (
            {
                "confidence": abuse_result.get("abuse_confidence"),
                "total_reports": abuse_result.get("total_reports"),
                "distinct_reporters": abuse_result.get("distinct_reporters"),
                "last_reported": abuse_result.get("last_reported_at"),
            }
            if abuse_result
            else None
        ),
        "network_context": {
            "country": vt_result.get("country") or abuse_result.get("country"),
            "asn": vt_result.get("asn"),
            "owner": vt_result.get("as_owner") or abuse_result.get("isp"),
            "network": vt_result.get("network"),
            "usage_type": abuse_result.get("usage_type"),
            "domain": abuse_result.get("domain"),
            "is_tor": abuse_result.get("is_tor"),
        },
    }

    return result


def normalize_domain_result(vt_result):
    stats = vt_result.get("analysis_stats")
    total = sum(stats.values()) if stats else None
    if stats is None:
        malicious = None
        suspicious = None
        total = None
    else:
        malicious = stats.get("malicious")
        suspicious = stats.get("suspicious")
    dns_records = []

    for record in vt_result.get("dns_records") or []:
        dns_records.append({"type": record.get("type"), "value": record.get("value")})

    return {
        "indicator": vt_result["artifact"],
        "type": "domain",
        "virustotal": {
            "malicious": malicious,
            "suspicious": suspicious,
            "total": total,
            "reputation": vt_result.get("reputation"),
        },
        "domain_context": {
            "registrar": vt_result.get("registrar"),
            "tld": vt_result.get("tld"),
            "creation_date": format_timestamp(vt_result.get("creation_date")),
            "expiration_date": format_timestamp(vt_result.get("expiration_date")),
            "first_seen": format_timestamp(vt_result.get("first_seen_date")),
        },
        "dns": {"records": dns_records},
        "tags": vt_result.get("tags") or [],
    }


def normalize_file_result(vt_result):
    stats = vt_result["analysis_stats"] or {}
    total = sum(stats.values())

    classification = vt_result.get("threat_classification") or {}

    sandbox_verdicts = {}

    for sandbox, verdict in (vt_result.get("sandbox_verdicts") or {}).items():
        sandbox_verdicts[sandbox] = verdict.get("category")

    return {
        "indicator": vt_result["artifact"],
        "type": "file",
        "virustotal": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total": total,
            "reputation": vt_result.get("reputation"),
            "threat_label": classification.get("suggested_threat_label"),
        },
        "file_context": {
            "name": vt_result.get("meaningful_name"),
            "type": vt_result.get("type_description"),
            "extension": vt_result.get("type_extension"),
            "size": vt_result.get("size"),
            "md5": vt_result.get("md5"),
            "sha1": vt_result.get("sha1"),
            "sha256": vt_result.get("sha256"),
            "tags": vt_result.get("tags") or [],
        },
        "timeline": {
            "first_submission": format_timestamp(
                vt_result.get("first_submission_date")
            ),
            "last_submission": format_timestamp(vt_result.get("last_submission_date")),
            "last_analysis": format_timestamp(vt_result.get("last_analysis_date")),
        },
        "sandbox": sandbox_verdicts,
    }
