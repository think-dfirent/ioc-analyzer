"""Terminal output: colors and printers for enrichment results
No calls or exit code here"""

import os
import sys

COLORS = {
    "heading": "1;36",
    "title": "1;35",
    "danger": "1;31",
    "warning": "33",
    "zero": "32",
    "muted": "90",
}


def color_text(value, color, stream=None):
    stream = sys.stdout if stream is None else stream
    text = str(value)
    if "NO_COLOR" in os.environ or not stream.isatty():
        return text
    if os.name == "nt":
        # Enable ANSI escapes on Windows consoles; fall back to plain text.
        import ctypes
        import msvcrt

        try:
            handle = ctypes.c_void_p(msvcrt.get_osfhandle(stream.fileno()))
            mode = ctypes.c_ulong()
            kernel = ctypes.windll.kernel32
            if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
                return text
            if not kernel.SetConsoleMode(handle, mode.value | 0x0004):
                return text
        except (OSError, ValueError, AttributeError):
            return text
    return f"\033[{COLORS[color]}m{text}\033[0m"


UNKNOWN = "Unknown"


def show(value, template="{}"):
    """Format one field for display, or "Unknown" when the provider sent no value.
    Only None and "" count as missing. 0 is real data.
    """
    if value is None or value == "":
        return UNKNOWN
    return template.format(value)


def print_section(title):
    print(color_text(f"\n[ {title} ]", "heading"))


def print_error(message):
    print(color_text(message, "danger", sys.stderr), file=sys.stderr)


def print_vt_stats(vt, status=None):
    print_section("VirusTotal")
    if vt is None:
        if status == "not_found":
            print(color_text("No VirusTotal record (never submitted or seen)", "muted"))
        else:
            print(color_text("Unavailable", "warning"))
        return
    for label, key in (("Malicious", "malicious"), ("Suspicious", "suspicious")):
        count = vt[key]
        value = UNKNOWN if count is None else f"{count} / {vt['total']}"
        tone = (
            "warning"
            if count is None
            else (
                "zero"
                if count == 0
                else ("danger" if key == "malicious" else "warning")
            )
        )
        print(f"{label:<14}: {color_text(value, tone)}")
    reputation = vt["reputation"]
    tone = "warning" if reputation is None else "danger" if reputation < 0 else "muted"
    print(f"Reputation     : {color_text(show(reputation), tone)}")


# print dispatcher
def print_analysis(result):
    print(color_text("=" * 70, "muted"))
    print(color_text(f"IOC ANALYSIS: {result['indicator']}", "title"))
    print(color_text(f"TYPE: {result['type'].upper()}", "heading"))
    print(color_text("=" * 70, "muted"))

    if result["type"] == "ip":
        print_ip_result(result)

    elif result["type"] == "domain":
        print_domain_result(result)

    elif result["type"] == "file":
        print_file_result(result)

    else:
        print("Unsupported IOC type.")

    print(color_text("=" * 70, "muted"))


def print_ip_result(result):
    vt = result["virustotal"]
    abuse = result["abuseipdb"]
    context = result["network_context"]

    print_vt_stats(vt, result.get("vt_status"))

    print_section("AbuseIPDB")
    if abuse is None:
        print(color_text("Unavailable", "warning"))
    else:
        confidence = abuse["confidence"]
        tone = (
            "warning"
            if confidence is None
            else "zero" if confidence == 0 else "warning"
        )
        value = show(confidence, "{}%")
        print(f"Confidence     : {color_text(value, tone)}")
        print(f"Reports        : {show(abuse['total_reports'])}")
        print(f"Reporters      : {show(abuse['distinct_reporters'])}")
        print(f"Last reported  : {show(abuse['last_reported'])}")

    print_section("Network Context")
    print(f"Country        : {show(context['country'])}")
    print(f"ASN            : {show(context['asn'], 'AS{}')}")
    print(f"Owner          : {show(context['owner'])}")
    print(f"Network        : {show(context['network'])}")
    print(f"Usage          : {show(context['usage_type'])}")
    print(f"Domain         : {show(context['domain'])}")
    print(
        f"Tor            : "
        f"{UNKNOWN if context['is_tor'] is None else 'Yes' if context['is_tor'] else 'No'}"
    )


def print_domain_result(result):
    vt = result["virustotal"]
    context = result["domain_context"]
    dns = result["dns"]

    print_vt_stats(vt)

    print_section("Domain Context")
    print(f"Registrar      : {show(context['registrar'])}")
    print(f"TLD            : {show(context['tld'])}")
    print(f"Created        : {show(context['creation_date'])}")
    print(f"Expires        : {show(context['expiration_date'])}")
    print(f"First Seen     : {show(context['first_seen'])}")

    print_section("DNS Records")

    if dns["records"]:
        for record in dns["records"]:
            print(f"{show(record['type']):<14}: {show(record['value'])}")
    else:
        print(color_text("No DNS records available", "muted"))

    if result["tags"]:
        print(f"\nTags           : {', '.join(result['tags'])}")


def print_file_result(result):
    vt = result["virustotal"]
    context = result["file_context"]
    timeline = result["timeline"]

    print_vt_stats(vt)
    if vt is not None:
        threat_label = vt.get("threat_label")
        print(
            f"Threat Label   : {color_text(show(threat_label), 'warning' if threat_label else 'muted')}"
        )

    print_section("File Context")
    print(f"Name           : {show(context['name'])}")
    print(f"Type           : {show(context['type'])}")
    print(f"Extension      : {show(context['extension'])}")
    print(f"Size           : {show(context['size'], '{} bytes')}")

    print_section("Hashes")
    print(f"MD5            : {show(context['md5'])}")
    print(f"SHA1           : {show(context['sha1'])}")
    print(f"SHA256         : {show(context['sha256'])}")

    print_section("Timeline")
    print(f"First Submitted: {show(timeline['first_submission'])}")
    print(f"Last Submitted : {show(timeline['last_submission'])}")
    print(f"Last Analysis  : {show(timeline['last_analysis'])}")

    if context["tags"]:
        print(f"\nTags           : {', '.join(context['tags'])}")

    if result["sandbox"]:
        print_section("Sandbox")

        for sandbox, verdict in result["sandbox"].items():
            tone = (
                "danger"
                if verdict == "malicious"
                else "warning" if verdict == "suspicious" else "muted"
            )
            print(f"{sandbox:<14}: {color_text(show(verdict), tone)}")
