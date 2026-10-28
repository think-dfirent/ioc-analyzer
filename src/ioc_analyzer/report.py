"""Terminal output: colors and printers for enrichment results
No calls or exit code here"""

import os, sys

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
        value = f"{count} / {vt['total']}" if count is not None else "Unavailable"
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
    print(f"Reputation     : {color_text(reputation, tone)}")


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
        tone = "zero" if confidence == 0 else "warning"
        value = "Unavailable" if confidence is None else f"{confidence}%"
        print(f"Confidence     : {color_text(value, tone)}")
        print(f"Reports        : {abuse['total_reports']}")
        print(f"Reporters      : {abuse['distinct_reporters']}")
        print(f"Last reported  : {abuse['last_reported']}")

    print_section("Network Context")
    print(f"Country        : {context['country']}")
    print(f"ASN            : AS{context['asn']}")
    print(f"Owner          : {context['owner']}")
    print(f"Network        : {context['network']}")
    print(f"Usage          : {context['usage_type']}")
    print(f"Domain         : {context['domain']}")
    print(
        f"Tor            : "
        f"{'Unavailable' if context['is_tor'] is None else 'Yes' if context['is_tor'] else 'No'}"
    )


def print_domain_result(result):
    vt = result["virustotal"]
    context = result["domain_context"]
    dns = result["dns"]

    print_vt_stats(vt)

    print_section("Domain Context")
    print(f"Registrar      : {context['registrar']}")
    print(f"TLD            : {context['tld']}")
    print(f"Created        : {context['creation_date']}")
    print(f"Expires        : {context['expiration_date']}")
    print(f"First Seen     : {context['first_seen']}")

    print_section("DNS Records")

    if dns["records"]:
        for record in dns["records"]:
            print(f"{record['type']:<14}: " f"{record['value']}")
    else:
        print(color_text("No DNS records available", "muted"))

    if result["tags"]:
        print(f"\nTags           : {', '.join(result['tags'])}")


def print_file_result(result):
    vt = result["virustotal"]
    context = result["file_context"]
    timeline = result["timeline"]

    print_vt_stats(vt)
    print(
        f"Threat Label   : {color_text(vt['threat_label'], 'warning' if vt['threat_label'] else 'muted')}"
    )

    print_section("File Context")
    print(f"Name           : {context['name']}")
    print(f"Type           : {context['type']}")
    print(f"Extension      : {context['extension']}")
    print(f"Size           : {context['size']} bytes")

    print_section("Hashes")
    print(f"MD5            : {context['md5']}")
    print(f"SHA1           : {context['sha1']}")
    print(f"SHA256         : {context['sha256']}")

    print_section("Timeline")
    print(f"First Submitted: {timeline['first_submission']}")
    print(f"Last Submitted : {timeline['last_submission']}")
    print(f"Last Analysis  : {timeline['last_analysis']}")

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
            print(f"{sandbox:<14}: {color_text(verdict, tone)}")
