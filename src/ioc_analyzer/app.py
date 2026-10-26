import pyperclip, sys, os
from dotenv import load_dotenv
from ioc_analyzer.extractors import (
    ip_extraction,
    domain_extraction,
    hash_extraction,
)
from ioc_analyzer.normalization import (
    normalize_file_result,
    normalize_domain_result,
    normalize_ip_result,
)
from ioc_analyzer.clients.virustotal import (
    VirusTotalClient,
)
from ioc_analyzer.clients.abuseipdb import AbuseIPDBClient
from ioc_analyzer.clients.errors import ProviderError, ProviderUnavailableError

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


def query_safely(provider, query, artifact):
    """Run one provider lookup and report provider failures instead of crashing

    Return a pair (ok, result):
    (True, data)
    (True, None) - provider answered but without record
    (False, None) - provider failed; return error
    Any other exception is a bug and crashes on purpose
    """
    try:
        return True, query(artifact)
    except ProviderUnavailableError:
        raise
    except ProviderError as exc:
        print_error(f"{artifact}: {provider} failed {exc}")
        return False, None


def main(argv=None):
    load_dotenv()
    try:
        vt_client = VirusTotalClient(api_key=os.getenv("VIRUSTOTAL_API"))
    except ValueError as exc:
        print_error(str(exc))
        return 1
    abuse_client = None
    try:
        abuse_client = AbuseIPDBClient(api_key=os.getenv("ABUSEIPDB_API"))
    except ValueError as exc:
        print_error(f"{exc} Continuing without AbuseIPDB")

    argv = sys.argv[1:] if argv is None else argv
    if argv:
        text = " ".join(argv)
    else:
        try:
            text = pyperclip.paste()
        except pyperclip.PyperclipException as exc:
            print_error(f"Cannot read clipboard: {exc}")
            return 1

    indicators = (
        [(ip, "ip") for ip in ip_extraction(text)]
        + [(domain, "domain") for domain in domain_extraction(text)]
        + [(value.lower(), "file") for value in hash_extraction(text)]
    )
    if not indicators:
        print("No supported IOCs found (public IPv4, domain, MD5, SHA1, SHA256).")
        return 1

    failed = False
    vt_enabled = True
    abuse_enabled = abuse_client is not None
    for artifact, kind in dict.fromkeys(indicators):
        vt_ok, vt = False, None
        if vt_enabled:
            try:
                vt_ok, vt = query_safely(
                    "VirusTotal", lambda a: vt_client.lookup(a, kind), artifact
                )
            except ProviderUnavailableError as exc:
                print_error(f"VirusTotal disabled for the rest of this run: {exc}")
                vt_enabled = False
        failed |= not vt_ok

        if kind == "ip":
            abuse_ok, abuse = False, None
            if abuse_enabled:
                try:
                    abuse_ok, abuse = query_safely(
                        "AbuseIPDB", abuse_client.lookup, artifact
                    )
                except ProviderUnavailableError as exc:
                    print_error(f"AbuseIPDB disabled for the rest of this run: {exc}")
                    abuse_enabled = False
            if abuse_client is not None:
                failed |= not abuse_ok
            vt_status = "not_found" if vt_ok and vt is None else None
            result = normalize_ip_result(vt, abuse, artifact, vt_status=vt_status)
        elif not vt_ok:
            continue
        elif vt is None:
            print(f"{artifact}: no VirusTotal record (never submitted or seen)")
            continue
        elif kind == "domain":
            result = normalize_domain_result(vt)
        else:
            result = normalize_file_result(vt)
        print_analysis(result)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
