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
from ioc_analyzer.report import print_analysis, print_error


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
        print_error(f"{artifact}: {provider} failed: {exc}")
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
