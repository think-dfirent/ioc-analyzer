"""Command-line entry point: read input, extract IOCs, enrich, print, return an exit code
This is the only module that talks to the outside world (environemnt, argv, clipboard, stdout, stderr)
Phase 4 replaces the argv with argparse
"""

import os, sys, pyperclip
from dotenv import load_dotenv

from ioc_analyzer.clients.abuseipdb import AbuseIPDBClient
from ioc_analyzer.clients.virustotal import VirusTotalClient
from ioc_analyzer.enrich import enrich
from ioc_analyzer.extractors import domain_extraction, hash_extraction, ip_extraction
from ioc_analyzer.report import print_analysis, print_error


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

    results = enrich(indicators, vt_client, abuse_client)
    for result in results:
        for error in result.errors:
            print_error(error)
        if result.report is not None:
            print_analysis(result.report)
        elif result.not_found:
            print(f"{result.indicator}: no VirusTotal record found")
    return 1 if any(result.failed for result in results) else 0
