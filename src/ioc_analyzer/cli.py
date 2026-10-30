"""Command-line entry point: read input, extract IOCs, enrich, print, return an exit code
This is the only module that talks to the outside world (environment, argv, clipboard, stdout, stderr)
"""

import argparse
import os

import pyperclip
from dotenv import load_dotenv

from ioc_analyzer.clients.abuseipdb import AbuseIPDBClient
from ioc_analyzer.clients.virustotal import VirusTotalClient
from ioc_analyzer.enrich import enrich
from ioc_analyzer.extractors import domain_extraction, hash_extraction, ip_extraction
from ioc_analyzer.report import print_analysis, print_error


def build_parser() -> argparse.ArgumentParser:
    """Describe the command line in one place: what a user may type and what it means.

    A function rather than a module-level object, so every call (and every test)
    gets a fresh parser with no state left over from a previous run.
    """
    parser = argparse.ArgumentParser(
        prog="ioc-analyzer",
        description=(
            "Extract IOCs (public IPv4, domains, MD5/SHA1/SHA256) from text and enrich them with VirusTotal and AbuseIPDB."
        ),
    )
    parser.add_argument(
        "text",
        nargs="*",
        help="text to scan; several words are joined with spaces. With no text, the clipboard is read.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    # Parse first: --help and usage errors must work without API keys or network.
    args = build_parser().parse_args(argv)
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

    if args.text:
        text = " ".join(args.text)
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
