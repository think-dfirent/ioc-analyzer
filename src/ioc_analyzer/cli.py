"""Command-line entry point: read input, extract IOCs, enrich, print, return an exit code
This is the only module that talks to the outside world (environment, argv, clipboard, stdout, stderr)
"""

import argparse
import os
import sys
from pathlib import Path

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
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "text",
        nargs="*",
        help="text to scan; several words are joined with spaces. "
        "Use - to read stdin. With no text and no --file, the clipboard is read. ",
    )
    source.add_argument(
        "--file",
        type=Path,
        metavar="PATH",
        help="read the text to scan from a UTF-8 file",
    )
    return parser


class InputError(Exception):
    """The text to scan could not be read: a usage problem, so exit code 2."""


def read_text(args: argparse.Namespace) -> str:
    """Return the text to scan from the one source the user chose
    Order: --file, stdin ("-"), words from argv, then the clipboard as the default.
    Raises InputError when that source cannot be read, so main() can report it and exit 2 instead of crashing with a traceback.
    """
    if args.file is not None:
        try:
            # utf-8-sig also accepts UTF-8 files that start with a BOM (Notepad does this).
            return args.file.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError as exc:
            raise InputError(
                f"Cannot read {args.file}: not UTF-8 "
                "(Windows PowerShell 5.1 '>' writes UTF-16; save it as UTF-8)"
            ) from exc
        except OSError as exc:
            raise InputError(f"Cannot read {args.file}: {exc.strerror}") from exc
    if args.text == ["-"]:
        return sys.stdin.read()
    if args.text:
        return " ".join(args.text)
    try:
        return pyperclip.paste()
    except pyperclip.PyperclipException as exc:
        raise InputError(f"Cannot read clipboard: {exc}") from exc


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

    try:
        text = read_text(args)
    except InputError as exc:
        print_error(str(exc))
        return 2

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
