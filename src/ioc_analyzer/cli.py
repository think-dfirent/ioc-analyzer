"""Command-line entry point: read input, extract IOCs, enrich, print, return an exit code
This is the only module that talks to the outside world (environment, argv, clipboard, stdout, stderr)
"""

import argparse
import logging
import os
import sys
from collections import Counter
from pathlib import Path

import pyperclip
from dotenv import load_dotenv

from ioc_analyzer import __version__
from ioc_analyzer.clients.abuseipdb import AbuseIPDBClient
from ioc_analyzer.clients.virustotal import VirusTotalClient
from ioc_analyzer.enrich import enrich
from ioc_analyzer.extractors import domain_extraction, hash_extraction, ip_extraction
from ioc_analyzer.report import print_analysis, print_error, set_color
from ioc_analyzer.serialize import to_json

logger = logging.getLogger(__name__)


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
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="plain text output, no ANSI colors (the NO_COLOR variable does the same)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show debug message on stderr",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print one JSON document to stdout (for scripts and SOAR); "
        "warnings and errors still go to stderr",
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


def configure_logging(verbose: bool) -> None:
    """Send log messages to stderr; -v shows our DEBUG messages.
    The level is set on our package logger, not the root logger, so -v shows ioc_analyzer's debug
    messages without the debug noise of requests/urllib3.
    basicConfig does nothing if logging is already set up, so tests keep their own capture.
    """
    logging.basicConfig(format="%(levelname)s %(name)s: %(message)s")
    level = logging.DEBUG if verbose else logging.WARNING
    logging.getLogger("ioc_analyzer").setLevel(level)


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
    # Set every run, both ways, so one run's choice never leaks into the next.
    set_color(not args.no_color)
    configure_logging(args.verbose)
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
        print_error(f"{exc}; Continuing without AbuseIPDB")

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
    logger.debug(
        "extracted %d indicator(s): %s",
        len(indicators),
        dict(Counter(kind for _, kind in indicators)),
    )
    if not indicators:
        if args.json:
            # A JSON consumer must always get a document, even an empty one.
            print(to_json([]))
        else:
            print("No supported IOCs found (public IPv4, domain, MD5, SHA1, SHA256).")
        return 1

    results = enrich(indicators, vt_client, abuse_client)
    if args.json:
        for result in results:
            for error in result.errors:
                print_error(error)
        print(to_json(results))
    else:
        for result in results:
            for error in result.errors:
                print_error(error)
            if result.report is not None:
                print_analysis(result.report)
            elif result.not_found:
                print(f"{result.indicator}: no VirusTotal record found")
    return 1 if any(result.failed for result in results) else 0
