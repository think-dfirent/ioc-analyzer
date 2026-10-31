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
from ioc_analyzer.clients.virustotal import DEFAULT_RATE_PER_MIN, VirusTotalClient
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
    """Send log messages to stderr: INFO and up by default, DEBUG with -v.

    INFO is on by default so waits and retries are visible; a terminal that
    goes quiet for a minute looks hung."""

    logging.basicConfig(format="%(levelname)s %(name)s: %(message)s")
    level = logging.DEBUG if verbose else logging.INFO
    logging.getLogger("ioc_analyzer").setLevel(level)


def env_int(name: str, default: int) -> int:
    """Read a whole number (0 or more) from the environment; unset or empty = default.

    Raises ValueError naming the variable, so main() can report a config error (exit 2)
    instead of Python's "invalid literal for int() with base 10".
    """
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        value = -1
    if value < 0:
        raise ValueError(f"{name} must be a whole number, 0 or more; got {raw!r}")
    return value


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
        vt_client = VirusTotalClient(
            api_key=os.getenv("VIRUSTOTAL_API"),
            rate_per_min=env_int("VIRUSTOTAL_RATE_PER_MIN", DEFAULT_RATE_PER_MIN),
        )
    except ValueError as exc:
        print_error(str(exc))
        return 2
    abuse_client = None
    try:
        abuse_client = AbuseIPDBClient(api_key=os.getenv("ABUSEIPDB_API"))
    except ValueError as exc:
        logger.warning("%s; continuing without AbuseIPDB", exc)

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
        # Not a failure: the tool worked, the text had nothing to look up.
        # A note on stderr; stdout stays empty (or an empty JSON document).
        print(
            "No supported IOCs found (public IPv4, domain, MD5, SHA1, SHA256).",
            file=sys.stderr,
        )
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
