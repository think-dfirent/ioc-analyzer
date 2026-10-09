# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A CLI that pulls IOCs (public IPv4 addresses, domains, MD5/SHA1/SHA256 hashes) out of free text and looks them up on VirusTotal and AbuseIPDB, then prints a colored report per indicator.

## Commands

The project uses a local virtualenv at `venv/` (Windows layout) with the package installed in editable mode (`pip install -e .`). Tests import `ioc_analyzer` as an installed package, so the editable install is required; there is no pytest config or `sys.path` hack.

```powershell
venv\Scripts\python.exe -m pip install -e . pytest      # setup
venv\Scripts\python.exe -m pytest                       # all tests
venv\Scripts\python.exe -m pytest tests/test_extractors.py::test_extract_domain   # single test
venv\Scripts\python.exe -m ioc_analyzer.app "text containing 8.8.8.8 or example.com"  # run
```

With no arguments, `app.main()` reads the input text from the clipboard (`pyperclip`). There is no console-script entry point; run it as a module. No linter/formatter is configured (the code style matches Black).

API keys are read from `.env` via `python-dotenv`: `VIRUSTOTAL_API` and `ABUSEIPDB_API`. `.env` is gitignored.

## Architecture

The data flows through three stages, each in its own module:

1. **Extraction** (`extractors.py`): regex-based `ip_extraction` (keeps only `ipaddress.is_global` addresses), `domain_extraction`, `hash_extraction`, and `is_domain`. `domain_extraction` first consumes full URLs (with and without a scheme) and keeps only their hostname, so URL paths and query strings never get parsed as domains; the remaining text is then scanned for bare domains.
2. **Provider query + parse** (`app.py`): `query_vt` / `query_abuse` call the APIs through `get_json`. `get_vt_url` picks the VT endpoint by artifact shape, and the `parse_vt_ip/domain/file` functions are chosen by the `data.type` field in the VT response. These turn raw API JSON into flat, provider-shaped dicts (e.g. `analysis_stats`, `as_owner`, `abuse_confidence`).
3. **Normalization** (`normalization.py`): `normalize_ip_result(vt, abuse, indicator)`, `normalize_domain_result(vt)`, and `normalize_file_result(vt)` merge provider dicts into one display-shaped dict with `indicator`, `type` (`ip`/`domain`/`file`) and sections such as `virustotal`, `network_context`, `domain_context`, `timeline`, `sandbox`. The `print_*_result` functions in `app.py` read exactly these keys, so a key rename in normalization means updating the printer too.

Failure handling: `query_safely` wraps each provider call and turns HTTP, network and parse errors into a stderr message and `None`. `normalize_ip_result` tolerates either provider being `None` (the section becomes `None`, and context fields fall back from VT to AbuseIPDB). Domains and files are skipped when VT fails. `main` returns exit code 1 if any lookup failed or no IOCs were found.

`clients/abuseipdb.py`, `clients/virustotal.py` and `tests/test_abuseipdb.py` are empty placeholders, apparently for moving the provider query/parse code out of `app.py`. All of that code still lives in `app.py`.

## Testing notes

- Tests are pure unit tests on extractors, VT URL/response parsing, and normalization, using hand-built dicts. Nothing hits the network, and `query_vt`/`query_abuse`/`main` are not tested.
- `tests/test_virustotal.py` currently ends with an unfinished `def test_parse_vt_ip_missing_required_data():` that has no body. It causes an `IndentationError` that stops pytest collection for the whole run. Finish or remove it before relying on `pytest` output, or deselect it with `--ignore=tests/test_virustotal.py`.
