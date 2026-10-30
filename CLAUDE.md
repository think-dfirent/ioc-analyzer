# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## How to work with me

- I'm learning software engineering. My goal is understanding, not speed.
- **During `docs/PLAN.md` work**, Claude Code writes the code (core logic included) and explains it: follow the plan's rules, keep commits small, and write the phase's learning note in `docs/learning/phase-N.md`. I learn from the finished code and the note afterwards.
- **Outside the plan**, the learning rules apply:
  - Do NOT write core logic (parsing, extraction, API clients, normalization) unless I explicitly ask.
  - Before suggesting a change, explain the approach and trade-offs first.
  - When reviewing my code, point out problems and ask me guiding questions instead of rewriting it.
  - You MAY write boilerplate: packaging config, CI, test fixtures, docs.
- Run `pytest` after changes and explain any failures.

## Plan

`docs/PLAN.md` is the roadmap from the current state to a product-grade tool, in numbered phases. One phase = one branch (`phase-N-short-name`) = one pull request; the next phase starts only after the owner merges the current one.

## Decisions

These hold across all work. If a task seems to need breaking one, stop and ask.

- Missing/unknown provider data displays as "Unknown"/"Unavailable", never 0 or 0/0.
- Provider 404 = "not found" (a valid answer), not a failure.
- 401/429 = provider unavailable for the rest of the run; stop calling it.
- stdout is for results only; diagnostics and errors go to stderr.
- Tests never touch the network.
- AbuseIPDB key missing → print one warning at startup and run without AbuseIPDB (it only covers IPs).

- CLI input: text, `--file` and (stdin) are mutually exclusive; giving more than one is a usage error (exit 2).
- Exit codes: 0 = every lookup answered (404 counts as an answer; no IOCs found counts too), 1 = some lookup failed (results may be partial), 2 = usage/config error (bad args, missing VT key, unreadable file or clipboard).
- `--json`: missing values are `null`, never "Unknown" (that is display-only, in report.py); each provider has a `status`: ok / not_found / unavailable / error.
- `--json` output has no colors and nothing but JSON on stdout; warnings go to stderr.
- Version lives in `ioc_analyzer/__init__.py` (`__version__`); keep pyproject.toml in sync by hand until Phase 7 makes it the single source.

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

With no arguments, `app.main()` reads the input text from the clipboard (`pyperclip`). There is no console-script entry point yet; run it as a module. No linter/formatter is configured yet (the code style matches Black).

API keys are read from `.env` via `python-dotenv`: `VIRUSTOTAL_API` and `ABUSEIPDB_API`. `.env` is gitignored.

## Architecture

The data flows through three stages:

1. **Extraction** (`extractors.py`): regex-based `ip_extraction` (keeps only `ipaddress.is_global` addresses), `domain_extraction`, `hash_extraction`, and `is_domain`. `domain_extraction` first consumes full URLs (with and without a scheme) and keeps only their hostname, so URL paths and query strings never get parsed as domains; the remaining text is then scanned for bare domains.
2. **Provider lookup + parse**:
   - VirusTotal lives in `clients/virustotal.py`. `VirusTotalClient` checks the key in its constructor; `lookup(artifact, kind)` builds the URL with `build_url` (endpoint chosen by `kind`: `ip`/`domain`/`file`), fetches it, and parses it with the matching `parse_vt_ip/domain/file`. It returns `None` on 404, raises `ProviderUnavailableError` on 401/429, and `ProviderError` on other HTTP errors, network errors, non-JSON bodies and missing required fields.
   - AbuseIPDB still lives in `app.py`: `query_abuse` calls `get_json` (raw `requests`). `clients/abuseipdb.py` is an empty placeholder; moving it there is Phase 2 of the plan.
   - `clients/errors.py` holds the shared exceptions. `ProviderUnavailableError` is a subclass of `ProviderError`.
   - The parsers turn raw API JSON into flat, provider-shaped dicts (e.g. `analysis_stats`, `as_owner`, `abuse_confidence`).
3. **Normalization** (`normalization.py`): `normalize_ip_result(vt, abuse, indicator)`, `normalize_domain_result(vt)`, and `normalize_file_result(vt)` merge provider dicts into one display-shaped dict with `indicator`, `type` (`ip`/`domain`/`file`) and sections such as `virustotal`, `network_context`, `domain_context`, `timeline`, `sandbox`. The `print_*_result` functions in `app.py` read exactly these keys, so a key rename in normalization means updating the printer too.

`app.py` currently mixes the CLI (`main`), the enrichment loop and terminal printing; splitting it is Phase 3 of the plan.

Failure handling: `query_safely` wraps each provider call and returns `(ok, value)`. It prints a stderr message and returns `(False, None)` for `ProviderError`, `requests` errors and `ValueError`/`KeyError`/`TypeError`, but re-raises `ProviderUnavailableError`, which `main` catches to stop calling VirusTotal for the rest of the run. `normalize_ip_result` tolerates either provider being `None` (the section becomes `None`, and context fields fall back from VT to AbuseIPDB). A domain or file with no VT record (404) prints "no VirusTotal record" and is not a failure; one whose VT lookup failed is skipped. `main` returns exit code 1 if the VT key is missing, no IOCs were found, or any lookup failed, and 0 otherwise.

## Testing notes

- All tests are offline. HTTP is faked with `monkeypatch`: `tests/test_virustotal_client.py` replaces `requests.get`, `tests/test_main.py` fakes the VT client's HTTP to test `main()` exit codes, and `tests/test_abuseipdb.py` replaces `app.get_json` to test `query_abuse`.
- The other tests are pure unit tests on extractors, VT parsers and normalization, using hand-built dicts.
