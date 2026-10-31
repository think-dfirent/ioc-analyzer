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
- 401 = provider unavailable for the rest of the run; stop calling it.
- 429 = wait for the rate window and retry once; a second 429 means quota is used up → unavailable for the rest of the run.
- Retry only transient failures (timeout, connection error, 5xx): at most 2 retries, waiting 1 s then 2 s. Never retry 401, 404, other 4xx, or a 200 with a bad body. Only GET lookups are ever retried.
- VirusTotal throttle: at most `VIRUSTOTAL_RATE_PER_MIN` calls in any rolling 60 s (default 4; 0 = off).
- Waits and retries are logged (INFO/WARNING, stderr); final per-indicator failures stay in `result.errors`. API keys never appear in logs or error messages.
- stdout is for results only; diagnostics and errors go to stderr.
- Tests never touch the network.
- AbuseIPDB key missing → print one warning at startup and run without AbuseIPDB (it only covers IPs).

- CLI input: text, `--file` and `-`(stdin) are mutually exclusive; giving more than one is a usage error (exit 2).
- Exit codes: 0 = every lookup answered (404 counts as an answer; no IOCs found counts too), 1 = some lookup failed (results may be partial), 2 = usage/config error (bad args, missing VT key, unreadable file or clipboard).
- `--json`: missing values are `null`, never "Unknown" (that is display-only, in report.py); each provider has a `status`: ok / not_found / unavailable / error.
- `--json` output has no colors and nothing but JSON on stdout; warnings go to stderr.
- Version lives in `ioc_analyzer/__init__.py` (`__version__`); keep pyproject.toml in sync by hand until Phase 7 makes it the single source.

## What this is

A CLI that pulls IOCs (public IPv4 addresses, domains, MD5/SHA1/SHA256 hashes) out of free text, looks them up on VirusTotal and AbuseIPDB, and prints a report per indicator (colored text, or JSON with `--json`). User-facing usage, the JSON shape and exit codes are in `README.md`.

## Commands

No packaging yet (Phase 7): dependencies are installed into `venv/` by hand and `src` is put on the path.

```powershell
$env:PYTHONPATH = "src"
pytest -q                                            # all tests
pytest tests/test_cli.py::test_no_iocs_is_not_a_failure   # one test
ruff check src tests                                 # lint (see note on tomllib below)
python -m ioc_analyzer.app --help                    # run
```

API keys come from `.env` via `python-dotenv`: `VIRUSTOTAL_API` (required) and `ABUSEIPDB_API` (optional). `.env` is gitignored.

Known lint noise: ruff flags the import order in `tests/test_cli.py` (I001) because `pyproject.toml` has no `requires-python`, so ruff treats `tomllib` as third-party. Phase 7 fixes this; don't "fix" the import order by hand.

## Architecture

```
cli.py  →  extractors.py  →  enrich.py  →  clients/  →  normalization.py
  │                              │
  └── report.py (text) ◄─────────┤
  └── serialize.py (JSON) ◄──────┘
```

- **`cli.py`** is the only module that touches the outside world: argv (`build_parser`), input (`read_text`: `--file`, `-` for stdin, text, clipboard), `.env`, logging setup (`configure_logging`), stdout/stderr and the exit code. `app.py` is a thin wrapper kept so `python -m ioc_analyzer.app` keeps working until Phase 7 adds a console script.
- **`extractors.py`**: regex-based `ip_extraction` (keeps only `ipaddress.is_global`), `domain_extraction` (consumes full URLs first and keeps only the hostname), `hash_extraction`.
- **`enrich.py`**: `enrich(indicators, vt_client, abuse_client)` returns one frozen `EnrichmentResult` per unique indicator. It holds `vt_status`/`abuse_status` (`ok`/`not_found`/`unavailable`/`error`; `abuse_status` is `None` for non-IPs), `report` and `errors`. It never prints or exits. Clients are typed as Protocols (`VTLookup`, `IPLookup`), so tests pass fakes.
- **`clients/`**: `VirusTotalClient.lookup(artifact, kind)` and `AbuseIPDBClient.lookup(artifact)`. Both check the key in the constructor (`ValueError`), and raise `ProviderUnavailableError` on 401/429 and `ProviderError` on other failures (`clients/errors.py`). VirusTotal returns `None` on 404.
- **`normalization.py`**: merges provider dicts into one report dict per indicator (`virustotal`, `network_context`, `domain_context`, `file_context`, …). These keys are read by `report.py` **and are public in `--json` output**, so renaming one is a breaking change.
- **`report.py`**: terminal text. `show()` turns `None` into "Unknown" (display only). `set_color()` is set once per run by the CLI.
- **`serialize.py`**: `to_json(results)` returns `{"results": [...]}` with `null` for missing values.

## Testing notes

- All tests are offline. HTTP is faked with `monkeypatch` on `requests.get` inside the client modules (`tests/test_virustotal_client.py`, `tests/test_abuseipdb_client.py`); `tests/test_cli.py` fakes HTTP to test `main()` end to end (flags, input sources, exit codes, stdout purity).
- `tests/test_enrich.py` uses `FakeClient` objects instead of HTTP; `tests/test_report.py` and `tests/test_serialize.py` build results by hand.
- argparse calls `sys.exit()` for `--help`, `--version` and usage errors, so those tests use `pytest.raises(SystemExit)` and check `.code`.
- Module-level settings (`report._color_enabled`, the `ioc_analyzer` logger level) are set by `main()` on every run, both ways, so one test's flags can't leak into the next.
