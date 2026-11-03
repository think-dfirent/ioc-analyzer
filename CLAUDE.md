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
- Version lives in `pyproject.toml`; code reads it with `importlib.metadata` (fallback `"0+unknown"` when not installed).
- Config: real environment variables win; otherwise one per-user file (`%APPDATA%\ioc-analyzer\.env`, `~/.config/ioc-analyzer/.env`), read with `dotenv_values()` and only for our own variables. The current folder is never searched (evidence folders may contain hostile files).
- Packaging: hatchling; `data/tlds.txt` must be inside the wheel. A change to packaging is verified by installing the built wheel into a fresh venv outside the repo, not by tests alone.
- `ioc-analyzer` is the command; `python -m ioc_analyzer` also works. (`python -m ioc_analyzer.app` was removed in 0.1.0.)
- Runtime dependencies have minimum versions only; dev tools live in `[dependency-groups]`.
- Text output prints each result as soon as its lookup finishes; `--json` prints one document when the run ends.
- A domain counts only if its TLD is in IANA's list (bundled `src/ioc_analyzer/data/tlds.txt`) or is `.example`/`.test`. Refresh the file by downloading it again; never edit it by hand.

- Defanged IOCs are refanged before extraction. Only bracketed markers count (`[.]` `(.)` `{.}` `[dot]` `(dot)` `{dot}` `[:]` `[://]`) plus `hxxp`/`hxxps`; bare words and spaces are never treated as defangs.
- Output (text and JSON) always shows the real, refanged value.
- Test fixtures are synthetic: never paste real alert text, customer names, internal hosts or usernames into this public repo. Use `.example`/`.test` domains, EICAR hashes, and IPs already published in public reports.

- CI (GitHub Actions) runs on pull requests and on pushes to `main`: ruff check, ruff format --check, pytest with coverage (fail under 90%), and a wheel smoke test (fresh venv, outside the checkout, dummy key, no network).
- CI matrix: Linux with Python 3.12 and 3.13, Windows with Python 3.13.
- CI never gets real API keys and never uses `pull_request_target`. Workflow permissions are `contents: read`; actions are pinned to full commit SHAs and updated by Dependabot.
- `main` is protected: changes land through pull requests with green CI; no direct pushes, no admin bypass.

- Public interface (what SemVer protects): the `ioc-analyzer` command and flags, exit codes, JSON field names and status values, setting names and the settings-file location. Below 1.0 these may change, but every change is listed in `CHANGELOG.md`.
- Releases are built by CI from a `vX.Y.Z` tag on `main`, attached to a GitHub Release with a build-provenance attestation. Never upload a wheel built locally. Not published to PyPI.
- Providers: no general provider interface until a third provider is actually needed (rule of three); `docs/architecture.md` lists every place a new provider touches.

## What this is

A CLI that pulls IOCs (public IPv4 addresses, domains, MD5/SHA1/SHA256 hashes) out of free text, looks them up on VirusTotal and AbuseIPDB, and prints a report per indicator (colored text, or JSON with `--json`). User-facing usage, the JSON shape and exit codes are in `README.md`.

## Commands

The package is installed in editable mode in `venv/`; no `PYTHONPATH` needed.

```powershell
pip install -e . --group dev                         # setup (pip 25.1+)
pytest -q                                            # all tests
pytest tests/test_cli.py::test_no_iocs_is_not_a_failure   # one test
ruff check src tests                                 # lint (rules set in pyproject.toml)
ioc-analyzer --help                                  # run (or: python -m ioc_analyzer)
```

Settings come from environment variables or the per-user file (see `config.py` and the README); a `.env` in the repo or current folder is not read. `.env.example` lists every setting.

CI (`.github/workflows/ci.yml`) runs on every PR and every push to `main`: `lint` (ruff check + format check), `test` (pytest, coverage must stay ≥ 90%, on Linux 3.12/3.13 and Windows 3.13) and `package` (build the wheel, install it into a fresh venv outside the checkout, smoke test with a dummy key). `main` is protected by a ruleset: changes land only through a PR with all five checks green. Run `ruff format src tests`, `ruff check src tests` and `pytest -q` locally before pushing; the pre-commit hook does the last two.

## Architecture

```
cli.py  →  extractors.py  →  enrich.py  →  clients/  →  normalization.py
  │                              │
  └── report.py (text) ◄─────────┤
  └── serialize.py (JSON) ◄──────┘
```

- **`cli.py`** is the only module that touches the outside world: argv (`build_parser`), input (`read_text`: `--file`, `-` for stdin, text, clipboard), settings (`config.load_settings`), logging setup (`configure_logging`), stdout/stderr and the exit code. The `ioc-analyzer` command and `__main__.py` both call `cli.main`; `app.py` is deprecated (prints a notice, removed in Phase 9).
- **`config.py`**: `load_settings()` returns only `VIRUSTOTAL_API`, `ABUSEIPDB_API`, `VIRUSTOTAL_RATE_PER_MIN`: environment first, then the per-user file from `settings_file()`, read with `dotenv_values` (never copied into `os.environ`; the current folder is never searched).
- **`extractors.py`**: `extract_indicators(text)` is the entry point. It calls `refang()` (bracketed markers and `hxxp` only), runs `ip_extraction` (public IPv4 only), `domain_extraction` (hostnames out of URLs first, then bare names) and `hash_extraction`, lowercases hashes and removes duplicates. `is_domain` requires a real TLD from `data/tlds.txt` (IANA, read once via `importlib.resources` and `@cache`) or `.example`/`.test`, and rejects `FILE_LIKE_TLDS` (`py`, `ps`, `one`, `cab`). `data/tlds.txt` must ship with the package (Phase 7).
- **`enrich.py`**: `enrich(indicators, vt_client, abuse_client)` returns one frozen `EnrichmentResult` per unique indicator. It holds `vt_status`/`abuse_status` (`ok`/`not_found`/`unavailable`/`error`; `abuse_status` is `None` for non-IPs), `report` and `errors`. It never prints or exits. Clients are typed as Protocols (`VTLookup`, `IPLookup`), so tests pass fakes.
- **`clients/`**: `VirusTotalClient.lookup(artifact, kind)` and `AbuseIPDBClient.lookup(artifact)`. Both check the key in the constructor (`ValueError`). In `_fetch` they sort failures by what a retry would do (`clients/errors.py`): `ProviderTransientError` (timeout, connection, 5xx), `ProviderRateLimitedError` (429), `ProviderUnavailableError` (401), plain `ProviderError` (other 4xx, bad body). `lookup` runs `_fetch` through `retry.call_with_retries` (2 retries at 1 s/2 s for transient; one 60 s wait for 429, then a second 429 becomes `ProviderUnavailableError`). VirusTotal also passes every attempt through `ratelimit.RateLimiter` (rolling window, `VIRUSTOTAL_RATE_PER_MIN`). VirusTotal returns `None` on 404. Clients take `sleep`/`clock` arguments (default `time.sleep`/`time.monotonic`, looked up in `__init__`) so tests control time.
- **`normalization.py`**: merges provider dicts into one report dict per indicator (`virustotal`, `network_context`, `domain_context`, `file_context`, …). These keys are read by `report.py` **and are public in `--json` output**, so renaming one is a breaking change.
- **`report.py`**: terminal text. `show()` turns `None` into "Unknown" (display only). `set_color()` is set once per run by the CLI.
- **`serialize.py`**: `to_json(results)` returns `{"results": [...]}` with `null` for missing values.

## Testing notes

- All tests are offline. HTTP is faked with `monkeypatch` on `requests.get` inside the client modules (`tests/test_virustotal_client.py`, `tests/test_abuseipdb_client.py`); `tests/test_cli.py` fakes HTTP to test `main()` end to end (flags, input sources, exit codes, stdout purity).
- `tests/test_enrich.py` uses `FakeClient` objects instead of HTTP; `tests/test_report.py` and `tests/test_serialize.py` build results by hand.
- argparse calls `sys.exit()` for `--help`, `--version` and usage errors, so those tests use `pytest.raises(SystemExit)` and check `.code`.
- Module-level settings (`report._color_enabled`, the `ioc_analyzer` logger level) are set by `main()` on every run, both ways, so one test's flags can't leak into the next.
- `tests/conftest.py` has an autouse `clock` fixture (`FakeClock`) that replaces `time.sleep` and `time.monotonic` in every test: nothing really sleeps, and `clock.sleeps` records every wait. Assert waits with it (`assert clock.sleeps == [1.0, 2.0]`). Faked sleep and clock must move together, or the rate limiter never sees time pass.
- Log messages are checked with `caplog` (under pytest, `basicConfig` adds no stderr handler, so `capsys.err` won't see them).
- `tests/test_secrets.py` runs the CLI with canary API keys through every outcome and asserts the keys never appear in stdout, stderr or logs. Never weaken it; if it fails, something is leaking.
- `tests/fixtures/` holds synthetic alert text (EDR alert, phishing headers) used by `tests/test_alert_fixtures.py`. Follow the fixture Decision: nothing copied from real alerts. True-positive checks use subset asserts (`<=`); false positives get their own test, so a known bug can be parked with `xfail(strict=True)`.
- `tests/conftest.py:isolated_settings` (autouse) points the settings file at an empty temp folder and removes our variables from the environment, so no test sees the developer's real keys. Tests set the variables they need with `monkeypatch.setenv`.
- `tests/test_entry_points.py` runs `python -m ioc_analyzer` in a real subprocess (with `sys.executable`) to prove process-level behaviour: the entry point works and exit codes reach the shell. Keep these few; everything else calls `cli.main()` directly.
- Tests need the package installed (`pip install -e .`); `test_version_comes_from_the_installed_package` fails otherwise.
- Coverage only measures code run inside the pytest process. `__main__.py` shows 0% although `tests/test_entry_points.py` proves it works in a subprocess. Treat the 90% floor as protection against untested modules, not as proof of quality; never write a test just to raise the number.
- Every test must pass on Windows as well as Linux (CI runs both). Use `pathlib` and `tmp_path`, never hard-coded `/` or `\` paths, and pass `platform`/`env` into code that branches on the OS, as `config.settings_file` does.
