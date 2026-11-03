# Changelog

All notable changes for users of `ioc-analyzer`. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/) — below 1.0, the public interface (command and flags, exit codes, JSON fields, setting names) may still change, and every such change is listed here.

## [0.1.0] - 2026-11-03

First release. Changes are listed against the earlier, unpackaged source version.

### Added

- `ioc-analyzer` command (also `python -m ioc_analyzer`), installable with `pip install .`; Python 3.12+.
- Input from text, `--file PATH`, stdin (`-`), or the clipboard; one source per run.
- `--json` output: `{"results": [...]}`, `null` for missing values, a `status` per provider (`ok`, `not_found`, `unavailable`, `error`).
- `--no-color`, `-v`/`--verbose`, `--version`.
- Documented exit codes: 0 every lookup answered, 1 some lookup failed, 2 usage or configuration error.
- Defanged IOCs are recognised: `hxxp`/`hxxps`, `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)`, `{dot}`, `[:]`, `[://]`.
- VirusTotal throttle, `VIRUSTOTAL_RATE_PER_MIN` (default 4 per rolling minute; 0 = off).
- Retries for timeouts, connection errors and HTTP 5xx (two retries, 1 s then 2 s).
- Results are printed as each lookup finishes; waits and retries are logged to stderr with timestamps.
- Per-user settings file (`%APPDATA%\ioc-analyzer\.env` or `~/.config/ioc-analyzer/.env`) and `.env.example`.

### Changed

- **Settings are no longer read from a `.env` in the current folder or the repo.** Move your keys to the per-user settings file, or set environment variables (see README → Settings).
- Only `VIRUSTOTAL_API`, `ABUSEIPDB_API` and `VIRUSTOTAL_RATE_PER_MIN` are read from the settings file; nothing from it is copied into the environment.
- A domain is looked up only if its top-level domain really exists (bundled IANA list): user names (`CORP\j.doe`), code (`Net.WebClient`) and file names (`payload.exe`, `detect.py`) are no longer sent to VirusTotal.
- HTTP 429 no longer disables a provider at once: the tool waits 60 s and tries once more; a second 429 disables it for the rest of the run.
- A missing VirusTotal key exits 2 (was 1). Finding no IOCs exits 0, with the note on stderr (was 1, on stdout).
- Missing provider data is shown as "Unknown" in text output (was `None`).

### Removed

- `python -m ioc_analyzer.app`. Use `ioc-analyzer` or `python -m ioc_analyzer`.

[0.1.0]: https://github.com/think-dfirent/ioc-analyzer/releases/tag/v0.1.0
