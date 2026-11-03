# Architecture

How `ioc-analyzer` turns text into results, what each module owns, and what to change to add a provider.

## Data flow

```
text ─► cli.read_text ─► extractors.extract_indicators ─► enrich.iter_enrich ─► report (text)
        (--file, stdin,   refang → IPs, domains,           one result per IOC     serialize (--json)
         argv, clipboard)  hashes; dedupe                  ▲
                                                           │ clients/ (HTTP, retry, rate limit)
                                                           │ normalization (provider data → report dict)
```

1. **Input.** `cli.read_text` reads exactly one source.
2. **Extraction.** `extract_indicators` refangs the text, then extracts public IPv4 addresses, domains with a real TLD and hashes, as `(value, kind)` pairs without duplicates.
3. **Enrichment.** `iter_enrich` asks VirusTotal about every IOC and AbuseIPDB about IPs, and yields one `EnrichmentResult` as soon as each lookup finishes. It never prints and never exits; problems come back as data (`errors`, per-provider `status`).
4. **Output.** The CLI prints each result as it arrives (`report.py`), or collects them all and prints one JSON document (`serialize.py`). The exit code comes from the results.

## Who owns what

| Module             | Owns                                                                 | Never does                                     |
| ------------------ | -------------------------------------------------------------------- | ---------------------------------------------- |
| `cli.py`           | argv, input, settings, logging setup, stdout/stderr, exit code       | HTTP, parsing provider data                    |
| `config.py`        | where settings come from (environment, then the per-user file)       | read the current folder; write to `os.environ` |
| `extractors.py`    | which strings are IOCs (refang, regexes, TLD list)                   | network                                        |
| `enrich.py`        | which provider to ask, per-provider status, what counts as failed    | print, exit, HTTP details                      |
| `clients/`         | HTTP for one provider each: auth, retries, rate limit, error classes | decide what a failure means for the run        |
| `normalization.py` | provider-shaped dicts → one report dict per IOC                      | network, display                               |
| `report.py`        | human-readable text, "Unknown" for missing data                      | decide exit codes                              |
| `serialize.py`     | the JSON contract (`null` for missing data)                          | display formatting                             |

Errors flow upward as exception classes (`clients/errors.py`): `ProviderTransientError` (retried), `ProviderRateLimitedError` (one wait, then unavailable), `ProviderUnavailableError` (stop calling this provider), plain `ProviderError` (this IOC failed).

## Adding a provider

There is no plug-in interface: with two providers, a general one would be premature (see Decisions in `CLAUDE.md`). Adding a third provider — say GreyNoise for IPs — touches these places:

1. **`clients/greynoise.py`.** A client with `lookup(artifact)` that returns a dict, returns `None` for "not found", and raises the classes from `clients/errors.py`. Copy `clients/abuseipdb.py`: key check in `__init__`, `_fetch` that maps status codes to error classes, `call_with_retries` around it. Add a `RateLimiter` if the provider limits per minute. Tests: `tests/test_greynoise_client.py`, HTTP faked with `monkeypatch`, never real.
2. **`config.py`.** Add the key's name to `SETTINGS`. Also add it to `.env.example`, the README settings table, `tests/conftest.py:isolated_settings`, and a canary key in `tests/test_secrets.py`.
3. **`enrich.py`.** A Protocol for the client, a `greynoise_status` field on `EnrichmentResult`, and the lookup inside `iter_enrich`, next to the AbuseIPDB block (same "disable for the rest of the run" handling).
4. **`normalization.py`.** A new parameter and a new section in `normalize_ip_result`.
5. **`report.py`.** A section in `print_ip_result`; use `show()` for missing values.
6. **`serialize.py`.** Add the provider to `providers` in `result_to_dict`. This changes the JSON contract, so it needs a `CHANGELOG.md` entry.
7. **`cli.py`.** Build the client from settings; if its key is missing, log a warning and continue without it, as for AbuseIPDB.

If a fourth provider ever comes, that's the moment to replace steps 3–6 with a list of providers that each own a name, a status and a report section.

## Where to look when something is wrong

| Symptom                                   | Start in                                                                                                               |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| An IOC is missing, or junk is looked up   | `extractors.py`; run with `-v` to see what was extracted                                                               |
| A provider fails or waits                 | `clients/<provider>.py`, `clients/retry.py`, `clients/ratelimit.py`; stderr shows each wait and retry with a timestamp |
| Exit code or stdout/stderr split is wrong | `cli.main`                                                                                                             |
| A field shows "Unknown" or `null`         | `normalization.py` (was the field mapped?) then the client's `parse_*` function                                        |
| Keys not found                            | `config.settings_file()`; the error message prints the exact path                                                      |
