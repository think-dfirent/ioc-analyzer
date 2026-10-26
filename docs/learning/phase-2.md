# Phase 2 — AbuseIPDB client

## What changed (plain words)

AbuseIPDB now has its own client, `AbuseIPDBClient` in `clients/abuseipdb.py`, built the same way as `VirusTotalClient`. `main()` creates it once at startup and uses it for every IP. The old `query_abuse` and `get_json` functions are gone, so `app.py` no longer makes any HTTP calls itself. `query_safely` now catches only `ProviderError`; any other exception is treated as a bug and crashes.

## Why

Before this phase, AbuseIPDB problems reached `main()` as a mix of `requests.HTTPError`, `ValueError`, `KeyError` and `TypeError`, and `query_safely` caught all of them with the same "unavailable" message. Two things went wrong because of that:

- A bad AbuseIPDB key (401) or an exhausted quota (429) was retried for every IP in the alert, printing the same error each time.
- A real bug in our own code (say, a typo that raises `TypeError`) was printed as "AbuseIPDB unavailable", so we would have blamed the provider for our own mistake.

Now an analyst who pastes ten IPs with a bad key sees one clear message, the other nine IPs skip AbuseIPDB, and VirusTotal results still print. A bug in our code stops the run with a traceback that points at the line.

## Key decisions and trade-offs

- **Missing AbuseIPDB key → warn and continue (Decision A).** AbuseIPDB only covers IPs, so a missing key should not block domain and hash lookups. The rejected option was to exit, as for a missing VirusTotal key: simpler, but it would make the whole tool unusable for a provider that adds context to one IOC type.
- **"Not configured" is not "failed".** If the key was never set, IPs without AbuseIPDB data do not change the exit code. If the key was set but AbuseIPDB stopped working mid-run (401/429), the remaining IPs do count as failed, because the user asked for data and did not get it. Two flags carry this: `abuse_client is not None` (configured?) and `abuse_enabled` (still usable?).
- **No "not found" for AbuseIPDB.** Unlike VirusTotal, every valid IP gets a report; a never-reported IP has `totalReports: 0`. So `lookup()` returns a report or raises, never `None`, and a 404 is treated as an ordinary `ProviderError`.
- **The IP goes in query parameters, not the URL path.** This follows the CHECK endpoint in the AbuseIPDB docs. A spy run found the original mismatch, and a test now asserts the exact URL.
- **Show AbuseIPDB's own error text.** When the response has no `data`, the first entry of its `errors` list (for example "The ip address must be a valid IPv4 or IPv6 address") goes into the `ProviderError` message, so the analyst learns why, not just that, it failed.
- **Error messages report what happened, not what we assume.** Messages use the real status code (`HTTP 401`) and do not claim a fixed daily limit, because the limit depends on the plan.
- **`max_age_days` is checked at startup (1–365).** A wrong value fails immediately with a clear message, instead of as a confusing 422 from the API mid-run.

## Python/engineering concepts used

- **Same pattern, second provider** → constructor checks the key, `_fetch` turns HTTP into "a dict or our errors", `lookup` validates and parses → `clients/abuseipdb.py:AbuseIPDBClient`.
- **Validate at the boundary** → check the response shape once, right where it arrives (`is it JSON? is it a dict? does it have data?`), so later code can trust it → `AbuseIPDBClient._fetch`, `AbuseIPDBClient.lookup`.
- **Chained comparison** → `1 <= max_age_days <= 365` reads as "between 1 and 365" → `AbuseIPDBClient.__init__`.
- **Optional dependency** → a client that may be `None`; code checks for it instead of failing → `app.py:main`.
- **Bound method** → `abuse_client.lookup` (no brackets) is a function that already knows its client; passed straight to `query_safely`, no `lambda` needed → `app.py:main`.
- **Catch only what you expect** → `query_safely` handles `ProviderError`, passes `ProviderUnavailableError` up, and lets everything else crash → `app.py:query_safely`.
- **Spy run** → replace `requests.get` with a function that prints the request instead of sending it, then compare with the API docs → debugging technique, no file in the repo.
- **pytest fixtures are requested by argument name** → a test only receives a fixture's value if the name is in its brackets; a name nothing provides is an error → `tests/test_abuseipdb_client.py`.
- **Patching a method on a class** → `monkeypatch.setattr(app.AbuseIPDBClient, "lookup", ...)` makes every client created during the test use the fake → `tests/test_main.py:test_unknown_ip_shows_no_record`.
- **Rebase** → replay a branch's commits on top of an updated `main`, so the branch includes work merged after it was created → `git rebase main`, then `git push --force-with-lease`.

## Read in this order

1. `tests/test_abuseipdb_client.py` — the test names list every behaviour the client promises.
2. `src/ioc_analyzer/clients/abuseipdb.py:AbuseIPDBClient._fetch` — status codes and response checks; compare it line by line with `VirusTotalClient._fetch`.
3. `src/ioc_analyzer/clients/abuseipdb.py:AbuseIPDBClient.lookup` and `_error_detail` — the "no data" check and where the error text comes from.
4. `src/ioc_analyzer/app.py:main` — the startup block (Decision A) and the two AbuseIPDB flags in the IP branch.
5. `src/ioc_analyzer/app.py:query_safely` — what it catches now, and its docstring explaining why it is narrow on purpose.
6. `tests/test_main.py` — `test_missing_abuseipdb_key_warns_and_continues` and `test_query_safely_lets_programming_errors_crash`.

## Check yourself

1. An analyst runs the tool with no AbuseIPDB key and one IP that VirusTotal knows. What exit code do they get, and which line of `main()` decides that?
2. Why does `VirusTotalClient.lookup` return `None` for a 404, while `AbuseIPDBClient.lookup` raises `ProviderError` for one?
3. If someone adds `except Exception` back to `query_safely`, which test fails, and what real-world problem would that change hide?
4. A response body is `{}`. Which check stops it, and why don't the JSON and dict checks in `_fetch` catch it?
5. Your Phase 2 branch was created before Phase 1 was merged. What would have gone wrong if you had merged it without rebasing first?
