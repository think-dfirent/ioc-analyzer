# Phase 1 — Correctness fixes

## What changed (plain words)

The extractor no longer treats filenames like `evil.exe` or `report.pdf` as domains. An IP that VirusTotal has never seen now shows "No VirusTotal record" instead of "Unavailable". Four unused imports were removed from `app.py`.

## Why

An analyst pastes an EDR alert: `cmd.exe spawned powershell.exe ... rundll32.exe loaded payload.dll ... beacon to cdn-update.top`. Before this phase the tool found 9 "domains", and only the last one was real. On a free VirusTotal key (4 lookups per minute) the first four filenames used up the budget, the fifth lookup got HTTP 429, VirusTotal was switched off for the run, and the real C2 domain was never checked. The filenames were not just noise: they pushed the one real IOC out of the report.

The IP change fixes a wording problem with real consequences. "Unavailable" means "something broke, try again". "No record" means "VirusTotal answered: nobody has submitted this". An IP nobody has seen is useful intel, not an error.

## Key decisions and trade-offs

- **Denylist of file extensions, not an allowlist of real TLDs.** An allowlist (~1,450 official TLDs) is the most precise option, but it is a large list to ship and keep current as new TLDs launch. A short denylist is easy to read and maintain.
- **Only extensions that can never be a TLD are on the list.** Some file extensions are real TLDs: `.zip`, `.mov`, `.sh`, `.py`, `.md`, `.app`. Attackers register domains under them (`.zip` was used for phishing soon after it launched, because `invoice.zip` looks like a file). Those are deliberately left out. Every entry on the list was checked against the public TLD list. Result: the filter can only remove strings that could never resolve, so it cannot hide a real domain.
- **Decide by the cost of each mistake.** Calling a file a domain costs one wasted lookup. Calling a real domain a file loses an IOC. The design makes the second mistake impossible and accepts a little of the first (an unlisted extension still gets looked up).
- **`vt_status` travels next to the data.** `None` alone could mean "not found" or "failed". Instead of guessing, `main` (which knows which happened) passes `vt_status="not_found"` through `normalize_ip_result` to the printer.
- **Known limitation:** domains written in non-Latin script (`пример.рф`) are not extracted; their punycode form (`example.xn--p1ai`) is. Defanged and international input is Phase 6.

## Python/engineering concepts used

- **`frozenset`** → a set that cannot change after it is created; `x in a_set` is instant however long the set is → `extractors.py:FILE_EXTENSIONS`.
- **Compiling a regex once** → `re.compile` at module level builds the pattern once instead of on every call → `extractors.py:DOMAIN_REGEX`.
- **`rsplit(".", 1)`** → split once from the right; `[1]` is the last part, the TLD → `extractors.py:is_domain`.
- **Guard clauses** → return early on each failed check instead of one long `and` chain → `extractors.py:is_domain`.
- **Status next to data** → when `None` can mean two things, carry an explicit status so later code does not guess → `app.py:main`, `normalization.py:normalize_ip_result`, `app.py:print_vt_stats`.
- **Linter (ruff, rule F401)** → a tool that finds unused imports reliably; humans miss them → `ruff check --select F401`.
- **Regression tests in both directions** → one test proves the bug is fixed (filenames rejected), another stops an over-correction (real `.zip` domains kept) → `tests/test_extractors.py`.

## Read in this order

1. `tests/test_extractors.py` — the two new parametrized tests. Read them first: they state the rule in plain examples.
2. `src/ioc_analyzer/extractors.py:is_domain` and `FILE_EXTENSIONS` — how the rule is enforced.
3. `src/ioc_analyzer/app.py:main` — the `vt_status` line in the IP branch.
4. `src/ioc_analyzer/app.py:print_vt_stats` — how the status changes the text and the color.
5. `tests/test_main.py:test_unknown_ip_shows_no_record` — why it fakes `query_abuse` as well as VirusTotal.

## Check yourself

1. Why would adding `"zip"` to `FILE_EXTENSIONS` be a security mistake, while adding `"exe"` is safe?
2. In the EDR alert example, how exactly does extracting filenames cause the real C2 domain to be missed? Name the snippet whose logic turns a 429 into "stop calling VirusTotal".
3. Why does "No VirusTotal record" use the grey `muted` color while "Unavailable" uses yellow `warning`?
4. `vt_status` is `None` both when VirusTotal found the IP and when the lookup failed. Why does the printer still show the right thing in both cases?
5. Which test would fail if someone deleted the `.lower()` in `is_domain`?
