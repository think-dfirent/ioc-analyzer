# Phase 6 — Better extraction (SOC reality)

## What changed (plain words)

The tool now reads defanged IOCs (`hxxps[:]//evil[.]example`, `185.220.101[.]4`) the way analysts and TI reports write them. A domain only counts if its top-level domain really exists, using IANA's official list bundled with the code, so user names, PowerShell code and email header fields no longer turn into wasted lookups. Extraction is tested on realistic, synthetic alert text instead of one-line strings.

## Why

An analyst pastes the IOC block from a vendor advisory. Every value in it is defanged, so before this phase the tool found nothing, printed "No supported IOCs found" and exited 0 — to a SOAR playbook, a clean alert. That silent miss was the most dangerous gap left. Building realistic fixtures then exposed the opposite problem: `CORP\j.doe`, `Net.WebClient` and `smtp.mailfrom` were extracted as domains. On a free VirusTotal key, four junk lookups cost a full minute per alert.

## Key decisions and trade-offs

- **One refang pass before extraction**, not defang-aware regexes. A pure function is easy to test, and a new defang style is one regex in one place. Rejected: teaching three extractors the same markers.
- **Brackets are the line.** `[.]` exists only to defang; a bare "dot" or a space around a dot is ordinary English. A "must stay unchanged" test list pins down what we don't touch.
- **Real values out, everywhere.** JSON and text both show the refanged value: a machine needs it, and a second field would change the JSON contract. A `--defang` switch for ticket-safe text is on the later list.
- **A real TLD list instead of context rules.** One rule removed all four false positives; context rules ("skip before @", "skip after \") would need a new rule per alert format. The list is a plain data file (no new dependency, no network at runtime) refreshed by download, never edited by hand.
- **The old file-extension blocklist was deleted.** None of its 48 entries is a real TLD, so the TLD check already rejected all of them. What remains is the small set of real TLDs that are usually file names (`py`, `ps`, `one`, `cab`). `.zip`, `.mov`, `.sh` and `.app` stay domains: a wasted lookup (false positive) is cheaper than a missed phishing domain (false negative).
- **Synthetic fixtures only.** The repo is public and Git history is permanent. Fixtures use `.example`/`.test` domains, EICAR hashes and a publicly listed IP. Documentation IP ranges (`192.0.2.x`) can't be used for positive cases, because the extractor correctly drops them as non-public.
- **IPv6 not built.** No alert source in use was named that contains IPv6; building it would be guessing.
- **Later list:** `--defang` output, IPv6 when a source needs it, honour `Retry-After` on 429, local result cache, JSON Lines output.

## Python/engineering concepts used

- **Pure function** → same input, same output, no side effects; trivial to test → `extractors.py:refang`.
- **Regex escaping** → `\.` is a dot, `.` is "any character"; `\[\.\]` vs `\[.\]` is the difference between `[.]` and `[x]` → `extractors.py:_DEFANGED_DOT`.
- **Lookahead `(?=...)`** → check what follows without consuming it → `extractors.py:_DEFANGED_SCHEME`.
- **Idempotency (again)** → `refang(refang(x)) == refang(x)`; safe to apply twice → `tests/test_refang.py`.
- **`importlib.resources.files`** → find a data file next to the package code, wherever it is installed; a relative path would depend on the current directory → `extractors.py:known_tlds`.
- **`@functools.cache`** → compute once, remember the result → `extractors.py:known_tlds`.
- **`frozenset`** → fast membership test, cannot be changed at runtime → `RESERVED_TLDS`, `FILE_LIKE_TLDS`.
- **Subset assertions (`<=`)** → "these must be found" without caring about the rest → `tests/test_alert_fixtures.py`.
- **`xfail(strict=True)`** → record a known bug as a test that is expected to fail; the day it passes, the suite fails until the marker is removed → used for the false-positive test, removed when the TLD check landed.
- **False positive vs false negative cost** → decide by what each mistake costs the analyst, not by which is "more correct" → `FILE_LIKE_TLDS` comment.
- **Dead code** → code that can no longer change any result; delete it, with evidence → the old `FILE_EXTENSIONS`.
- **Git hooks** → a local script Git runs before each commit; turns a repeated mistake into an automatic check → `.git/hooks/pre-commit` (not pushed).

## Read in this order

1. `tests/fixtures/edr_alert.txt` and `phishing_headers.txt` — the input, as an analyst sees it.
2. `extractors.py:refang` and `tests/test_refang.py` — what is undone, and what is deliberately left alone.
3. `extractors.py:extract_indicators` — the whole step from text to `(value, kind)` list.
4. `extractors.py:known_tlds` and `is_domain` — the TLD rule and the four exceptions.
5. `tests/test_alert_fixtures.py` — true positives, negatives, and the false-positive test.
6. `tests/test_tlds.py` — the two tests that guard the FP/FN trade-off in opposite directions.

## Check yourself

1. Why does `cmd(.)exe` in a pasted detection rule not become a domain lookup, even though refang turns it into `cmd.exe`?
2. A colleague proposes treating `evil dot com` as a defang. Give one input where that would invent an IOC, and say which test would catch it.
3. `known_tlds()` is cached. What breaks in a test that tries to swap in a different `tlds.txt`, and how would you fix the test?
4. Why is `microsoft-update.zip` looked up but `invoice.one` is not? What would change your mind about either?
5. Commit `12208ac` fails its own tests on a fresh clone, though the branch tip passes. Why does that matter for `git bisect`, and which check now stops it happening again?
