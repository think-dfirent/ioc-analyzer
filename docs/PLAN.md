# ioc-analyzer — plan to product-grade

Written for Claude Code. Baseline: commit `940c8c0` (2026-10-22). Tests pass, VirusTotal client done, `main()` exit codes tested.

"Product-grade" here means: a SOC analyst or a script can run it every day and trust the result. It installs with one command, behaves predictably when providers fail, has machine-readable output, has tests and CI, and is documented. It does NOT mean a web service, database, Docker, or microservices.

## Rules for Claude Code (read before every phase)

1. **Mode change.** For this plan, the owner has asked Claude Code to write core logic too. This overrides "Do NOT write core logic" in CLAUDE.md for tasks in this plan only. Update CLAUDE.md's "How to work with me" section accordingly in Phase 0.
2. **One phase = one branch = one pull request.** Branch name `phase-N-short-name`. Do not start the next phase until the owner has merged the current one.
3. **Small commits.** One logical change per commit, Conventional Commit prefixes (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`, `ci:`). Every commit must leave `pytest` green.
4. **Tests come with the change**, in the same commit or the one right before it. Bug fixes start with a failing test that reproduces the bug.
5. **Never call real APIs in tests.** Fake HTTP with `monkeypatch`, as `tests/test_virustotal_client.py` already does.
6. **Keep the decisions** in CLAUDE.md's `## Decisions` section. If a task seems to need breaking one, stop and ask.
7. **Write a learning note** for every phase in `docs/learning/phase-N.md` (see template at the end). The owner will learn from the code afterward, so explain why, in plain words, with no unexplained jargon.
8. **No new dependencies** unless the phase lists them. Ask before adding anything else.
9. **Don't over-engineer.** If a simpler approach meets the acceptance criteria, use it.

## Phase 0 — Ground rules and decisions (small)

- Update CLAUDE.md:
  - "How to work with me": add that during PLAN.md work, Claude Code writes the code and explains it; outside the plan, the old learning rules apply.
  - Add `## Decisions`:
    - Missing/unknown provider data displays as "Unknown"/"Unavailable", never 0 or 0/0.
    - Provider 404 = "not found" (a valid answer), not a failure.
    - 401/429 = provider unavailable for the rest of the run; stop calling it.
    - stdout is for results only; diagnostics and errors go to stderr.
    - Tests never touch the network.
  - Remove stale notes (old broken-test note, "apparently" wording) and point to this plan.
- Commit this file as `docs/PLAN.md`.

**Done when:** CLAUDE.md is accurate and has a Decisions section; PLAN.md is in the repo.

## Phase 1 — Correctness fixes

- `domain_extraction` must not return filenames (`evil.exe`, `report.pdf`, `invoice.docx`). Choose an approach and explain the trade-off in the learning note (e.g. denylist of common file extensions vs. TLD allowlist: which false positives and false negatives each one causes).
- An IP that VirusTotal returns 404 for must display "No VirusTotal record", not "Unavailable" (domains and files already do this).
- Remove unused imports in `app.py`.

**Done when:** regression tests exist for each fix; all tests pass.

## Phase 2 — AbuseIPDB client (same pattern as VirusTotal)

- Create `clients/abuseipdb.py` with `AbuseIPDBClient`, mirroring `VirusTotalClient`: key checked in the constructor, timeout, status handling (401/429 → `ProviderUnavailableError`; other errors → `ProviderError`), parser that turns missing fields into `ProviderError`.
- Move `query_abuse` and `get_json` out of `app.py`.
- Simplify `query_safely`: only catch `ProviderError`. It should no longer catch `KeyError`/`TypeError`/`ValueError`, because those now mean a bug in our code and should crash loudly.
- AbuseIPDB key missing: VT-only mode with a clear warning, or exit with an error? Ask the owner, then record the answer in Decisions.

**Done when:** `tests/test_abuseipdb_client.py` covers found, 401, 429, 5xx, network error, non-JSON, missing field; `app.py` has no direct `requests` calls.

## Phase 3 — Split app.py into clear layers

Today `app.py` mixes the CLI, the enrichment loop and terminal printing. Split it into:

- `enrich.py` — takes text (or indicators) and clients, returns a list of result objects. No printing, no `sys.exit`.
- `report.py` — turns results into terminal text (the colors and `print_*` functions move here).
- `cli.py` — argument parsing, reads input, calls `enrich`, calls `report`, returns the exit code.
- Use a small `dataclass` (or `TypedDict`) for one enrichment result so the shape is written down in one place, instead of each printer guessing dict keys.

**Done when:** `app.py` is gone or is a thin wrapper; `enrich` is tested without printing anything; behaviour is unchanged (existing tests pass, adjusted only for new import paths).

## Phase 4 — A real command-line interface

Use `argparse` (standard library, no new dependency):

- `ioc-analyzer "text..."`, `ioc-analyzer --file alert.txt`, `cat alert.txt | ioc-analyzer -`, and no arguments = clipboard (current behaviour).
- `--json`: print results as JSON (one array) so a SIEM/SOAR script can consume it. Document the JSON shape in the README.
- `--no-color` (in addition to the existing `NO_COLOR` support).
- `-v/--verbose`: show debug logging.
- `--version`.
- Documented exit codes: `0` all lookups OK, `1` some lookup failed, `2` bad usage/config (e.g. missing key, unreadable file). Note: argparse already uses 2 for usage errors.

**Done when:** each flag has a test (use `capsys` to capture output); `--json` output is valid JSON with a test that loads it.

## Phase 5 — Reliability

- **Rate limiting:** the VirusTotal public API allows a small number of lookups per minute (4/min on the free tier at the time of writing). Add a simple throttle in the client, with the rate configurable via `.env` (`VIRUSTOTAL_RATE_PER_MIN`, default 4), so pasting a 10-IOC alert waits instead of failing.
- **Retries:** retry at most 2 times, with a growing wait (backoff), only for timeouts, connection errors and 5xx. Never retry 401/404. Explain in the learning note why some errors are worth retrying and others aren't.
- **Logging:** replace ad-hoc stderr prints for diagnostics with the `logging` module (`logging.getLogger(__name__)` per module), configured once in `cli.py`. Never log API keys.
- **Tests:** fake time/sleep so the rate-limit and retry tests run instantly.

**Done when:** 10 IOCs on a free key complete without 429 errors (verified manually by the owner); retry and throttle behaviour are covered by fast tests.

## Phase 6 — Better extraction (SOC reality)

- Accept defanged IOCs: `hxxp://`, `hxxps://`, `[.]`, `(.)`, `[:]`. Results are shown refanged.
- Optional, ask first: IPv6 support.
- Add tests using realistic alert text (an EDR alert, a phishing email header block).

**Done when:** defanged examples are extracted correctly and covered by tests.

## Phase 7 — Packaging and configuration

- `pyproject.toml`: `[build-system]`, `requires-python = ">=3.12"` (the code uses 3.12-only f-string syntax), `[project.scripts] ioc-analyzer = "ioc_analyzer.cli:main"`, dev dependencies under `[project.optional-dependencies] dev = ["pytest", "pytest-cov", "ruff"]`, ruff and pytest config.
- Add `.env.example` listing every setting (no real keys).
- Install check: `pip install -e ".[dev]"` then `ioc-analyzer --version` works.

**Done when:** a fresh clone installs and runs with the README's steps only.

## Phase 8 — Quality gates and CI

- `ruff check` and `ruff format`, fix everything they report.
- GitHub Actions workflow `.github/workflows/ci.yml`: on push and pull request → install → ruff check → ruff format --check → pytest with coverage. Python 3.12 and 3.13.
- Add the CI badge to the README.

**Done when:** CI is green on the PR, and a deliberately failing test makes it red (show this once in the learning note, then remove it).

## Phase 9 — Documentation and release

- `README.md`: what it does, install, setup keys, usage examples (text, file, stdin, clipboard, `--json`), sample output, exit codes, JSON schema, limitations (rate limits, what isn't extracted).
- `docs/architecture.md`: the data flow (extract → enrich → report), what each module owns, how to add a new provider.
- `CHANGELOG.md`, bump version to `0.1.0`, tag `v0.1.0`.

**Done when:** someone who has never seen the project can install it, run it and add a provider using the docs alone.

## Explicitly out of scope (don't build these)

- Web API / FastAPI, database or caching layer, Docker, async, plugins, a GUI.
- Revisit only if a real need appears (e.g. running it as a scheduled job → Docker; repeated lookups wasting quota → SQLite cache).

## Learning note template (`docs/learning/phase-N.md`)

```markdown
# Phase N — <name>

## What changed (plain words)

2–4 sentences.

## Why

The problem this solves, ideally as a SOC scenario ("an analyst pastes 10 IOCs and...").

## Key decisions and trade-offs

- Decision → what we chose, what we rejected, and why.

## Python/engineering concepts used

- Concept → one-line plain explanation → where it appears (file:function).

## Read in this order

1. file:function — what to look for
2. ...

## Check yourself

3–5 questions the owner should be able to answer after reading (no answers given).
```
