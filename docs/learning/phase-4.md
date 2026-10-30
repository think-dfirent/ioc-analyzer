# Phase 4 — A real command-line interface

## What changed (plain words)

The tool now has a proper command line built with `argparse`: input from text, `--file`, stdin (`-`) or the clipboard, plus `--json`, `--no-color`, `-v` and `--version`. Each result records what happened with each provider (`ok` / `not_found` / `unavailable` / `error`), and `--json` prints that as one document a script can parse. Exit codes now follow a written contract: 0 answered, 1 some lookup failed, 2 usage/config error.

## Why

A SOAR playbook runs `ioc-analyzer --json --file alert.txt` on every new alert. It can't read colours or eyeball "Unknown"; it parses stdout and branches on the exit code. Before this phase the only output was coloured text, a missing VT key and "the alert had no IOCs" both returned 1 (so the playbook would page someone for an empty alert), and nothing said _why_ a provider's data was missing. A CLI is an API: two kinds of users (an analyst at a terminal, and automation) depend on its contract, and automation breaks silently when the contract changes.

## Key decisions and trade-offs

- **Contract first, code second.** The five rules (input, exit codes, null vs "Unknown", stdout purity, version source) went into CLAUDE.md Decisions before any code, so every snippet could be checked against them. Rejected: designing flags as we went, which is how CLIs end up with exit codes nobody can explain.
- **One input source per run, enforced by argparse.** A mutually exclusive group rejects text + `--file` with exit 2. Rejected: picking one silently, which gives a wrong but normal-looking answer.
- **No IOCs = exit 0.** The tool worked; the text was empty of indicators. The playbook gets `{"results": []}` and decides for itself. Rejected: exit 1 (false alarm on every IOC-less alert) and a new exit 3 (no consumer needs it yet).
- **Missing VT key = exit 2, not 1.** It is a config problem: retrying won't help, fixing `.env` will.
- **`null` in JSON, "Unknown" only on screen.** `"Unknown" > 5` crashes in Python and is _true_ in jq (strings sort above numbers), which would flag missing data as malicious. JSON lives in its own module (`serialize.py`) so `report.show()` can never leak into it.
- **Per-provider `status` stored on the result, not inferred.** Before, "why is this missing?" had to be reconstructed from `report is None`, `not_found` and `errors`. A playbook needs to tell `unavailable` (fix the key) from `error` (retry later). `vt_status` has no default, so forgetting to set it is a `TypeError`, not a silent "ok".
- **`{"results": [...]}` instead of a bare list.** Adding a field later (a summary, the tool version) doesn't break existing consumers.
- **`type=Path` and our own reading, not `argparse.FileType`.** We choose the encoding (`utf-8-sig`, strict) and the error message; FileType opens the file during parsing and leaks the handle.
- **Module-level switches for colour and log level.** Passing a `color` flag through every printer would change ten signatures for a tool that runs once. The trade-off is global state, so `main()` sets both switches every run, both ways, and a test runs `main()` twice to prove nothing leaks.
- **`-v` sets the level on the `ioc_analyzer` logger, not the root.** You see our debug messages without urllib3's. Full logging is Phase 5; this phase only adds the switch.
- **Version in `__init__.py`, guarded by a test.** `importlib.metadata` needs an installed package, which we don't have until Phase 7. Two copies of the version exist until then, and `test_version_matches_pyproject` stops them drifting.

Behaviour changes (call them out in the PR): missing VT key exits 2 (was 1); no IOCs exits 0 with the note on stderr (was 1, note on stdout); clipboard failure exits 2 (was 1).

## Python/engineering concepts used

- **argparse** → declares the command line once; generates `--help`, rejects bad input with exit 2 → `cli.py:build_parser`.
- **Mutually exclusive group** → argparse refuses two options from the same group → `cli.py:build_parser`.
- **`action="version"` / `--help` call `sys.exit()`** → tests catch `SystemExit` and check `.code` → `tests/test_cli.py`.
- **`main(argv=None) -> int`** → tests call `main([...])` directly, no subprocess; `None` means "read `sys.argv`" → `cli.py:main`.
- **Exit codes as an API** → 0/1/2 tell automation what to do next → `cli.py:main`, README.
- **stdout vs stderr** → results vs diagnostics; `--json | jq` only works if stdout holds nothing else → `cli.py:main`.
- **Custom exception for a boundary** → `InputError` turns many read failures into one "exit 2" path → `cli.py:read_text`.
- **`raise ... from exc`** → keeps the original error attached for debugging → `cli.py:read_text`.
- **`Literal` types** → only listed strings are valid; a typo is a type error → `enrich.py:Status`.
- **Derived property replacing a stored field** → `not_found` is computed from `vt_status`, so the two can't disagree → `enrich.py:EnrichmentResult`.
- **`json.dumps` defaults** → `ensure_ascii=True` keeps output ASCII-safe on Windows consoles → `serialize.py:to_json`.
- **Logger hierarchy** → `getLogger(__name__)` per module; a level on `ioc_analyzer` covers all its children → `cli.py:configure_logging`.
- **Lazy log formatting** → `logger.debug("... %d", n)` only builds the string when DEBUG is on → `cli.py:main`.
- **`tomllib`** → standard-library TOML reader (opens files in binary mode) → `tests/test_cli.py:test_version_matches_pyproject`.
- **Mutation check** → break the code on purpose and confirm a test goes red; a test that can't fail proves nothing → every snippet this phase.

## Read in this order

1. `README.md` — the contract as a user sees it: flags, exit codes, JSON shape.
2. `cli.py:build_parser` — every flag in one place.
3. `cli.py:read_text` and `InputError` — one source per run, every failure becomes exit 2.
4. `cli.py:main` — the order: parse → switches → keys → input → extract → enrich → output → exit code.
5. `enrich.py:Status` and `EnrichmentResult` — what each status means and who sets it.
6. `serialize.py` — the whole JSON format in two functions.
7. `tests/test_cli.py` — find the test for each exit code and for stdout purity (`json.loads(captured.out)`).

## Check yourself

1. A playbook gets exit 1 and a JSON document. What should it do with the results, and how does it find out what failed?
2. Why is `vt_status` required with no default, while `abuse_status` defaults to `None`? What would go wrong with `vt_status="ok"` as a default?
3. `jq '.results[] | select(.report.virustotal.malicious > 5)'` — what would this select if missing counts were `"Unknown"` instead of `null`?
4. Why does `test_without_verbose_debug_messages_are_hidden` run `main(["-v", ...])` first?
5. You rename `total_reports` to `report_count` in `normalization.py`. Every test still passes. Who breaks, and where in this repo is that risk written down?
