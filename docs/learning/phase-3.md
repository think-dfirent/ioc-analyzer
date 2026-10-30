# Phase 3 — Split app.py into clear layers

## What changed (plain words)

`app.py` used to do everything: read the input, call the providers, decide what counts as a failure, and print coloured text. It is now split into three modules with one job each. `enrich.py` looks up indicators and returns results as data, `report.py` turns results into terminal text, and `cli.py` talks to the outside world (environment, argv, clipboard, stdout/stderr) and returns the exit code. `app.py` is a two-line wrapper kept so old commands still work. At the end of the phase, one deliberate behaviour change: missing fields print "Unknown" instead of `None` / `ASNone`.

## Why

Phase 4 adds `--json` so a SOAR playbook can consume the results. With the old `app.py`, the only "result" was text already printed to the terminal, so JSON output would have meant parsing our own coloured output or duplicating the enrichment loop. Now `enrich()` returns a list of `EnrichmentResult` objects, and any output format (terminal today, JSON next phase) is just another consumer of that list.

The second reason is testing. Before, testing "AbuseIPDB 500 keeps the VT result" meant faking HTTP, running `main()`, and reading captured stdout. Now `tests/test_enrich.py` passes a fake client to `enrich()` and checks fields on the result: no HTTP, no printing, no `capsys`.

## Key decisions and trade-offs

- **Pure refactor first, behaviour changes in their own commits.** Every move commit had to keep the output byte-identical (checked with a golden run: one IP, one domain, one hash, compared before and after). The "Unknown" display fix came last, in its own `fix:` commit. Rejected: fixing things while moving them. That makes a diff impossible to review, because you can't tell "moved" lines from "changed" lines.
- **Errors come back as data, not exceptions or prints.** `_query()` returns `(data, None)` or `(None, message)`, and `enrich()` collects messages in `EnrichmentResult.errors`. The caller decides how to show them (stderr today, a JSON field later). The exception is `ProviderUnavailableError` (401/429): `_query()` re-raises it, because it changes control flow ("stop calling this provider for the rest of the run"), not just one result.
- **`failed` is computed from `errors`, not stored.** A stored `failed=True` could disagree with an empty `errors` tuple. A `@property` can't.
- **`EnrichmentResult` is frozen and uses a tuple for `errors`.** Once built, a result can't be changed by a printer or a later step. Data flowing through a pipeline should not be edited in place by the consumers.
- **`report` stays a dict (for now).** The normalizers already return dicts and the printers read them. Turning them into dataclasses too would double the size of the phase for no current gain. Revisit when the JSON shape is designed in Phase 4.
- **Protocols instead of concrete client types.** `enrich()` asks for "something with a `lookup()` method" (`VTLookup`, `IPLookup`), not specifically `VirusTotalClient`. That is what lets tests pass a `FakeClient` with no HTTP at all, and later lets a third provider plug in without changing `enrich()`'s signature.
- **`functools.partial` instead of a lambda inside the loop.** A lambda created in a loop looks up `artifact` when it is _called_, not when it is _created_ (late binding; ruff warns with B023). Here it was called immediately so it worked by luck. `partial` captures the values at creation time, so it's correct no matter when it runs.
- **Keep `app.py` as a wrapper.** Deleting it would break `python -m ioc_analyzer.app` for anyone (including scheduled jobs) still using it. Phase 7 adds a real `ioc-analyzer` command; the wrapper can go then.
- **Unknown vs Unavailable vs 0.** "Unavailable" = the whole provider failed, so its section is replaced. "Unknown" = the provider answered but this field was missing. "0" = real data ("0 reports" means AbuseIPDB checked and nobody reported it). `show()` tests `is None`, never truthiness, because `0 or "Unknown"` would turn real evidence into "we don't know".

## Python/engineering concepts used

- **Separation of concerns** → each module has one reason to change: new provider → `enrich.py`; new output format → `report.py` (or a new module); new flag → `cli.py`.
- **`@dataclass(frozen=True)`** → generates `__init__`, `__eq__`, `__repr__`; `frozen` makes assigning to a field raise an error → `enrich.py:EnrichmentResult`.
- **`@property`** → a method read like an attribute, computed every time → `EnrichmentResult.failed`.
- **`Literal["ip", "domain", "file"]`** → a type that allows only those strings; mypy flags `"hash"` → `enrich.py:Kind`.
- **`typing.Protocol` (structural typing)** → "any object with these methods fits", no inheritance needed → `enrich.py:VTLookup`, `IPLookup`.
- **`functools.partial`** → freeze some arguments of a function now, call it later → `enrich.py:enrich`.
- **`dict.fromkeys(items)`** → removes duplicates and keeps the original order (a `set` would lose the order) → `enrich.py:enrich`.
- **Characterization tests** → tests written _before_ a refactor to pin down current behaviour, so the refactor can prove it changed nothing → `tests/test_cli.py` (the AbuseIPDB 401/500 tests).
- **"Patch where the name is looked up"** → a function reads globals from the module where it is _defined_. After the move, `main` reads `load_dotenv` from `cli`, so tests must patch `cli`, not `app` → `tests/test_cli.py:fake_vt`, `fake_both`.
- **Moves you can prove** → `git mv` keeps file history; `git diff --staged -M --stat` shows renames; `git diff --color-moved` dims lines that moved unchanged.
- **`is None` vs truthiness** → `if not value` treats `0`, `""` and `[]` as missing; `if value is None` doesn't → `report.py:show`.

## Read in this order

1. `cli.py:main` — the whole program in ~40 lines: config → input → extract → `enrich` → print → exit code.
2. `enrich.py:EnrichmentResult` — the shape of one result; read the docstring as the contract.
3. `enrich.py:_query` — the three outcomes: data, error message, or re-raised "provider unavailable".
4. `enrich.py:enrich` — the two flags `vt_enabled` / `abuse_enabled` and why AbuseIPDB has both "configured?" and "still usable?".
5. `tests/test_enrich.py` — `FakeClient`, and how each test sets up one provider behaviour.
6. `report.py:show` and `tests/test_report.py` — the Unknown/0 rule and the test that guards both directions.

## Check yourself

1. Phase 4 adds `--json`. Which of `cli.py`, `enrich.py`, `report.py` must change, and which must _not_? Why?
2. Why does `_query()` return an error message for a 500 but re-raise for a 401? What would go wrong if it returned a message for the 401 too?
3. `failed` could have been a normal field set by `enrich()`. Describe a bug that design allows and the `@property` design prevents.
4. After the move, `monkeypatch.setattr(app, "load_dotenv", ...)` fails with `AttributeError`. Explain why, and why that failure is better than a patch that silently does nothing.
5. An analyst sees `Reports: Unknown` for one IP and `Reports: 0` for another. What does each tell them, and which line of code keeps them from being confused?
