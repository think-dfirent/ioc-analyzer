# Phase 7 — Packaging and configuration

## What changed (plain words)

The tool is now a real Python package: `pip install .` gives you an `ioc-analyzer` command that works from any folder, with no `PYTHONPATH` trick. Settings come from environment variables or one file in your user config folder, and only our three settings are read from it. The version is written once, in `pyproject.toml`. `python -m ioc_analyzer` works; the old `python -m ioc_analyzer.app` still works but warns that it will be removed.

## Why

A colleague who cloned the repo had to know to set `PYTHONPATH=src` and to keep a `.env` next to the code. Worse, after a real install the tool would have looked for `.env` inside `site-packages` and found nothing, and with the default build backend the TLD list would not have been in the package at all — a crash on the first domain. None of this showed up in tests, because tests ran from the source folder. Packaging bugs only appear when you install the way a user does.

## Key decisions and trade-offs

- **hatchling, verified by looking inside the wheel.** A setuptools build without extra config left `data/tlds.txt` out; hatchling includes every non-ignored file in the package folder. "The tests pass" proved nothing here: an editable install reads from `src/`. The proof is a wheel installed into a fresh venv outside the repo.
- **Settings: environment first, then one per-user file, allowlisted.** `load_dotenv()` would search upward from the calling file, and a "search the current folder" fix would read a `.env` planted in an evidence folder. `load_dotenv` also copies every variable into the environment, and `requests` obeys `HTTPS_PROXY`, so a planted file could route our requests, API key included, through an attacker. `dotenv_values()` plus a three-name allowlist reads only what we need.
- **The version lives in `pyproject.toml`** and the code reads it with `importlib.metadata`, falling back to `"0+unknown"` when not installed. Rejected: two hand-synced copies guarded by a test.
- **Minimum dependency versions, no pins, no caps.** Pins belong in a lock file for a specific deployment; upper caps cause more conflicts than they prevent.
- **`[dependency-groups]` (PEP 735) for dev tools** instead of `optional-dependencies`: dev tools are not a user-facing feature and stay out of the published metadata.
- **Explicit ruff rules.** Ruff's defaults changed between versions; writing `select` down means every machine fails on the same things.
- **Deprecate, then delete.** `app.py` warns for one phase and goes in Phase 9, so old scripts get a visible notice instead of a silent break.
- **Process-level tests, few and narrow.** Three subprocess tests prove what only a real process can (the `-m` entry point, exit codes reaching the shell); everything else stays in-process and fast.

## Python/engineering concepts used

- **`pyproject.toml`** → one file describing how to build, install and run the package → repo root.
- **Build backend** → the tool `pip` calls to turn source into a wheel (`hatchling` here) → `[build-system]`.
- **Wheel** → a zip of the installed files plus metadata; `python -m zipfile -l` shows what really ships.
- **Editable install** → the installed package points back at `src/`, so edits apply without reinstalling — and packaging mistakes stay hidden.
- **Console script entry point** → pip generates `ioc-analyzer(.exe)` that calls `cli:main` and exits with its return value → `[project.scripts]`.
- **`__main__.py`** → what `python -m package` runs → `src/ioc_analyzer/__main__.py`.
- **`importlib.metadata.version`** → read the installed package's version at runtime → `__init__.py`.
- **`importlib.resources.files`** (from Phase 6) → find data shipped inside the package, wherever it is installed.
- **`requires-python`** → pip refuses to install on an older Python, instead of a `SyntaxError` at import.
- **Allowlist vs blocklist** → read only the names you need, instead of trusting a whole file → `config.py:SETTINGS`.
- **Dependency injection, again** → `load_settings(env, path)` and `settings_file(env, platform)` take what they read as parameters, so tests never touch the real environment, and the Windows rule is tested on Linux.
- **Autouse isolation fixture** → `isolated_settings` makes "tests never see real keys" automatic.
- **`git commit --amend` + `git push --force-with-lease`** → rewrite your own unpushed-to-others history safely; never `pull` an amended branch.
- **Pre-commit hook with ruff + pytest** → this phase it caught nothing, because it was added after the problem: a dead import that kept vacuous test patches alive. Now it would.

## Read in this order

1. `pyproject.toml` — every section, top to bottom.
2. `src/ioc_analyzer/__init__.py` — the version and its fallback.
3. `src/ioc_analyzer/config.py` — the module docstring first: it is the threat model.
4. `cli.py:main` — where settings are loaded and turned into clients.
5. `tests/test_config.py` — the planted-`.env` and `HTTPS_PROXY` tests.
6. `src/ioc_analyzer/__main__.py`, `app.py`, `tests/test_entry_points.py` — the entry points and how they are proven.

## Check yourself

1. Why did all tests pass with setuptools even though the installed tool would crash on the first domain?
2. An analyst runs `ioc-analyzer` inside an extracted phishing kit whose `.env` sets `HTTPS_PROXY`. Walk through what happens now, and what `load_dotenv(find_dotenv(usecwd=True))` would have done.
3. Why does `test_old_app_module_still_works_but_warns_on_stderr` check that **stdout** is unchanged?
4. The five leftover `monkeypatch.setattr(cli, "load_dotenv", ...)` lines passed for a whole commit. What were they actually testing, and what made the problem visible?
5. Your local branch "diverged" from GitHub after an amend. Why would `git pull` have made it worse?
