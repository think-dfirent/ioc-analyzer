# Phase 0 — Ground rules and decisions

## What changed (plain words)
No code changed. The roadmap is now in the repo as `docs/PLAN.md`. `CLAUDE.md` now says how Claude Code works during the plan, lists the project's lasting decisions, and describes the code as it is today. The out-of-date notes are gone: the broken-test note and the "placeholder" wording about `clients/virustotal.py`.

## Why
An instruction file that is wrong is worse than none. Before this change, `CLAUDE.md` said VirusTotal code lived in `app.py` and that a broken test stopped pytest. Neither was true any more. Anyone reading it, human or AI, would have planned work against code that no longer exists. Think of a SOC runbook that still names a decommissioned server: people waste time on it.

## Key decisions and trade-offs
- **Decisions written down in one place** → `## Decisions` in `CLAUDE.md`. The rejected option was leaving them implicit in the code. Rules like "404 is not a failure" or "never show 0/0 for missing data" are easy to break by accident in a later refactor. A written rule gives every future change something to check against.
- **Plan mode vs. learning mode** → kept both, with the plan as the boundary. Dropping the learning rules entirely would also have worked, but you still want to write code yourself outside the plan, so the old rules stay for that.
- **PLAN.md committed with only formatting changes** → the text is the same as the original, with markdown headings and bold labels restored. That way the repo copy is the single source of truth.

## Python/engineering concepts used
- **Architecture Decision Records (lightweight)** → a short written "we chose X because Y" that outlives the conversation where it was decided → `CLAUDE.md` `## Decisions`.
- **Conventional Commits** → commit messages start with a type (`docs:`, `feat:`, `fix:` …) so history is easy to scan and tools can build changelogs → `git log`.
- **One branch per phase** → each pull request is small enough to review in one sitting, and `main` always holds a finished phase → branch `phase-0-ground-rules`.

## Read in this order
1. `docs/PLAN.md` — the rules section first, then skim the phases to see where the project is going.
2. `CLAUDE.md` `## Decisions` — the five rules every later phase must keep.
3. `CLAUDE.md` `## Architecture` — compare each claim with `src/ioc_analyzer/app.py` and `clients/virustotal.py` and check that it is true.

## Check yourself
1. Why does "provider 404 = not found, not a failure" change what exit code `main()` should return for an unknown hash?
2. Why should a 401 stop all further VirusTotal calls, while a 500 only fails the current indicator?
3. If a SOC script pipes `ioc-analyzer --json` into `jq`, what breaks when an error message is printed to stdout instead of stderr?
4. Which statement in the old `CLAUDE.md` would have misled someone starting Phase 2, and how?
