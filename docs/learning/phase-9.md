# Phase 9 — Documentation and release

## What changed (plain words)

The README now opens with a real run, uses the `ioc-analyzer` command everywhere and ends with a Limitations section. `docs/architecture.md` explains the data flow, what each module owns, and every place a new provider would touch. `CHANGELOG.md` lists what changed for users. The deprecated `python -m ioc_analyzer.app` was removed as promised, the version is `0.1.0`, and releases are built by CI from a tag on `main`, with a signed provenance attestation.

## Why

Until now the only people who could use the tool were the two who built it. A stranger needs to see what it does in one screen, install it without help, know what it does not do before relying on it, and — for a security tool — be able to check that the file they downloaded was built from the published code and not on someone's laptop.

## Key decisions and trade-offs

- **The first reader is an analyst**, so a real, cleaned sample output comes first (no prompts, paths or work IOCs; `--no-color`; EICAR and 8.8.8.8 only).
- **Limitations are documented, not discovered.** IPv6, emails and full URLs are not extracted; free-tier speed; file-like TLDs.
- **No provider interface yet (rule of three).** With two providers a general interface would be premature; `architecture.md` lists the 7 touch points instead, and the plan's "Done when" was changed explicitly, with the reason recorded.
- **`0.1.0` and a defined public interface.** Command and flags, exit codes, JSON fields and status values, setting names and file location. Below 1.0 they may change; every change goes in `CHANGELOG.md`. 1.0 means a promise not to break playbooks, not "finished".
- **The changelog is for users, not a copy of `git log`.** Grouped by effect (Added / Changed / Removed), with the change that silently breaks setups — settings no longer read from `.env` in the current folder — first.
- **Deprecate, then remove.** `app.py` warned for one phase and was removed on schedule, marked `refactor!:` as a breaking change.
- **Releases come from CI, never a laptop.** The release workflow refuses tags that are not on `main` or do not match `pyproject.toml`, builds once, attests the files, and publishes them. Write permission exists only in the job that creates the release.
- **Not on PyPI.** Users install from the GitHub Release or `pip install git+...@v0.1.0`; PyPI (with trusted publishing) is a 1.0 question.

## Python/engineering concepts used

- **Semantic versioning** → MAJOR.MINOR.PATCH; below 1.0 anything may change; the version describes the public interface, not the code.
- **Public interface** → what users and scripts depend on, as opposed to internal code that may change freely.
- **Keep a Changelog** → user-facing change log grouped by effect.
- **Conventional Commits `!`** → marks a breaking change in the commit history.
- **Annotated tag** → a tag object with tagger, date and message (`git tag -a`).
- **Release from CI** → reproducible build on a clean runner from exactly the tagged commit.
- **Build provenance attestation** → a signed record that this file (by hash) was built by this workflow from this commit; `gh attestation verify` checks it.
- **Per-job permissions** → the job that runs third-party build code cannot write to the repo.
- **Rule of three** → generalise when the third case arrives, not before.
- **Documentation as a deliverable** → the README-only fresh-clone test found two real bugs in Phase 7; docs are tested by following them.

## Read in this order

1. `README.md` top to bottom, as if you had never seen the project.
2. `CHANGELOG.md` — then compare with `git log --oneline v0.1.0`.
3. `docs/architecture.md` — the "Owns / Never does" table and the provider checklist.
4. `.github/workflows/release.yml` — the two guards, the permissions per job, build once / publish once.
5. The `v0.1.0` release page and its attestation.

## Check yourself

1. Which of these needs a CHANGELOG entry, and which version bump: a new `--defang` flag; renaming JSON `abuseipdb` to `abuse_ipdb`; a faster regex with the same results?
2. Someone pushes a tag `v0.1.1` on an unmerged branch. Walk through what the release workflow does.
3. Why does the `release` job download the files from `build` instead of building them again?
4. What exactly does `gh attestation verify` prove, and what does it _not_ prove about the code?
5. A colleague asks you to add GreyNoise. Using only `docs/architecture.md`, list the files you will change and the tests you will write.
