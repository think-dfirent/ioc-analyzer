# Phase 5 — Reliability

## What changed (plain words)

Lookups now survive the everyday ways an API misbehaves. Timeouts, dropped connections and 5xx errors are retried twice with a growing wait; a 429 gets one 60 s wait and one more try before the provider is given up for the run; and VirusTotal calls are throttled to a rolling 4 per minute (configurable) so a 10-IOC alert waits instead of being refused. Diagnostics moved from red stderr prints to `logging`, every wait is announced, and a test guarantees API keys never appear in any output.

## Why

An analyst pastes an alert with 10 IOCs. Before this phase, on a free VirusTotal key, lookups 5–10 hit 429 and the run disabled VirusTotal for everything after, so six indicators came back empty. A single 502 from AbuseIPDB lost that IP's data even though the same request would have worked a second later. In SOAR nobody is watching to "just run it again". Reliability here means: wait when waiting helps, give up quickly when it doesn't, and always say which one happened.

## Key decisions and trade-offs

- **Retry by "would the next try be different?", not by "whose fault is it?".** Timeout, connection error, 5xx: likely different → retry. 401, 404, other 4xx, a 200 with a bad body: same answer again → don't. 503 is the classic retryable code; it literally means "temporarily unavailable".
- **Exceptions carry the classification.** `ProviderTransientError` and `ProviderRateLimitedError` are subclasses of `ProviderError`, raised by the client (which knows what a status means) and handled by `retry.py` (which knows what to do). `enrich()` did not change at all.
- **429 changed a Decision, on purpose.** "429 = unavailable for the run" made sense without a throttle. Now 429 can mean "too fast" (wait helps) or "quota gone" (it doesn't), and the status code can't tell which. So: wait once, try once; a second 429 means the quota is gone. Rejected: honouring `Retry-After` (better, but more code than this phase needs — on the later list).
- **Two separate retry budgets.** A 429 and a 503 are unrelated problems; sharing one counter would let a rate-limit wait eat a retry the 503 deserved.
- **Rolling window, not fixed spacing.** With 4 per 60 s, alerts with up to 4 IOCs never wait; fixed 15 s spacing would make the 4th IOC wait 45 s. The limiter computes the exact wait once instead of polling.
- **Throttle per HTTP attempt, not per lookup.** The provider counts requests; retries use quota too.
- **Design against the documented limit, observed behaviour tunes the default.** The owner sent 20 lookups without a 429. That shows the limit wasn't enforced that day, not that it doesn't exist. Default stays 4 (the documented free tier); `VIRUSTOTAL_RATE_PER_MIN=0` turns it off.
- **Inject time, guard the suite.** Clients take `sleep` and `clock`; the autouse `FakeClock` fixture replaces both in every test, so the whole suite still runs in well under a second and every wait is asserted exactly. `sleep=None` + lookup in `__init__` (not `sleep=time.sleep` as a default) — a default argument is bound when the module loads, before any test can replace it.
- **Logging split.** Final per-indicator failures stay in `result.errors` (they are results; JSON carries them). Recoverable problems are `logger.warning`, waits are `logger.info`, extraction details `logger.debug`. The default level moved to INFO so waits are visible without `-v`.
- **Not done (later list):** honour `Retry-After`; a `--deadline` flag if a playbook step timeout ever bites; per-day quota tracking.

## Python/engineering concepts used

- **Transient vs permanent failure** → the rule that decides what to retry → `clients/virustotal.py:_fetch`, `clients/abuseipdb.py:_fetch`.
- **Exponential-ish backoff** → wait longer after each failure so a struggling server can recover → `clients/retry.py:DEFAULT_DELAYS`.
- **Idempotency** → repeating a request has the same effect as sending it once; only such requests (GETs) may be retried automatically → `clients/retry.py` docstring.
- **Exception hierarchy as a protocol** → subclasses let each layer catch exactly what it handles → `clients/errors.py`.
- **`raise ... from exc`** → the converted error keeps the original as its cause → `retry.py` (429 → unavailable).
- **`while True` with bounded budgets** → every branch must return, raise, or use up a finite budget, or the loop hangs → `retry.py:call_with_retries`.
- **Rolling-window rate limiter** → `deque` of start times; drop old ones, wait for the oldest to expire → `clients/ratelimit.py`.
- **`time.monotonic` vs `time.time`** → monotonic never jumps backwards when the system clock is corrected → `ratelimit.py`.
- **Dependency injection** → pass collaborators (`sleep`, `clock`) in instead of reaching for globals, so tests can supply fakes → client constructors.
- **Default arguments are evaluated once** → `def f(sleep=time.sleep)` captures the function at import time → why clients use `sleep=None`.
- **Autouse fixtures / `conftest.py`** → shared test setup applied to every test automatically → `tests/conftest.py:clock`.
- **Logger hierarchy** → `ioc_analyzer.clients.retry` inherits the level set on `ioc_analyzer` → `cli.py:configure_logging`.
- **Canary values** → plant something unmistakable and check where it shows up → `tests/test_secrets.py`.
- **Mutation checking** → break the code on purpose; a test that stays green proves nothing. This phase it also found a hang (a `while True` that never gave up).

## Read in this order

1. `clients/errors.py` — the four failure kinds and what each tells the caller.
2. `clients/virustotal.py:_fetch` — where each status code becomes one of those kinds.
3. `clients/retry.py:call_with_retries` — the two budgets and why every branch ends.
4. `clients/ratelimit.py:RateLimiter.wait` — the rolling window in ~15 lines.
5. `tests/conftest.py` — `FakeClock`, and why both `sleep` and `monotonic` are replaced.
6. `tests/test_retry.py` and `tests/test_ratelimit.py` — read the asserted `clock.sleeps` lists as a timeline.
7. `tests/test_secrets.py` — what it tries, and the four leaks it catches.

## Check yourself

1. A lookup gets 503, then 429, then 503, then 200. List every wait the tool makes, and say which budget each one uses.
2. Why is a 200 response with broken JSON _not_ retried, while a dropped connection is?
3. With `VIRUSTOTAL_RATE_PER_MIN=4`, a lookup at t=0 fails with 503 and retries at t=1. Three more lookups follow immediately. When does the 5th request start, and why not at t=60?
4. Someone changes a client constructor to `sleep=time.sleep`. Which tests slow down, by how much, and why does the autouse fixture not save them?
5. Name two ways an API key could leak into a log line in this codebase, and the test that would catch each.
