# Golden-output regression harness (SCALE-00c)

The safety gate the scaling design ([../../docs/SCALING_DESIGN.md](../../docs/SCALING_DESIGN.md), ticket
**SCALE-00c**) requires before any behaviour-preserving refactor. It freezes the
output of the scan pipeline and fails loudly if a code change shifts it.

## Why this exists
The big refactors in the scaling plan (especially **WS0** — routing all egress
through one client) are *meant* to preserve behaviour. Without a baseline to diff
against, a subtle change to a checker's or scorer's output shape silently corrupts
the `scans.results` blob. This harness captures a known-good baseline and asserts
equivalence after a change — *modulo* volatile fields (timestamps, durations,
scan ids), with exact comparison everywhere else.

## What it gates today
The **scoring / financial-impact layer** (`scoring_analytics.py` and everything
feeding `insurance.*`). This path is fully **deterministic and offline** — it
replays frozen scan fixtures through the current code with **no network calls**
(via `regen_outputs_from_cache._rescore`; Monte Carlo is seeded at
`scoring_analytics.py:2620`). A change that moves a risk score, RSI, DBI,
Monte-Carlo percentile, or the result *shape* fails the check.

## What it gates now (checker level) — the chicken-and-egg is broken
The **network checkers** are now gated too, via `http_cassette.py` +
`checker_gate.py`. The design assumed a checker-level gate was blocked on WS0 (you
can't intercept every call until it flows through one client). That premise is
false: **every outbound call already funnels through `requests`** (egress audit,
2026-06-28 — no urllib3/httpx/aiohttp/socket), so the universal seam is
`requests.sessions.Session.request`, one layer below WS0. Recording there makes a
checker re-runnable offline **today, before WS0** — so WS0's correctness evidence
(a committed cassette + frozen result blob) no longer depends on durable infra to
exist. See "Checker-level gate" below.

## Usage
Run from the `security_scanner/` directory:

```bash
# Freeze / refresh baselines (first run, or after an INTENTIONAL output change)
py tooling/regression/golden.py --capture

# CI gate: assert current code reproduces the baselines (exit 1 on any drift)
py tooling/regression/golden.py --check

# Narrow to one fixture
py tooling/regression/golden.py --check --fixture phishield
```

`--check` also runs a **determinism self-check** (two back-to-back rescores must
match) so nondeterminism creeping into the scoring code is caught even before the
baseline diff.

## Files
| File | Purpose |
|---|---|
| `result_diff.py` | Reusable structural comparator: volatile-field masking, numeric tolerance, JSON-path-addressed diffs. No scanner imports. |
| `golden.py` | Capture/check driver over the scoring fixtures in `FIXTURES`. |
| `http_cassette.py` | Record/replay over `requests.sessions.Session.request`. Canonical, secret-redacted keys; replay serves responses with zero network. The interception layer the checker-level gate stands on. |
| `checker_gate.py` | `record_baseline(name, fn)` / `verify(name, fn)` — freeze a checker's outbound calls + result blob, then assert a refactor changed neither under replay. Catches the three WS0 failure modes (new/changed call, dropped call, changed output). |
| `test_result_diff.py` | 14 unit tests for the comparator. |
| `test_http_cassette.py` | 19 offline unit tests for the cassette. |
| `test_checker_gate.py` | 8 offline unit tests proving the gate catches each WS0 failure mode. |
| `baselines/*.json` | Frozen scoring baselines (commit these). |
| `checker_baselines/*.{cassette,result}.json` | Per-checker baselines, created by `record_baseline` (commit these). |

All test files run without pytest: `py tooling/regression/<file>.py`.

## Fixtures
Defined in `golden.py:FIXTURES`, built on the existing `test_fixtures/` blobs:
- `phishield_finance_r10m` — `phishield_R10M_finance_2026-05-15.json`, finance, R10M
- `takealot_retail_r135b` — `takealot_baseline.json`, retail, R13.5B

Add a fixture by appending to `FIXTURES` and re-running `--capture`.

## The WS0 workflow this enables
1. `--capture` to freeze the current scoring baseline.
2. Refactor (e.g. route a provider through the WS0 client wrapper).
3. `--check` — must stay green for the scoring layer.
4. For checker-level coverage, capture a fixture *before* the refactor, re-run the
   checker *after*, and `diff()` the two blobs (the comparator already supports
   this; the deterministic re-run is the part WS0's seam unblocks).

## Checker-level gate (built)
`http_cassette.py` + `checker_gate.py` deliver this. The WS0 migration workflow,
per call site / checker:

```python
from tooling.regression import checker_gate as cg

# 1. BEFORE refactor — freeze the checker's outbound calls + result (needs network
#    + any API keys; pick a stable target). Commit the two baseline files.
cg.record_baseline("breaches_hibp",
                   lambda: BreachChecker().check("phishield.com"))

# 2. Refactor the checker to route its requests.* calls through provider_client /
#    HTTP (WS0).

# 3. AFTER refactor — re-run under replay (no network) and assert nothing drifted.
r = cg.verify("breaches_hibp", lambda: BreachChecker().check("phishield.com"))
assert r.ok, str(r)
```

The cassette key ignores request headers + timeout, so WS0 adding an identifying
User-Agent / default timeout passes; a changed URL/param/body, a dropped or added
call, or any change to the computed result fails.

**Scope boundary:** the cassette captures HTTP only. A checker that also depends on
DNS / TLS / sockets / whois isn't made *fully* deterministic by replay — but WS0
changes only the HTTP egress path, so request-fidelity + output-equivalence over a
frozen cassette is the right contract. Stub non-HTTP sources in `fn` if you need a
byte-stable full-result diff for such a checker.
