# Service-Level Objectives (WS9 / SCALE-12)

Headline SLOs for the scanner platform, with the error-budget burn policy that
drives paging and load-shedding. Targets are initial — tune against real percentiles
from the Prometheus metrics (`/metrics`).

| SLO | Target | Drives |
|---|---|---|
| Scan completion **p95** (common path: no-fraud, ≤ small-IP) | **< 8 min** | job-timeout sizing (WS2), capacity |
| Queue admission **p99** (submit → 202/429) | **< 1 s** | the web tier stays thin (enqueue-only) |
| Availability (submit + results read) | **99.5%** monthly | paging |
| Failed-scan rate (terminal, non-degraded) | **< 2%** rolling 7-day | breaker / DLQ health (WS7) |

The latency SLO is set on the **common** path; the verified worst case (fraud +
many-IP) is the **hard job ceiling** (WS2), not the SLO.

## Metrics backing these (Prometheus, `GET /metrics`)
- `scans_total{status=started|completed|failed}` → failed-scan rate, throughput
- `scan_duration_seconds` (histogram) → scan p95
- `scan_queue_depth` (gauge) → backpressure / load-shed trigger
- `provider_calls_total{provider}` → API-credit burn (cross-check vs the usage ledger)
- `checker_duration_seconds{checker}` → per-checker latency profile
- `circuit_breaker_open_total{provider}` → provider health

Traces (OpenTelemetry, correlation id = `scan_id`) export via OTLP when
`OTEL_EXPORTER_OTLP_ENDPOINT` is set.

## Error budget + burn policy
The 99.5% availability and < 2% failed-scan targets define the budget. Tie burn to
action (this is the explicit SLO-breach → backpressure link):

- **Fast burn** — budget consumed ≥ **10×** the sustainable rate → **page**.
- **Sustained burn** — failed-scan rate or queue-wait p95 breaching for **> 1 h** →
  **load-shed**: the WS2/SCALE-16 queue-full `429` / "queued, ETA" starts rejecting
  at submit rather than letting the queue grow unbounded.

## Alerts (suggested)
- `scan_queue_depth` > capacity for > 10 min → scale workers / shed.
- `rate(scans_total{status="failed"}[1h]) / rate(scans_total{status="started"}[1h])`
  > 0.02 → page (breaker/DLQ health).
- `provider_calls_total` daily delta approaching the WS5b cap → FinOps alert.
