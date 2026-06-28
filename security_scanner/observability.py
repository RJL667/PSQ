"""Observability (WS9 / SCALE-12): metrics, tracing, structured logs.

Prometheus metrics (scrape ``GET /metrics``):
  * ``scans_total{status}``         — started / completed / failed
  * ``scan_duration_seconds``       — full-scan wall time (histogram, p95 SLO)
  * ``scan_queue_depth``            — queued jobs (set at scrape time)
  * ``provider_calls_total{provider}`` — metered paid/free provider calls (credit burn)
  * ``checker_duration_seconds{checker}`` — per-checker time (from checker_durations)
  * ``circuit_breaker_open_total{provider}`` — breaker trips

OpenTelemetry tracing: correlation id = scan_id. Spans export via OTLP when
``OTEL_EXPORTER_OTLP_ENDPOINT`` is set; otherwise tracing is a no-op (zero overhead),
so this is safe to leave wired in dev. SLO targets + burn policy live in
``docs/SLOs.md``.
"""
from __future__ import annotations

import logging
import os
import sys
import time
from contextlib import contextmanager

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

SCANS = Counter("scans_total", "Scans by terminal status", ["status"])
SCAN_DURATION = Histogram("scan_duration_seconds", "Full-scan wall time",
                          buckets=(30, 60, 120, 240, 360, 480, 600, 900, 1200))
QUEUE_DEPTH = Gauge("scan_queue_depth", "Queued scan jobs")
PROVIDER_CALLS = Counter("provider_calls_total", "Metered provider calls", ["provider"])
CHECKER_DURATION = Histogram("checker_duration_seconds", "Per-checker wall time",
                             ["checker"], buckets=(1, 5, 15, 30, 60, 120, 180, 300))
BREAKER_OPEN = Counter("circuit_breaker_open_total", "Circuit-breaker trips", ["provider"])

CONTENT_TYPE = CONTENT_TYPE_LATEST


def metrics_text() -> bytes:
    return generate_latest()


def record_provider_call(provider: str, method: str = "") -> None:
    try:
        PROVIDER_CALLS.labels(provider=provider).inc()
    except Exception:
        pass


def record_checker_durations(durations: dict) -> None:
    for name, secs in (durations or {}).items():
        try:
            CHECKER_DURATION.labels(checker=str(name)).observe(float(secs))
        except Exception:
            pass


def set_queue_depth(n: int) -> None:
    try:
        QUEUE_DEPTH.set(n)
    except Exception:
        pass


# --- structured logging ---------------------------------------------------
def get_logger(name: str = "scanner") -> logging.Logger:
    log = logging.getLogger(name)
    if not log.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(logging.Formatter(
            '{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s",'
            '"msg":"%(message)s"}'))
        log.addHandler(h)
        log.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
    return log


# --- tracing (OpenTelemetry; no-op unless an exporter is configured) -------
_tracer = None


def _get_tracer():
    global _tracer
    if _tracer is not None:
        return _tracer
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.resources import Resource
        provider = TracerProvider(resource=Resource.create({"service.name": "phishield-scanner"}))
        endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        if endpoint:
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer("scanner")
    except Exception:
        _tracer = False  # tracing unavailable -> spans are no-ops
    return _tracer


@contextmanager
def scan_span(scan_id: str, domain: str = ""):
    """Trace one scan; correlation id = scan_id. No-op if OTel isn't exporting."""
    t = _get_tracer()
    if not t:
        yield
        return
    with t.start_as_current_span("scan") as span:
        try:
            span.set_attribute("scan.id", scan_id)
            if domain:
                span.set_attribute("scan.domain", domain)
        except Exception:
            pass
        yield


@contextmanager
def observe_scan(scan_id: str, domain: str = ""):
    """Wrap a full scan: counts started/completed/failed + records duration + traces."""
    SCANS.labels(status="started").inc()
    t0 = time.perf_counter()
    try:
        with scan_span(scan_id, domain):
            yield
        SCANS.labels(status="completed").inc()
    except Exception:
        SCANS.labels(status="failed").inc()
        raise
    finally:
        SCAN_DURATION.observe(time.perf_counter() - t0)
