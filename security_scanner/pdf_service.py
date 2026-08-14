"""PDF rendering decoupled into its own worker pool + object storage (WS4 / SCALE-07).

reportlab rendering is ~10-30s and spikes memory (it forced MAX_CONCURRENT=2). This
moves it off the request path: on scan completion a PDF job is enqueued to a separate
pool that renders and stores the bytes in object storage (R2/S3/local). The download
endpoint then serves from the store; reportlab runs in the request path only as a
render-on-first-request fallback for a tier that wasn't pre-rendered.

Object storage replaces the ephemeral ``scans/`` archive + ``_pdf_cache`` (both lost
on Render's disk) — keyed by scan_id so the WS10 DR sweep can reconcile against the
``scans`` table.
"""
from __future__ import annotations

import os
from typing import Optional

from object_store import make_object_store
from job_queue import InProcessJobQueue

TIERS = ("assessment", "summary", "full")


# Bump when a RENDER change should invalidate every stored PDF.
#
# The key carried no version, so a stored PDF outlived the code that produced
# it. When the Executive Summary's inverted credential verdict was fixed on
# 2026-08-14, every client who had already downloaded one was still being
# served the wrong artefact from object storage -- the fix had landed and the
# PDFs had not. It took a manual purge of 17 blobs, which is a step nobody will
# remember next time.
#
# History: v1 = pre-2026-08-14. v2 = credential verdict read from risk_level
# instead of an inverted score threshold, plus the degraded-render hardening.
RENDER_VERSION = "v2"


def pdf_key(scan_id: str, tier: str) -> str:
    tier = tier if tier in TIERS else "full"
    return f"pdfs/{scan_id}/{RENDER_VERSION}/{tier}.pdf"


def get_pdf(scan_id: str, tier: str) -> Optional[bytes]:
    return make_object_store().get(pdf_key(scan_id, tier))


def pdf_url(scan_id: str, tier: str, expires: int = 3600) -> Optional[str]:
    return make_object_store().url(pdf_key(scan_id, tier), expires)


def render_and_store(scan_id: str, tier: str, results: dict) -> bytes:
    """Render one tier and persist it to object storage. Returns the bytes."""
    from pdf_report import generate_pdf
    from credential_redaction import redact_credentials
    tier = tier if tier in TIERS else "full"
    # Reports show only masked breached-credential accounts (Manual 6.4); the
    # unmasked list is delivered exclusively via the encrypted export.
    data = redact_credentials(results)
    data["scan_id"] = scan_id
    pdf_bytes = generate_pdf(data, report_type=tier)
    try:
        make_object_store().put(pdf_key(scan_id, tier), pdf_bytes, "application/pdf")
    except Exception:
        pass  # best-effort cache; serving the bytes is what matters
    return pdf_bytes


def _handler(payload: dict):
    """Render one tier. A failure here MUST be counted.

    job_queue swallows handler exceptions on the grounds that "the handler
    records failure itself" -- which run_scan does and this did not. The result
    was three silent swallows in a row (queue, store, enqueue call site), so a
    tier that could not build produced no log line, no metric and no alarm. The
    first anyone knew was a client clicking download.
    """
    tier = payload.get("tier", "full")
    try:
        render_and_store(payload["scan_id"], tier, payload["results"])
    except Exception as e:
        try:
            from observability import PDF_RENDER_FAILURES
            PDF_RENDER_FAILURES.labels(tier=tier).inc()
        except Exception:
            pass
        import logging
        logging.getLogger(__name__).exception(
            "PDF render failed for scan=%s tier=%s: %s",
            payload.get("scan_id"), tier, e)
        raise


# Separate pool sized for reportlab's memory (independent of the scan worker pool).
_PDF_QUEUE = InProcessJobQueue(
    _handler, workers=int(os.environ.get("PDF_WORKERS", "1")),
    maxsize=int(os.environ.get("PDF_QUEUE_MAXSIZE", "200")))


def enqueue_pdf(scan_id: str, tier: str, results: dict) -> bool:
    """Queue a render in the PDF pool (no-op-safe; render-on-request still backs it)."""
    return _PDF_QUEUE.enqueue(scan_id, {"scan_id": scan_id, "tier": tier,
                                        "results": results})
