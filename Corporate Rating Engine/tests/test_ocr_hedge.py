"""Offline tests for the parallel hedged OCR path (no network: _ocr is patched)."""
import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("CORP_OCR_HEDGE_AFTER", "0.3")
os.environ.setdefault("CORP_OCR_TIMEOUT", "2")
import document_extract as de  # noqa: E402


def _reset():
    de._ocr_cache.clear()
    de.OCR_HEDGE_AFTER = 0.3


def test_hedge_wins_over_stuck_call():
    _reset()
    calls = []
    lock = threading.Lock()

    def fake(data, mime, uid, cid, timeout):
        with lock:
            calls.append(time.time())
            n = len(calls)
        if n == 1:
            time.sleep(1.5)  # first copy hangs
            return "slow"
        return "fast"
    de._ocr = fake
    t = time.time()
    txt, err, st = de.ocr_page_hedged(b"page-a", "image/jpeg")
    assert txt == "fast" and err is None
    assert st["attempts"] == 2
    assert time.time() - t < 1.0


def test_retry_after_error_then_cache():
    _reset()
    n = {"c": 0}

    def fake(data, mime, uid, cid, timeout):
        n["c"] += 1
        if n["c"] == 1:
            raise RuntimeError("HTTP 0")
        return "ok text"
    de._ocr = fake
    txt, err, st = de.ocr_page_hedged(b"page-b", "image/jpeg")
    assert txt == "ok text" and st["attempts"] == 2
    txt2, _, st2 = de.ocr_page_hedged(b"page-b", "image/jpeg")
    assert txt2 == "ok text" and st2["cached"] and n["c"] == 2


def test_gives_up_after_attempts():
    _reset()

    def fake(data, mime, uid, cid, timeout):
        raise RuntimeError("boom")
    de._ocr = fake
    txt, err, st = de.ocr_page_hedged(b"page-c", "image/jpeg")
    assert txt == "" and "boom" in err and st["attempts"] == de.OCR_ATTEMPTS


def test_pages_run_in_parallel():
    _reset()

    def fake(data, mime, uid, cid, timeout):
        time.sleep(0.25)
        return "t" + data.decode()
    de._ocr = fake
    from concurrent.futures import ThreadPoolExecutor
    t = time.time()
    with ThreadPoolExecutor(12) as p:
        out = list(p.map(lambda i: de.ocr_page_hedged(str(i).encode(), "image/jpeg")[0], range(12)))
    assert out == ["t%d" % i for i in range(12)]
    assert time.time() - t < 0.8
