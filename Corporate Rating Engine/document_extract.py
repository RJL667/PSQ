"""document_extract.py — convert an uploaded risk-assessment form to text.

Phase 1 (this module): local, on-prem extraction for the common machine-readable
formats — native (text) PDFs, Word, Excel, plain text. Scanned/image PDFs and images
are detected and flagged for the vision step (Claude PDF/vision), which is wired in Phase 2.

Returns a uniform dict:
  { ok, format, pages, native, chars, needs_ocr, text, blocks, notes }
"""
import hashlib
import os
import re
import threading
import time
from collections import OrderedDict
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

# [CORP_OCR_2026-10-15] Scanned pages are OCR'd through the stack's shared OCR shim
# (pii-proxy /v1/ocr -> Gemini vision), the same path Veilguard's own document reader
# uses. ocr_client.py is a vendored copy of services/_shared/ocr_client.py because the
# corp-rating build context and /app mount do not include _shared. Set CORP_OCR=0 to
# switch it off (scans are then flagged needs_ocr and /api/map refuses them, as before).
OCR_ENABLED = os.environ.get("CORP_OCR", "1").strip().lower() not in ("0", "false", "no")
OCR_MAX_PAGES = max(1, int(os.environ.get("CORP_OCR_MAX_PAGES", "60")))

# [OCR_SPEED_2026-10-29] A form's scanned pages are all sent at once (one call per page, up to
# CORP_OCR_WORKERS in flight), each call has a short timeout, and a page with no answer after
# CORP_OCR_HEDGE_AFTER seconds gets a second copy sent: the first good answer wins. Before this,
# 4 pages ran at a time with a 180 s timeout, so one stuck Gemini call held a form for minutes.
OCR_WORKERS = max(1, int(os.environ.get("CORP_OCR_WORKERS", "16")))
# Benchmark (prod, 2026-10-29): flash-lite page calls p90 ~4.5 s, max ~6.5 s; about 1 call in 40
# never answers. Hedging at 6 s caps a stuck page at ~10 s instead of a 45-70 s timeout chain.
OCR_TIMEOUT = float(os.environ.get("CORP_OCR_TIMEOUT", "20"))
OCR_HEDGE_AFTER = float(os.environ.get("CORP_OCR_HEDGE_AFTER", "6"))
OCR_ATTEMPTS = max(1, int(os.environ.get("CORP_OCR_ATTEMPTS", "3")))
# What each scanned page is sent as: "pdf" (single-page PDF, the old behaviour) or "jpeg"
# (grayscale page image at CORP_OCR_DPI). Model / thinking budget are passed to the OCR shim.
# Benchmark default: 150 dpi grayscale JPEG on gemini-2.5-flash-lite had the best typed-text recall
# (73/82 vs 67/82 for the old pdf + 2.5-flash + thinking) at ~4.5 s per form.
OCR_INPUT = os.environ.get("CORP_OCR_INPUT", "jpeg").strip().lower()
OCR_DPI = int(os.environ.get("CORP_OCR_DPI", "150"))
OCR_MODEL = os.environ.get("CORP_OCR_MODEL", "gemini-2.5-flash-lite").strip()
OCR_THINKING = int(os.environ.get("CORP_OCR_THINKING_BUDGET", "-1"))
# Cap on output tokens per page call (0 = no cap). Stops a repetition loop from running on.
# Benchmark: normal flash-lite pages use under ~1,100 output tokens; a looping page ran to the cap
# (6000 tokens, ~13 s). 3000 leaves ~3x headroom and halves the cost of a loop.
OCR_MAX_OUT = int(os.environ.get("CORP_OCR_MAX_OUTPUT_TOKENS", "3000"))
# Same page bytes -> same text: a re-upload of a form (or a retry) is answered from memory.
# In-process only, never written to disk (client forms).
OCR_CACHE_MAX = int(os.environ.get("CORP_OCR_CACHE_PAGES", "400"))
OCR_CACHE_TTL = float(os.environ.get("CORP_OCR_CACHE_TTL", "3600"))
_ocr_cache = OrderedDict()
_ocr_cache_lock = threading.Lock()
_call_pool = ThreadPoolExecutor(max_workers=OCR_WORKERS * 2, thread_name_prefix="ocrcall")

# Per-PAGE detection so nothing slips through: a genuine text page yields hundreds of characters,
# a scanned/image page yields ~none. Any page under this threshold is routed to OCR.
PAGE_TEXT_MIN = 40

# Scan-seed detection — most of what an external scan needs (domain/website/IP) is already on
# the assessment form. These seeds are extracted LOCALLY and used to trigger the scanner in the
# closed environment; they are still redacted before the mapping LLM call (no conflict).
_EMAIL_DOMAIN = re.compile(r"[\w.+-]+@([a-z0-9.-]+\.[a-z]{2,})", re.I)
_URL = re.compile(r"\b(?:https?://|www\.)([a-z0-9.-]+\.[a-z]{2,})", re.I)
_DOMAIN = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:co\.za|org\.za|net\.za|gov\.za|ac\.za|web\.za|com|net|org|io|biz|info|africa|za))\b", re.I)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SKIP_DOMAINS = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "example.com", "google.com"}


def find_scan_seeds(text):
    """Candidate external-scan targets found in the form (broker confirms the primary domain)."""
    text = text or ""
    domains = set()
    for pat in (_EMAIL_DOMAIN, _URL, _DOMAIN):
        for m in pat.findall(text):
            d = m.lower().strip(".")
            if d and d not in _SKIP_DOMAINS and not d.endswith((".png", ".jpg", ".jpeg", ".pdf", ".docx")):
                domains.add(d)
    ips = set(_IP.findall(text))
    ips = {ip for ip in ips if all(0 <= int(o) <= 255 for o in ip.split("."))}
    return {"domains": sorted(domains)[:25], "ips": sorted(ips)[:25]}


def _ocr(data: bytes, mime: str, user_id: str = "", conversation_id: str = "",
         timeout: float = 180.0) -> str:
    from ocr_client import ocr_bytes  # local import: only needed for scans
    return ocr_bytes(data, mime, timeout=timeout, user_id=user_id or "",
                     conversation_id=conversation_id or "", model=OCR_MODEL,
                     thinking_budget=OCR_THINKING, max_output_tokens=OCR_MAX_OUT)


def _cache_get(key):
    with _ocr_cache_lock:
        hit = _ocr_cache.get(key)
        if hit and time.time() - hit[0] < OCR_CACHE_TTL:
            _ocr_cache.move_to_end(key)
            return hit[1]
        _ocr_cache.pop(key, None)
    return None


def _cache_put(key, text):
    if OCR_CACHE_MAX <= 0:
        return
    with _ocr_cache_lock:
        _ocr_cache[key] = (time.time(), text)
        _ocr_cache.move_to_end(key)
        while len(_ocr_cache) > OCR_CACHE_MAX:
            _ocr_cache.popitem(last=False)


def ocr_page_hedged(data: bytes, mime: str, user_id: str = "", conversation_id: str = ""):
    """OCR one page: short timeout, a second copy after OCR_HEDGE_AFTER s without an answer,
    up to OCR_ATTEMPTS calls in total; the first non-empty answer wins.
    Returns (text, error, stats)."""
    key = hashlib.sha256(mime.encode() + b"|" + (OCR_MODEL or "default").encode() + b"|"
                         + str(OCR_THINKING).encode() + b"|" + data).hexdigest()
    cached = _cache_get(key)
    if cached:
        return cached, None, {"attempts": 0, "cached": True, "secs": 0.0}
    t0 = time.time()
    futs, errors, attempts = set(), [], 0

    def launch():
        nonlocal attempts
        attempts += 1
        futs.add(_call_pool.submit(_ocr, data, mime, user_id, conversation_id, OCR_TIMEOUT))

    launch()
    while futs:
        done, _ = wait(futs, timeout=OCR_HEDGE_AFTER, return_when=FIRST_COMPLETED)
        if not done:
            if attempts < OCR_ATTEMPTS:
                launch()          # hedge: slow call, send another copy alongside it
            continue
        for f in done:
            futs.discard(f)
            try:
                txt = (f.result() or "").strip()
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc)[:200])
                continue
            if txt:
                _cache_put(key, txt)
                return txt, None, {"attempts": attempts, "cached": False,
                                   "secs": round(time.time() - t0, 2)}
            errors.append("empty OCR result")
        if not futs and attempts < OCR_ATTEMPTS:
            launch()              # failed outright: retry straight away
    return "", "; ".join(errors[-2:]) or "OCR failed", {"attempts": attempts, "cached": False,
                                                        "secs": round(time.time() - t0, 2)}


def _page_payload(doc, pno):
    """(bytes, mime) for one scanned page, per CORP_OCR_INPUT."""
    import fitz
    if OCR_INPUT == "jpeg":
        pix = doc[pno - 1].get_pixmap(dpi=OCR_DPI, colorspace=fitz.csGRAY, alpha=False)
        return pix.tobytes("jpeg", jpg_quality=80), "image/jpeg"
    sub = fitz.open()
    try:
        sub.insert_pdf(doc, from_page=pno - 1, to_page=pno - 1)
        return sub.tobytes(), "application/pdf"
    finally:
        sub.close()


def extract(filepath: str, filename: str, user_id: str = "", conversation_id: str = "",
            ocr: bool = None) -> dict:
    """ocr=None -> follow CORP_OCR; True/False forces it on/off for this call."""
    do_ocr = OCR_ENABLED if ocr is None else bool(ocr)
    ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()
    try:
        if ext == "pdf":
            r = _extract_pdf(filepath, do_ocr, user_id, conversation_id)
        elif ext in ("docx",):
            r = _extract_docx(filepath)
        elif ext in ("xlsx", "xlsm"):
            r = _extract_xlsx(filepath)
        elif ext in ("txt", "md", "csv"):
            r = _extract_text(filepath, ext)
        elif ext in ("png", "jpg", "jpeg", "tif", "tiff", "bmp", "webp"):
            r = _extract_image(filepath, ext, do_ocr, user_id, conversation_id)
        elif ext == "doc":
            return {"ok": False, "format": "doc", "error": "Legacy .doc not supported — please save as .docx or PDF."}
        else:
            return {"ok": False, "format": ext or "unknown", "error": f"Unsupported file type: .{ext or '?'}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "format": ext, "error": f"Extraction failed: {exc}"}
    # candidate external-scan targets (domains/IPs on the form) — used locally to seed the scanner
    if r.get("ok"):
        r["scan_seeds"] = find_scan_seeds(r.get("text", ""))
    return r


def _extract_pdf(filepath: str, do_ocr: bool = False, user_id: str = "",
                 conversation_id: str = "") -> dict:
    """Per-page classification: each page is either a text page (extract) or a scanned/image
    page (OCR it). needs_ocr stays True if ANY scanned page could not be OCR'd, so a hybrid
    document can't be silently mapped from its text pages alone (fail closed)."""
    import fitz  # PyMuPDF
    doc = fitz.open(filepath)
    # try/finally, not a bare close(): a page that raises inside get_text would
    # otherwise leak the handle AND PyMuPDF's mmap of the whole file, in a
    # long-lived service. Same shape as preview.py, thumbs.py and host_docs.py.
    page_text, scan_pdfs = {}, {}
    try:
        pages = doc.page_count
        text_pages, ocr_pages = [], []
        for i, page in enumerate(doc):
            t = (page.get_text("text") or "").strip()
            if len(t) >= PAGE_TEXT_MIN:
                page_text[i + 1] = t
                text_pages.append(i + 1)
            else:
                ocr_pages.append(i + 1)   # little/no embedded text -> OCR (err toward OCR so nothing is missed)
        if do_ocr and ocr_pages:
            # One payload per scanned page, so each OCR result maps back to its page.
            for pno in ocr_pages[:OCR_MAX_PAGES]:
                scan_pdfs[pno] = _page_payload(doc, pno)
    finally:
        doc.close()

    notes, ocr_done, ocr_failed, ocr_errors = [], [], [], []
    ocr_stats = {}
    if scan_pdfs:
        t_ocr = time.time()

        def _one(pno):
            data, mime = scan_pdfs[pno]
            txt, err, st = ocr_page_hedged(data, mime, user_id, conversation_id)
            ocr_stats[pno] = st
            return pno, txt, err
        with ThreadPoolExecutor(max_workers=min(OCR_WORKERS, len(scan_pdfs))) as pool:
            for pno, txt, err in pool.map(_one, sorted(scan_pdfs)):
                if txt:
                    page_text[pno] = txt
                    ocr_done.append(pno)
                else:
                    ocr_failed.append(pno)
                    if err:
                        ocr_errors.append("page %d: %s" % (pno, err[:200]))
    unread = [p for p in ocr_pages if p not in ocr_done]
    needs_ocr = len(unread) > 0

    blocks = [{"page": p, "text": page_text[p], "source": "ocr" if p in ocr_done else "text"}
              for p in sorted(page_text)]
    parts = [b["text"] for b in blocks]
    total = sum(len(p) for p in parts)
    kind = "scanned/image PDF" if not text_pages else "mixed PDF (some text pages, some scanned)"
    ocr_secs = round(time.time() - t_ocr, 2) if scan_pdfs else 0.0
    if ocr_done:
        notes.append("Detected a %s: %d page(s) had no embedded text and were read by OCR (page %s) in %.1f s."
                     % (kind, len(ocr_done), _pages_str(ocr_done), ocr_secs))
    if needs_ocr:
        why = ("OCR is switched off" if not do_ocr else
               "over the %d-page OCR limit" % OCR_MAX_PAGES if not ocr_failed else
               "OCR failed")
        notes.append("%d of %d page(s) are scanned and still unread (page %s): %s."
                     % (len(unread), pages, _pages_str(unread), why))
        notes.extend(ocr_errors[:3])
    return {"ok": True, "format": "pdf", "pages": pages, "native": not ocr_pages,
            "chars": total, "needs_ocr": needs_ocr,
            "text": "\n\n".join(parts), "blocks": blocks,
            "text_pages": text_pages, "ocr_pages": unread, "scanned_pages": ocr_pages,
            "ocr_read_pages": ocr_done, "ocr_seconds": ocr_secs,
            "ocr_stats": {str(k): v for k, v in sorted(ocr_stats.items())}, "notes": notes}


def _pages_str(pages):
    return ", ".join(map(str, pages[:12])) + ("…" if len(pages) > 12 else "")


_IMG_MIME = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "tif": "image/tiff",
             "tiff": "image/tiff", "bmp": "image/bmp", "webp": "image/webp"}


def _extract_image(filepath: str, ext: str, do_ocr: bool, user_id: str = "",
                   conversation_id: str = "") -> dict:
    base = {"ok": True, "format": "image", "pages": 1, "native": False, "scanned_pages": [1]}
    if not do_ocr:
        return dict(base, chars=0, needs_ocr=True, text="", blocks=[], ocr_pages=[1], ocr_read_pages=[],
                    notes=["Image file — OCR is switched off, so it cannot be read."])
    data, mime = Path(filepath).read_bytes(), _IMG_MIME.get(ext, "image/png")
    if ext in ("tif", "tiff", "bmp"):
        # Gemini takes png/jpeg/webp; convert the rest via PyMuPDF.
        import fitz
        pix = fitz.Pixmap(filepath)
        try:
            data, mime = pix.tobytes("png"), "image/png"
        finally:
            pix = None
    text, err, _st = ocr_page_hedged(data, mime, user_id, conversation_id)
    if not text:
        return dict(base, chars=0, needs_ocr=True, text="", blocks=[], ocr_pages=[1], ocr_read_pages=[],
                    notes=["Image file — OCR failed: %s" % (err or "no text")[:200]])
    return dict(base, chars=len(text), needs_ocr=not text, text=text,
                blocks=[{"page": 1, "text": text, "source": "ocr"}],
                ocr_pages=[] if text else [1], ocr_read_pages=[1] if text else [],
                notes=["Image file — read by OCR."])


def _extract_docx(filepath: str) -> dict:
    import docx  # python-docx
    d = docx.Document(filepath)
    parts = [p.text for p in d.paragraphs if p.text and p.text.strip()]
    # tables (risk assessments are often tabular Q/A)
    for ti, table in enumerate(d.tables):
        rows = []
        for row in table.rows:
            cells = [c.text.strip() for c in row.cells]
            if any(cells):
                rows.append(" | ".join(cells))
        if rows:
            parts.append("[Table %d]\n%s" % (ti + 1, "\n".join(rows)))
    text = "\n".join(parts)
    return {"ok": True, "format": "docx", "pages": None, "native": True,
            "chars": len(text), "needs_ocr": False, "text": text,
            "blocks": [{"page": None, "text": text}], "notes": []}


def _extract_xlsx(filepath: str) -> dict:
    import openpyxl
    wb = openpyxl.load_workbook(filepath, data_only=True, read_only=True)
    parts = []
    for ws in wb.worksheets:
        rows = []
        for row in ws.iter_rows(values_only=True):
            cells = [str(c) for c in row if c is not None]
            if cells:
                rows.append(" | ".join(cells))
        if rows:
            parts.append("[Sheet: %s]\n%s" % (ws.title, "\n".join(rows)))
    wb.close()
    text = "\n\n".join(parts)
    return {"ok": True, "format": "xlsx", "pages": len(parts), "native": True,
            "chars": len(text), "needs_ocr": False, "text": text,
            "blocks": [{"page": None, "text": text}], "notes": []}


def _extract_text(filepath: str, ext: str) -> dict:
    text = Path(filepath).read_text(encoding="utf-8", errors="replace")
    return {"ok": True, "format": ext, "pages": None, "native": True,
            "chars": len(text), "needs_ocr": False, "text": text,
            "blocks": [{"page": None, "text": text}], "notes": []}
