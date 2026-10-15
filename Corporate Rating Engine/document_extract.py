"""document_extract.py — convert an uploaded risk-assessment form to text.

Phase 1 (this module): local, on-prem extraction for the common machine-readable
formats — native (text) PDFs, Word, Excel, plain text. Scanned/image PDFs and images
are detected and flagged for the vision step (Claude PDF/vision), which is wired in Phase 2.

Returns a uniform dict:
  { ok, format, pages, native, chars, needs_ocr, text, blocks, notes }
"""
import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# [CORP_OCR_2026-10-15] Scanned pages are OCR'd through the stack's shared OCR shim
# (pii-proxy /v1/ocr -> Gemini vision), the same path Veilguard's own document reader
# uses. ocr_client.py is a vendored copy of services/_shared/ocr_client.py because the
# corp-rating build context and /app mount do not include _shared. Set CORP_OCR=0 to
# switch it off (scans are then flagged needs_ocr and /api/map refuses them, as before).
OCR_ENABLED = os.environ.get("CORP_OCR", "1").strip().lower() not in ("0", "false", "no")
OCR_WORKERS = max(1, int(os.environ.get("CORP_OCR_WORKERS", "4")))
OCR_MAX_PAGES = max(1, int(os.environ.get("CORP_OCR_MAX_PAGES", "60")))

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


def _ocr(data: bytes, mime: str, user_id: str = "", conversation_id: str = "") -> str:
    from ocr_client import ocr_bytes  # local import: only needed for scans
    return ocr_bytes(data, mime, user_id=user_id or "", conversation_id=conversation_id or "")


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
            # One single-page PDF per scanned page, so each OCR result maps back to its page.
            for pno in ocr_pages[:OCR_MAX_PAGES]:
                sub = fitz.open()
                try:
                    sub.insert_pdf(doc, from_page=pno - 1, to_page=pno - 1)
                    scan_pdfs[pno] = sub.tobytes()
                finally:
                    sub.close()
    finally:
        doc.close()

    notes, ocr_done, ocr_failed, ocr_errors = [], [], [], []
    if scan_pdfs:
        def _one(pno):
            try:
                return pno, _ocr(scan_pdfs[pno], "application/pdf", user_id, conversation_id).strip(), None
            except Exception as exc:  # noqa: BLE001
                return pno, "", str(exc)
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
    if ocr_done:
        notes.append("Detected a %s: %d page(s) had no embedded text and were read by OCR (page %s)."
                     % (kind, len(ocr_done), _pages_str(ocr_done)))
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
            "ocr_read_pages": ocr_done, "notes": notes}


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
    try:
        text = _ocr(data, mime, user_id, conversation_id).strip()
    except Exception as exc:  # noqa: BLE001
        return dict(base, chars=0, needs_ocr=True, text="", blocks=[], ocr_pages=[1], ocr_read_pages=[],
                    notes=["Image file — OCR failed: %s" % str(exc)[:200]])
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
