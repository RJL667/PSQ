"""
Corporate Rating Engine — Flask Backend
Serves the static web app + a small API for quote persistence in SQLite.
Sibling of the SME Rating Engine backend.

Phishield UMA (Pty) Ltd
"""

import os
import uuid
import json
import sqlite3
import base64
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

import document_extract

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("DB_PATH", str(BASE_DIR / "corporate_quotes.db"))
PDF_DIR = BASE_DIR / "quote_pdfs"
UPLOAD_DIR = BASE_DIR / "ingest_uploads"

app = Flask(__name__, static_folder=None)  # no blanket static serving: see public_file()
app.secret_key = os.environ.get("SECRET_KEY", "corp-dev-key-change-in-prod")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB upload cap
CORS(app)


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quotes (
                id              TEXT PRIMARY KEY,
                quote_ref       TEXT UNIQUE NOT NULL,
                company_name    TEXT,
                website         TEXT,
                sub_industry    TEXT,
                turnover        REAL,
                cover           REAL,
                excess          REAL,
                vat             REAL,
                maturity        TEXT,
                fp_mode         TEXT,
                fp_adjustable   REAL,
                mdr             TEXT,
                benefits        TEXT,
                base_premium    REAL,
                final_premium   REAL,
                inputs          TEXT,
                result          TEXT,
                pdf_filename    TEXT,
                status          TEXT DEFAULT 'final',
                created_by      TEXT DEFAULT '',
                created_at      TEXT NOT NULL,
                updated_at      TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_corp_company   ON quotes(company_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_corp_quote_ref ON quotes(quote_ref)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_corp_created   ON quotes(created_at)")
    print(f"Corporate DB ready at {DB_PATH}")


# --------------------------------------------------------------------------
# Static files
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(str(BASE_DIR), "index.html")


# Only the web app's own assets are served. Everything else in the service folder (source code,
# the questionnaire model, the client workbook under _source/, uploads, the quote DB) stays private.
PUBLIC_FILES = frozenset({
    "index.html", "assessment.html", "corporate-rating.css", "assessment.js",
    "corporate-data.js", "corporate-engine.js", "corporate-rating.js", "jspdf.min.js",
    "casebook.html", "casebook.js",
})
PUBLIC_ASSET_EXT = (".png", ".svg", ".ico", ".jpg", ".jpeg", ".webp", ".woff", ".woff2")


@app.route("/<path:filename>")
def public_file(filename):
    name = filename.strip("/")
    if name in PUBLIC_FILES or ("/" not in name and not name.startswith(".")
                                and name.lower().endswith(PUBLIC_ASSET_EXT)):
        return send_from_directory(str(BASE_DIR), name)
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "corporate-rating-engine"})


# --------------------------------------------------------------------------
# API: ingest a risk-assessment form -> text (Phase 1: local extraction)
# --------------------------------------------------------------------------
ALLOWED_EXT = {"pdf", "docx", "xlsx", "xlsm", "txt", "md", "csv",
               "png", "jpg", "jpeg", "tif", "tiff", "bmp", "webp"}


@app.route("/api/ingest", methods=["POST"])
def ingest():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "No file uploaded (expected form field 'file')."}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"ok": False, "error": "Empty filename."}), 400
    name = secure_filename(f.filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_EXT:
        return jsonify({"ok": False, "error": f"Unsupported file type: .{ext or '?'}"}), 415

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_DIR / (uuid.uuid4().hex + "_" + name)
    f.save(str(dest))
    try:
        result = document_extract.extract(str(dest), name,
                                          user_id=request.headers.get("x-user-id") or "",
                                          conversation_id=request.headers.get("x-conversation-id") or "")
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"Extraction error: {exc}"}), 500

    result["filename"] = name
    result["stored_as"] = dest.name
    result["bytes"] = dest.stat().st_size
    # Trim very large text in the response (full text kept server-side for the mapping phase)
    if result.get("ok") and len(result.get("text", "")) > 200_000:
        result["text"] = result["text"][:200_000] + "\n\n…[truncated for preview]"
    return jsonify(result), (200 if result.get("ok") else 422)


# --------------------------------------------------------------------------
# API: map an ingested form against our questionnaire (Phase 2)
#   redact (PII out) -> Claude (or offline mock) -> rehydrate -> TIDE-style scorecard
# --------------------------------------------------------------------------
@app.route("/api/map", methods=["POST"])
def map_assessment_route():
    import mapping
    data = request.get_json(force=True) or {}
    stored = secure_filename(data.get("stored_as", ""))
    extra_terms = data.get("extra_terms", []) or []
    prefer = data.get("engine", "auto")  # auto | claude | mock
    # The pii-proxy admits the Claude call against the REAL Veilguard user (x-user-id) and keys
    # redaction/rehydration on the conversation. Never substitute one for the other: a conversation
    # id sent as the user is refused by seat admission (unknown_user).
    user_id = request.headers.get("x-user-id") or None
    conv_id = request.headers.get("x-conversation-id") or None

    text = data.get("text", "")
    if stored:
        path = UPLOAD_DIR / stored
        if not path.exists():
            return jsonify({"ok": False, "error": "Uploaded file not found — re-upload the form."}), 404
        ex = document_extract.extract(str(path), stored, user_id=user_id or "",
                                      conversation_id=conv_id or "")
        if not ex.get("ok"):
            return jsonify({"ok": False, "error": ex.get("error", "Extraction failed.")}), 422
        # Do NOT map a document that has un-read (scanned) pages — nothing may slip through.
        if ex.get("needs_ocr"):
            oc = ex.get("ocr_pages", []) or []
            return jsonify({"ok": False, "needs_ocr": True, "ocr_pages": oc, "pages": ex.get("pages"),
                            "error": ("%d of %d page(s) are scanned and not yet read (page %s). "
                                      "Run OCR first (redaction server or local) so the whole form is mapped — "
                                      "not just its text pages." % (len(oc), ex.get("pages"),
                                                                    ", ".join(map(str, oc[:12]))))}), 422
        text = ex.get("text", "") or text
    if not text.strip():
        return jsonify({"ok": False, "error": "No text to map."}), 400

    try:
        result = mapping.map_assessment(text, extra_terms=extra_terms, prefer=prefer,
                                        sid=conv_id, user_id=user_id)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"Mapping error: {exc}"}), 500
    return jsonify(result), (200 if result.get("ok") else 422)


# --------------------------------------------------------------------------
# API: the rating workbook's Cybersecurity Questionnaire, evaluated server-side.
#   posture (workbook H282) -> maturity multiplier (price sheet C12) -> premium modifier,
#   applied only once the condensed conditions of cover are met.
# --------------------------------------------------------------------------
@app.route("/api/questionnaire", methods=["GET"])
def questionnaire_describe():
    import questionnaire
    return jsonify(questionnaire.describe())


@app.route("/api/questionnaire/selftest", methods=["GET"])
def questionnaire_selftest():
    import questionnaire
    res = questionnaire.selftest()
    ok = not res["mismatches"] and not res["condition_row_drift"]
    return jsonify(dict(res, ok=ok)), (200 if ok else 500)


def _save_pdf_b64(b64, name="proposal_form.pdf"):
    raw = base64.b64decode(b64.split(",", 1)[-1] if b64.startswith("data:") else b64)
    if not raw.startswith(b"%PDF"):
        raise ValueError("pdf_base64 is not a PDF")
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_DIR / (uuid.uuid4().hex + "_" + (secure_filename(name) or "proposal_form.pdf"))
    dest.write_bytes(raw)
    return dest


@app.route("/api/assess", methods=["POST"])
def assess_route():
    """Score a proposal form against the workbook questionnaire + conditions of cover.

    Body (JSON), one of:
      {"answers": {"40": "Weekly", "152": "Yes", ...}}           explicit answers by workbook row
      {"stored_as": "<name from /api/ingest>"}                    a filled fillable-PDF proposal form
      {"pdf_base64": "...", "filename": "form.pdf"}               the same, inline
    Optional: "answers" also overlays a form; "context": {"funds_protect": bool, "soe": bool,
      "public_sector": bool, "confirmed": [condition ids the broker confirmed]}.
    Multipart: field "file" (PDF) + optional "context" (JSON string).
    """
    import questionnaire
    if request.files.get("file"):
        f = request.files["file"]
        data = {"context": json.loads(request.form.get("context") or "{}"),
                "answers": json.loads(request.form.get("answers") or "{}")}
        name = secure_filename(f.filename or "proposal_form.pdf")
        if not name.lower().endswith(".pdf"):
            return jsonify({"ok": False, "error": "Upload the proposal form as a PDF."}), 415
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        path = UPLOAD_DIR / (uuid.uuid4().hex + "_" + name)
        f.save(str(path))
    else:
        data = request.get_json(force=True, silent=True) or {}
        path = None
        stored = secure_filename(data.get("stored_as", ""))
        try:
            if data.get("pdf_base64"):
                path = _save_pdf_b64(data["pdf_base64"], data.get("filename") or "proposal_form.pdf")
            elif stored:
                path = UPLOAD_DIR / stored
                if not path.exists():
                    return jsonify({"ok": False, "error": "Uploaded file not found — re-upload the form."}), 404
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
    ctx = data.get("context") or {}
    answers = data.get("answers") or {}
    try:
        if path is not None:
            result = questionnaire.assess_form(str(path), answers=answers, context=ctx)
        elif isinstance(answers, dict) and answers:
            result = questionnaire.assess(answers, ctx)
        else:
            return jsonify({"ok": False, "error": "Send answers, stored_as, pdf_base64 or a file."}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"Assessment error: {exc}"}), 500
    return jsonify(result), (200 if result.get("ok") else 422)


# --------------------------------------------------------------------------
# API: save quote
# --------------------------------------------------------------------------
@app.route("/api/quotes", methods=["POST"])
def save_quote():
    data = request.get_json(force=True)
    quote_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    quote_ref = data.get("quote_ref") or f"CRE-{datetime.now():%Y%m%d}-{uuid.uuid4().hex[:4]}"
    company = data.get("company_name", "Unknown")

    # Optional client-rendered PDF (base64) — archived under quote_pdfs/YYYY/MM/Company/
    pdf_filename = None
    pdf_b64 = data.get("pdf_base64")
    if pdf_b64:
        dt = datetime.now()
        safe = "".join(c if c.isalnum() or c in " _-" else "_" for c in company).strip() or "Unknown"
        folder = PDF_DIR / str(dt.year) / f"{dt.month:02d}" / safe
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{quote_ref}.pdf"
        try:
            path.write_bytes(base64.b64decode(pdf_b64))
            pdf_filename = str(path.relative_to(BASE_DIR))
        except Exception as exc:
            print(f"PDF save error: {exc}")

    with get_db() as conn:
        conn.execute("""
            INSERT INTO quotes (
                id, quote_ref, company_name, website, sub_industry, turnover, cover,
                excess, vat, maturity, fp_mode, fp_adjustable, mdr, benefits,
                base_premium, final_premium, inputs, result, pdf_filename,
                status, created_by, created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            quote_id, quote_ref, company, data.get("website", ""), data.get("sub_industry", ""),
            data.get("turnover", 0), data.get("cover", 0), data.get("excess", 0), data.get("vat", 0),
            data.get("maturity", ""), data.get("fp_mode", ""), data.get("fp_adjustable", 0),
            data.get("mdr", ""), json.dumps(data.get("benefits", [])),
            data.get("base_premium", 0), data.get("final_premium", 0),
            json.dumps(data.get("inputs", {})), json.dumps(data.get("result", {})),
            pdf_filename, "final", data.get("created_by", ""), now, now,
        ))

    return jsonify({"id": quote_id, "quote_ref": quote_ref, "pdf_path": pdf_filename,
                    "message": "Quote saved"}), 201


@app.route("/api/quotes", methods=["GET"])
def list_quotes():
    company = request.args.get("company", "")
    limit = int(request.args.get("limit", 100))
    query = ("SELECT id, quote_ref, company_name, sub_industry, turnover, cover, "
             "final_premium, status, created_at FROM quotes WHERE 1=1")
    params = []
    if company:
        query += " AND company_name LIKE ?"
        params.append(f"%{company}%")
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/quotes/<quote_id>", methods=["GET"])
def get_quote(quote_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM quotes WHERE id = ?", (quote_id,)).fetchone()
    if not row:
        return jsonify({"error": "Quote not found"}), 404
    return jsonify(dict(row))


@app.route("/api/quotes/<quote_id>", methods=["DELETE"])
def archive_quote(quote_id):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        res = conn.execute("UPDATE quotes SET status='archived', updated_at=? WHERE id=?", (now, quote_id))
        if res.rowcount == 0:
            return jsonify({"error": "Quote not found"}), 404
    return jsonify({"message": "Quote archived", "id": quote_id})


@app.route("/api/quotes/<quote_id>/pdf", methods=["GET"])
def download_pdf(quote_id):
    with get_db() as conn:
        row = conn.execute("SELECT pdf_filename FROM quotes WHERE id = ?", (quote_id,)).fetchone()
    if not row or not row["pdf_filename"]:
        return jsonify({"error": "PDF not found"}), 404
    pdf_path = BASE_DIR / row["pdf_filename"]
    if not pdf_path.exists():
        return jsonify({"error": "PDF file missing"}), 404
    return send_file(str(pdf_path), mimetype="application/pdf", as_attachment=True, download_name=pdf_path.name)


# --------------------------------------------------------------------------
# Casebook: past deals (forms + what was actually quoted) as test cases
# --------------------------------------------------------------------------
def _cb_call(fn, *args, **kw):
    import casebook
    try:
        return jsonify(fn(casebook, *args, **kw))
    except casebook.CaseError as exc:
        code = 404 if "not found" in str(exc).lower() else 400
        return jsonify({"ok": False, "error": str(exc)}), code


def _reviewer():
    auth = request.authorization
    return (auth.username if auth and auth.username else "") or request.headers.get("X-Reviewer", "")


@app.route("/api/cases", methods=["GET"])
def cases_list():
    return _cb_call(lambda cb: cb.list_cases())


@app.route("/api/cases", methods=["POST"])
def cases_create():
    data = request.get_json(force=True, silent=True) or {}
    return _cb_call(lambda cb: cb.create(data))


@app.route("/api/cases/<case_id>", methods=["GET"])
def cases_get(case_id):
    return _cb_call(lambda cb: cb.get(case_id))


@app.route("/api/cases/<case_id>", methods=["PATCH"])
def cases_update(case_id):
    data = request.get_json(force=True, silent=True) or {}
    return _cb_call(lambda cb: cb.update_meta(case_id, data))


@app.route("/api/cases/<case_id>/documents", methods=["POST"])
def cases_add_documents(case_id):
    files = request.files.getlist("file")
    if not files:
        return jsonify({"ok": False, "error": "No file uploaded (expected form field 'file')."}), 400
    role = request.form.get("role", "other")
    return _cb_call(lambda cb: [cb.add_document(case_id, f.filename, f, role) for f in files])


@app.route("/api/cases/<case_id>/documents/<name>", methods=["GET"])
def cases_get_document(case_id, name):
    import casebook
    try:
        p = casebook.document_path(case_id, name)
    except casebook.CaseError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 404
    return send_file(str(p), as_attachment=request.args.get("download") == "1", download_name=p.name)


@app.route("/api/cases/<case_id>/documents/<name>", methods=["PATCH"])
def cases_set_role(case_id, name):
    data = request.get_json(force=True, silent=True) or {}
    return _cb_call(lambda cb: cb.set_role(case_id, name, data.get("role", "other")))


@app.route("/api/cases/<case_id>/process", methods=["POST"])
def cases_process(case_id):
    return _cb_call(lambda cb: cb.process(case_id))


@app.route("/api/cases/<case_id>/review", methods=["PUT"])
def cases_review(case_id):
    data = request.get_json(force=True, silent=True) or {}

    def run(cb):
        saved = cb.save_review(case_id, data, _reviewer())
        saved["result"] = cb.process(case_id)
        return saved
    return _cb_call(run)


@app.route("/api/casebook/learnings", methods=["GET"])
def casebook_learnings():
    return _cb_call(lambda cb: cb.learnings())


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5003))
    print(f"Corporate Rating Engine running at http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
else:
    init_db()
