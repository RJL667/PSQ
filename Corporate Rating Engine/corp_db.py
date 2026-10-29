"""
Corporate Rating Engine — quote store.

Postgres when DATABASE_URL is set (production: schema `corp` in the shared rater database,
next to the SME rater's quotes, so one database feeds the ERP). SQLite at DB_PATH otherwise
(local development and tests).

One record per quote option. Every pricing route writes here: the rater's Save button,
quotes priced by Veilguard, and back-filled history. `source` tells them apart and
`status` / `status_history` track a quote from priced to bound.
"""
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SCHEMA = os.environ.get("CORP_DB_SCHEMA", "corp")

STATUSES = ("draft", "priced", "instructed", "quoted", "approved", "bound",
            "declined", "not_taken_up", "superseded", "archived")
SOURCES = ("rater_ui", "veilguard", "backfill_veilguard", "backfill_email", "api")
PRICING_METHODS = ("engine", "sme_plus_20", "hybrid", "manual", "historical")

T, N, J, B = "text", "num", "json", "bool"
COLUMNS = [
    ("id", T), ("quote_ref", T), ("base_ref", T), ("option_no", N),
    ("product", T), ("source", T), ("pricing_method", T),
    ("company_name", T), ("website", T), ("broker", T), ("policy_ref", T),
    ("main_industry", T), ("sub_industry", T), ("turnover", N),
    ("cover", N), ("excess", N), ("vat", N), ("maturity", T),
    ("fp_mode", T), ("fp_adjustable", N), ("fp_authorised", N), ("fp_unauthorised", N),
    ("bi_waiting_hours", N), ("cbi_waiting_hours", N),
    ("mdr", T), ("discretionary", N), ("risk_bursary", B), ("quote_type", T),
    ("benefits", J),
    ("base_premium", N), ("final_premium", N), ("premium_ex_rm", N), ("monthly", N),
    ("quoted_premium", N),
    ("engine_premium", N), ("engine_version", T), ("calc_check", T),
    ("inputs", J), ("result", J),
    ("conditions", J), ("endorsements", J), ("posture", J), ("basis", J),
    ("instruction_text", T), ("instruction_sent_at", T),
    ("thread_id", T), ("message_id", T),
    ("admin_quote_number", T), ("admin_quote_files", J),
    ("status", T), ("status_history", J),
    ("pdf_filename", T), ("notes", T),
    ("created_by", T), ("created_at", T), ("updated_at", T),
]
COLNAMES = [c for c, _ in COLUMNS]
KIND = dict(COLUMNS)
SUMMARY_COLS = ["id", "quote_ref", "base_ref", "option_no", "company_name", "sub_industry",
                "turnover", "cover", "quoted_premium", "final_premium", "status", "source",
                "pricing_method", "admin_quote_number", "created_by", "created_at", "updated_at"]


def is_pg():
    return bool(os.environ.get("DATABASE_URL"))


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _table():
    return f"{SCHEMA}.quotes" if is_pg() else "quotes"


def _ph():
    return "%s" if is_pg() else "?"


@contextmanager
def connect():
    if is_pg():
        import psycopg2
        from psycopg2.extras import RealDictCursor
        conn = psycopg2.connect(os.environ["DATABASE_URL"], cursor_factory=RealDictCursor)
    else:
        conn = sqlite3.connect(os.environ.get("DB_PATH", str(BASE_DIR / "corporate_quotes.db")))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _sqltype(kind):
    if is_pg():
        return {T: "TEXT", N: "DOUBLE PRECISION", J: "JSONB", B: "BOOLEAN"}[kind]
    return {T: "TEXT", N: "REAL", J: "TEXT", B: "INTEGER"}[kind]


def init_schema():
    """Idempotent: create the table, add any missing columns, create indexes."""
    with connect() as conn:
        cur = conn.cursor()
        if is_pg():
            cur.execute("SELECT 1 FROM pg_namespace WHERE nspname = %s", (SCHEMA,))
            if not cur.fetchone():
                cur.execute(f"CREATE SCHEMA {SCHEMA}")
        defs = []
        for c, k in COLUMNS:
            d = f"{c} {_sqltype(k)}"
            if c == "id":
                d += " PRIMARY KEY"
            elif c == "quote_ref":
                d += " UNIQUE NOT NULL"
            elif c == "created_at":
                d += " NOT NULL"
            defs.append(d)
        cur.execute(f"CREATE TABLE IF NOT EXISTS {_table()} ({', '.join(defs)})")
        if is_pg():
            for c, k in COLUMNS:
                cur.execute(f"ALTER TABLE {_table()} ADD COLUMN IF NOT EXISTS {c} {_sqltype(k)}")
        else:
            have = {r[1] for r in cur.execute("PRAGMA table_info(quotes)").fetchall()}
            for c, k in COLUMNS:
                if c not in have:
                    cur.execute(f"ALTER TABLE quotes ADD COLUMN {c} {_sqltype(k)}")
        for c in ("company_name", "created_at", "updated_at", "status", "base_ref", "thread_id", "source"):
            idx = f"idx_corp_{c}"
            cur.execute(f"CREATE INDEX IF NOT EXISTS {idx} ON {_table()} ({c})")


def _enc(col, v):
    k = KIND[col]
    if v is None:
        return None
    if k == J:
        if is_pg():
            from psycopg2.extras import Json
            return Json(v)
        return json.dumps(v)
    if k == B:
        return bool(v) if is_pg() else int(bool(v))
    if k == N:
        try:
            return float(v)
        except (TypeError, ValueError):
            return None
    return v if isinstance(v, str) else str(v)


def _dec(row):
    if row is None:
        return None
    d = dict(row)
    if not is_pg():
        for c, k in COLUMNS:
            if k == J and isinstance(d.get(c), str):
                try:
                    d[c] = json.loads(d[c])
                except ValueError:
                    pass
            elif k == B and d.get(c) is not None:
                d[c] = bool(d[c])
    return d


def _one(cur, sql, args):
    cur.execute(sql, args)
    return cur.fetchone()


def get(quote_id):
    with connect() as conn:
        return _dec(_one(conn.cursor(), f"SELECT * FROM {_table()} WHERE id = {_ph()}", (quote_id,)))


def get_by_ref(quote_ref):
    with connect() as conn:
        return _dec(_one(conn.cursor(), f"SELECT * FROM {_table()} WHERE quote_ref = {_ph()}", (quote_ref,)))


def _history_entry(status, by, note, at):
    return {"at": at, "status": status, "by": by or "", "note": note or ""}


def save(rec, by="", note=""):
    """Insert a new quote option, or update the one with the same quote_ref.

    Returns (row, created). Status changes append to status_history; id, quote_ref and
    created_at never change on update, and an empty pdf_filename never erases one.
    """
    rec = {k: v for k, v in rec.items() if k in KIND}
    if not rec.get("quote_ref"):
        raise ValueError("quote_ref is required")
    if rec.get("status") and rec["status"] not in STATUSES:
        raise ValueError(f"unknown status {rec['status']!r}")
    now = now_iso()
    p = _ph()
    with connect() as conn:
        cur = conn.cursor()
        old = _dec(_one(cur, f"SELECT * FROM {_table()} WHERE quote_ref = {p}", (rec["quote_ref"],)))
        if old:
            upd = {k: v for k, v in rec.items()
                   if k not in ("id", "quote_ref", "created_at", "status_history")}
            if not upd.get("pdf_filename"):
                upd.pop("pdf_filename", None)
            if upd.get("status") and upd["status"] != old.get("status"):
                hist = list(old.get("status_history") or [])
                hist.append(_history_entry(upd["status"], by, note, now))
                upd["status_history"] = hist
            upd["updated_at"] = now
            cols = list(upd)
            cur.execute(f"UPDATE {_table()} SET {', '.join(f'{c} = {p}' for c in cols)} WHERE id = {p}",
                        [_enc(c, upd[c]) for c in cols] + [old["id"]])
            qid, created = old["id"], False
        else:
            rec.setdefault("id", str(uuid.uuid4()))
            rec.setdefault("product", "corporate")
            rec.setdefault("status", "priced")
            rec.setdefault("created_at", now)
            rec["updated_at"] = now
            # Back-filled history arrives with its own timeline; everything else starts one here.
            rec["status_history"] = rec.get("status_history") or [
                _history_entry(rec["status"], by, note or "created", rec["created_at"])]
            cols = list(rec)
            cur.execute(f"INSERT INTO {_table()} ({', '.join(cols)}) VALUES ({', '.join([p] * len(cols))})",
                        [_enc(c, rec[c]) for c in cols])
            qid, created = rec["id"], True
    return get(qid), created


def set_status(quote_id, status, by="", note="", fields=None):
    """Move a quote to a new status (and optionally set the admin quote number etc.)."""
    if status not in STATUSES:
        raise ValueError(f"unknown status {status!r}")
    row = get(quote_id)
    if not row:
        return None
    rec = dict(fields or {})
    rec.update({"quote_ref": row["quote_ref"], "status": status})
    out, _ = save(rec, by=by, note=note)
    return out


def list_sme(since="", limit=200):
    """Read-only view of the SME rater's quotes (public.quotes in the same Postgres database),
    so the ERP reads both raters through one feed. Empty outside Postgres."""
    if not is_pg():
        return []
    with connect() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM public.quotes WHERE COALESCE(updated_at, created_at) > %s "
                    "ORDER BY COALESCE(updated_at, created_at) ASC LIMIT %s", (since or "", int(limit)))
        out = []
        for r in cur.fetchall():
            d = dict(r)
            d["product"] = "sme"
            d.setdefault("updated_at", d.get("created_at"))
            d["updated_at"] = d.get("updated_at") or d.get("created_at")
            out.append(d)
        return out


def list_quotes(company="", status="", source="", since="", base_ref="", limit=100, full=False,
                ascending=False):
    p = _ph()
    cols = "*" if full else ", ".join(SUMMARY_COLS)
    q, args = f"SELECT {cols} FROM {_table()} WHERE 1=1", []
    like = "ILIKE" if is_pg() else "LIKE"
    if company:
        q += f" AND company_name {like} {p}"; args.append(f"%{company}%")
    if status:
        q += f" AND status = {p}"; args.append(status)
    if source:
        q += f" AND source = {p}"; args.append(source)
    if base_ref:
        q += f" AND base_ref = {p}"; args.append(base_ref)
    if since:
        q += f" AND updated_at > {p}"; args.append(since)
    order = "updated_at ASC" if ascending else "created_at DESC"
    q += f" ORDER BY {order} LIMIT {p}"; args.append(int(limit))
    with connect() as conn:
        cur = conn.cursor()
        cur.execute(q, args)
        return [_dec(r) for r in cur.fetchall()]
