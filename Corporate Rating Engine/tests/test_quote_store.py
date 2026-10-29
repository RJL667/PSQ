"""Quote store: one save path, server recalculation, status history, ERP export feed.

Runs against SQLite always, and against a throwaway Postgres too when `pgserver` is installed.
Run: cd "Corporate Rating Engine" && python3 -m pytest tests/test_quote_store.py -q
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

SVC = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SVC))

BENEFITS = [
    "Business Interruption Loss", "Multimedia Liability Claims", "Regulatory Expenses and Penalties",
    "Third Party Claims", "Emergency Response Costs", "Data Restoration Costs",
    "PCI Fines and Penalties", "Computer Crime",
]


def _inputs(cover=15_000_000):
    return {
        "turnover": 300_000_000, "cover": cover,
        "subIndustry": "Services - Business Services",
        "maturityOverride": "Moderate", "vat": 0.15, "excess": 75_000,
        "fpAdjustableAmount": 0, "fundsProtect": True, "mdr": "No MDR",
        "benefits": [{"name": n, "included": n not in ("PCI Fines and Penalties", "Computer Crime"),
                      "sublimitRatio": 1} for n in BENEFITS],
    }


def _pg_uri():
    try:
        import pgserver  # noqa: F401
        import psycopg2  # noqa: F401
    except ImportError:
        return None
    import pgserver
    d = tempfile.mkdtemp(prefix="corp_pg_")
    return pgserver.get_server(d, cleanup_mode="stop").get_uri()


_PG = {"uri": None, "tried": False}


@pytest.fixture(params=["sqlite", "postgres"])
def client(request, tmp_path, monkeypatch):
    if request.param == "postgres":
        if not _PG["tried"]:
            _PG["tried"], _PG["uri"] = True, _pg_uri()
        if not _PG["uri"]:
            pytest.skip("pgserver not installed")
        monkeypatch.setenv("DATABASE_URL", _PG["uri"])
        monkeypatch.setenv("CORP_DB_SCHEMA", "corp_test_" + tmp_path.name.replace("-", "_")[-20:].lower())
    else:
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("DB_PATH", str(tmp_path / "q.db"))
    monkeypatch.setenv("CASEBOOK_DIR", str(tmp_path / "casebook"))
    monkeypatch.setenv("PDF_DIR", str(tmp_path / "pdfs"))
    import importlib
    import corp_db
    importlib.reload(corp_db)
    import app as A
    importlib.reload(A)
    A.init_db()
    return A.app.test_client()


def _engine(inputs):
    import engine_runner
    return engine_runner.compute(inputs)


def test_engine_runner_matches_node():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    inp = _inputs()
    js = ("global.CORP_DATA=require('./corporate-data.js');const E=require('./corporate-engine.js');"
          "process.stdout.write(JSON.stringify(E.computePremium(%s)))" % json.dumps(inp))
    out = json.loads(subprocess.check_output([node, "-e", js], cwd=str(SVC)))
    py = _engine(inp)
    assert py["ok"] and out["ok"]
    assert abs(py["finalPremium"] - out["finalPremium"]) < 1e-6


def test_ui_save_recalculates_and_matches(client):
    inp = _inputs()
    fp = _engine(inp)["finalPremium"]
    r = client.post("/api/quotes", json={"quote_ref": "CRE-T-1", "company_name": "Acme", "cover": inp["cover"],
                                         "final_premium": fp, "inputs": inp, "result": {"option": 1}})
    assert r.status_code == 201, r.json
    assert r.json["calc_check"] == "match"
    row = client.get("/api/quotes/" + r.json["id"]).json
    assert row["source"] == "rater_ui" and row["status"] == "priced"
    assert row["engine_version"] and row["result"]["engine"]["finalPremium"] == pytest.approx(fp)
    assert row["quoted_premium"] == pytest.approx(fp / 1.06)
    assert row["status_history"][0]["status"] == "priced"


def test_tampered_premium_flagged_and_replaced(client):
    inp = _inputs()
    fp = _engine(inp)["finalPremium"]
    r = client.post("/api/quotes", json={"quote_ref": "CRE-T-2", "company_name": "Acme",
                                         "final_premium": fp - 5000, "inputs": inp})
    assert r.json["calc_check"] == "mismatch"
    assert r.json["final_premium"] == pytest.approx(fp)
    row = client.get("/api/quotes/CRE-T-2").json
    assert row["result"]["client_final_premium"] == pytest.approx(fp - 5000)


def test_resave_updates_in_place(client):
    inp = _inputs()
    a = client.post("/api/quotes", json={"quote_ref": "CRE-T-3-Opt2", "company_name": "Acme", "inputs": inp}).json
    assert a["created"] and a["calc_check"] == "server_only"
    b = client.post("/api/quotes", json={"quote_ref": "CRE-T-3-Opt2", "company_name": "Acme Ltd", "inputs": inp})
    assert b.status_code == 200 and not b.json["created"] and b.json["id"] == a["id"]
    row = client.get("/api/quotes/" + a["id"]).json
    assert row["company_name"] == "Acme Ltd" and row["base_ref"] == "CRE-T-3" and row["option_no"] == 2


def test_non_engine_method_keeps_its_own_figure(client):
    inp = _inputs()
    r = client.post("/api/quotes", json={
        "quote_ref": "VG-T-4", "company_name": "Beta", "source": "veilguard", "pricing_method": "sme_plus_20",
        "quoted_premium": 84477.60, "final_premium": 89546.26, "inputs": inp,
        "basis": {"sme_band": 6, "uplift": 0.2}, "conditions": ["Weekly backups"]})
    assert r.json["calc_check"] == "not_engine_priced"
    row = client.get("/api/quotes/VG-T-4").json
    assert row["quoted_premium"] == pytest.approx(84477.60)
    assert row["engine_premium"] > 0 and row["conditions"] == ["Weekly backups"]
    assert row["basis"]["sme_band"] == 6


def test_status_flow_and_history(client):
    qid = client.post("/api/quotes", json={"quote_ref": "VG-T-5", "company_name": "Gamma",
                                           "source": "veilguard", "pricing_method": "manual"}).json["id"]
    for st, extra in (("instructed", {"instruction_text": "Hi, please quote"}),
                      ("quoted", {"admin_quote_number": "QT0000001"}),
                      ("approved", {})):
        r = client.post(f"/api/quotes/{qid}/status", json=dict(extra, status=st, by="uw", note=st))
        assert r.status_code == 200, r.json
    row = client.get("/api/quotes/" + qid).json
    assert [h["status"] for h in row["status_history"]] == ["priced", "instructed", "quoted", "approved"]
    assert row["admin_quote_number"] == "QT0000001"
    assert client.post(f"/api/quotes/{qid}/status", json={"status": "nonsense"}).status_code == 400


def test_bad_source_rejected(client):
    r = client.post("/api/quotes", json={"quote_ref": "X", "source": "elsewhere"})
    assert r.status_code == 400


def test_export_feed_pages_by_updated_at(client):
    for i in range(5):
        client.post("/api/quotes", json={"quote_ref": f"E-{i}", "company_name": f"Co{i}",
                                         "pricing_method": "manual"})
    seen, since = [], ""
    for _ in range(5):
        page = client.get(f"/api/export/quotes?limit=2&since={since}").json
        seen += [q["quote_ref"] for q in page["quotes"]]
        since = page["next_since"]
        if not page["has_more"]:
            break
    assert sorted(set(seen)) == [f"E-{i}" for i in range(5)]
    assert "status_history" in page["quotes"][0] if page["quotes"] else True


def test_archive(client):
    qid = client.post("/api/quotes", json={"quote_ref": "A-1", "pricing_method": "manual"}).json["id"]
    assert client.delete("/api/quotes/" + qid).status_code == 200
    assert client.get("/api/quotes/" + qid).json["status"] == "archived"
