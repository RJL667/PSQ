"""Tests for the casebook (past deals as test cases) and its API routes.

Run: cd veilguard/services/corp-rating && python3 -m pytest tests/test_casebook.py -q
"""
import json
import os
import sys
from pathlib import Path

import pytest

SVC = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SVC))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CASEBOOK_DIR", str(tmp_path / "casebook"))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "q.db"))
    import app as A
    A.DB_PATH = str(tmp_path / "q.db")
    A.init_db()
    return A.app.test_client()


def _example():
    import questionnaire as q
    m = q._model()
    return {str(x["row"]): x["default"] for x in m["questions"] if x.get("default") not in (None, "", " ")}


def test_create_requires_client(client):
    r = client.post("/api/cases", json={"insurer": "X"})
    assert r.status_code == 400


def test_create_and_get(client):
    r = client.post("/api/cases", json={"client": "Acme Ltd", "insurer": "Bryte",
                                        "actual": {"decision": "quoted", "premium": "R 120,000"}})
    assert r.status_code == 200
    cid = r.json["id"]
    assert cid.endswith(cid.split("-")[-1]) and "acme-ltd" in cid
    assert r.json["actual"]["premium"] == 120000.0
    g = client.get("/api/cases/" + cid).json
    assert g["case"]["client"] == "Acme Ltd"
    assert g["documents"] == [] and g["result"] is None


def test_bad_ids_are_rejected(client):
    assert client.get("/api/cases/nope").status_code == 404
    assert client.get("/api/cases/..%2fetc").status_code == 404
    assert client.get("/api/cases/x/documents/..%2f..%2fapp.py").status_code == 404


def test_unsupported_upload_rejected(client):
    cid = client.post("/api/cases", json={"client": "A"}).json["id"]
    import io
    r = client.post(f"/api/cases/{cid}/documents", data={"file": (io.BytesIO(b"x"), "evil.exe")},
                    content_type="multipart/form-data")
    assert r.status_code == 400


def test_review_answers_assess_and_compare(client):
    cid = client.post("/api/cases", json={"client": "Strong Co", "actual": {"decision": "quoted"}}).json["id"]
    ans = _example()
    r = client.put(f"/api/cases/{cid}/review",
                   json={"answers": ans, "confirmed": ["entities_minimum", "firewall"]})
    assert r.status_code == 200
    res = r.json["result"]
    assert res["assessment"]["ok"]
    assert res["answer_sources"] == {"review": len(ans)}
    checks = {c["check"]: c for c in res["comparison"]["checks"]}
    assert "decision" in checks
    # the listing reflects the processed case
    row = next(c for c in client.get("/api/cases").json if c["id"] == cid)
    assert row["status"] == "processed" and row["verdict"] in ("match", "mismatch")


def test_maturity_band_comparison(client):
    cid = client.post("/api/cases", json={"client": "Band Co"}).json["id"]
    first = client.put(f"/api/cases/{cid}/review", json={"answers": _example()}).json["result"]
    band = first["assessment"]["maturity"]["band"]
    client.patch(f"/api/cases/{cid}", json={"actual": {"maturity_band": str(band).upper()}})
    res = client.post(f"/api/cases/{cid}/process").json
    chk = next(c for c in res["comparison"]["checks"] if c["check"] == "maturity_band")
    assert chk["match"] is True


def test_corrections_become_learnings(client):
    cid = client.post("/api/cases", json={"client": "Learn Co", "insurer": "Other", "form_type": "scan"}).json["id"]
    r = client.put(f"/api/cases/{cid}/review", json={"answers": {"40": "Weekly"}})
    assert r.json["learnings_added"] == 1
    # saving the same answer again adds nothing
    r = client.put(f"/api/cases/{cid}/review", json={"answers": {"40": "Weekly"}})
    assert r.json["learnings_added"] == 0
    l = client.get("/api/casebook/learnings").json
    assert l["total"] == 1
    assert l["recent"][0]["row"] == 40 and l["recent"][0]["insurer"] == "Other"
    assert "Other / scan" in l["by_form"]


def test_folder_drop_is_adopted(client):
    root = Path(os.environ["CASEBOOK_DIR"])
    (root / "Dropped_Client").mkdir(parents=True, exist_ok=True)
    (root / "Dropped_Client" / "terms quote.txt").write_text("Premium R100k", encoding="utf-8")
    (root / "Dropped_Client" / "proposal form.txt").write_text("Backups: weekly", encoding="utf-8")
    ids = [c["id"] for c in client.get("/api/cases").json]
    assert "Dropped_Client" in ids
    g = client.get("/api/cases/Dropped_Client").json
    roles = {d["name"]: d["role"] for d in g["documents"]}
    assert roles == {"terms_quote.txt": "quote", "proposal_form.txt": "proposal"}
    res = client.post("/api/cases/Dropped_Client/process").json
    assert res["needs_mapping"] == ["proposal_form.txt"]
    assert res["assessment"] is None and res["comparison"]["verdict"] in ("no_actual", "not_assessed")
    assert (root / "Dropped_Client" / "text" / "proposal_form.txt.txt").is_file()


def test_document_download_and_role(client):
    import io
    cid = client.post("/api/cases", json={"client": "Doc Co"}).json["id"]
    up = client.post(f"/api/cases/{cid}/documents", data={"file": (io.BytesIO(b"hello"), "notes.txt"), "role": "other"},
                     content_type="multipart/form-data")
    assert up.status_code == 200 and up.json[0]["name"] == "notes.txt"
    assert client.get(f"/api/cases/{cid}/documents/notes.txt").data == b"hello"
    r = client.patch(f"/api/cases/{cid}/documents/notes.txt", json={"role": "quote"})
    assert r.json["notes.txt"] == "quote"


def test_casebook_page_is_served(client):
    assert client.get("/casebook.html").status_code == 200
    assert client.get("/casebook.js").status_code == 200
