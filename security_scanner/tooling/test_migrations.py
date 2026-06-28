"""Unit tests for the WS1 migration runner. py tooling/test_migrations.py (sqlite)"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import scanner_db as db

_p = _f = 0
def check(n, c):
    global _p, _f
    print(f"  {'PASS' if c else 'FAIL'}  {n}")
    _p += 1 if c else 0
    _f += 0 if c else 1


tmp = Path(tempfile.mkdtemp()) / "mig.db"
db.configure(database_url="", sqlite_path=str(tmp))

applied = db.migrate()
check("first migrate applies all versions",
      applied == [v for v, _ in db.MIGRATIONS] and len(applied) == 3)
again = db.migrate()
check("second migrate is a no-op (idempotent)", again == [])

rows = db._run("SELECT version FROM schema_migrations ORDER BY version", fetch="all")
check("ledger records every version",
      [r["version"] for r in rows] == [v for v, _ in db.MIGRATIONS])

# tables from the migrations exist + are usable
db.save_scan("m1", "x.io")
check("scans table works post-migrate", db.fetch_scan("m1") is not None)
db.enqueue_job("j1", "m1", {"scan_id": "m1"})
check("scan_jobs table works post-migrate", db.queue_depth() == 1)
db._run("INSERT INTO usage (provider, day, calls) VALUES (?,?,?)", ("hibp", "2026-06-28", 5))
row = db._run("SELECT calls FROM usage WHERE provider='hibp'", fetch="one")
check("usage table works post-migrate", row and row["calls"] == 5)

try:
    tmp.unlink()
except OSError:
    pass
print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
