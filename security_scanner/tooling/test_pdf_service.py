"""Unit tests for pdf_service + object_store factory (WS4). py tooling/test_pdf_service.py"""
from __future__ import annotations

import sys
import tempfile
import time
import types
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# Fake pdf_report so we don't pull in reportlab; render reflects the tier.
_fake = types.ModuleType("pdf_report")
_fake.generate_pdf = lambda results, report_type="full": b"%PDF-" + report_type.encode()
sys.modules["pdf_report"] = _fake

import object_store as os_mod
from object_store import LocalObjectStore
import pdf_service as ps

_p = _f = 0
def check(n, c):
    global _p, _f
    print(f"  {'PASS' if c else 'FAIL'}  {n}")
    _p += 1 if c else 0
    _f += 0 if c else 1


tmp = Path(tempfile.mkdtemp()) / "objstore"
os_mod.reset_for_tests(LocalObjectStore(str(tmp)))

check("pdf_key namespaced by scan+tier", ps.pdf_key("s1", "full") == "pdfs/s1/full.pdf")
check("pdf_key whitelists tier", ps.pdf_key("s1", "../evil") == "pdfs/s1/full.pdf")

b = ps.render_and_store("s1", "full", {"domain": "x"})
check("render_and_store returns bytes", b == b"%PDF-full")
check("get_pdf retrieves stored bytes", ps.get_pdf("s1", "full") == b"%PDF-full")
check("get_pdf miss for un-rendered tier", ps.get_pdf("s1", "summary") is None)
check("url present for stored pdf (file uri)",
      (ps.pdf_url("s1", "full") or "").startswith("file:"))

# PDF worker pool renders asynchronously
ok = ps.enqueue_pdf("s2", "assessment", {"domain": "y"})
check("enqueue_pdf accepted", ok is True)
for _ in range(40):
    if ps.get_pdf("s2", "assessment") is not None:
        break
    time.sleep(0.05)
check("PDF pool rendered + stored async", ps.get_pdf("s2", "assessment") == b"%PDF-assessment")

# factory default is local
os_mod.reset_for_tests(None)
check("make_object_store default = LocalObjectStore",
      type(os_mod.make_object_store()).__name__ == "LocalObjectStore")
os_mod.reset_for_tests(None)

import shutil
shutil.rmtree(tmp.parent, ignore_errors=True)
print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
