import os, tempfile
os.environ.setdefault("PYTHONUTF8", "1")
HERE = os.path.dirname(os.path.abspath(__file__))
SEC = os.path.dirname(HERE)
docx_path = os.path.join(SEC, "docs", "calibration_prep", "06_DRYRUN_OUTCOMES.docx")
pdf_path = os.path.join(SEC, "docs", "calibration_prep", "06_DRYRUN_OUTCOMES.pdf")
from docx2pdf import convert
convert(docx_path, pdf_path)
import fitz
d = fitz.open(pdf_path)
outdir = os.path.join(tempfile.gettempdir(), "dryrun_audit")
os.makedirs(outdir, exist_ok=True)
paths = []
for i, page in enumerate(d):
    pix = page.get_pixmap(dpi=140)
    p = os.path.join(outdir, f"page{i+1}.png")
    pix.save(p); paths.append(p)
print("PAGES", len(d))
for p in paths:
    print(p)
