import os, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
SEC = os.path.dirname(HERE)
docx_path = os.path.join(SEC, "docs", "calibration_prep", "06_DRYRUN_OUTCOMES.docx")
tmp = os.path.join(tempfile.gettempdir(), "dryrun_audit2")
os.makedirs(tmp, exist_ok=True)
pdf_path = os.path.join(tmp, "06_v2.pdf")
from docx2pdf import convert
convert(docx_path, pdf_path)
import fitz
d = fitz.open(pdf_path)
print("PAGES", len(d))
for i, page in enumerate(d):
    pix = page.get_pixmap(dpi=140)
    p = os.path.join(tmp, f"page{i+1}.png")
    pix.save(p); print(p)
