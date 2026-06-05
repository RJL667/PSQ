import os, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
SEC = os.path.dirname(HERE)
pdf_path = os.path.join(SEC, "docs", "calibration_prep", "06_DRYRUN_OUTCOMES.pdf")
import fitz
d = fitz.open(pdf_path)
page = d[1]  # page 2 -> the agenda
# crop to the middle band (Tier A + Tier B numbering region)
rect = page.rect
clip = fitz.Rect(rect.x0, rect.height*0.18, rect.x1, rect.height*0.72)
pix = page.get_pixmap(dpi=200, clip=clip)
out = os.path.join(tempfile.gettempdir(), "dryrun_audit", "p2_agenda.png")
pix.save(out)
print(out)
