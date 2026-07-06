"""QA: compare legacy vs ported PDFs word-by-word (text + rounded position).

Usage:
    node tools/pdf_parity.mjs <outDir>      # writes legacy_*.pdf + new_*.pdf
    py tools/compare_pdfs.py <outDir>       # diffs each pair

Proves the verbatim jsPDF port (src/lib/pdf.js) renders identically to the legacy
generatePDF (../../SME Rating Engine/sme-rating.js). Needs pdfplumber.
"""
import sys, glob, os
import pdfplumber

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(__file__)
scenarios = sorted({os.path.basename(p)[len("legacy_"):-4]
                    for p in glob.glob(os.path.join(OUT, "legacy_*.pdf"))})

def words(path):
    out = []
    with pdfplumber.open(path) as pdf:
        for pi, page in enumerate(pdf.pages):
            for w in page.extract_words(use_text_flow=True, keep_blank_chars=False):
                out.append((pi, round(w["x0"]), round(w["top"]), w["text"]))
    return out

overall_ok = True
for name in scenarios:
    lw = words(os.path.join(OUT, f"legacy_{name}.pdf"))
    nw = words(os.path.join(OUT, f"new_{name}.pdf"))
    lt = [w[3] for w in lw]
    nt = [w[3] for w in nw]
    if lw == nw:
        print(f"[IDENTICAL] {name}: {len(lw)} words, same text + positions")
        continue
    if lt == nt:
        shifts = [(abs(a[1]-b[1]), abs(a[2]-b[2])) for a, b in zip(lw, nw)]
        mx = max((max(s) for s in shifts), default=0)
        print(f"[TEXT-MATCH] {name}: {len(lw)} words identical text; max position shift {mx}pt")
        continue
    overall_ok = False
    print(f"[DIFF] {name}: legacy {len(lt)} words vs new {len(nt)} words")
    import difflib
    sm = difflib.SequenceMatcher(a=lt, b=nt)
    shown = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            continue
        print(f"   {tag}: legacy[{i1}:{i2}]={lt[i1:i2][:8]}  new[{j1}:{j2}]={nt[j1:j2][:8]}")
        shown += 1
        if shown >= 6:
            break

print()
print("PDF PARITY: ALL MATCH" if overall_ok else "PDF PARITY: DIFFERENCES FOUND")
sys.exit(0 if overall_ok else 1)
