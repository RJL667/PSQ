"""
Generate the Phishield Cyber Risk Scanner User Manual (.docx).

Run: py generate_manual.py

This is a thin orchestrator that assembles the manual from the
``manual_parts/`` package. Each part exposes ``build(doc)`` and appends its
sections to a shared python-docx Document:

    part1_intro                  Cover, TOC, §1 Introduction, §2 Getting Started
    part2_discovery_core         §4.1 Discovery, §4.2 Core Security
    part3_email_network          §4.3 Information Security, §4.4 Email, §4.5 Network
    part4_exposure               §4.6 Exposure & Reputation
    part5_tech_compliance_insurance  §4.7-4.8, §5 Insurance Analytics (deep dive)
    part6_reports_scoring_glossary   §6 Reports, §7 Scoring, §8-11 + Glossary

History: prior to 2026-05-18 this file was a ~1,400-line monolith with all
content inline. The monolith fell out of sync with the cat-modelling /
disclosure overhaul (SCN-014..029) because those updates were written into
``manual_parts/`` (a refactor that was never wired up). The refactor is now
the single source of truth and the monolith was retired. The old monolith
remains in git history (commit prior to the cutover) if it is ever needed.

Helper note: ``manual_parts/helpers.py`` (aliased by top-level
``manual_helpers.py``) provides the shared formatting helpers. part1 resolves
helpers via injection (``set_helpers``) with thin fallbacks; parts 2-6
import the shared helpers directly. The injection below ensures the
cover / TOC / intro render with the same styling as the rest of the manual.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from docx import Document
from docx.shared import Pt
from docx.oxml.ns import qn


def _assert_no_blank_pages(doc):
    """Fail the build if any blank page exists (two page breaks with no
    intervening text). python-docx has no pagination model, so a content
    grep cannot see this — this structural check is the layout gate that a
    'spot check' previously missed. Parts must not emit trailing page
    breaks; the orchestrator owns inter-part pagination."""
    seq = []
    for p in doc.paragraphs:
        has_pb = False
        for r in p.runs:
            for br in r._r.findall(qn("w:br")):
                if br.get(qn("w:type")) == "page":
                    has_pb = True
        ppr = p._p.find(qn("w:pPr"))
        if ppr is not None and ppr.find(qn("w:pageBreakBefore")) is not None:
            has_pb = True
        seq.append((p.text.strip(), has_pb))
    pb = [i for i, (_, b) in enumerate(seq) if b]
    blanks = []
    for a, c in zip(pb, pb[1:]):
        if not any(seq[k][0] for k in range(a + 1, c + 1)):
            ctx = next((seq[k][0][:60] for k in range(a, -1, -1)
                        if seq[k][0]), "")
            blanks.append((a, c, ctx))
    if blanks:
        raise AssertionError(
            "Blank page(s) detected — consecutive page breaks with no text "
            "between:\n" + "\n".join(
                f"  para {a}->{c} after: {ctx!r}" for a, c, ctx in blanks))

from manual_parts import helpers as H
from manual_parts import (
    part1_intro,
    part2_discovery_core,
    part3_email_network,
    part4_exposure,
    part5_tech_compliance_insurance,
    part6_reports_scoring_glossary,
)

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "Phishield_Cyber_Risk_Scanner_User_Manual.docx")


def main():
    doc = Document()
    normal = doc.styles["Normal"].font
    normal.name = "Calibri"
    normal.size = Pt(10)

    # part1 prefers injected helpers over its thin internal fallbacks.
    part1_intro.set_helpers(
        add_h1=H.add_h1, add_h2=H.add_h2, add_h3=H.add_h3,
        add_body=H.add_body, add_bold_body=H.add_bold_body,
        add_bullet=H.add_bullet, add_tip=H.add_tip,
        add_warning=H.add_warning, add_note=H.add_note,
    )

    parts = [
        part1_intro,
        part2_discovery_core,
        part3_email_network,
        part4_exposure,
        part5_tech_compliance_insurance,
        part6_reports_scoring_glossary,
    ]
    for i, part in enumerate(parts):
        if i:
            doc.add_page_break()
        part.build(doc)

    _assert_no_blank_pages(doc)
    doc.save(OUTPUT)
    print(f"Manual saved to: {OUTPUT}")


if __name__ == "__main__":
    main()
