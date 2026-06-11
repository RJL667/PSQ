# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #19): redesign the exec-deck supply-chain slide
(_assessment_slide_supply_chain) + fix the no_data->"Not run" mislabel.

Problems addressed (user review of the exec deck):
  1. A checker that RAN and found nothing (status `no_data`) rendered as
     "Not run" - reads as a failure, not the positive due-diligence result it
     is. Now CLEAN. Genuinely-absent / errored = "Not assessed"; skipped /
     not-WordPress / no-declared-suppliers = "Not applicable".
  2. An exec deck showed a 7-card grid mostly full of "Not run" / "Not
     applicable" tiles. Replaced with ONE plain-language VERDICT
     ("<severity> EXPOSURE - N of M assessed signals flagged"), only the
     signals with a MATERIAL finding (in plain English, S-N codes dropped),
     and a footnote of what was checked / not applicable. The signal-by-signal
     S-1..S-10 detail already lives in the full technical report + HTML
     (cat_dependency_manifests / cat_vendor_breach / ... ), so nothing is lost.

REPORTING-ONLY - presentation of already-scored signals; no scoring change.
CRLF-preserving mutator + AST validation. NOT shipped."""
import ast
import os

PR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "pdf_report.py")
s = open(PR, encoding="utf-8").read()
assert "\r" not in s

# --- A. _classify: distinguish clean / not-applicable / not-assessed ---
OLD_A = (
    "    def _classify(payload):\n"
    "        if payload.get(\"status\") == \"skipped\":\n"
    "            return \"INFO\", \"Not applicable / not detected\"\n"
    "        if payload.get(\"status\") not in (\"completed\",):\n"
    "            return \"INFO\", \"Not run\"\n"
    "        return None\n"
)
NEW_A = (
    "    def _classify(payload):\n"
    "        # A checker that RAN and found nothing (no_data) is CLEAN, not\n"
    "        # \"not run\". skipped = not applicable; absent/error = not assessed.\n"
    "        st = payload.get(\"status\")\n"
    "        if st == \"skipped\":\n"
    "            return \"NA\", \"Not applicable\"\n"
    "        if st == \"no_data\":\n"
    "            return \"CLEAN\", \"No exposure found\"\n"
    "        if st == \"completed\":\n"
    "            return None\n"
    "        if st in (None, \"error\"):\n"
    "            return \"UNKNOWN\", \"Not assessed (no scan data)\"\n"
    "        return \"UNKNOWN\", \"Not assessed\"\n"
)
assert s.count(OLD_A) == 1, ("_classify anchor", s.count(OLD_A))
s = s.replace(OLD_A, NEW_A, 1)

# --- B. S-1 no declared suppliers -> NA ---
OLD_B = (
    "        if declared == 0:\n"
    "            sev, metric = \"INFO\", \"No broker-declared suppliers\"\n"
)
NEW_B = (
    "        if declared == 0:\n"
    "            sev, metric = \"NA\", \"No declared suppliers\"\n"
)
assert s.count(OLD_B) == 1, ("S-1 declared anchor", s.count(OLD_B))
s = s.replace(OLD_B, NEW_B, 1)

# --- C. S-10 not WordPress -> NA ---
OLD_C = (
    "        if not cms.get(\"is_wordpress\"):\n"
    "            sev, metric = \"INFO\", \"Not WordPress\"\n"
)
NEW_C = (
    "        if not cms.get(\"is_wordpress\"):\n"
    "            sev, metric = \"NA\", \"Not WordPress\"\n"
)
assert s.count(OLD_C) == 1, ("S-10 not-WP anchor", s.count(OLD_C))
s = s.replace(OLD_C, NEW_C, 1)

# --- D. Replace the 7-card grid render with the rolled-up exec verdict ---
OLD_D = (
    "    def card_cell(card):\n"
    "        return [\n"
    "            Paragraph(card[\"label\"], label_st),\n"
    "            Spacer(1, 3),\n"
    "            _asx_pill(card[\"severity\"], _SC_SEV_HEX.get(card[\"severity\"], \"#475569\"),\n"
    "                       font_size=9),\n"
    "            Spacer(1, 8),\n"
    "            Paragraph(card[\"headline\"], headline_st),\n"
    "            Spacer(1, 6),\n"
    "            Paragraph(card[\"metric\"], metric_st),\n"
    "            Spacer(1, 5),\n"
    "            Paragraph(card[\"support\"], support_st),\n"
    "        ]\n"
    "\n"
    "    rows = []\n"
    "    for i in range(0, len(cards), 2):\n"
    "        pair = cards[i:i + 2]\n"
    "        cells = [card_cell(c) for c in pair]\n"
    "        while len(cells) < 2:\n"
    "            cells.append([Paragraph(\"\", support_st)])  # pad\n"
    "        rows.append(cells)\n"
    "\n"
    "    grid = Table(rows, colWidths=[(ASX_INNER_W - 16) / 2] * 2,\n"
    "                  rowHeights=[125] * len(rows))\n"
    "    grid.setStyle(TableStyle([\n"
    "        (\"BACKGROUND\",   (0, 0), (-1, -1), ASX_WHITE),\n"
    "        (\"VALIGN\",       (0, 0), (-1, -1), \"TOP\"),\n"
    "        (\"LEFTPADDING\",  (0, 0), (-1, -1), 16),\n"
    "        (\"RIGHTPADDING\", (0, 0), (-1, -1), 16),\n"
    "        (\"TOPPADDING\",   (0, 0), (-1, -1), 14),\n"
    "        (\"BOTTOMPADDING\", (0, 0), (-1, -1), 14),\n"
    "        (\"INNERGRID\",    (0, 0), (-1, -1), 0.4, colors.HexColor(\"#cbd5e1\")),\n"
    "        (\"BOX\",          (0, 0), (-1, -1), 0.4, colors.HexColor(\"#cbd5e1\")),\n"
    "    ]))\n"
    "\n"
    "    return [\n"
    "        Paragraph(\"SUPPLY-CHAIN EXPOSURE\", _style_section_label()),\n"
    "        Paragraph(\"Risk Inherited From Vendors, CDNs, and Declared Suppliers\",\n"
    "                   _style_slide_title(28)),\n"
    "        Paragraph(\n"
    "            \"Approximately 12% of breaches have a supply-chain root cause \"\n"
    "            \"(IBM Cost of a Data Breach 2024) and dwell ~48% longer than \"\n"
    "            \"direct breaches. Six external signals are surfaced here; each \"\n"
    "            \"feeds the Ransomware Susceptibility Index and the financial-\"\n"
    "            \"impact vulnerability uplift.\",\n"
    "            _style_intro(),\n"
    "        ),\n"
    "        Spacer(1, 8),\n"
    "        grid,\n"
    "    ]\n"
)
NEW_D = (
    "    # -- Executive roll-up: ONE verdict + only material-finding signals --\n"
    "    # The signal-by-signal S-1..S-10 detail lives in the full technical\n"
    "    # report + HTML; an executive deck carries a single verdict and only the\n"
    "    # signals with a material finding (no \"not run\"/\"not applicable\" tiles).\n"
    "    _SC_PLAIN = {\n"
    "        \"S-1 Related Domains\": (\"Declared suppliers\",\n"
    "            \"A supplier or sister-company domain you rely on is compromised and used to reach you.\"),\n"
    "        \"S-3 Dependency Manifests\": (\"Exposed code dependencies\",\n"
    "            \"Your software 'parts list' is publicly readable, letting attackers target known flaws with no reconnaissance.\"),\n"
    "        \"S-2 Third-Party JavaScript\": (\"Website third-party scripts\",\n"
    "            \"A third-party script on your site (analytics, ads, CDN) is hijacked to skim customer or card data.\"),\n"
    "        \"S-4 Email-Vendor Surface\": (\"Email service providers\",\n"
    "            \"An email vendor in your sending chain is abused to phish your staff and customers in your name.\"),\n"
    "        \"S-10 CMS Plugin Surface\": (\"Website plugins\",\n"
    "            \"Out-of-date website plugins are a leading ransomware entry point for SA SMEs.\"),\n"
    "        \"S-5 Vendor Breach Correlation\": (\"Known vendor breaches\",\n"
    "            \"A vendor that holds your data or login keys has a publicly-known breach; key rotation is often left incomplete.\"),\n"
    "        \"Phase 4f Cross-Correlation\": (\"Cross-checked vendor exposure\",\n"
    "            \"Several independent signals point at the SAME vendor - the highest-priority item to rotate.\"),\n"
    "    }\n"
    "    _SEV_ORDER = {\"CRITICAL\": 4, \"HIGH\": 3, \"MEDIUM\": 2, \"LOW\": 1, \"CLEAN\": 0}\n"
    "    flagged = [c for c in cards if c[\"severity\"] in (\"CRITICAL\", \"HIGH\", \"MEDIUM\")]\n"
    "    clean = [c for c in cards if c[\"severity\"] in (\"LOW\", \"CLEAN\")]\n"
    "    na = [c for c in cards if c[\"severity\"] == \"NA\"]\n"
    "    unknown = [c for c in cards if c[\"severity\"] not in\n"
    "               (\"CRITICAL\", \"HIGH\", \"MEDIUM\", \"LOW\", \"CLEAN\", \"NA\")]\n"
    "    assessed = flagged + clean\n"
    "    flagged.sort(key=lambda c: -_SEV_ORDER.get(c[\"severity\"], 0))\n"
    "\n"
    "    if flagged:\n"
    "        worst = flagged[0][\"severity\"]\n"
    "        verdict_text, vhex = worst + \" EXPOSURE\", _SC_SEV_HEX.get(worst, \"#475569\")\n"
    "        sub = (str(len(flagged)) + \" of \" + str(len(assessed)) +\n"
    "               \" assessed supply-chain signal(s) flagged for attention.\")\n"
    "    elif assessed:\n"
    "        verdict_text, vhex = \"LOW EXPOSURE\", _SC_SEV_HEX[\"LOW\"]\n"
    "        sub = \"All \" + str(len(assessed)) + \" assessed supply-chain signal(s) are clean.\"\n"
    "    else:\n"
    "        verdict_text, vhex = \"NOT ASSESSED\", \"#475569\"\n"
    "        sub = \"No external supply-chain signals could be assessed on this scan.\"\n"
    "\n"
    "    vsub_st = ParagraphStyle(\"sc_vsub\", fontSize=11, fontName=ASX_SANS,\n"
    "                              textColor=ASX_GREY_BODY, leading=15)\n"
    "    fname_st = ParagraphStyle(\"sc_fn\", fontSize=13, fontName=ASX_SANS_BOLD,\n"
    "                               textColor=ASX_NAVY, leading=16)\n"
    "    frisk_st = ParagraphStyle(\"sc_fr\", fontSize=10, fontName=ASX_SANS,\n"
    "                               textColor=ASX_GREY_BODY, leading=14)\n"
    "    fdetail_st = ParagraphStyle(\"sc_fd\", fontSize=9.5, fontName=ASX_SANS_BOLD,\n"
    "                                 textColor=ASX_NAVY, leading=13)\n"
    "    foot_st = ParagraphStyle(\"sc_foot\", fontSize=8.5, fontName=ASX_SANS,\n"
    "                              textColor=ASX_GREY_MUTED, leading=12)\n"
    "\n"
    "    out = [\n"
    "        Paragraph(\"SUPPLY-CHAIN EXPOSURE\", _style_section_label()),\n"
    "        Paragraph(\"Risk Inherited From Vendors, CDNs, and Suppliers\",\n"
    "                   _style_slide_title(28)),\n"
    "        Spacer(1, 6),\n"
    "        _asx_pill(verdict_text, vhex, font_size=12),\n"
    "        Spacer(1, 7),\n"
    "        Paragraph(sub, vsub_st),\n"
    "        Spacer(1, 8),\n"
    "        Paragraph(\n"
    "            \"About one in eight breaches has a supply-chain root cause (IBM \"\n"
    "            \"Cost of a Data Breach 2024) and they take roughly 48% longer to \"\n"
    "            \"contain. The signals below are what that means for this \"\n"
    "            \"organisation.\",\n"
    "            _style_intro()),\n"
    "        Spacer(1, 12),\n"
    "    ]\n"
    "\n"
    "    if flagged:\n"
    "        frows = []\n"
    "        for c in flagged:\n"
    "            pn, pr = _SC_PLAIN.get(c[\"label\"], (c[\"label\"], c.get(\"headline\", \"\")))\n"
    "            frows.append([[\n"
    "                _asx_pill(c[\"severity\"], _SC_SEV_HEX.get(c[\"severity\"], \"#475569\"),\n"
    "                           font_size=9),\n"
    "                Spacer(1, 5),\n"
    "                Paragraph(pn, fname_st),\n"
    "                Spacer(1, 3),\n"
    "                Paragraph(pr, frisk_st),\n"
    "                Spacer(1, 3),\n"
    "                Paragraph(\"What we found: \" + str(c[\"metric\"]), fdetail_st),\n"
    "            ]])\n"
    "        out.append(Table(frows, colWidths=[ASX_INNER_W], style=TableStyle([\n"
    "            (\"BACKGROUND\",   (0, 0), (-1, -1), colors.HexColor(\"#fbfbfd\")),\n"
    "            (\"VALIGN\",       (0, 0), (-1, -1), \"TOP\"),\n"
    "            (\"LEFTPADDING\",  (0, 0), (-1, -1), 16),\n"
    "            (\"RIGHTPADDING\", (0, 0), (-1, -1), 16),\n"
    "            (\"TOPPADDING\",   (0, 0), (-1, -1), 13),\n"
    "            (\"BOTTOMPADDING\", (0, 0), (-1, -1), 13),\n"
    "            (\"LINEBELOW\",    (0, 0), (-1, -2), 0.4, colors.HexColor(\"#e2e8f0\")),\n"
    "            (\"BOX\",          (0, 0), (-1, -1), 0.5, colors.HexColor(\"#cbd5e1\")),\n"
    "        ])))\n"
    "    else:\n"
    "        out.append(Paragraph(\n"
    "            \"No material supply-chain exposure was identified on this scan - \"\n"
    "            \"every assessed external signal is within normal bounds. This is a \"\n"
    "            \"positive due-diligence result, not an absence of checking.\", frisk_st))\n"
    "\n"
    "    def _plain_names(cardlist):\n"
    "        return \", \".join(_SC_PLAIN.get(c[\"label\"], (c[\"label\"],))[0]\n"
    "                          for c in cardlist) or \"none\"\n"
    "    foot = \"<b>Assessed:</b> \" + _plain_names(assessed) + \". \"\n"
    "    if na:\n"
    "        foot += \"<b>Not applicable:</b> \" + _plain_names(na) + \". \"\n"
    "    if unknown:\n"
    "        foot += \"<b>Not assessed (no scan data):</b> \" + _plain_names(unknown) + \". \"\n"
    "    foot += \"Full signal-by-signal detail is in the technical report.\"\n"
    "    out += [Spacer(1, 12), Paragraph(foot, foot_st)]\n"
    "    return out\n"
)
assert s.count(OLD_D) == 1, ("render-grid anchor", s.count(OLD_D))
s = s.replace(OLD_D, NEW_D, 1)

assert "\r" not in s
assert "Executive roll-up: ONE verdict" in s
assert "verdict_text, vhex = worst + \" EXPOSURE\"" in s
ast.parse(s)
with open(PR, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(PR, encoding="utf-8").read())
print("OK pdf_report.py: item #19 exec supply-chain verdict + no_data/clean fix wired (AST valid).")
