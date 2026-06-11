"""One-shot splitter: pdf_report.py -> pdf_data / pdf_helpers / pdf_cards / pdf_report.

Pure line-range moves. Segments are copied byte-for-byte (CRLF preserved);
only the new module headers / import blocks are new text.
Run from the security_scanner directory:  py tooling/_split_pdf_report.py
"""
import io
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "pdf_report.py")

with open(SRC, "rb") as f:
    raw = f.read()
text = raw.decode("utf-8")
lines = text.splitlines(keepends=True)
assert len(lines) == 7108, f"unexpected line count {len(lines)} - file changed since the split was mapped"

NL = "\r\n"


def seg(a, b):
    """1-indexed inclusive line range."""
    return "".join(lines[a - 1:b])


# --- sanity anchors (fail loudly if the map is stale) ----------------------
assert lines[40].startswith("# Brief descriptions"), lines[40]
assert lines[41].startswith("# review-by: 2026-12-02"), lines[41]
assert lines[42].startswith("CVE_DESCRIPTIONS"), lines[42]
assert lines[102].startswith("PAGE_W"), lines[102]
assert lines[504].startswith("def _tl"), lines[504]
assert lines[510].startswith("def cat_ssl"), lines[510]
assert lines[4708].rstrip() != "" , lines[4708]      # last line of _build_attackers_view
assert "CYBER SECURITY ASSESSMENT" in lines[4712], lines[4712]
assert lines[4745].startswith("    return _ASSESSMENT_STATS_DEFAULT"), lines[4745]
assert lines[4747].startswith("def _load_assessment_brand"), lines[4747]
assert lines[4801].startswith("_BRAND_CACHE"), lines[4801]
assert lines[4804].startswith("def _brand"), lines[4804]
assert lines[4813].startswith("_ASX_CURRENT_BRAND"), lines[4813]

# ---------------------------------------------------------------------------
# pdf_data.py
# ---------------------------------------------------------------------------
pdf_data = (
    '"""' + NL +
    "PHISHIELD Cyber Risk Assessment — static data tables for the PDF generator." + NL +
    "Split out of pdf_report.py (pure move — no behaviour change)." + NL +
    '"""' + NL +
    NL +
    seg(41, 101)
)

# ---------------------------------------------------------------------------
# pdf_helpers.py
# ---------------------------------------------------------------------------
helpers_header = (
    '"""' + NL +
    "PHISHIELD Cyber Risk Assessment — shared low-level PDF rendering helpers." + NL +
    "Colour palette, page geometry, styles, gauges, card scaffolding and the" + NL +
    "brand-config loader. Split out of pdf_report.py (pure move — no behaviour" + NL +
    "change)." + NL +
    '"""' + NL +
    NL +
    "from reportlab.lib.pagesizes import A4" + NL +
    "from reportlab.lib import colors" + NL +
    "from reportlab.lib.units import mm" + NL +
    "from reportlab.lib.styles import ParagraphStyle" + NL +
    "from reportlab.lib.enums import TA_CENTER" + NL +
    "from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, KeepTogether" + NL +
    "from reportlab.graphics.shapes import Drawing, Rect, Circle, String" + NL
)
pdf_helpers = (
    helpers_header +
    seg(19, 39) +      # colour palette (banner + C_* constants)
    NL +
    seg(102, 498) +    # geometry, risk colours, gauges, styles, header/footer,
                       # section helpers, badges, kv rows, card scaffolding
    NL + NL +
    seg(505, 508) +    # _tl
    NL +
    seg(4747, 4809)    # _load_assessment_brand, _BRAND_CACHE, _brand
)

# ---------------------------------------------------------------------------
# pdf_cards.py
# ---------------------------------------------------------------------------
cards_header = (
    '"""' + NL +
    "PHISHIELD Cyber Risk Assessment — per-category card and section renderers" + NL +
    "for the PDF reports. Split out of pdf_report.py (pure move — no behaviour" + NL +
    "change)." + NL +
    '"""' + NL +
    NL +
    "from reportlab.lib import colors" + NL +
    "from reportlab.lib.units import mm" + NL +
    "from reportlab.lib.styles import ParagraphStyle" + NL +
    "from reportlab.lib.enums import TA_CENTER" + NL +
    "from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, KeepTogether" + NL +
    NL +
    "from pdf_data import CVE_DESCRIPTIONS" + NL +
    "from pdf_helpers import (" + NL +
    "    C_NAVY, C_BLUE, C_BLUE_LIGHT, C_GREEN, C_GREEN_BG, C_AMBER, C_AMBER_BG," + NL +
    "    C_RED, C_RED_BG, C_CRITICAL, C_CRITICAL_BG, C_GREY_1, C_GREY_2, C_GREY_3," + NL +
    "    C_GREY_4, C_WHITE, C_BLACK, INNER_W," + NL +
    "    build_cat_card, kv_row, make_traffic_circle, not_assessed_card," + NL +
    "    _cat_table, _tl," + NL +
    ")" + NL
)
pdf_cards = (
    cards_header +
    seg(499, 504) +    # "Per-category data extractors" banner
    seg(509, 4709)     # cat_ssl ... _build_attackers_view
)

# ---------------------------------------------------------------------------
# pdf_report.py (shrunk)
# ---------------------------------------------------------------------------
report_imports = (
    NL +
    "# Split modules (pure move 2026-06-11): static data tables, shared low-level" + NL +
    "# rendering helpers, and per-category card renderers. Names are imported" + NL +
    "# explicitly so the public surface of pdf_report is unchanged." + NL +
    "from pdf_data import CVE_DESCRIPTIONS" + NL +
    "from pdf_helpers import (" + NL +
    "    C_NAVY, C_BLUE, C_BLUE_LIGHT, C_GREEN, C_GREEN_BG, C_AMBER, C_AMBER_BG," + NL +
    "    C_RED, C_RED_BG, C_CRITICAL, C_CRITICAL_BG, C_GREY_1, C_GREY_2, C_GREY_3," + NL +
    "    C_GREY_4, C_WHITE, C_BLACK," + NL +
    "    PAGE_W, PAGE_H, MARGIN, INNER_W," + NL +
    "    risk_color, risk_bg, tl_color, make_traffic_circle, make_risk_gauge," + NL +
    "    build_styles, section_header, section_with_first_card, badge_text," + NL +
    "    kv_row, issues_cell, build_cat_card, not_assessed_card," + NL +
    "    _header_footer, _section_header_banner, _risk_colour_value, _colour_issue," + NL +
    "    _cat_table, _tl, _load_assessment_brand, _brand," + NL +
    ")" + NL +
    "from pdf_cards import (" + NL +
    "    cat_ssl, cat_email, cat_email_hardening, cat_headers, cat_waf, cat_dns," + NL +
    "    cat_hrp, cat_cloud, cat_vpn, origin_discovery_block, cat_breaches," + NL +
    "    cat_dnsbl, cat_admin, cat_subdomains, cat_tech, cat_domain," + NL +
    "    cat_security_policy, cat_glasswing, cat_payment, cat_shodan, cat_dehashed," + NL +
    "    cat_hudson_rock, cat_intelx, cat_credential_risk, cat_virustotal," + NL +
    "    cat_securitytrails, cat_privacy_compliance, cat_compliance_frameworks," + NL +
    "    cat_website, cat_web_ranking, cat_info_disclosure, cat_fraudulent_domains," + NL +
    "    cat_related_domains, cat_dependency_manifests, cat_third_party_js," + NL +
    "    cat_email_vendor_surface, cat_cms_plugin_sbom, cat_credential_remediation," + NL +
    "    cat_credential_correlation, cat_third_party_correlation, cat_vendor_breach," + NL +
    "    cat_rsi, cat_dbi, cat_remediation, cat_financial_impact," + NL +
    "    loss_exposure_scenarios_block, risk_probability_block, cover_ladder_block," + NL +
    "    records_assumption_disclosure, civil_liability_disclosure," + NL +
    "    peer_benchmark_card, waf_coverage_notice, waf_card_disclaimer," + NL +
    "    flag_audit_panel, scan_duration_profile, cat_risk_mitigations," + NL +
    "    build_summary_table, _build_legend, _build_vulnerability_posture," + NL +
    "    _build_attackers_view, _supply_chain_attacker_findings," + NL +
    "    _kill_chain_severities, _finding_colour," + NL +
    ")" + NL
)
pdf_report = (
    seg(1, 18) +       # docstring + original reportlab/stdlib imports
    report_imports +
    seg(4710, 4746) +  # assessment-deck banner, default stats, stats loader
    seg(4810, 7108)    # deck (_asx_*/_assessment_*), generate_pdf, invoice
)

for name, content in (
    ("pdf_data.py", pdf_data),
    ("pdf_helpers.py", pdf_helpers),
    ("pdf_cards.py", pdf_cards),
    ("pdf_report.py", pdf_report),
):
    path = os.path.join(ROOT, name)
    with open(path, "wb") as f:
        f.write(content.encode("utf-8"))
    print(f"wrote {name}: {content.count(NL)} lines")
print("done")
