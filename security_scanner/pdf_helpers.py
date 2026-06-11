"""
PHISHIELD Cyber Risk Assessment — shared low-level PDF rendering helpers.
Colour palette, page geometry, styles, gauges, card scaffolding and the
brand-config loader. Split out of pdf_report.py (pure move — no behaviour
change).
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.graphics.shapes import Drawing, Rect, Circle, String

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
C_NAVY      = colors.HexColor("#0f2744")
C_BLUE      = colors.HexColor("#1d4ed8")
C_BLUE_LIGHT= colors.HexColor("#dbeafe")
C_GREEN     = colors.HexColor("#16a34a")
C_GREEN_BG  = colors.HexColor("#dcfce7")
C_AMBER     = colors.HexColor("#d97706")
C_AMBER_BG  = colors.HexColor("#fef3c7")
C_RED       = colors.HexColor("#dc2626")
C_RED_BG    = colors.HexColor("#fee2e2")
C_CRITICAL  = colors.HexColor("#991b1b")
C_CRITICAL_BG = colors.HexColor("#fecaca")
C_GREY_1    = colors.HexColor("#f8fafc")
C_GREY_2    = colors.HexColor("#e2e8f0")
C_GREY_3    = colors.HexColor("#94a3b8")
C_GREY_4    = colors.HexColor("#475569")
C_WHITE     = colors.white
C_BLACK     = colors.HexColor("#0f172a")


PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
INNER_W = PAGE_W - 2 * MARGIN


def risk_color(risk_level: str):
    return {"Low": C_GREEN, "Medium": C_AMBER, "High": C_RED, "Critical": C_CRITICAL}.get(risk_level, C_GREY_3)


def risk_bg(risk_level: str):
    return {"Low": C_GREEN_BG, "Medium": C_AMBER_BG, "High": C_RED_BG, "Critical": C_CRITICAL_BG}.get(risk_level, C_GREY_1)


def tl_color(level: str):
    """Traffic light colour from string key."""
    return {"green": C_GREEN, "amber": C_AMBER, "red": C_RED, "crimson": C_CRITICAL, "blue": C_BLUE}.get(level, C_GREY_3)


# ---------------------------------------------------------------------------
# Custom drawing helpers
# ---------------------------------------------------------------------------

def make_traffic_circle(color, size=10):
    d = Drawing(size, size)
    d.add(Circle(size / 2, size / 2, size / 2 - 0.5,
                 fillColor=color, strokeColor=C_WHITE, strokeWidth=0.5))
    return d


def make_risk_gauge(score: int, width=INNER_W, height=16 * mm) -> Drawing:
    """Horizontal colour-banded gauge with a position marker."""
    d = Drawing(width, height)
    bar_y, bar_h = 5 * mm, 6 * mm
    zones = [
        (0,   200, C_GREEN),
        (200, 400, C_AMBER),
        (400, 600, C_RED),
        (600, 1000, C_CRITICAL),
    ]
    for start, end, col in zones:
        x = (start / 1000) * width
        w = ((end - start) / 1000) * width
        d.add(Rect(x, bar_y, w, bar_h, fillColor=col, strokeColor=None, rx=0))

    # Zone labels
    for label, x_frac in [("Low", 0.1), ("Medium", 0.3), ("High", 0.5), ("Critical", 0.75)]:
        sx = x_frac * width
        d.add(String(sx, bar_y + bar_h / 2 - 2, label,
                     fontSize=6, fillColor=C_WHITE, textAnchor="middle"))

    # Score marker (black triangle / rectangle)
    mx = (score / 1000) * width
    mx = max(2, min(mx, width - 2))
    d.add(Rect(mx - 2, bar_y - 3 * mm, 4, bar_h + 6 * mm,
               fillColor=C_BLACK, strokeColor=None))

    # Score label above marker
    d.add(String(mx, bar_y + bar_h + 3.5 * mm, str(score),
                 fontSize=7, fillColor=C_BLACK, textAnchor="middle"))
    return d


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

def build_styles():
    S = {}
    base = dict(fontName="Helvetica", textColor=C_BLACK, leading=14)

    S["cover_title"] = ParagraphStyle("cover_title", fontSize=26, fontName="Helvetica-Bold",
                                       textColor=C_NAVY, leading=30, spaceAfter=4)
    S["cover_sub"]   = ParagraphStyle("cover_sub",   fontSize=13, textColor=C_GREY_4,
                                       leading=18, spaceAfter=2, **{k: v for k, v in base.items() if k not in ("textColor", "leading")})
    S["cover_domain"]= ParagraphStyle("cover_domain",fontSize=18, fontName="Helvetica-Bold",
                                       textColor=C_BLUE, leading=22)
    S["section_hdr"] = ParagraphStyle("section_hdr", fontSize=11, fontName="Helvetica-Bold",
                                       textColor=C_WHITE, leading=14, leftIndent=4)
    S["cat_title"]   = ParagraphStyle("cat_title",   fontSize=10, fontName="Helvetica-Bold",
                                       textColor=C_NAVY, leading=14)
    S["body"]        = ParagraphStyle("body",         fontSize=8,  leading=11, textColor=C_BLACK)
    S["body_muted"]  = ParagraphStyle("body_muted",   fontSize=7,  leading=10, textColor=C_GREY_4)
    S["issue"]       = ParagraphStyle("issue",        fontSize=8, leading=10, textColor=C_RED,
                                       leftIndent=8)
    S["rec_num"]     = ParagraphStyle("rec_num",      fontSize=8,  fontName="Helvetica-Bold",
                                       textColor=C_BLUE, leading=11)
    S["rec_body"]    = ParagraphStyle("rec_body",     fontSize=8,  leading=11, textColor=C_BLACK,
                                       leftIndent=18, firstLineIndent=-18)
    S["footer"]      = ParagraphStyle("footer",       fontSize=6.5, textColor=C_GREY_3,
                                       alignment=TA_CENTER)
    S["disclaimer"]  = ParagraphStyle("disclaimer",   fontSize=7,  leading=10, textColor=C_GREY_4)
    S["kv_key"]      = ParagraphStyle("kv_key",       fontSize=8, textColor=C_GREY_4, leading=10)
    S["kv_val"]      = ParagraphStyle("kv_val",       fontSize=8, textColor=C_BLACK,  leading=10)
    S["stat"]        = ParagraphStyle("stat",         fontSize=8, fontName="Helvetica",
                                       textColor=C_BLACK, leading=11, spaceBefore=2, spaceAfter=2,
                                       leftIndent=12, bulletIndent=6)
    S["cta"]         = ParagraphStyle("cta",          fontSize=8, fontName="Helvetica",
                                       textColor=C_BLACK, leading=11, spaceBefore=2, spaceAfter=3,
                                       leftIndent=12, bulletIndent=6)
    S["contact"]     = ParagraphStyle("contact",      fontSize=9, fontName="Helvetica-Bold",
                                       textColor=C_BLUE, leading=13, alignment=TA_CENTER)
    S["fsp"]         = ParagraphStyle("fsp",          fontSize=8, fontName="Helvetica",
                                       textColor=C_GREY_3, leading=11, alignment=TA_CENTER)
    S["vp_legend"]   = ParagraphStyle("vp_legend",    fontSize=8, fontName="Helvetica",
                                       textColor=C_GREY_4, leading=10, leftIndent=4)
    return S


# ---------------------------------------------------------------------------
# Header / footer callback
# ---------------------------------------------------------------------------

def _header_footer(canvas, doc, domain, timestamp):
    canvas.saveState()
    w, h = A4

    # Top bar
    canvas.setFillColor(C_NAVY)
    canvas.rect(0, h - 12 * mm, w, 12 * mm, fill=True, stroke=False)
    canvas.setFillColor(C_WHITE)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(MARGIN, h - 7 * mm, _brand()["report_header_text"])
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(w - MARGIN, h - 7 * mm, domain)

    # Bottom bar
    canvas.setFillColor(C_GREY_2)
    canvas.rect(0, 0, w, 9 * mm, fill=True, stroke=False)
    canvas.setFillColor(C_GREY_4)
    canvas.setFont("Helvetica", 6.5)
    canvas.drawString(MARGIN, 3.5 * mm, _brand()["footer_fsp_text"])
    canvas.drawRightString(w - MARGIN, 3.5 * mm,
                           f"Page {doc.page}  |  {timestamp[:10]}")
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Section helpers
# ---------------------------------------------------------------------------

def _section_header_banner(title: str, S: dict) -> Table:
    """Return just the navy banner Table for a section header."""
    tbl = Table([[Paragraph(f"  {title}", S["section_hdr"])]], colWidths=[INNER_W])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
    ]))
    return tbl


def section_header(title: str, S: dict) -> list:
    tbl = _section_header_banner(title, S)
    tbl.keepWithNext = True
    trailing = Spacer(1, 3 * mm)
    trailing.keepWithNext = True
    return [Spacer(1, 4 * mm), tbl, trailing]


def section_with_first_card(title: str, S: dict, card_flowables: list) -> list:
    """Combine a section header with the first card's KeepTogether to prevent
    orphaned headers. The section banner is placed inside the KeepTogether so
    ReportLab treats header + card as one atomic block.

    card_flowables: the list returned by a cat_* function (first element is
    typically a KeepTogether).
    """
    if not card_flowables:
        return section_header(title, S)

    banner = _section_header_banner(title, S)

    # If the first flowable is a KeepTogether, inject the banner inside it
    if isinstance(card_flowables[0], KeepTogether):
        kt = card_flowables[0]
        # Prepend banner + spacer into the KeepTogether's internal flowables
        inner = [Spacer(1, 4 * mm), banner, Spacer(1, 3 * mm)] + list(kt._content)
        card_flowables[0] = KeepTogether(inner)
    else:
        # Fallback: wrap banner + enough flowables to prevent orphan.
        # Pull items until we hit the first KeepTogether (which is the actual card)
        # or up to 5 items, whichever comes first.
        first_items = [Spacer(1, 4 * mm), banner, Spacer(1, 3 * mm)]
        to_keep = 0
        for j, fl in enumerate(card_flowables):
            to_keep = j + 1
            first_items.append(fl)
            if isinstance(fl, KeepTogether) or to_keep >= 5:
                break
        card_flowables = [KeepTogether(first_items)] + card_flowables[to_keep:]

    return card_flowables


def badge_text(text: str, bg, fg=C_WHITE) -> Table:
    """Inline coloured badge."""
    t = Table([[Paragraph(f"<b>{text}</b>", ParagraphStyle("b", fontSize=7,
               textColor=fg, leading=9))]], colWidths=[None])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), bg),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("ROUNDEDCORNERS", (0, 0), (-1, -1), [3, 3, 3, 3]),
    ]))
    return t


def _risk_colour_value(val: str) -> str:
    """Wrap risk keywords in value text with appropriate colour tags."""
    v = str(val)
    vl = v.lower()
    # Full-value matches (the entire cell is a risk indicator)
    if vl in ("critical risk", "critical", "yes — critical", "no — critical",
              "critical exposure", "rdp exposed", "exposed"):
        return f"<font color='#991b1b'><b>{v}</b></font>"
    if vl in ("high risk", "high"):
        return f"<font color='#dc2626'><b>{v}</b></font>"
    if vl in ("medium risk", "medium"):
        return f"<font color='#92400e'><b>{v}</b></font>"
    if vl in ("low risk", "low", "low exposure"):
        return f"<font color='#166534'><b>{v}</b></font>"
    # Keyword matches within text
    if "CRITICAL" in v or "EXPOSED" in v:
        v = v.replace("CRITICAL", "<font color='#991b1b'><b>CRITICAL</b></font>")
        v = v.replace("EXPOSED", "<font color='#991b1b'><b>EXPOSED</b></font>")
        return v
    if "CISA KEV" in v:
        v = v.replace("CISA KEV", "<font color='#991b1b'><b>CISA KEV</b></font>")
        return v
    if "HIGH RISK" in v or "HIGH" in v.upper().split("—")[0]:
        v = v.replace("HIGH RISK", "<font color='#dc2626'><b>HIGH RISK</b></font>")
        v = v.replace("HIGH", "<font color='#dc2626'><b>HIGH</b></font>")
        return v
    if "MISSING" in v or "Missing" in v:
        return f"<font color='#dc2626'>{v}</font>"
    if "DANGEROUS" in v:
        return f"<font color='#991b1b'><b>{v}</b></font>"
    if "Weak" in v or "RISK" in v:
        return f"<font color='#d97706'>{v}</font>"
    if "No —" in v or "Not detected" in v or "Not found" in v or "Not configured" in v:
        return f"<font color='#d97706'>{v}</font>"
    # Positive indicators
    if vl in ("present", "yes", "ok", "detected", "strong", "disabled"):
        return f"<font color='#16a34a'>{v}</font>"
    if v.startswith("Present") or v.startswith("Yes") or v.startswith("Supported"):
        return f"<font color='#16a34a'>{v}</font>"
    return v


def kv_row(key, value, S, alt=False):
    bg = C_GREY_1 if alt else C_WHITE
    val_str = str(value) if value is not None else "—"
    coloured_val = _risk_colour_value(val_str)
    row = [Paragraph(key, S["kv_key"]), Paragraph(coloured_val, S["kv_val"])]
    return row, bg


def _colour_issue(text: str) -> str:
    """Apply colour to an issue line based on severity keywords."""
    t = str(text)
    if t.startswith("CRITICAL:") or "CRITICAL" in t.upper()[:20]:
        return f"<font color='#991b1b'><b>{t}</b></font>"
    if "High-risk" in t or "high-risk" in t:
        return f"<font color='#dc2626'>{t}</font>"
    if "Medium-risk" in t or "medium-risk" in t:
        return f"<font color='#92400e'>{t}</font>"
    return t


def issues_cell(issues: list, S, fallback: str = "") -> Paragraph:
    if not issues:
        msg = fallback or "No issues detected"
        colour = "#6b7280" if fallback else "#16a34a"  # grey for context, green for clean
        return Paragraph(f"<font color='{colour}'>{msg}</font>", S["body"])
    lines = "<br/>".join(f"\u2022 {_colour_issue(i)}" for i in issues[:6])
    if len(issues) > 6:
        lines += f"<br/>\u2022 \u2026and {len(issues) - 6} more"
    return Paragraph(lines, S["issue"])


# ---------------------------------------------------------------------------
# Category card builders
# ---------------------------------------------------------------------------

def _cat_table(rows, bgs, col_widths, S):
    tbl = Table(rows, colWidths=col_widths)
    style = [
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 0.25, C_GREY_2),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]
    for i, bg in enumerate(bgs):
        style.append(("BACKGROUND", (0, i), (-1, i), bg))
        # Make separator rows very thin
        if bg == C_GREY_2:
            style.append(("TOPPADDING", (0, i), (-1, i), 0))
            style.append(("BOTTOMPADDING", (0, i), (-1, i), 0))
            style.append(("FONTSIZE", (0, i), (-1, i), 2))
    tbl.setStyle(TableStyle(style))
    return tbl


def build_cat_card(title: str, tl_col, summary: str, data_rows: list, issues: list, S, fallback: str = "") -> list:
    """
    data_rows: list of (key, value) tuples
    fallback: context-aware message shown when issues list is empty
    Returns a list of flowables for one category card.
    """
    # Title bar
    title_tbl = Table([
        [make_traffic_circle(tl_col, 10), Paragraph(f"<b>{title}</b>", S["cat_title"]),
         Paragraph(f"<i>{summary}</i>", S["body_muted"])]
    ], colWidths=[18, 80 * mm, INNER_W - 18 - 80 * mm])
    title_tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND",    (0, 0), (-1, -1), C_GREY_1),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (0, 0), 4),
        ("LEFTPADDING",   (1, 0), (-1, -1), 6),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.5, C_GREY_2),
        ("BOX",           (0, 0), (-1, -1), 0.25, C_GREY_2),
    ]))

    # Risk-level background colours for group headers
    _RISK_BG = {
        "critical": C_CRITICAL_BG, "high": C_RED_BG,
        "medium": C_AMBER_BG, "low": C_GREEN_BG, "info": C_BLUE_LIGHT,
    }
    _RISK_FG = {
        "critical": "#991b1b", "high": "#dc2626",
        "medium": "#92400e", "low": "#166534", "info": "#1e40af",
    }

    # Data + issues side-by-side
    rows, bgs = [], []
    alt_idx = 0
    for k, v in data_rows:
        if k == "———":
            # Separator row — thin coloured line
            r = [Paragraph("", S["kv_key"]), Paragraph("", S["kv_val"])]
            rows.append(r); bgs.append(C_GREY_2)
        elif str(k).startswith("\u25b6"):
            # Port/service group header — colour-coded by risk level
            # Format: "▶critical:Port 21/FTP" or just "▶ Port 21/FTP"
            key_text = str(k)
            risk_level = "info"
            if ":" in key_text[1:]:
                parts = key_text[1:].split(":", 1)
                risk_level = parts[0].strip().lower()
                key_text = "\u25b6 " + parts[1].strip()
            bg = _RISK_BG.get(risk_level, C_BLUE_LIGHT)
            fg = _RISK_FG.get(risk_level, "#1e40af")
            r = [Paragraph(f"<b><font color='{fg}'>{key_text}</font></b>", S["kv_key"]),
                 Paragraph(f"<b><font color='{fg}'>{v}</font></b>", S["kv_val"])]
            rows.append(r); bgs.append(bg)
            alt_idx = 0
        else:
            r, bg = kv_row(k, v, S, alt=alt_idx % 2 == 0)
            rows.append(r); bgs.append(bg)
            alt_idx += 1

    data_tbl = _cat_table(rows, bgs, [40 * mm, INNER_W - 40 * mm], S) if rows else None

    issues_para = issues_cell(issues, S, fallback=fallback)
    issues_block = Table([[issues_para]], colWidths=[INNER_W])
    issues_block.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("BACKGROUND",    (0, 0), (-1, -1), C_WHITE),
        ("GRID",          (0, 0), (-1, -1), 0.25, C_GREY_2),
    ]))

    parts = [Spacer(1, 1 * mm), title_tbl]
    if data_tbl:
        parts.append(data_tbl)
    parts.append(issues_block)
    parts.append(Spacer(1, 3 * mm))
    return [KeepTogether(parts)]


def not_assessed_card(title: str, reason: str, S: dict) -> list:
    """Muted card for a check that did NOT run on this scan. Rendering the
    absence explicitly lets an underwriter distinguish "assessed — no
    findings" from "not assessed"; a silently omitted card otherwise reads
    as a clean pass (card back-test gap)."""
    return build_cat_card(title, C_GREY_4, "Not assessed", [], [], S,
                          fallback=reason)


def _tl(condition_green, condition_amber):
    if condition_green:   return C_GREEN
    if condition_amber:   return C_AMBER
    return C_RED


def _load_assessment_brand() -> dict:
    """Load brand config from brand_assets/brand.json with safe Phishield fallbacks.
    Image paths in the result are absolute and only present if the file exists
    on disk; slide renderers should treat them as optional."""
    import json as _json
    from pathlib import Path as _Path
    base = _Path(__file__).parent / "brand_assets"
    cfg_path = base / "brand.json"
    fallback = {
        "company_name": "Phishield",
        "legal_entity": "Phishield UMA (Pty) Ltd",
        "regulatory_text": "Authorised Financial Services Provider FSP 46418",
        "broker_label": "Phishield broker",
        # Identity strings for the summary/full report tiers and invoices.
        # Defaults mirror the brand.json values exactly so rendering is
        # unchanged when the JSON is missing or unreadable.
        "website": "www.phishield.com",
        "report_header_text": "PHISHIELD Cyber Protect  |  Risk Assessment Report",
        "footer_fsp_text": "PHISHIELD UMA (Pty) Ltd | Authorised Financial Services Provider | FSP 46418",
        "doc_author": "PHISHIELD / Bryte Insurance",
        "contact_text": "To discuss cyber insurance options or arrange a remediation "
                        "assessment, contact the Phishield broker or visit www.phishield.com",
        "disclaimer_fsp_sentence": "Phishield UMA (Pty) Ltd is an Authorised Financial "
                                   "Services Provider (FSP 46418).",
        "invoice_brand_name": "PHISHIELD",
        "invoice_tagline": "Cyber Insurance Brokers — Powered by Bryte Insurance",
        "invoice_footer_text": "Phishield (Pty) Ltd | Authorised Financial Services Provider | "
                               "Underwritten by Bryte Insurance Company Limited (FSP 17703)",
        "logo_file": "logo.png",
        "cover_hero_file": "cover_hero.jpg",
        "findings_hero_file": "findings_hero.jpg",
    }
    cfg = dict(fallback)
    try:
        if cfg_path.exists():
            data = _json.loads(cfg_path.read_text(encoding="utf-8"))
            for k in fallback:
                if data.get(k):
                    cfg[k] = data[k]
    except Exception:
        pass

    def _resolve(filename):
        p = base / filename
        return str(p) if p.exists() else None

    cfg["logo_path"]          = _resolve(cfg["logo_file"])
    cfg["cover_hero_path"]    = _resolve(cfg["cover_hero_file"])
    cfg["findings_hero_path"] = _resolve(cfg["findings_hero_file"])
    return cfg


# Cached brand config shared by every tier (summary/full builders, the
# header/footer painter — which can't take extra args — and invoices).
_BRAND_CACHE = None


def _brand() -> dict:
    global _BRAND_CACHE
    if _BRAND_CACHE is None:
        _BRAND_CACHE = _load_assessment_brand()
    return _BRAND_CACHE
