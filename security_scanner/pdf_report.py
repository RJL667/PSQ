"""
PHISHIELD Cyber Risk Assessment — PDF Report Generator
Produces a professional, print-ready A4 PDF using ReportLab.
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.graphics.shapes import Drawing, Rect, Circle, Line, String
from reportlab.graphics import renderPDF

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
    S["cat_title"]   = ParagraphStyle("cat_title",   fontSize=9,  fontName="Helvetica-Bold",
                                       textColor=C_NAVY, leading=12)
    S["body"]        = ParagraphStyle("body",         fontSize=8,  leading=11, textColor=C_BLACK)
    S["body_muted"]  = ParagraphStyle("body_muted",   fontSize=7,  leading=10, textColor=C_GREY_4)
    S["issue"]       = ParagraphStyle("issue",        fontSize=7.5, leading=10, textColor=C_RED,
                                       leftIndent=8)
    S["rec_num"]     = ParagraphStyle("rec_num",      fontSize=8,  fontName="Helvetica-Bold",
                                       textColor=C_BLUE, leading=11)
    S["rec_body"]    = ParagraphStyle("rec_body",     fontSize=8,  leading=11, textColor=C_BLACK,
                                       leftIndent=12)
    S["footer"]      = ParagraphStyle("footer",       fontSize=6.5, textColor=C_GREY_3,
                                       alignment=TA_CENTER)
    S["disclaimer"]  = ParagraphStyle("disclaimer",   fontSize=7,  leading=10, textColor=C_GREY_4)
    S["kv_key"]      = ParagraphStyle("kv_key",       fontSize=7.5, textColor=C_GREY_4, leading=10)
    S["kv_val"]      = ParagraphStyle("kv_val",       fontSize=7.5, textColor=C_BLACK,  leading=10)
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
    canvas.drawString(MARGIN, h - 7 * mm, "PHISHIELD  |  Cyber Risk Assessment Report")
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(w - MARGIN, h - 7 * mm, domain)

    # Bottom bar
    canvas.setFillColor(C_GREY_2)
    canvas.rect(0, 0, w, 9 * mm, fill=True, stroke=False)
    canvas.setFillColor(C_GREY_4)
    canvas.setFont("Helvetica", 6.5)
    canvas.drawString(MARGIN, 3.5 * mm,
                      "Passive external assessment only. For insurance underwriting use. "
                      "Bryte Insurance Company Limited (FSP 17703).")
    canvas.drawRightString(w - MARGIN, 3.5 * mm,
                           f"Page {doc.page}  |  {timestamp[:10]}")
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Section helpers
# ---------------------------------------------------------------------------

def section_header(title: str, S: dict) -> list:
    tbl = Table([[Paragraph(f"  {title}", S["section_hdr"])]], colWidths=[INNER_W])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
    ]))
    return [Spacer(1, 4 * mm), tbl, Spacer(1, 2 * mm)]


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


def kv_row(key, value, S, alt=False):
    bg = C_GREY_1 if alt else C_WHITE
    row = [Paragraph(key, S["kv_key"]), Paragraph(str(value) if value is not None else "—", S["kv_val"])]
    return row, bg


def issues_cell(issues: list, S) -> Paragraph:
    if not issues:
        return Paragraph("<font color='#16a34a'>No issues detected</font>", S["body"])
    lines = "<br/>".join(f"• {i}" for i in issues[:6])
    if len(issues) > 6:
        lines += f"<br/>• …and {len(issues) - 6} more"
    return Paragraph(lines, S["issue"])


# ---------------------------------------------------------------------------
# Category card builders
# ---------------------------------------------------------------------------

def _cat_table(rows, bgs, col_widths, S):
    tbl = Table(rows, colWidths=col_widths)
    style = [
        ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 0.25, C_GREY_2),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]
    for i, bg in enumerate(bgs):
        style.append(("BACKGROUND", (0, i), (-1, i), bg))
    tbl.setStyle(TableStyle(style))
    return tbl


def build_cat_card(title: str, tl_col, summary: str, data_rows: list, issues: list, S) -> list:
    """
    data_rows: list of (key, value) tuples
    Returns a list of flowables for one category card.
    """
    # Title bar
    title_tbl = Table([
        [make_traffic_circle(tl_col, 10), Paragraph(f"<b>{title}</b>", S["cat_title"]),
         Paragraph(f"<i>{summary}</i>", S["body_muted"])]
    ], colWidths=[14, 80 * mm, INNER_W - 14 - 80 * mm])
    title_tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND",    (0, 0), (-1, -1), C_GREY_1),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 0.25, C_GREY_2),
    ]))

    # Data + issues side-by-side
    rows, bgs = [], []
    for i, (k, v) in enumerate(data_rows):
        r, bg = kv_row(k, v, S, alt=i % 2 == 0)
        rows.append(r); bgs.append(bg)

    data_tbl = _cat_table(rows, bgs, [40 * mm, 80 * mm], S) if rows else None

    issues_para = issues_cell(issues, S)
    issues_block = Table([[issues_para]], colWidths=[INNER_W])
    issues_block.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("BACKGROUND",    (0, 0), (-1, -1), C_WHITE),
        ("GRID",          (0, 0), (-1, -1), 0.25, C_GREY_2),
    ]))

    parts = [title_tbl]
    if data_tbl:
        parts.append(data_tbl)
    parts.append(issues_block)
    parts.append(Spacer(1, 3 * mm))
    return [KeepTogether(parts)]


# ---------------------------------------------------------------------------
# Per-category data extractors
# ---------------------------------------------------------------------------

def _tl(condition_green, condition_amber):
    if condition_green:   return C_GREEN
    if condition_amber:   return C_AMBER
    return C_RED


def cat_ssl(d, S):
    ssl = d.get("ssl", {})
    cert = ssl.get("certificate", {})
    tls  = ssl.get("tls_versions", {})
    cip  = ssl.get("cipher_suite", {})
    grade = ssl.get("grade", "?")
    col = _tl(grade in ("A+", "A", "B"), grade == "C")
    rows = [
        ("Grade",         grade),
        ("Subject",       cert.get("subject", "—")),
        ("Issuer",        cert.get("issuer", "—")),
        ("Expiry",        cert.get("expiry_date", "—")),
        ("Days left",     cert.get("days_until_expiry", "—")),
        ("TLS 1.0/1.1",   ("Enabled — RISK" if tls.get("TLS 1.0") or tls.get("TLS 1.1") else "Disabled")),
        ("TLS 1.2/1.3",   ("Supported" if tls.get("TLS 1.2") or tls.get("TLS 1.3") else "Not detected")),
        ("Cipher",        f"{cip.get('name','—')} ({'Weak' if cip.get('is_weak') else 'Strong'})"),
        ("HSTS",          "Present" if ssl.get("hsts") else "Missing"),
    ]
    return build_cat_card("SSL / TLS", col, f"Grade: {grade}", rows, ssl.get("issues", []), S)


def cat_email(d, S):
    em  = d.get("email_security", {})
    spf = em.get("spf", {})
    dm  = em.get("dmarc", {})
    dkim= em.get("dkim", {})
    mx  = em.get("mx", {})
    score = em.get("score", 0)
    col = _tl(score >= 8, score >= 5)
    rows = [
        ("SPF",    ("Present" + (" — DANGEROUS +all" if spf.get("dangerous") else "") if spf.get("present") else "Missing")),
        ("DMARC",  f"Present — policy: {dm.get('policy','—')}" if dm.get("present") else "Missing"),
        ("DKIM",   ("Found: " + ", ".join(dkim.get("selectors_found", []))) if dkim.get("selectors_found") else "Not found"),
        ("MX",     f"{len(mx.get('records', []))} record(s)"),
        ("Score",  f"{score}/10"),
    ]
    return build_cat_card("Email Authentication (SPF/DKIM/DMARC)", col, f"Score {score}/10", rows, em.get("issues", []), S)


def cat_email_hardening(d, S):
    eh   = d.get("email_hardening", {})
    mts  = eh.get("mta_sts", {})
    bimi = eh.get("bimi", {})
    dane = eh.get("dane", {})
    score= eh.get("score", 0)
    col  = _tl(score >= 7, score >= 3)
    rows = [
        ("MTA-STS", f"Present — mode: {mts.get('mode','?')}" if mts.get("present") else "Not configured"),
        ("BIMI",    "Present" + (" + VMC" if bimi.get("has_vmc") else "") if bimi.get("present") else "Not configured"),
        ("DANE/TLSA", "Present" if dane.get("present") else "Not configured"),
        ("Score",   f"{score}/10"),
    ]
    return build_cat_card("Advanced Email Hardening (MTA-STS/DANE/BIMI)", col, f"Score {score}/10", rows, eh.get("issues", []), S)


def cat_headers(d, S):
    hh    = d.get("http_headers", {})
    score = hh.get("score", 0)
    col   = _tl(score >= 80, score >= 50)
    rows  = [(name, "Present" if data.get("present") else "MISSING")
             for name, data in hh.get("headers", {}).items()]
    return build_cat_card("HTTP Security Headers", col, f"{score}% coverage", rows, hh.get("issues", []), S)


def cat_waf(d, S):
    waf = d.get("waf", {})
    col = C_GREEN if waf.get("detected") else C_AMBER
    rows = [
        ("WAF detected",  waf.get("waf_name", "None detected") if waf.get("detected") else "Not detected"),
        ("All detected",  ", ".join(waf.get("all_detected", [])) or "—"),
    ]
    return build_cat_card("WAF / DDoS Protection", col, "Detected" if waf.get("detected") else "Not detected", rows, waf.get("issues", []), S)


def cat_dns(d, S):
    dns  = d.get("dns_infrastructure", {})
    ports= dns.get("open_ports", [])
    high = [p for p in ports if p["risk"] == "high"]
    col  = _tl(len(high) == 0 and len(ports) <= 2, len(high) == 0)
    port_str = ", ".join(f"{p['port']}/{p['service']}" for p in ports) or "None"
    rows = [
        ("Open ports",    port_str),
        ("High-risk ports", ", ".join(f"{p['port']}/{p['service']}" for p in high) or "None"),
        ("Server header", dns.get("server_info", {}).get("Server", "—")),
        ("X-Powered-By",  dns.get("server_info", {}).get("X-Powered-By", "—")),
        ("Reverse DNS",   dns.get("reverse_dns") or "—"),
    ]
    # Add exploit intelligence per risky port
    risky = [p for p in ports if p.get("risk") in ("high", "medium")]
    for p in risky:
        rows.append(("", ""))  # spacer row
        sev = p.get("typical_severity", "").upper() or p.get("risk", "").upper()
        rows.append((f"Port {p['port']}/{p['service']}", f"{sev} RISK"))
        if p.get("exploits"):
            rows.append(("  Typical exploits", p["exploits"][:120]))
        cvss = p.get("typical_cvss")
        epss = p.get("typical_epss")
        if cvss or epss:
            detail = []
            if cvss: detail.append(f"CVSS {cvss}")
            if epss: detail.append(f"EPSS {int(epss*100)}%")
            if p.get("in_kev"): detail.append("CISA KEV")
            rows.append(("  Vuln metrics", " | ".join(detail)))
        if p.get("typical_cves"):
            rows.append(("  Notable CVEs", ", ".join(p["typical_cves"][:3])))
        if p.get("insurance_risk"):
            rows.append(("  Insurance risk", p["insurance_risk"][:120]))
    return build_cat_card("DNS & Open Ports", col, f"{len(ports)} open port(s)", rows, dns.get("issues", []), S)


def cat_hrp(d, S):
    hrp  = d.get("high_risk_protocols", {})
    svcs = hrp.get("exposed_services", [])
    col  = C_CRITICAL if svcs else C_GREEN
    rows = []
    if not svcs:
        rows.append(("Status", "No critical services exposed"))
    for s in svcs:
        rows.append((s["service"], f"Port {s['port']} — EXPOSED"))
        if s.get("exploits"):
            rows.append(("  Known exploits", s["exploits"][:120]))
        cvss = s.get("typical_cvss")
        epss = s.get("typical_epss")
        if cvss or epss:
            detail = []
            if cvss: detail.append(f"CVSS {cvss}")
            if epss: detail.append(f"EPSS {int(epss*100)}%")
            if s.get("in_kev"): detail.append("CISA KEV")
            rows.append(("  Vuln metrics", " | ".join(detail)))
        if s.get("typical_cves"):
            rows.append(("  Notable CVEs", ", ".join(s["typical_cves"][:3])))
        if s.get("insurance_risk"):
            rows.append(("  Insurance risk", s["insurance_risk"][:120]))
        if s.get("underwriting_impact"):
            rows.append(("  Underwriting impact", s["underwriting_impact"][:120]))
    return build_cat_card("Database & Service Exposure", col,
                          f"{len(svcs)} critical exposure(s)", rows, hrp.get("issues", []), S)


def cat_cloud(d, S):
    cdn = d.get("cloud_cdn", {})
    rows = [
        ("Provider",     cdn.get("provider") or "Not detected"),
        ("CDN detected", "Yes" if cdn.get("cdn_detected") else "No"),
        ("Hosting type", cdn.get("hosting_type", "Unknown")),
        ("IP addresses", ", ".join(cdn.get("ip_addresses", [])) or "—"),
    ]
    return build_cat_card("Cloud & CDN Infrastructure", C_BLUE, cdn.get("provider") or "Unknown", rows, cdn.get("issues", []), S)


def cat_vpn(d, S):
    vpn = d.get("vpn_remote", {})
    col = C_CRITICAL if vpn.get("rdp_exposed") else (C_GREEN if vpn.get("vpn_detected") else C_AMBER)
    rows = [
        ("RDP exposed",  "YES — CRITICAL" if vpn.get("rdp_exposed") else "No"),
        ("VPN detected", vpn.get("vpn_name") or ("Detected" if vpn.get("vpn_detected") else "Not detected")),
    ]
    return build_cat_card("VPN & Remote Access", col,
                          "RDP EXPOSED" if vpn.get("rdp_exposed") else (vpn.get("vpn_name") or "None detected"),
                          rows, vpn.get("issues", []), S)


def cat_breaches(d, S):
    br    = d.get("breaches", {})
    count = br.get("breach_count", 0)
    col   = _tl(count == 0, count <= 3)
    rows  = [
        ("Total breaches",   count),
        ("Most recent",      br.get("most_recent_breach") or "N/A"),
        ("Data types exposed", ", ".join(br.get("data_classes", [])[:5]) or "—"),
    ]
    if br.get("breaches"):
        for b in br["breaches"][:4]:
            rows.append((b.get("name", "—"), f"{b.get('date','?')} — {b.get('pwn_count', 0):,} accounts"))
    return build_cat_card("Credential Exposure (HIBP)", col, f"{count} breach(es)", rows, br.get("issues", []), S)


def cat_dnsbl(d, S):
    bl  = d.get("dnsbl", {})
    all_listed = bl.get("ip_listings", []) + bl.get("domain_listings", [])
    col = C_CRITICAL if all_listed else C_GREEN
    rows = [
        ("IP blacklists",     ", ".join(bl.get("ip_listings", [])) or "Clean"),
        ("Domain blacklists", ", ".join(bl.get("domain_listings", [])) or "Clean"),
        ("Status",            "BLACKLISTED" if all_listed else "Not listed"),
    ]
    return build_cat_card("IP / Domain Reputation (DNSBL)", col,
                          "Blacklisted" if all_listed else "Clean", rows, bl.get("issues", []), S)


def cat_admin(d, S):
    adm   = d.get("exposed_admin", {})
    exposed = adm.get("exposed", [])
    col   = C_CRITICAL if adm.get("critical_count", 0) > 0 else (C_RED if adm.get("high_count", 0) > 0 else C_GREEN)
    rows  = [(e["path"], f"HTTP {e['status']} — {e['risk'].upper()}") for e in exposed[:8]] or [("Status", "No sensitive paths exposed")]
    return build_cat_card("Exposed Admin Panels & Sensitive Paths", col,
                          f"{len(exposed)} path(s) found", rows, adm.get("issues", []), S)


def cat_subdomains(d, S):
    subs  = d.get("subdomains", {})
    risky = subs.get("risky_subdomains", [])
    col   = C_AMBER if risky else C_GREEN
    rows  = [
        ("Total subdomains", subs.get("total_count", 0)),
        ("Risky subdomains", len(risky)),
        ("Risky names",      ", ".join(risky[:6]) or "None"),
    ]
    return build_cat_card("Subdomain Exposure (CT Logs)", col,
                          f"{subs.get('total_count',0)} found, {len(risky)} risky",
                          rows, subs.get("issues", []), S)


def cat_tech(d, S):
    ts   = d.get("tech_stack", {})
    eols = ts.get("eol_detected", [])
    col  = C_CRITICAL if eols else C_GREEN
    rows = [("CMS", f"{ts.get('cms',{}).get('detected','None')} {ts.get('cms',{}).get('version','') or ''}")] + \
           [(e["software"], e["note"]) for e in eols[:5]] + \
           [("Server software", sw) for sw in ts.get("server_software", [])[:3]]
    return build_cat_card("Technology Stack & EOL Software", col,
                          f"{len(eols)} EOL component(s)", rows, ts.get("issues", []), S)


def cat_domain(d, S):
    di  = d.get("domain_intel", {})
    col = C_AMBER if di.get("issues") else C_GREEN
    age = di.get("domain_age_days")
    rows = [
        ("Registrar",      di.get("registrar") or "Unknown"),
        ("Created",        di.get("creation_date") or "Unknown"),
        ("Expires",        di.get("expiry_date") or "Unknown"),
        ("Age",            f"{age} days ({round(age/365,1)} years)" if age else "Unknown"),
        ("WHOIS privacy",  "Protected" if di.get("privacy_protected") else "Public"),
    ]
    return build_cat_card("Domain Intelligence (WHOIS)", col,
                          f"Age: {round(age/365,1)}y" if age else "Unknown",
                          rows, di.get("issues", []), S)


def cat_security_policy(d, S):
    sp  = d.get("security_policy", {})
    stxt= sp.get("security_txt", {})
    col = C_GREEN if stxt.get("present") else C_AMBER
    rows = [
        ("security.txt",   f"Found at {stxt.get('path','')}" if stxt.get("present") else "Not found"),
        ("PGP key",        "Yes" if stxt.get("has_pgp") else "No"),
        ("robots.txt",     f"Present — {sp.get('robots_txt',{}).get('disallows_count',0)} disallow rules"
                           if sp.get("robots_txt", {}).get("present") else "Not found"),
    ]
    return build_cat_card("Security Policy & Vulnerability Disclosure", col,
                          "VDP present" if stxt.get("present") else "No VDP", rows, sp.get("issues", []), S)


def cat_payment(d, S):
    pay = d.get("payment_security", {})
    col = C_CRITICAL if pay.get("self_hosted_payment_form") else (C_AMBER if pay.get("has_payment_page") and not pay.get("payment_page_https") else C_GREEN)
    rows = [
        ("Payment page",         "Detected" if pay.get("has_payment_page") else "Not found"),
        ("Payment provider",     pay.get("payment_provider") or ("Self-hosted — PCI RISK" if pay.get("self_hosted_payment_form") else "Unknown")),
        ("Page HTTPS",           "Yes" if pay.get("payment_page_https") else ("N/A" if not pay.get("has_payment_page") else "NO — CRITICAL")),
        ("Self-hosted card form", "YES — PCI risk" if pay.get("self_hosted_payment_form") else "No"),
    ]
    return build_cat_card("Payment Security (PCI)", col,
                          pay.get("payment_provider") or ("PCI Risk" if pay.get("self_hosted_payment_form") else "N/A"),
                          rows, pay.get("issues", []), S)


def cat_shodan(d, S):
    sv    = d.get("shodan_vulns", {})
    crit  = sv.get("critical_count", 0)
    high  = sv.get("high_count", 0)
    med   = sv.get("medium_count", 0)
    low   = sv.get("low_count", 0)
    total = crit + high + med + low
    col   = C_CRITICAL if crit > 0 else (C_RED if high > 0 else (C_AMBER if med > 0 else C_GREEN))
    summary = f"{total} CVE(s)" if total > 0 else "Clean"

    # Summary rows
    rows = [
        ("IP scanned",   sv.get("ip") or "—"),
        ("Total CVEs",   total),
        ("Breakdown",    f"Critical: {crit}  |  High: {high}  |  Medium: {med}  |  Low: {low}"),
        ("Open ports",   ", ".join(str(p) for p in sv.get("open_ports", [])) or "—"),
    ]
    if sv.get("tags"):
        rows.append(("Tags", ", ".join(sv["tags"])))

    # EPSS / KEV aggregate stats
    kev_count = sv.get("kev_count", 0)
    max_epss = sv.get("max_epss", 0)
    high_epss = sv.get("high_epss_count", 0)
    if kev_count > 0:
        rows.append(("CISA KEV", f"{kev_count} CVE(s) confirmed actively exploited"))
    if max_epss > 0:
        rows.append(("Max EPSS", f"{max_epss * 100:.1f}% probability of exploitation (30-day)"))
    if high_epss > 0:
        rows.append(("High EPSS (≥10%)", f"{high_epss} CVE(s) with significant exploitation probability"))

    # Detailed CVE rows with severity + CVSS + EPSS + KEV
    for cve in sv.get("cves", [])[:8]:
        sev = cve.get("severity", "unknown").upper()
        cvss = cve.get("cvss_score", 0)
        desc = cve.get("description", "")[:100]
        epss = cve.get("epss_score")
        kev = cve.get("kev_exploited", False)
        label = f"{sev}  |  CVSS {cvss}"
        if epss is not None:
            label += f"  |  EPSS {epss * 100:.1f}%"
        if kev:
            label += "  |  KEV: EXPLOITED"
        if desc:
            label += f"  —  {desc}"
        rows.append((cve.get("cve_id", ""), label))

    return build_cat_card("CVE / Known Vulnerabilities", col, summary, rows, sv.get("issues", []), S)


def cat_external_ips(d, S):
    ext = d.get("external_ips", {})
    agg = ext.get("aggregate_vulns", {})
    total_ips = ext.get("total_unique_ips", 0)
    crit = agg.get("critical_count", 0)
    high = agg.get("high_count", 0)
    kev = agg.get("kev_count", 0)
    col = C_CRITICAL if crit > 0 or kev > 0 else (C_RED if high > 0 else (C_AMBER if agg.get("total_cves", 0) > 0 else C_GREEN))
    summary = f"{total_ips} IPs found"

    rows = [
        ("Total unique IPs",  total_ips),
        ("IPv4 / IPv6",       f"{ext.get('ipv4_count', 0)} / {ext.get('ipv6_count', 0)}"),
        ("Unique ASNs",       ext.get("unique_asns", 0)),
        ("Unique countries",  ext.get("unique_countries", 0)),
    ]
    if agg.get("total_cves", 0) > 0:
        rows.append(("Total CVEs across IPs", agg["total_cves"]))
        rows.append(("Severity breakdown",    f"Critical: {crit}  |  High: {high}  |  Medium: {agg.get('medium_count', 0)}"))
        rows.append(("IPs with CVEs",         agg.get("ips_with_vulns", 0)))
    if agg.get("max_cvss", 0) > 0:
        rows.append(("Max CVSS",              agg["max_cvss"]))
    if agg.get("max_epss", 0) > 0:
        rows.append(("Max EPSS",              f"{agg['max_epss'] * 100:.1f}%"))
    if kev > 0:
        rows.append(("CISA KEV",              f"{kev} CVE(s) confirmed actively exploited"))

    # Per-IP details (top 10)
    for ip_entry in ext.get("ip_addresses", [])[:10]:
        ip = ip_entry.get("ip", "")
        org = ip_entry.get("org", "")
        country = ip_entry.get("country", "")
        vuln = ip_entry.get("shodan") or {}
        cve_count = vuln.get("cve_count", 0)
        risk_score = vuln.get("risk_score", 100)
        risk_label = vuln.get("risk_label", "Low")
        label_parts = [f"Score: {risk_score}/100 ({risk_label})"]
        if org:
            label_parts.append(org)
        if country:
            label_parts.append(country)
        if vuln.get("open_ports"):
            label_parts.append(f"Ports: {', '.join(str(p) for p in vuln['open_ports'][:6])}")
        if cve_count > 0:
            label_parts.append(f"{cve_count} CVE(s)")
        if vuln.get("max_cvss", 0) > 0:
            label_parts.append(f"CVSS {vuln['max_cvss']}")
        if vuln.get("kev_count", 0) > 0:
            label_parts.append("KEV: EXPLOITED")
        sources = ", ".join(ip_entry.get("sources", []))[:50]
        rows.append((f"{ip} ({sources})", "  |  ".join(label_parts)))
        # Add remediation row if there are issues
        remediation = vuln.get("remediation", "")
        if remediation and risk_score < 80:
            rows.append(("  → Remediation", remediation))

    return build_cat_card("External IP Discovery", col, summary, rows, ext.get("issues", []), S)


def cat_dehashed(d, S):
    dh     = d.get("dehashed", {})
    status = dh.get("status", "completed")
    total  = dh.get("total_entries", 0)
    col    = (C_CRITICAL if total > 50 else C_RED if total > 10 else
              C_AMBER if total > 0 else (C_BLUE if status == "no_api_key" else C_GREEN))
    summary = "No API key" if status == "no_api_key" else (f"{total} records" if total > 0 else "Clean")
    rows = [
        ("Status",        "API key not configured" if status == "no_api_key" else status),
        ("Total records", total),
        ("Unique emails", dh.get("unique_emails", 0)),
        ("Passwords in leaks", "Yes — CRITICAL" if dh.get("has_passwords") else "No"),
    ]
    if dh.get("sample_emails"):
        rows.append(("Sample emails", " | ".join(dh["sample_emails"][:3])))
    return build_cat_card("Dehashed Credential Leaks", col, summary, rows, dh.get("issues", []), S)


def cat_website(d, S):
    ws    = d.get("website_security", {})
    score = ws.get("score", 0)
    col   = _tl(score >= 80, score >= 50)
    ck    = ws.get("cookies", {})
    rows  = [
        ("HTTPS enforced", "Yes" if ws.get("https_enforced") else "No"),
        ("Mixed content",  "Detected" if ws.get("mixed_content") else "None"),
        ("CMS",            f"{ws.get('cms',{}).get('detected','None')} {ws.get('cms',{}).get('version','') or ''}"),
        ("Cookie Secure",  "OK" if ck.get("secure", True) else "Issues"),
        ("Cookie HttpOnly","OK" if ck.get("httponly", True) else "Issues"),
    ]
    return build_cat_card("Website Security", col, f"{score}%", rows, ws.get("issues", []), S)


def cat_web_ranking(d, S):
    wr = d.get("web_ranking", {})
    rank = wr.get("rank")
    # Support both HEAD and Sarel's data formats
    if wr.get("ranked") is not None:
        col = C_GREEN if wr.get("ranked") else C_AMBER
        rows = [
            ("Ranked",      "Yes" if wr.get("ranked") else "Not in top 1M"),
            ("Position",    f"#{rank:,}" if rank else "—"),
            ("Popularity",  wr.get("popularity", "Unranked")),
            ("Rank Band",   wr.get("rank_label", "Unranked")),
        ]
        return build_cat_card("Web Ranking (Tranco)", col, wr.get("rank_label", "Unranked"), rows, wr.get("issues", []), S)
    else:
        score = wr.get("score", 30)
        col = _tl(score >= 70, score >= 40)
        rows = [
            ("Tranco Rank", f"#{rank:,}" if rank else "Not in top 1M"),
            ("In List", "Yes" if wr.get("in_list") else "No"),
            ("Score", f"{score}/100"),
        ]
        return build_cat_card("Web Ranking (Tranco)", col,
                              f"#{rank:,}" if rank else "Unranked",
                              rows, wr.get("issues", []), S)


def cat_info_disclosure(d, S):
    info = d.get("info_disclosure", {})
    score = info.get("score", 100)
    col = _tl(score >= 90, score >= 60)
    exposed = info.get("exposed_paths", [])
    rows = [("Exposed Paths", str(len(exposed)))]
    for p in exposed[:5]:
        rows.append((p.get("path", ""), f"{p.get('risk_level','').upper()} — {p.get('description','')}"))
    if len(exposed) > 5:
        rows.append(("...", f"+{len(exposed)-5} more"))
    return build_cat_card("Information Disclosure", col, f"{score}%",
                          rows, info.get("issues", []), S)


def cat_fraudulent_domains(d, S):
    fd     = d.get("fraudulent_domains", {})
    found  = fd.get("fraudulent_domains_found", 0)
    col    = C_CRITICAL if found > 3 else (C_RED if found > 0 else C_GREEN)
    rows   = [
        ("Variants checked",  fd.get("variants_checked", 0)),
        ("Lookalikes found",  found),
    ]
    for dom in fd.get("domains", [])[:5]:
        rows.append((dom.get("type", "lookalike"), f"{dom.get('domain','')} ({dom.get('cert_issuer','')})"))
    return build_cat_card("Fraudulent Domains (Typosquat)", col, f"{found} found", rows, fd.get("issues", []), S)


def cat_rsi(results, S):
    """RSI (Ransomware Susceptibility Index) card for PDF — insurance analytics."""
    ins = results if "rsi" in results else results.get("insurance", {})
    rsi = ins.get("rsi", {})
    score = rsi.get("rsi_score", 0)
    col = C_CRITICAL if score >= 0.75 else (C_RED if score >= 0.50 else (C_AMBER if score >= 0.25 else C_GREEN))
    rows = [
        ("RSI Score", f"{score:.3f} / 1.000"),
        ("Risk Label", rsi.get("risk_label", "Unknown")),
        ("Base Score", f"{rsi.get('base_score', 0):.3f}"),
        ("Industry", f"{rsi.get('industry', 'other').capitalize()} (x{rsi.get('industry_multiplier', 1.0)})"),
        ("Size Multiplier", f"x{rsi.get('size_multiplier', 1.0)}"),
    ]
    for f in rsi.get("contributing_factors", [])[:8]:
        rows.append((f"  P{f['priority']}: {f['factor']}", f"+{f['impact']:.2f}"))
    return build_cat_card("Ransomware Susceptibility Index (RSI)", col,
                          f"{score:.2f} — {rsi.get('risk_label', '')}",
                          rows, [], S)


def cat_insurance_financial_impact(results, S):
    """Financial Impact Analysis card for PDF — insurance analytics."""
    ins = results if "financial_impact" in results else results.get("insurance", {})
    fin = ins.get("financial_impact", {})
    total = fin.get("total", {})
    likely = total.get("most_likely", 0)
    col = C_CRITICAL if likely > 500000 else (C_RED if likely > 200000 else (C_AMBER if likely > 50000 else C_GREEN))

    rows = []
    for name, key in [("Data Breach", "data_breach"), ("Ransomware", "ransomware"), ("Business Interruption", "business_interruption")]:
        sc = fin.get("scenarios", {}).get(key, {})
        rows.append((name, f"${sc.get('min',0):,.0f} / ${sc.get('most_likely',0):,.0f} / ${sc.get('max',0):,.0f}"))
    rows.append(("TOTAL", f"${total.get('min',0):,.0f} / ${total.get('most_likely',0):,.0f} / ${total.get('max',0):,.0f}"))

    rec = fin.get("insurance_recommendations", {})
    rows.append(("", ""))
    rows.append(("Suggested Deductible", f"${rec.get('suggested_deductible',0):,.0f}"))
    rows.append(("Expected Annual Loss", f"${rec.get('expected_annual_loss',0):,.0f}"))
    rows.append(("Recommended Coverage", f"${rec.get('recommended_coverage',0):,.0f}"))

    return build_cat_card("Financial Impact Analysis (FAIR)", col,
                          f"${likely:,.0f} est. annual loss",
                          rows, [], S)


def cat_dbi(results, S):
    """Data Breach Index card for PDF — insurance analytics."""
    ins = results if "dbi" in results else results.get("insurance", {})
    dbi = ins.get("dbi", {})
    score = dbi.get("dbi_score", 50)
    col = _tl(score >= 80, score >= 40)
    rows = [("DBI Score", f"{score}/{dbi.get('max_score', 100)} — {dbi.get('label', '')}")]
    for key, comp in dbi.get("components", {}).items():
        rows.append((key.replace("_", " ").capitalize(), f"{comp.get('value', '')} ({comp.get('points', 0)}/{comp.get('max', 0)} pts)"))
    return build_cat_card("Data Breach Index (DBI)", col,
                          f"{score}/100 — {dbi.get('label', '')}",
                          rows, [], S)


def cat_remediation(results, S):
    """Remediation Roadmap card for PDF — insurance analytics."""
    ins = results if "remediation" in results else results.get("insurance", {})
    rem = ins.get("remediation", {})
    steps = rem.get("steps", [])
    if not steps:
        return []
    savings = rem.get("total_potential_savings", 0)
    col = C_BLUE

    rows = [
        ("Current RSI", f"{rem.get('current_rsi', 0):.3f}"),
        ("Projected RSI (after fixes)", f"{rem.get('simulated_rsi', 0):.3f}"),
        ("Total Potential Savings", f"${savings:,.0f}/year"),
        ("", ""),
    ]
    for i, step in enumerate(steps[:10], 1):
        rows.append((f"#{i} (P{step['priority']})", f"{step['action']} — saves ${step['annual_savings_estimate']:,.0f}/yr"))
    return build_cat_card("Remediation Roadmap — Before/After", col,
                          f"{len(steps)} steps — ${savings:,.0f} savings",
                          rows, [], S)


def cat_ransomware_risk(d, S):
    rsi   = d.get("ransomware_risk", {})
    score = rsi.get("rsi_score", 0)
    label = rsi.get("rsi_label", "N/A")
    col   = (C_CRITICAL if score >= 0.8 else C_RED if score >= 0.5 else
             C_AMBER if score >= 0.25 else C_GREEN)
    rows  = [
        ("RSI Score",       f"{score} / 1.0"),
        ("Risk Level",      label),
        ("Industry",        rsi.get("industry", "Other")),
    ]
    if rsi.get("annual_revenue_zar"):
        rows.append(("Annual Revenue", f"R {rsi['annual_revenue_zar']:,.0f}"))
    for f in rsi.get("contributing_factors", [])[:5]:
        rows.append((f["factor"], f"+{f['impact']}"))
    return build_cat_card("Ransomware Susceptibility (RSI)", col, f"{score}", rows, rsi.get("issues", []), S)


def cat_data_breach_index(d, S):
    dbi   = d.get("data_breach_index", {})
    score = dbi.get("dbi_score", 0)
    label = dbi.get("dbi_label", "N/A")
    col   = (C_CRITICAL if score < 25 else C_RED if score < 50 else
             C_AMBER if score < 75 else C_GREEN)
    rows  = [
        ("DBI Score",              f"{score} / 100"),
        ("Risk Level",             label),
        ("Breach Count",           dbi.get("breach_count", 0)),
        ("Most Recent Breach",     dbi.get("most_recent_breach") or "None"),
        ("Sensitive Data Exposed", "Yes" if dbi.get("has_sensitive_data") else "No"),
        ("Credential Leaks",       f"{dbi.get('credential_leaks', 0):,}"),
    ]
    return build_cat_card("Data Breach Index (DBI)", col, f"{score}/100", rows, dbi.get("issues", []), S)


def cat_financial_impact(d, S):
    fin = d.get("financial_impact", {})
    if fin.get("status") != "completed":
        return build_cat_card("Financial Impact (FAIR Model)", C_BLUE, "N/A",
                              [("Status", "Revenue not provided — skipped")], [], S)

    eal    = fin.get("estimated_annual_loss", {})
    sc     = fin.get("scenarios", {})
    ins    = fin.get("insurance_recommendation", {})
    most_l = eal.get("most_likely", 0)
    col    = C_CRITICAL if fin.get("score", 50) < 30 else (C_RED if fin["score"] < 50 else
              C_AMBER if fin["score"] < 70 else C_GREEN)

    rows = [
        ("Industry",             fin.get("industry", "Other")),
        ("Annual Revenue",       f"R {fin.get('annual_revenue_zar', 0):,.0f}"),
        ("",                     ""),
        ("Est. Annual Loss (Min)",  f"R {eal.get('minimum', 0):,.0f}"),
        ("Est. Annual Loss (Likely)", f"R {most_l:,.0f}"),
        ("Est. Annual Loss (Max)",    f"R {eal.get('maximum', 0):,.0f}"),
        ("",                     ""),
        ("Data Breach Loss",     f"R {sc.get('data_breach', {}).get('estimated_loss', 0):,.0f}  (P={sc.get('data_breach', {}).get('probability', 0)})"),
        ("  Records at risk",    f"{sc.get('data_breach', {}).get('estimated_records', 0):,} @ R{sc.get('data_breach', {}).get('cost_per_record', 0):,.0f}/rec"),
        ("  POPIA regulatory",   f"R {sc.get('data_breach', {}).get('regulatory_fine', 0):,.0f}"),
        ("Ransomware Loss",      f"R {sc.get('ransomware', {}).get('estimated_loss', 0):,.0f}  (RSI={sc.get('ransomware', {}).get('rsi_score', 0)})"),
        ("  Avg downtime",       f"{sc.get('ransomware', {}).get('avg_downtime_days', 0)} days"),
        ("  Ransom estimate",    f"R {sc.get('ransomware', {}).get('ransom_estimate', 0):,.0f}"),
        ("Bus. Interruption",    f"R {sc.get('business_interruption', {}).get('estimated_loss', 0):,.0f}  (P={sc.get('business_interruption', {}).get('probability', 0)})"),
        ("",                     ""),
        ("Min. Insurance Cover", f"R {ins.get('minimum_cover_zar', 0):,.0f}"),
        ("Rec. Insurance Cover", f"R {ins.get('recommended_cover_zar', 0):,.0f}"),
        ("Premium Risk Tier",    ins.get("premium_risk_tier", "N/A")),
    ]
    return build_cat_card("Financial Impact (FAIR Model)", col,
                          f"R {most_l:,.0f}", rows, fin.get("issues", []), S)


def cat_risk_mitigations(d, S):
    fin = d.get("financial_impact", {})
    mit = fin.get("risk_mitigations", {})
    findings = mit.get("findings", [])
    if fin.get("status") != "completed" or not findings:
        return []

    total_savings = mit.get("total_potential_savings", 0)
    current = mit.get("current_annual_loss", 0)
    mitigated = mit.get("mitigated_annual_loss", 0)
    summary = mit.get("summary", {})

    rows = [
        ("Current Annual Loss",  f"R {current:,.0f}"),
        ("Mitigated Annual Loss", f"R {mitigated:,.0f}"),
        ("Total Potential Savings", f"R {total_savings:,.0f}"),
        ("", ""),
    ]

    # Summary counts
    for sev in ("critical", "high", "medium"):
        s = summary.get(sev, {})
        if s.get("count", 0) > 0:
            rows.append((f"{sev.title()} Findings", f"{s['count']} — R {s['total_savings_zar']:,.0f} savings"))

    rows.append(("", ""))

    # Individual findings
    for i, f in enumerate(findings):
        sev = f.get("severity", "Medium")
        savings = f.get("estimated_annual_savings_zar", 0)
        rows.append((f"[{sev}] {f.get('recommendation', '')}",
                      f"R {savings:,.0f}"))

    rows.append(("", ""))
    rows.append(("Note", "Savings are modelled projections based on FAIR methodology"))

    return build_cat_card("Risk Mitigation Recommendations", C_GREEN,
                          f"Save R {total_savings:,.0f}", rows, [], S)


# ---------------------------------------------------------------------------
# Executive summary table
# ---------------------------------------------------------------------------

def build_summary_table(results: dict, S) -> Table:
    cats = results.get("categories", {})

    def row(label, value, col):
        circ = make_traffic_circle(col, 9)
        return [circ, Paragraph(label, S["kv_key"]), Paragraph(str(value), S["kv_val"])]

    ssl_grade = cats.get("ssl", {}).get("grade", "?")
    em_score  = cats.get("email_security", {}).get("score", 0)
    hh_score  = cats.get("http_headers", {}).get("score", 0)
    br_count  = cats.get("breaches", {}).get("breach_count", 0)
    adm_c     = cats.get("exposed_admin", {}).get("critical_count", 0)
    adm_h     = cats.get("exposed_admin", {}).get("high_count", 0)
    hrp_c     = cats.get("high_risk_protocols", {}).get("critical_count", 0)
    bl        = cats.get("dnsbl", {}).get("blacklisted", False)
    waf       = cats.get("waf", {}).get("detected", False)
    vpn_rdp   = cats.get("vpn_remote", {}).get("rdp_exposed", False)

    # Insurance analytics
    ins       = results.get("insurance", {})
    rsi_score = ins.get("rsi", {}).get("rsi_score")
    dbi_score = ins.get("dbi", {}).get("score")

    rows = [
        row("SSL Grade",             ssl_grade,
            _tl(ssl_grade in ("A+", "A", "B"), ssl_grade == "C")),
        row("Email Security Score",  f"{em_score}/10",
            _tl(em_score >= 8, em_score >= 5)),
        row("HTTP Security Headers", f"{hh_score}%",
            _tl(hh_score >= 80, hh_score >= 50)),
        row("Known Data Breaches",   br_count,
            _tl(br_count == 0, br_count <= 3)),
        row("Exposed Admin Panels",  adm_c + adm_h,
            _tl(adm_c + adm_h == 0, adm_c == 0)),
        row("DB/Service Exposure",   f"{hrp_c} critical service(s)",
            C_CRITICAL if hrp_c > 0 else C_GREEN),
        row("IP/Domain Blacklisted", "YES" if bl else "No",
            C_CRITICAL if bl else C_GREEN),
        row("WAF Protection",        "Detected" if waf else "Not detected",
            C_GREEN if waf else C_AMBER),
        row("RDP Exposed",           "YES — CRITICAL" if vpn_rdp else "No",
            C_CRITICAL if vpn_rdp else C_GREEN),
        row("External IPs",          f"{cats.get('external_ips', {}).get('total_unique_ips', 0)} IPs ({cats.get('external_ips', {}).get('aggregate_vulns', {}).get('ips_with_vulns', 0)} with CVEs)",
            _tl(cats.get("external_ips", {}).get("aggregate_vulns", {}).get("critical_count", 0) == 0,
                cats.get("external_ips", {}).get("aggregate_vulns", {}).get("high_count", 0) == 0)),
    ]

    # Add insurance rows if available
    if rsi_score is not None:
        rows.insert(0, row("Ransomware Susceptibility", f"{rsi_score:.2f}",
            _tl(rsi_score < 0.3, rsi_score < 0.6)))
    if dbi_score is not None:
        rows.insert(1 if rsi_score is not None else 0,
            row("Data Breach Index", f"{dbi_score}/100",
            _tl(dbi_score >= 70, dbi_score >= 40)))

    # RSI / DBI / Financial Impact / Fraudulent Domains / Web Ranking (Sarel's categories)
    rsi      = cats.get("ransomware_risk", {})
    rsi_val  = rsi.get("rsi_score", 0)
    rows.append(row("Ransomware Susceptibility (RSI)", f"{rsi_val} / 1.0 — {rsi.get('rsi_label', 'N/A')}",
                     C_CRITICAL if rsi_val >= 0.8 else C_RED if rsi_val >= 0.5 else C_AMBER if rsi_val >= 0.25 else C_GREEN))

    dbi      = cats.get("data_breach_index", {})
    dbi_val  = dbi.get("dbi_score", 0)
    rows.append(row("Data Breach Index (DBI)", f"{dbi_val}/100 — {dbi.get('dbi_label', 'N/A')}",
                     C_CRITICAL if dbi_val < 25 else C_RED if dbi_val < 50 else C_AMBER if dbi_val < 75 else C_GREEN))

    fin       = cats.get("financial_impact", {})
    if fin.get("status") == "completed":
        fin_ml = fin.get("estimated_annual_loss", {}).get("most_likely", 0)
        rows.append(row("Est. Annual Loss (FAIR)", f"R {fin_ml:,.0f}",
                         C_CRITICAL if fin.get("score", 50) < 30 else C_AMBER if fin["score"] < 70 else C_GREEN))

    fd_count = cats.get("fraudulent_domains", {}).get("fraudulent_domains_found", 0)
    rows.append(row("Fraudulent Domains", f"{fd_count} lookalike(s)",
                     C_CRITICAL if fd_count > 3 else C_RED if fd_count > 0 else C_GREEN))

    wr_label = cats.get("web_ranking", {}).get("rank_label", "Unranked")
    rows.append(row("Web Ranking (Tranco)", wr_label,
                     C_GREEN if cats.get("web_ranking", {}).get("ranked") else C_AMBER))

    tbl = Table(rows, colWidths=[14, 70 * mm, INNER_W - 14 - 70 * mm])
    style = [
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 0.25, C_GREY_2),
    ]
    for i in range(0, len(rows), 2):
        style.append(("BACKGROUND", (0, i), (-1, i), C_GREY_1))
    for i in range(1, len(rows), 2):
        style.append(("BACKGROUND", (0, i), (-1, i), C_WHITE))
    tbl.setStyle(TableStyle(style))
    return tbl


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_pdf(results: dict) -> bytes:
    buffer = io.BytesIO()
    domain    = results.get("domain_scanned", "Unknown")
    timestamp = results.get("scan_timestamp", datetime.utcnow().isoformat())
    risk_score= results.get("overall_risk_score", 0)
    risk_level= results.get("risk_level", "Unknown")
    recs      = results.get("recommendations", [])
    cats      = results.get("categories", {})

    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=MARGIN, leftMargin=MARGIN,
        topMargin=20 * mm, bottomMargin=16 * mm,
        title=f"Cyber Risk Assessment — {domain}",
        author="PHISHIELD / Bryte Insurance",
    )

    S = build_styles()

    def hf(canvas, doc):
        _header_footer(canvas, doc, domain, timestamp)

    story = []

    # ── Cover ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("CYBER RISK ASSESSMENT REPORT", S["cover_title"]))
    story.append(Paragraph("External Passive Security Evaluation", S["cover_sub"]))
    story.append(Spacer(1, 4 * mm))
    story.append(HRFlowable(width=INNER_W, thickness=0.5, color=C_GREY_2))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(f"Domain assessed:", S["body_muted"]))
    story.append(Paragraph(domain, S["cover_domain"]))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(f"Assessment date: {timestamp[:10]}    |    Scan time: {timestamp[11:19]} UTC", S["body_muted"]))
    story.append(Spacer(1, 8 * mm))

    # Risk score block
    rc = risk_color(risk_level)
    rb = risk_bg(risk_level)
    score_tbl = Table([
        [Paragraph(f"<b>{risk_score}</b>", ParagraphStyle("rs", fontSize=48, fontName="Helvetica-Bold",
                    textColor=rc, leading=52, alignment=TA_CENTER)),
         Paragraph(f"<b>{risk_level.upper()} RISK</b>",
                   ParagraphStyle("rl", fontSize=20, fontName="Helvetica-Bold",
                                  textColor=rc, leading=24, alignment=TA_LEFT)),
        ],
        [Paragraph("out of 1000", ParagraphStyle("ou", fontSize=9, textColor=C_GREY_3,
                    alignment=TA_CENTER)), ""],
    ], colWidths=[50 * mm, INNER_W - 50 * mm])
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), rb),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("SPAN",          (1, 0), (1, 1)),
        ("ROUNDEDCORNERS",(0, 0), (-1, -1), [6, 6, 6, 6]),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 5 * mm))

    # Gauge
    story.append(make_risk_gauge(risk_score))
    story.append(Spacer(1, 6 * mm))

    # Executive summary table
    story.append(Paragraph("<b>Executive Summary</b>", S["cat_title"]))
    story.append(Spacer(1, 2 * mm))
    story.append(build_summary_table(results, S))

    # ── Insurance Analytics ─────────────────────────────────────────────────
    if results.get("insurance"):
        story.append(PageBreak())
        story += section_header("INSURANCE ANALYTICS", S)
        story += cat_rsi(results, S)
        story += cat_insurance_financial_impact(results, S)
        story += cat_dbi(results, S)
        story += cat_remediation(results, S)

    story.append(PageBreak())

    # ── Discovery ─────────────────────────────────────────────────────────────
    story += section_header("DISCOVERY", S)
    story += cat_web_ranking(cats, S)

    # ── Core Security ────────────────────────────────────────────────────────
    story += section_header("CORE SECURITY", S)
    story += cat_ssl(cats, S)
    story += cat_headers(cats, S)
    story += cat_waf(cats, S)
    story += cat_website(cats, S)

    # ── Information Security ──────────────────────────────────────────────────
    story += section_header("INFORMATION SECURITY", S)
    story += cat_info_disclosure(cats, S)

    # ── Email Security ───────────────────────────────────────────────────────
    story += section_header("EMAIL SECURITY", S)
    story += cat_email(cats, S)
    story += cat_email_hardening(cats, S)

    # ── Network & Infrastructure ─────────────────────────────────────────────
    story += section_header("NETWORK & INFRASTRUCTURE", S)
    story += cat_dns(cats, S)
    story += cat_hrp(cats, S)
    story += cat_cloud(cats, S)
    story += cat_vpn(cats, S)
    story += cat_external_ips(cats, S)

    # ── Risk Quantification ───────────────────────────────────────────────────
    story += section_header("RISK QUANTIFICATION", S)
    story += cat_ransomware_risk(cats, S)
    story += cat_data_breach_index(cats, S)
    story += cat_financial_impact(cats, S)
    story += cat_risk_mitigations(cats, S)

    # ── Exposure & Reputation ────────────────────────────────────────────────
    story += section_header("EXPOSURE & REPUTATION", S)
    story += cat_breaches(cats, S)
    story += cat_dnsbl(cats, S)
    story += cat_admin(cats, S)
    story += cat_subdomains(cats, S)
    story += cat_shodan(cats, S)
    story += cat_dehashed(cats, S)
    story += cat_fraudulent_domains(cats, S)
    story += cat_web_ranking(cats, S)

    # ── Technology & Governance ──────────────────────────────────────────────
    story += section_header("TECHNOLOGY & GOVERNANCE", S)
    story += cat_tech(cats, S)
    story += cat_domain(cats, S)
    story += cat_security_policy(cats, S)
    story += cat_payment(cats, S)

    # ── Recommendations ──────────────────────────────────────────────────────
    if recs:
        story += section_header("REMEDIATION RECOMMENDATIONS", S)
        for i, rec in enumerate(recs, 1):
            story.append(Paragraph(f"{i}.", S["rec_num"]))
            story.append(Paragraph(rec, S["rec_body"]))
            story.append(Spacer(1, 2 * mm))

    # ── Disclaimer ───────────────────────────────────────────────────────────
    story.append(Spacer(1, 6 * mm))
    story.append(HRFlowable(width=INNER_W, thickness=0.5, color=C_GREY_2))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        "DISCLAIMER: This report is based solely on passive, external assessment of publicly observable "
        "infrastructure and does not constitute a full security audit. Results reflect point-in-time observations. "
        "Bryte Insurance Company Limited (FSP 17703) accepts no liability for decisions made solely on the basis "
        "of this automated assessment. For insurance purposes this report must be reviewed by a qualified underwriter.",
        S["disclaimer"]
    ))

    doc.build(story, onFirstPage=hf, onLaterPages=hf)
    return buffer.getvalue()
