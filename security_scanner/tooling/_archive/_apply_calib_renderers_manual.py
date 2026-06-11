# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX calibration mutator (2026-06-05): propagate the T1 band re-fit and the
T3 availability re-anchor into the renderer + manual surfaces (the 'manual = the
lock' rule), plus the T2 manual note. CRLF-safe. NOT shipped by this script.

  pdf_report.py        T1 band text (probability-card caption)
  templates/results.html  T1 band text (probability-card footnote)
  part5 manual         T1 band paragraph + T3 availability paragraph + note
  part3 manual         T2 email-auth remediation-credit note
"""
import ast, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def mutate(relpath, edits, is_py=True):
    p = os.path.join(ROOT, relpath)
    s = open(p, encoding="utf-8").read()
    assert "\r" not in s, (relpath, "expected normalised content")
    for tag, old, new in edits:
        assert s.count(old) == 1, (relpath, tag, s.count(old))
        s = s.replace(old, new, 1)
    if is_py:
        ast.parse(s)
    with open(p, "wb") as f:
        f.write(s.replace("\n", "\r\n").encode("utf-8"))
    if is_py:
        ast.parse(open(p, encoding="utf-8").read())
    print(f"OK {relpath}: {len(edits)} edit(s) applied (AST valid, CRLF restored).")


# ── pdf_report.py — T1 band caption ────────────────────────────────────────
mutate("pdf_report.py", [(
    "T1 pdf band caption",
    "            \"always greater than or equal to it. Provisional bands: &lt;5% Low, \"\n"
    "            \"5-15% Typical, 15-30% Elevated, &gt;30% High.\",\n",
    "            \"always greater than or equal to it. Relative posture bands \"\n"
    "            \"(&lt;8% Low, 8-18% Typical, 18-28% Elevated, &gt;28% High): the \"\n"
    "            \"combined rate sits above per-org material-incident claims \"\n"
    "            \"frequency (Coalition 2025 1.2-5.7%/yr), so read it as relative \"\n"
    "            \"posture rather than a calibrated annual claim rate.\",\n",
)])

# ── templates/results.html — T1 band footnote ──────────────────────────────
mutate("templates/results.html", [(
    "T1 html band footnote",
    "nests above the data-breach figure (always &ge; it). Provisional bands: &lt;5% Low / 5-15% Typical / 15-30% Elevated / &gt;30% High.<br>",
    "nests above the data-breach figure (always &ge; it). Relative posture bands: &lt;8% Low / 8-18% Typical / 18-28% Elevated / &gt;28% High &mdash; the combined rate sits above per-org claims frequency (Coalition 2025 1.2-5.7%/yr), so read as relative posture, not a calibrated annual rate.<br>",
)], is_py=False)

# ── part5 manual — T1 band paragraph + T3 availability paragraph + note ─────
mutate("manual_parts/part5_tech_compliance_insurance.py", [
    ("T1 part5 band bullet",
     "    add_bullet(doc,\n"
     "        \"The total cyber-incident probability is graded on a separate, \"\n"
     "        \"provisional multi-channel band set: below 5% Low, 5 to 15% Typical, \"\n"
     "        \"15 to 30% Elevated, and above 30% High. These bands are provisional \"\n"
     "        \"pending a dedicated multi-channel calibration and are labelled as \"\n"
     "        \"provisional in the report.\"\n"
     "    )\n",
     "    add_bullet(doc,\n"
     "        \"The total cyber-incident probability is graded on a separate, relative \"\n"
     "        \"multi-channel posture band set: below 8% Low, 8 to 18% Typical, 18 to \"\n"
     "        \"28% Elevated, and above 28% High (re-fit from 5/15/30 on 5 June 2026 so \"\n"
     "        \"a genuinely low-risk posture can reach Low). These are relative-posture \"\n"
     "        \"bands: the combined breach-and-ransomware rate sits above the per-\"\n"
     "        \"organisation material-incident claims frequency reported by cyber \"\n"
     "        \"insurers (Coalition's 2025 study: 1.2 percent a year below 25 million \"\n"
     "        \"dollars of revenue, rising to 5.7 percent above 100 million; Cyentia \"\n"
     "        \"IRIS under 2 percent for small and medium business), because it \"\n"
     "        \"aggregates both channels as an index. They should be read as relative \"\n"
     "        \"posture rather than a calibrated annual claim rate; a dedicated \"\n"
     "        \"frequency-calibration pass on the ransomware loss-event frequency is a \"\n"
     "        \"recorded next step.\"\n"
     "    )\n"),
    ("T3 part5 availability body + note",
     "    add_body(doc,\n"
     "        \"A third and separate line reports an availability resilience \"\n"
     "        \"indicator. It spans outage and availability risk arising from both \"\n"
     "        \"denial-of-service and system or infrastructure-failure causes, and is \"\n"
     "        \"derived heuristically from the WAF, CDN, hosting-concentration (single \"\n"
     "        \"autonomous system) and DNS-blocklist signals. It is reported as an \"\n"
     "        \"indicative measure only: it is not a calibrated probability, and \"\n"
     "        \"because outage and system-failure cover varies between policies and \"\n"
     "        \"over time it carries no statement of policy coverage. It describes the \"\n"
     "        \"risk - the stable and prevalent fact - and is kept on its own line \"\n"
     "        \"because it is a different risk type (availability rather than breach or \"\n"
     "        \"extortion) measured on different signals.\"\n"
     "    )\n"
     "    add_note(doc,\n"
     "        \"The availability resilience indicator is flagged in the JSON output as \"\n"
     "        \"not calibrated. A FAIR re-anchoring of this figure is a recorded future \"\n"
     "        \"step and is required before it is ever presented as a calibrated rate.\"\n"
     "    )\n",
     "    add_body(doc,\n"
     "        \"A third and separate line reports an availability resilience \"\n"
     "        \"indicator. It spans outage and availability risk arising from both \"\n"
     "        \"denial-of-service and system or infrastructure-failure causes. Its base \"\n"
     "        \"rate is FAIR-anchored to the Uptime Institute's annual outage analysis \"\n"
     "        \"(the serious-or-severe outage rate, roughly 3 percent a year), with \"\n"
     "        \"additive increments for the availability-relevant control gaps: absence \"\n"
     "        \"of a CDN or DDoS-mitigation service (the primary lever), single-homed \"\n"
     "        \"hosting on one autonomous system (secondary), and absence of a web \"\n"
     "        \"application firewall (a smaller, layer-7-flood-only contribution, since \"\n"
     "        \"most volumetric denial-of-service is absorbed at the CDN edge rather \"\n"
     "        \"than the firewall). Because outage and system-failure cover varies \"\n"
     "        \"between policies and over time it carries no statement of policy \"\n"
     "        \"coverage. It describes the risk - the stable and prevalent fact - and \"\n"
     "        \"is kept on its own line because it is a different risk type \"\n"
     "        \"(availability rather than breach or extortion) measured on different \"\n"
     "        \"signals.\"\n"
     "    )\n"
     "    add_note(doc,\n"
     "        \"The availability resilience indicator's base rate is now FAIR-anchored \"\n"
     "        \"to published outage-frequency data; the per-control increments remain \"\n"
     "        \"directional and the JSON output still flags the figure as not fully \"\n"
     "        \"calibrated. It describes availability risk and is not presented as a \"\n"
     "        \"coverage statement.\"\n"
     "    )\n"),
])

# ── part3 manual — T2 email-auth remediation-credit note ───────────────────
mutate("manual_parts/part3_email_network.py", [(
    "T2 part3 remediation note",
    "        \"is treated as +all (Pass) per RFC 7208. The penalty magnitudes are \"\n"
    "        \"conservative and calibration-gated. Where a non-enforcing soft-fail \"\n"
    "        \"or neutral SPF is found, the report's remediation recommends \"\n"
    "        \"hardening the policy to a terminal -all and includes it in the \"\n"
    "        \"expected-loss mitigation estimate.\"\n",
    "        \"is treated as +all (Pass) per RFC 7208. The qualifier score penalties \"\n"
    "        \"are unchanged; the expected-loss remediation credit for hardening a \"\n"
    "        \"soft-fail or neutral SPF was recalibrated on 5 June 2026 - trimmed \"\n"
    "        \"about a quarter (keeping the email-authentication credits in a \"\n"
    "        \"four-to-two-to-one ratio) because DMARC and SPF enforcement block only \"\n"
    "        \"exact-domain spoofing, a minority of the phishing and business-email-\"\n"
    "        \"compromise surface (the 2025 Verizon DBIR puts phishing at about 16 \"\n"
    "        \"percent of breaches). Where a non-enforcing soft-fail or neutral SPF is \"\n"
    "        \"found, the report's remediation recommends hardening the policy to a \"\n"
    "        \"terminal -all and includes it in the expected-loss mitigation estimate.\"\n",
)])

print("ALL renderer + manual calibration edits applied.")
