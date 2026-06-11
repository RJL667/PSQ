# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #17d, card pass): the MANUAL LOCK. Adds the methodology
paragraphs for the reporting-only probability cards + cover-sizing ladder +
remediation re-portrayal to manual_parts/part5_tech_compliance_insurance.py.

Per the anchoring-mechanism rule, the manual paragraph IS the lock: no card is
'done' until its anchor is written into part5 financial methodology. Third-person,
every number anchored (Cyentia IRIS / BitSight / SecurityScorecard for the breach
bands; the 0.30 LEF scalar already documented; P50/P95/P99.6 definitional), no
intuited numbers. Inserted before the 'Coverage-adjusted tail' subsection.

CRLF-preserving mutator + AST validation. NOT shipped."""
import ast
import os

P5 = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "manual_parts", "part5_tech_compliance_insurance.py")
s = open(P5, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

NEW_MANUAL = (
    "    add_h2(doc, \"Probability and cover reporting views (FAIR decomposition)\")\n"
    "\n"
    "    add_body(doc,\n"
    "        \"The financial impact is reported across the three axes of the FAIR \"\n"
    "        \"decomposition: a frequency view (annual probability), a severity view \"\n"
    "        \"(the cover-sizing ladder below), and an expected-loss view (the \"\n"
    "        \"estimated annual loss). These are presentation re-expressions of \"\n"
    "        \"signals already scored elsewhere in the model; they introduce no new \"\n"
    "        \"weighting and no double-counting.\"\n"
    "    )\n"
    "\n"
    "    add_body(doc,\n"
    "        \"Two annual-probability figures are reported, nested and separately \"\n"
    "        \"defined, so that frequency is not confused with severity and the two \"\n"
    "        \"probabilities are not confused with each other.\"\n"
    "    )\n"
    "    add_bullet(doc,\n"
    "        \"Data-breach probability is the FAIR loss-event frequency p_breach \"\n"
    "        \"(Vulnerability x TEF x 0.30) defined above - the annual likelihood \"\n"
    "        \"specifically of a data breach, meaning a confidentiality loss or \"\n"
    "        \"exfiltration of records.\"\n"
    "    )\n"
    "    add_bullet(doc,\n"
    "        \"Total cyber-incident probability is the annual likelihood of any \"\n"
    "        \"modelled cyber incident. It combines the breach channel and the \"\n"
    "        \"ransomware channel as an independent union - one minus the product \"\n"
    "        \"of one-minus-each-channel-probability - where the ransomware-channel \"\n"
    "        \"frequency is the RSI score multiplied by the same 0.30 loss-event-\"\n"
    "        \"frequency scalar used for the breach leg. It nests above the data-\"\n"
    "        \"breach figure and is by construction always greater than or equal to \"\n"
    "        \"it.\"\n"
    "    )\n"
    "\n"
    "    add_body(doc,\n"
    "        \"Each probability is graded against its own band set; reusing one band \"\n"
    "        \"set across both figures would mislabel a typical multi-channel rate.\"\n"
    "    )\n"
    "    add_bullet(doc,\n"
    "        \"The data-breach probability is graded on firm public breach-rate \"\n"
    "        \"bands: below 1% Strong, 1 to 2% Good, 2 to 3% Typical, 3 to 6% \"\n"
    "        \"Elevated, 6 to 12% High, and above 12% Critical. These cut-offs \"\n"
    "        \"follow the same published evidence as the probability curve - the \"\n"
    "        \"Cyentia IRIS small-and-medium-business annual loss-event rate (under \"\n"
    "        \"2%), and the BitSight and SecurityScorecard rating-to-breach ladders.\"\n"
    "    )\n"
    "    add_bullet(doc,\n"
    "        \"The total cyber-incident probability is graded on a separate, \"\n"
    "        \"provisional multi-channel band set: below 5% Low, 5 to 15% Typical, \"\n"
    "        \"15 to 30% Elevated, and above 30% High. These bands are provisional \"\n"
    "        \"pending a dedicated multi-channel calibration and are labelled as \"\n"
    "        \"provisional in the report.\"\n"
    "    )\n"
    "\n"
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
    "    )\n"
    "\n"
    "    add_body(doc,\n"
    "        \"The cover-sizing ladder is a simplified three-tier view drawn from the \"\n"
    "        \"same severity distribution as the Loss Exposure Scenarios table: a \"\n"
    "        \"typical severe breach at the median severity (P50), a bad breach at \"\n"
    "        \"the P95 severity, and a catastrophic breach at the 1-in-250 (P99.6) \"\n"
    "        \"severity. The three tiers are used because the top return-period \"\n"
    "        \"percentiles (P99, P99.5 and P99.6) compress to within roughly 7% of \"\n"
    "        \"one another, so a P50-to-P99.6 spread gives the broker a more \"\n"
    "        \"meaningful cover band. The ladder reports the severity of a single \"\n"
    "        \"severe event and is therefore posture-independent: the figures do not \"\n"
    "        \"move with the security score, consistent with the compound catastrophe \"\n"
    "        \"construction described above. Cover selection remains the \"\n"
    "        \"responsibility of the insured in consultation with the broker.\"\n"
    "    )\n"
    "\n"
    "    add_body(doc,\n"
    "        \"The expected-loss remediation panel is presented frequency-first. It \"\n"
    "        \"leads with the movement in the data-breach probability and its grade, \"\n"
    "        \"before and after the modelled remediations, with the percentage \"\n"
    "        \"reduction in modelled annual exposure and the catastrophe cover figure \"\n"
    "        \"(the 1-in-250 severity) as context. Because severity is posture-\"\n"
    "        \"independent, the catastrophe cover figure is unchanged by remediation - \"\n"
    "        \"remediation lowers the likelihood of a loss, not the worst-case \"\n"
    "        \"severity of one. The absolute Rand saving is retained as a secondary \"\n"
    "        \"figure.\"\n"
    "    )\n"
    "\n"
)
OLD_ANCHOR = "    add_h2(doc, \"Coverage-adjusted tail (WAF blind-spot)\")\n"
assert s.count(OLD_ANCHOR) == 1, ("Coverage-adjusted tail anchor", s.count(OLD_ANCHOR))
s = s.replace(OLD_ANCHOR, NEW_MANUAL + OLD_ANCHOR, 1)

assert "\r" not in s
assert "Probability and cover reporting views (FAIR decomposition)" in s
assert "availability resilience" in s
ast.parse(s)
with open(P5, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
chk = open(P5, encoding="utf-8").read()
ast.parse(chk)
print("OK part5: item #17d manual-lock paragraphs added (AST valid).")
