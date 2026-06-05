# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #17c, card pass): wire the reporting-only probability cards +
cover-sizing ladder + remediation re-portrayal into the HTML report
(templates/results.html). REPORTING-ONLY presentation of already-scored signals.

Adds: (A) a Cyber-Risk Probability card (3 distinct, separately-graded annual-
likelihood concepts; total cyber-incident nested above the breach figure) after
the context strip; (B) a Cover-Sizing Ladder card after the Loss Exposure
Scenarios; (C) a re-portrayed lead strip on the Risk Mitigation card (breach-grade
movement + %-exposure reduction + posture-independent catastrophe cover).

CRLF-preserving mutator (read utf-8 -> assert no CR -> count==1 -> replace ->
write CRLF). Jinja2 syntax-validated. NOT shipped."""
import os

HTML = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "templates", "results.html")
s = open(HTML, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

# ---------------------------------------------------------------------------
# A. Cyber-Risk Probability card, inserted before the Estimated Annual Loss range.
# ---------------------------------------------------------------------------
RP_BLOCK = (
    "        {# Cyber-Risk Probability — reporting-only FAIR frequency view (item #17). #}\n"
    "        {# THREE distinct, separately-graded annual-likelihood concepts. #}\n"
    "        {% set rp = fin.risk_probability if fin.risk_probability is defined else {} %}\n"
    "        {% if rp %}\n"
    "        {% set rp_db = rp.data_breach if rp.data_breach is defined else {} %}\n"
    "        {% set rp_ci = rp.cyber_incident if rp.cyber_incident is defined else {} %}\n"
    "        {% set rp_av = rp.availability_resilience if rp.availability_resilience is defined else {} %}\n"
    "        <div style=\"background:linear-gradient(135deg, rgba(99,102,241,0.08), rgba(99,102,241,0.02));border:1px solid rgba(99,102,241,0.3);border-radius:10px;padding:16px 18px;margin-bottom:14px;\">\n"
    "          <div style=\"font-size:.85rem;font-weight:700;color:var(--text);margin-bottom:4px;\">Cyber-Risk Probability</div>\n"
    "          <div style=\"font-size:.72rem;color:var(--muted);margin-bottom:12px;line-height:1.5;\">\n"
    "            Modelled annual likelihood of a cyber loss event, shown as three distinct and separately-graded measures. A frequency view of signals already scored elsewhere in this report &mdash; it carries no additional scoring weight.\n"
    "          </div>\n"
    "          <table style=\"width:100%;border-collapse:collapse;font-size:.82rem;\">\n"
    "            <thead>\n"
    "              <tr style=\"background:rgba(99,102,241,0.12);\">\n"
    "                <th style=\"text-align:left;padding:8px 10px;font-weight:600;color:var(--text);\">Annual cyber-risk probability</th>\n"
    "                <th style=\"text-align:right;padding:8px 10px;font-weight:600;color:var(--text);white-space:nowrap;\">Likelihood</th>\n"
    "                <th style=\"text-align:center;padding:8px 10px;font-weight:600;color:var(--text);\">Grade</th>\n"
    "              </tr>\n"
    "            </thead>\n"
    "            <tbody>\n"
    "              <tr style=\"border-bottom:1px solid rgba(255,255,255,0.06);\">\n"
    "                <td style=\"padding:8px 10px;font-weight:700;color:var(--text);\">Total cyber-incident <span style=\"color:var(--muted);font-weight:400;\">(breach + ransomware)</span></td>\n"
    "                <td style=\"padding:8px 10px;text-align:right;font-weight:700;white-space:nowrap;\">{{ '%.1f'|format(rp_ci.probability_pct | default(0)) }}%</td>\n"
    "                <td style=\"padding:8px 10px;text-align:center;\">{{ rp_ci.grade | default('—') }}</td>\n"
    "              </tr>\n"
    "              <tr style=\"border-bottom:1px solid rgba(255,255,255,0.06);\">\n"
    "                <td style=\"padding:8px 10px 8px 28px;color:var(--muted);\">of which: data breach</td>\n"
    "                <td style=\"padding:8px 10px;text-align:right;font-weight:700;white-space:nowrap;\">{{ '%.2f'|format(rp_db.probability_pct | default(0)) }}%</td>\n"
    "                <td style=\"padding:8px 10px;text-align:center;\">{{ rp_db.grade | default('—') }}</td>\n"
    "              </tr>\n"
    "              <tr>\n"
    "                <td style=\"padding:8px 10px;color:var(--muted);\">Availability resilience <span style=\"font-size:.7rem;\">(indicative)</span></td>\n"
    "                <td style=\"padding:8px 10px;text-align:right;white-space:nowrap;\">{{ '%.0f'|format(rp_av.indicator_pct | default(0)) }}%</td>\n"
    "                <td style=\"padding:8px 10px;text-align:center;color:var(--muted);\">Indicative</td>\n"
    "              </tr>\n"
    "            </tbody>\n"
    "          </table>\n"
    "          <div style=\"font-size:.7rem;color:var(--muted);margin-top:10px;line-height:1.55;\">\n"
    "            <strong style=\"color:var(--text);\">Total cyber-incident probability</strong> &mdash; likelihood of ANY modelled cyber incident, combining the breach and ransomware channels; nests above the data-breach figure (always &ge; it). Provisional bands: &lt;5% Low / 5-15% Typical / 15-30% Elevated / &gt;30% High.<br>\n"
    "            <strong style=\"color:var(--text);\">Data-breach probability</strong> &mdash; likelihood specifically of a data breach (record exfiltration). Firm public bands (Cyentia IRIS SMB &lt;2%/yr, BitSight, SecurityScorecard): &lt;1% Strong / 1-2% Good / 2-3% Typical / 3-6% Elevated / 6-12% High / &gt;12% Critical.<br>\n"
    "            <strong style=\"color:var(--text);\">Availability resilience indicator</strong> &mdash; an indicative signal of outage / availability risk (DDoS + system / infrastructure failure). Describes the risk only; not a calibrated probability and not a coverage statement.\n"
    "          </div>\n"
    "        </div>\n"
    "        {% endif %}\n"
    "\n"
    "        {# Estimated Annual Loss range #}\n"
)
OLD_RP = "        {# Estimated Annual Loss range #}\n"
assert s.count(OLD_RP) == 1, ("Estimated Annual Loss anchor", s.count(OLD_RP))
s = s.replace(OLD_RP, RP_BLOCK, 1)

# ---------------------------------------------------------------------------
# B. Cover-Sizing Ladder card, inserted before the Per-scenario MC breakdown.
# ---------------------------------------------------------------------------
CL_BLOCK = (
    "        {# Cover-Sizing Ladder — severity-PML tiers (P50/P95/P99.6), posture-independent. Item #17. #}\n"
    "        {% set cl = fin.cover_ladder if fin.cover_ladder is defined else {} %}\n"
    "        {% if cl %}\n"
    "        <div style=\"background:linear-gradient(135deg, rgba(29,78,216,0.08), rgba(29,78,216,0.02));border:1px solid rgba(29,78,216,0.3);border-radius:10px;padding:16px 18px;margin-bottom:14px;\">\n"
    "          <div style=\"font-size:.85rem;font-weight:700;color:var(--text);margin-bottom:4px;\">Cover-Sizing Ladder</div>\n"
    "          <div style=\"font-size:.72rem;color:var(--muted);margin-bottom:12px;line-height:1.5;\">\n"
    "            The modelled severity of a single severe cyber event across three cover tiers &mdash; the simplified client-facing companion to the Loss Exposure Scenarios above. These are the magnitude of a realised event and do not move with security posture.\n"
    "          </div>\n"
    "          <table style=\"width:100%;border-collapse:collapse;font-size:.82rem;\">\n"
    "            <thead>\n"
    "              <tr style=\"background:rgba(29,78,216,0.15);\">\n"
    "                <th style=\"text-align:left;padding:8px 10px;font-weight:600;color:var(--text);\">Cover tier</th>\n"
    "                <th style=\"text-align:right;padding:8px 10px;font-weight:600;color:var(--text);white-space:nowrap;\">Modelled severity</th>\n"
    "                <th style=\"text-align:right;padding:8px 10px;font-weight:600;color:var(--text);\">Reference</th>\n"
    "              </tr>\n"
    "            </thead>\n"
    "            <tbody>\n"
    "              <tr style=\"border-bottom:1px solid rgba(255,255,255,0.06);\">\n"
    "                <td style=\"padding:8px 10px;\">Typical severe breach</td>\n"
    "                <td style=\"padding:8px 10px;text-align:right;font-weight:700;white-space:nowrap;\">R&nbsp;{{ '{:,.0f}'.format(cl.typical_severe.loss_zar | default(0)) }}</td>\n"
    "                <td style=\"padding:8px 10px;text-align:right;color:var(--muted);\">P50 severity</td>\n"
    "              </tr>\n"
    "              <tr style=\"border-bottom:1px solid rgba(255,255,255,0.06);\">\n"
    "                <td style=\"padding:8px 10px;\">Bad breach</td>\n"
    "                <td style=\"padding:8px 10px;text-align:right;font-weight:700;white-space:nowrap;\">R&nbsp;{{ '{:,.0f}'.format(cl.bad.loss_zar | default(0)) }}</td>\n"
    "                <td style=\"padding:8px 10px;text-align:right;color:var(--muted);\">P95 severity</td>\n"
    "              </tr>\n"
    "              <tr>\n"
    "                <td style=\"padding:8px 10px;font-weight:700;color:var(--critical);\">Catastrophic breach</td>\n"
    "                <td style=\"padding:8px 10px;text-align:right;font-weight:700;color:var(--critical);white-space:nowrap;\">R&nbsp;{{ '{:,.0f}'.format(cl.catastrophic.loss_zar | default(0)) }}</td>\n"
    "                <td style=\"padding:8px 10px;text-align:right;color:var(--critical);\">1-in-250 / P99.6</td>\n"
    "              </tr>\n"
    "            </tbody>\n"
    "          </table>\n"
    "        </div>\n"
    "        {% endif %}\n"
    "\n"
    "        {# Per-scenario MC breakdown #}\n"
)
OLD_CL = "        {# Per-scenario MC breakdown #}\n"
assert s.count(OLD_CL) == 1, ("Per-scenario MC anchor", s.count(OLD_CL))
s = s.replace(OLD_CL, CL_BLOCK, 1)

# ---------------------------------------------------------------------------
# C. Re-portrayed lead strip on the Risk Mitigation card.
# ---------------------------------------------------------------------------
OLD_MIT = (
    "      <div class=\"cat-body\">\n"
    "        <!-- Impact summary strip -->\n"
)
NEW_MIT = (
    "      <div class=\"cat-body\">\n"
    "        {# Re-portrayed lead (item #17): breach-grade movement + %-reduction + posture-independent catastrophe cover. #}\n"
    "        {% set rs = mit.remediation_summary if mit.remediation_summary is defined else {} %}\n"
    "        {% if rs %}\n"
    "        <div style=\"display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-top:10px;margin-bottom:6px;\">\n"
    "          <div style=\"padding:12px;background:var(--surface2);border-radius:8px;border:1px solid var(--low);\">\n"
    "            <div style=\"font-size:.7rem;color:var(--muted);text-transform:uppercase;font-weight:600;\">Data-breach likelihood</div>\n"
    "            <div style=\"font-size:.98rem;font-weight:800;margin-top:4px;line-height:1.4;\">{{ '%.2f'|format(rs.breach_probability_before_pct | default(0)) }}% <span style=\"color:var(--muted);font-size:.78rem;font-weight:600;\">({{ rs.breach_grade_before }})</span> &rarr; <span style=\"color:var(--low);\">{{ '%.2f'|format(rs.breach_probability_after_pct | default(0)) }}%</span> <span style=\"color:var(--muted);font-size:.78rem;font-weight:600;\">({{ rs.breach_grade_after }})</span></div>\n"
    "          </div>\n"
    "          <div style=\"padding:12px;background:var(--surface2);border-radius:8px;\">\n"
    "            <div style=\"font-size:.7rem;color:var(--muted);text-transform:uppercase;font-weight:600;\">Reduction in modelled exposure</div>\n"
    "            <div style=\"font-size:1.2rem;font-weight:800;color:var(--low);margin-top:4px;\">{{ rs.exposure_reduction_pct | default(0) }}%</div>\n"
    "          </div>\n"
    "          <div style=\"padding:12px;background:var(--surface2);border-radius:8px;\">\n"
    "            <div style=\"font-size:.7rem;color:var(--muted);text-transform:uppercase;font-weight:600;\">Catastrophe cover (1-in-250)</div>\n"
    "            <div style=\"font-size:1.2rem;font-weight:800;margin-top:4px;\">R&nbsp;{{ '{:,.0f}'.format(rs.catastrophe_cover_zar | default(0)) }}</div>\n"
    "            <div style=\"font-size:.66rem;color:var(--muted);margin-top:2px;\">Unchanged &mdash; severity-driven</div>\n"
    "          </div>\n"
    "        </div>\n"
    "        {% endif %}\n"
    "        <!-- Impact summary strip -->\n"
)
assert s.count(OLD_MIT) == 1, ("Risk Mitigation cat-body anchor", s.count(OLD_MIT))
s = s.replace(OLD_MIT, NEW_MIT, 1)

# ---------------------------------------------------------------------------
# Validate + write (CRLF-preserving).
# ---------------------------------------------------------------------------
assert "\r" not in s
assert "Cyber-Risk Probability" in s
assert "Cover-Sizing Ladder" in s
assert "remediation_summary" in s

# Jinja2 syntax validation (parse only; no render).
try:
    from jinja2 import Environment
    Environment().parse(s)
    jinja_ok = "Jinja2 parse OK"
except ImportError:
    jinja_ok = "jinja2 not importable here - skipped (will validate on render)"

with open(HTML, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print(f"OK templates/results.html: item #17c renderers wired (prob card + cover ladder + remediation lead). {jinja_ok}")
