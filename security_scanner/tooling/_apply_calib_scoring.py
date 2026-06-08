# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX calibration mutator (2026-06-05) for scoring_analytics.py. Three
targets, CRLF-safe (text-mode read normalises \\r\\n -> \\n; binary write restores):

  T1  Cyber-incident posture bands 5/15/30 -> 8/18/28 + honest relative relabel.
      Keeps p_ransomware = rsi x 0.30 (consistent with the ALE incident-type
      probabilities); the true-frequency recast belongs with the colleague-gated
      RW_LEF / warm-annual-loss item and is NOT done here.
  T2  SPF/DMARC remediation probability_reduction: 0.08/0.04/0.02 -> 0.06/0.03/
      0.015 (4:2:1 retained) + No-DKIM 0.02 -> 0.015 (ladder consistency).
  T3  p_interruption FAIR re-anchor: base 0.05 -> 0.03, noWAF 0.05 -> 0.015,
      noCDN 0.05 -> 0.035, singleASN 0.05 -> 0.025, cap 0.50 -> 0.18; basis text.

NOT shipped by this script - run, then 2-step gate, then route via local master."""
import ast, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SA = os.path.join(ROOT, "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised content"
n = 0

# ── T1a: _CYBER_INCIDENT_BANDS tuple + header comment ──────────────────────
OLD = (
    "# Provisional total cyber-incident bands (multi-channel: breach + ransomware).\n"
    "_CYBER_INCIDENT_BANDS = (\n"
    "    (5.0, \"Low\"), (15.0, \"Typical\"), (30.0, \"Elevated\"), (float(\"inf\"), \"High\"),\n"
    ")\n"
)
NEW = (
    "# Relative multi-channel cyber-incident posture bands (breach + ransomware).\n"
    "# Re-fit 2026-06-05: 5/15/30 -> 8/18/28 so a genuinely low-risk posture can\n"
    "# reach 'Low' (the old <5% Low band was practically unreachable once the\n"
    "# ransomware channel is included). RELATIVE-posture bands: the combined rate\n"
    "# sits ABOVE per-org material-incident claims frequency (Coalition 2025\n"
    "# 1.2%/yr <$25M -> 5.7%/yr >$100M; Cyentia IRIS <2% SMB) because the\n"
    "# ransomware loss-event-frequency lever (RW_LEF) is pending the warm-annual-\n"
    "# loss recalibration (colleague-gated). Read as relative posture, not a\n"
    "# calibrated annual claim rate; a frequency-calibration pass is recorded next.\n"
    "_CYBER_INCIDENT_BANDS = (\n"
    "    (8.0, \"Low\"), (18.0, \"Typical\"), (28.0, \"Elevated\"), (float(\"inf\"), \"High\"),\n"
    ")\n"
)
assert s.count(OLD) == 1, ("T1a bands tuple", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# ── T1b: inline bands list in the cyber_incident output dict ───────────────
OLD = (
    "                    \"bands\": [\n"
    "                        {\"upper_pct\": 5, \"grade\": \"Low\"},\n"
    "                        {\"upper_pct\": 15, \"grade\": \"Typical\"},\n"
    "                        {\"upper_pct\": 30, \"grade\": \"Elevated\"},\n"
    "                        {\"upper_pct\": None, \"grade\": \"High\"},\n"
    "                    ],\n"
)
NEW = (
    "                    \"bands\": [\n"
    "                        {\"upper_pct\": 8, \"grade\": \"Low\"},\n"
    "                        {\"upper_pct\": 18, \"grade\": \"Typical\"},\n"
    "                        {\"upper_pct\": 28, \"grade\": \"Elevated\"},\n"
    "                        {\"upper_pct\": None, \"grade\": \"High\"},\n"
    "                    ],\n"
)
assert s.count(OLD) == 1, ("T1b inline bands", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# ── T1c: band_anchor honest relabel ────────────────────────────────────────
OLD = (
    "                    \"band_anchor\": (\n"
    "                        \"PROVISIONAL multi-channel bands (not yet firm-anchored). \"\n"
    "                        \"The breach band is deliberately NOT reused - that \"\n"
    "                        \"mislabels a typical multi-channel rate as 'High'.\"\n"
    "                    ),\n"
)
NEW = (
    "                    \"band_anchor\": (\n"
    "                        \"Relative multi-channel posture bands (8/18/28). The \"\n"
    "                        \"combined breach+ransomware rate sits above per-org \"\n"
    "                        \"material-incident claims frequency (Coalition 2025 \"\n"
    "                        \"1.2%/yr <$25M to 5.7%/yr >$100M; Cyentia IRIS <2% SMB) \"\n"
    "                        \"because it aggregates both channels as an index; read \"\n"
    "                        \"as relative posture, not a calibrated annual claim rate. \"\n"
    "                        \"A frequency-calibration pass (ransomware LEF) is next.\"\n"
    "                    ),\n"
)
assert s.count(OLD) == 1, ("T1c band_anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# ── T2: SPF/DMARC remediation magnitudes (4 values + 2 comment blocks) ─────
OLD = "\"probability_reduction\": 0.08, \"label\": \"Implement email authentication (SPF/DMARC/DKIM)\"}"
NEW = "\"probability_reduction\": 0.06, \"label\": \"Implement email authentication (SPF/DMARC/DKIM)\"}"
assert s.count(OLD) == 1, ("T2 absence rung", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

OLD = (
    "        # DMARC published but NOT enforcing (p=none): the primary anti-spoofing\n"
    "        # control is in monitor-only mode (BEC vector). probability_reduction\n"
    "        # CONSERVATIVE + CALIBRATION-GATED - half the full-absence rung (0.08),\n"
    "        # double the SPF-qualifier rung (0.02); CISA BOD 18-01 / NIST SP 800-177\n"
    "        # / M3AAWG target p=reject. Unconditional (nothing above DMARC moots it).\n"
    "        {\"pattern\": r\"DMARC policy is 'none'\",                \"severity\": \"High\",     \"scenario\": \"data_breach\",            \"probability_reduction\": 0.04, \"label\": \"Enforce DMARC (move policy from p=none to quarantine or reject)\"},\n"
)
NEW = (
    "        # DMARC published but NOT enforcing (p=none): the primary anti-spoofing\n"
    "        # control is in monitor-only mode (BEC vector). probability_reduction\n"
    "        # CALIBRATED 2026-06-05 (0.04 -> 0.03): half the full-absence rung\n"
    "        # (0.06), double the SPF-qualifier rung (0.015). Scale cut ~25% from the\n"
    "        # provisional set because DMARC enforcement only blocks EXACT-domain\n"
    "        # spoofing - a minority of the phishing/BEC surface (DBIR 2025: phishing\n"
    "        # = 16% of breaches; lookalike / display-name / ATO route around DMARC).\n"
    "        # The 4:2:1 ratio is retained. CISA BOD 18-01 / NIST SP 800-177 / M3AAWG\n"
    "        # target p=reject. Unconditional (nothing above DMARC moots it).\n"
    "        {\"pattern\": r\"DMARC policy is 'none'\",                \"severity\": \"High\",     \"scenario\": \"data_breach\",            \"probability_reduction\": 0.03, \"label\": \"Enforce DMARC (move policy from p=none to quarantine or reject)\"},\n"
)
assert s.count(OLD) == 1, ("T2 dmarc p=none", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

OLD = "\"probability_reduction\": 0.02, \"label\": \"Enable DKIM signing on your mail server\"}"
NEW = "\"probability_reduction\": 0.015, \"label\": \"Enable DKIM signing on your mail server\"}"
assert s.count(OLD) == 1, ("T2 dkim rung", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

OLD = (
    "        # SPF present but non-enforcing (~all/?all) with no enforcing DMARC -\n"
    "        # harden to -all. probability_reduction CONSERVATIVE + CALIBRATION-GATED\n"
    "        # (anchored to the secondary email-hardening rung; tune at calibration).\n"
    "        {\"pattern\": r\"SPF ends with '[~?]all'\",          \"severity\": \"Medium\",   \"scenario\": \"data_breach\",            \"probability_reduction\": 0.02, \"label\": \"Harden SPF to a hard-fail policy ('-all')\"},\n"
)
NEW = (
    "        # SPF present but non-enforcing (~all/?all) with no enforcing DMARC -\n"
    "        # harden to -all. probability_reduction CALIBRATED 2026-06-05 (0.02 ->\n"
    "        # 0.015): the lowest email-auth rung (= No-DKIM), 1/4 of the absence\n"
    "        # rung (0.06). SPF hard-fail without DMARC = no From-alignment, no\n"
    "        # reporting; necessary-not-sufficient (NIST SP 800-177; M3AAWG).\n"
    "        {\"pattern\": r\"SPF ends with '[~?]all'\",          \"severity\": \"Medium\",   \"scenario\": \"data_breach\",            \"probability_reduction\": 0.015, \"label\": \"Harden SPF to a hard-fail policy ('-all')\"},\n"
)
assert s.count(OLD) == 1, ("T2 spf qualifier", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# ── T3a: p_interruption FAIR re-anchor ─────────────────────────────────────
OLD = (
    "        p_interruption = min(0.5, 0.05\n"
    "                             + (0.05 if not waf_detected else 0)\n"
    "                             + (0.05 if not cdn_detected else 0)\n"
    "                             + (0.05 if single_asn else 0))\n"
)
NEW = (
    "        # FAIR-anchored 2026-06-05. Base = Uptime Institute AOA serious/severe\n"
    "        # outage rate (~3%/yr). Increments reflect the availability-relevant\n"
    "        # control gaps: CDN/DDoS-mitigation is the PRIMARY lever (+0.035),\n"
    "        # multi-homing / hosting redundancy secondary (single ASN +0.025), and\n"
    "        # WAF is L7-flood ONLY (+0.015) - most volumetric DDoS is mitigated at\n"
    "        # the CDN edge, not the WAF ruleset, so WAF is no longer the largest\n"
    "        # availability term. Cap 0.18 (even fully-exposed self-hosted single-\n"
    "        # homed orgs sit ~10-12%/yr empirically). Base FAIR-anchored; per-\n"
    "        # control increments directional.\n"
    "        p_interruption = min(0.18, 0.03\n"
    "                             + (0.015 if not waf_detected else 0)\n"
    "                             + (0.035 if not cdn_detected else 0)\n"
    "                             + (0.025 if single_asn else 0))\n"
)
assert s.count(OLD) == 1, ("T3a p_interruption", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# ── T3b: availability card definition + basis ──────────────────────────────
OLD = (
    "                        \"policy and over time). Heuristic; NOT a calibrated \"\n"
    "                        \"probability.\"\n"
    "                    ),\n"
)
NEW = (
    "                        \"policy and over time). Base FAIR-anchored to outage \"\n"
    "                        \"data; per-control increments directional.\"\n"
    "                    ),\n"
)
assert s.count(OLD) == 1, ("T3b card definition", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

OLD = (
    "                    \"basis\": (\n"
    "                        \"Heuristic over WAF / CDN / single-ASN / DNSBL \"\n"
    "                        \"availability signals. Indicative-only pending FAIR \"\n"
    "                        \"re-anchoring (deferred).\"\n"
    "                    ),\n"
)
NEW = (
    "                    \"basis\": (\n"
    "                        \"FAIR-anchored base (Uptime Institute AOA serious/severe \"\n"
    "                        \"outage rate ~3%/yr) plus availability-control increments: \"\n"
    "                        \"CDN/DDoS-mitigation (primary), hosting redundancy / \"\n"
    "                        \"multi-ASN (secondary), WAF (L7-flood only). Base \"\n"
    "                        \"FAIR-anchored; per-control increments directional.\"\n"
    "                    ),\n"
)
assert s.count(OLD) == 1, ("T3b card basis", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

ast.parse(s)
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(SA, encoding="utf-8").read())
print(f"OK scoring_analytics.py: {n} calibration edits applied (T1 bands+anchor, "
      f"T2 4 magnitudes, T3 p_interruption+card). AST valid, CRLF restored.")
