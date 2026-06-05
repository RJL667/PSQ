# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX one-off (task #14, step G): drop the cat-redesign methodology
paragraphs into the user manual.

part5_tech_compliance_insurance.py:
  * C1 cost component -> records-driven catastrophe liability (class-action anchor)
  * C2 cost component -> POPIA enforcement-anchored expected fine (0.02 x R5M)
  * C3 cost component -> BI downtime PERT(2,14,90)
  * Monte Carlo -> recovery PERT(2,14,90) + new 'Compound aggregation' section
    (loss-given-event tail) + systemic-supply-chain disclosure note
  * Probability model -> convex vulnerability curve + 0.30 LEF Cyentia anchor
  * DBI -> K3 credential-combination discount note
part4_exposure.py:
  * retire the stale 'see FIN-9 ... conditional LGB Pareto refinement' note.

CRLF-preserving, anchored count==1, mirrors _apply_item07/08/09*.py. NOT shipped.
"""
import os

MP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "manual_parts")
P5 = os.path.join(MP, "part5_tech_compliance_insurance.py")
P4 = os.path.join(MP, "part4_exposure.py")


def mutate(path, edits, inserts):
    s = open(path, encoding="utf-8").read()
    assert "\r" not in s, ("expected normalised buffer", path)
    for label, old, new in edits:
        n = s.count(old)
        assert n == 1, (path, label, "count", n)
        s = s.replace(old, new, 1)
    for label, anchor, block, where in inserts:
        n = s.count(anchor)
        assert n == 1, (path, label, "anchor count", n)
        if where == "before":
            s = s.replace(anchor, block + anchor, 1)
        else:
            s = s.replace(anchor, anchor + block, 1)
    assert "\r" not in s
    with open(path, "wb") as f:
        f.write(s.replace("\n", "\r\n").encode("utf-8"))


# ── part5 replacements ───────────────────────────────────────────────────────
p5_edits = [
    ("P5.C1-bullet",
     "    add_bullet(doc,\n"
     "        \"C1: Post-breach liability (residual) — notification costs, credit \"\n"
     "        \"monitoring, legal fees, reputational damage, and customer churn. \"\n"
     "        \"This is the residual after C2-C5 are allocated.\"\n"
     "    )\n",
     "    add_bullet(doc,\n"
     "        \"C1: Post-breach liability - notification costs, credit monitoring, \"\n"
     "        \"legal fees, reputational damage, and customer churn. The central \"\n"
     "        \"(expected-loss) view computes C1 as the residual of the IBM SA \"\n"
     "        \"breach anchor after C2-C5 are allocated. The catastrophe view \"\n"
     "        \"computes C1 instead as a records-driven stand-alone liability: a \"\n"
     "        \"realised catastrophe breach exposes approximately the full record \"\n"
     "        \"base, so catastrophe-C1 equals the estimated records held \"\n"
     "        \"multiplied by a per-record liability of R90, carrying a lognormal \"\n"
     "        \"heavy tail, floored at the central residual. The R90 figure is the \"\n"
     "        \"international class-action settlement anchor (Anthem approximately \"\n"
     "        \"R27, Capital One approximately R33 and Equifax approximately R53 \"\n"
     "        \"per affected person, plus legal and credit-monitoring load). For \"\n"
     "        \"smaller organisations the residual floor dominates; for large \"\n"
     "        \"consumer record-holders the records-driven term dominates.\"\n"
     "    )\n"),

    ("P5.C2-bullet",
     "    add_bullet(doc,\n"
     "        \"C2: Regulatory fines per jurisdiction — POPIA fines (up to \"\n"
     "        \"R10 million), GDPR exposure (4% of global turnover, uncapped) if \"\n"
     "        \"applicable, and PCI DSS fines if applicable. Jurisdiction-specific \"\n"
     "        \"calculations based on the scan input toggles.\"\n"
     "    )\n",
     "    add_bullet(doc,\n"
     "        \"C2: Regulatory fines per jurisdiction. The expected (P50) POPIA \"\n"
     "        \"figure is enforcement-anchored as the probability of a fine given \"\n"
     "        \"a breach (0.02) multiplied by the expected fine given that a fine \"\n"
     "        \"is levied (R5 million), giving R100 000 expected. Both inputs are \"\n"
     "        \"anchored to POPIA's entire administrative-fine record to date: two \"\n"
     "        \"Section 109 fines (Department of Justice 2023 and Department of \"\n"
     "        \"Basic Education 2024), each R5 million, both public-sector and \"\n"
     "        \"both for failure to comply with an enforcement notice, with zero \"\n"
     "        \"private-commercial fines. The catastrophe view uses the full \"\n"
     "        \"R10 million Section 109 statutory ceiling. GDPR exposure (4% of \"\n"
     "        \"global turnover, uncapped) and PCI DSS fines are added where the \"\n"
     "        \"scan input toggles indicate they apply.\"\n"
     "    )\n"),

    ("P5.C3-bullet",
     "    add_bullet(doc,\n"
     "        \"C3: Business interruption — revenue loss during recovery. Uses a \"\n"
     "        \"SA-calibrated PERT distribution for recovery time: PERT(3, 25, 120) \"\n"
     "        \"days, reflecting the Sophos SA 2025 finding that SA organisations \"\n"
     "        \"take a median of 25 days to recover from ransomware.\"\n"
     "    )\n",
     "    add_bullet(doc,\n"
     "        \"C3: Business interruption - revenue loss during recovery. The \"\n"
     "        \"Monte Carlo recovery-time distribution is PERT(2, 14, 90) days \"\n"
     "        \"(mode 14, mean approximately 24.7, maximum 90): the 14-day mode \"\n"
     "        \"reflects a good incident-response / Sophos Rapid Response \"\n"
     "        \"recovery, the approximately 25-day mean matches the Coveware and \"\n"
     "        \"IBM 2025 average of around 24 days, and the 90-day maximum is the \"\n"
     "        \"insurance indemnity-period cap. The central business-interruption \"\n"
     "        \"figure retains a 25-day point estimate, equal to the new \"\n"
     "        \"distribution mean.\"\n"
     "    )\n"),

    ("P5.mc-recovery-param",
     "        \"Key PERT parameters include SA recovery time PERT(3, 25, 120) \"\n",
     "        \"Key PERT parameters include SA recovery time PERT(2, 14, 90) \"\n"),
]

p5_inserts = [
    # Compound aggregation section + systemic-SC disclosure note, before Loss Exposure.
    ("P5.compound-section",
     "    add_h2(doc, \"Loss Exposure Scenarios (FAIS-safe cover sizing)\")\n",
     "    add_h2(doc, \"Compound aggregation for the catastrophe tail\")\n"
     "\n"
     "    add_body(doc,\n"
     "        \"The expected-loss and most-likely figures are computed by \"\n"
     "        \"probability-weighting each incident type (probability multiplied \"\n"
     "        \"by severity). For the return-period tail this construction is \"\n"
     "        \"replaced by a compound, loss-given-event aggregation: in each \"\n"
     "        \"simulated year every incident type either occurs (a Bernoulli \"\n"
     "        \"draw against its annual probability) or does not, and when it \"\n"
     "        \"occurs the full incident severity is realised rather than a \"\n"
     "        \"probability-scaled fraction. A catastrophe is a realised severe \"\n"
     "        \"year, and the severity of that year is independent of security \"\n"
     "        \"posture; posture changes the frequency of loss events, not the \"\n"
     "        \"size of a realised one. The compound mean equals the probability-\"\n"
     "        \"weighted expected loss, so the expected-loss and remediation \"\n"
     "        \"figures are unchanged; only the 1-in-100, 1-in-200 and 1-in-250 \"\n"
     "        \"return periods are taken from the compound distribution. This \"\n"
     "        \"prevents the catastrophe view from collapsing toward zero as an \"\n"
     "        \"organisation improves its posture: a realised data-breach or \"\n"
     "        \"ransomware event remains expensive even for a well-defended firm.\"\n"
     "    )\n"
     "\n"
     "    add_note(doc,\n"
     "        \"Supply-chain catastrophe is handled without double-counting. The \"\n"
     "        \"severity of a supplier-vectored breach is already inside the \"\n"
     "        \"records-driven C1 liability, and the supply-chain signal raises \"\n"
     "        \"the breach probability through a single vulnerability uplift. A \"\n"
     "        \"correlated systemic supply-chain catastrophe, in which many \"\n"
     "        \"insureds are compromised through one shared vendor (as in the \"\n"
     "        \"MOVEit 2023 event), is an accumulation risk that is disclosed and \"\n"
     "        \"managed at portfolio level rather than priced into an individual \"\n"
     "        \"insured's loss number, mirroring the South African Covid-19 \"\n"
     "        \"business-interruption precedent of disclosing rather than \"\n"
     "        \"modelling correlated systemic loss.\"\n"
     "    )\n"
     "\n",
     "before"),

    # Convex curve + 0.30 LEF Cyentia anchor, after the p_breach calibration body.
    ("P5.lef-anchor",
     "        \"factor aligns modelled probabilities with observed SA claims \"\n"
     "        \"frequencies.\"\n"
     "    )\n",
     "\n"
     "    add_body(doc,\n"
     "        \"Vulnerability is a convex function of the 0-1000 risk score, the \"\n"
     "        \"score divided by 1000 and raised to the power 1.8, so the \"\n"
     "        \"modelled breach probability accelerates only toward the Critical \"\n"
     "        \"band rather than rising linearly. The curve shape and the 0.30 \"\n"
     "        \"loss-event-frequency scalar are anchored to published breach-\"\n"
     "        \"likelihood evidence: the Cyentia IRIS small-and-medium-business \"\n"
     "        \"annual loss-event rate (under 2%), BitSight and Marsh rating-to-\"\n"
     "        \"incident absolutes (a rating above 700 corresponds to under 1%, \"\n"
     "        \"and below 500 to roughly 3%), and the SecurityScorecard A-to-F \"\n"
     "        \"breach-likelihood ladder, which is steeply convex. At a neutral \"\n"
     "        \"threat environment the calibrated curve places a well-postured \"\n"
     "        \"organisation under 2%, a mid-posture organisation around 5%, and \"\n"
     "        \"a Critical-posture organisation at 12% and above.\"\n"
     "    )\n",
     "after"),

    # K3 credential-combination discount, after the DBI tip.
    ("P5.k3-note",
     "        \"password reset combined with mandatory multi-factor authentication.\"\n"
     "    )\n",
     "\n"
     "    add_note(doc,\n"
     "        \"Credential signals are combined conservatively. When multiple \"\n"
     "        \"weaker credential indicators co-occur, their combined \"\n"
     "        \"contribution is discounted by a flat factor of 0.3 rather than \"\n"
     "        \"summed, reflecting the empirically low validity of leaked-\"\n"
     "        \"credential corpora in credential-stuffing attacks (roughly 1 to 3 \"\n"
     "        \"per cent of leaked pairs still authenticate). Recency of \"\n"
     "        \"publication is deliberately not used as a freshness proxy, \"\n"
     "        \"because the publication date of a breach list is not the age of \"\n"
     "        \"the underlying credentials.\"\n"
     "    )\n",
     "after"),
]

mutate(P5, p5_edits, p5_inserts)
print("OK part5_tech_compliance_insurance.py: cat-redesign methodology paragraphs added.")


# ── part4: retire the stale FIN-9 conditional-LGB-Pareto note ────────────────
p4_edits = [
    ("P4.fin9-retire",
     "        \"lies in the 12-20% band. The FAIR model under-estimates \"\n"
     "        \"loss-given-breach for the 12% SC-vectored slice — see \"\n"
     "        \"FIN-9 in the gap analysis for the conditional LGB Pareto \"\n"
     "        \"refinement that addresses this.\"\n",
     "        \"lies in the 12-20% band. The catastrophe model captures this \"\n"
     "        \"loss-given-breach severity through the records-driven C1 \"\n"
     "        \"liability (a supplier-vectored breach still exposes the \"\n"
     "        \"insured's full record base), and discloses correlated systemic \"\n"
     "        \"supply-chain catastrophe at portfolio level. The earlier \"\n"
     "        \"conditional-Pareto loss-given-breach widening was retired to \"\n"
     "        \"keep one signal mapped to one channel and avoid double-counting.\"\n"),
]
mutate(P4, p4_edits, [])
print("OK part4_exposure.py: stale FIN-9 conditional-LGB note retired.")
