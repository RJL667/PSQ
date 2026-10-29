# Underwriting nuances (from the underwriter, 2026-10-15)

## Training plan
- File high-confidence conversations only; the 4 medium-confidence ones wait until training has progressed.
- Work from the most recent month backwards, 10 cases per batch.
- Build confidence in form reading and mapping first. Pricing reductions come later.

## Primary goal
- Test and train the proposal / risk assessment form tool.
- Build a database of each competitor form in the market (insurer, form version, question layout).
- Map every competitor form accurately against Phishield's questionnaire rows and conditions of cover.

## Discount nuance
- The typical maximum MDR discount passed on SOEs is about 15%, even when the requirement is
  Sophos MDR Complete with endpoints deployed. (Underwriter to confirm the exact figure.)
- The rater's price-sheet tiers currently allow up to 30% (Complete with endpoints). An SOE cap
  needs to be applied on top of that.

## SOE / public admin cap (confirmed 2026-10-15)
- Max MDR discount 15% applies to every risk rated as public administration that carries the
  Sophos MDR condition of cover (SOEs, municipalities, water boards, public entities).

## Ground truth for every case
- The instruction email to the quoting assistant states premium, benefits and requirements.
- The conditions listed there are the minimum-requirement conditions still outstanding after the
  underwriter's assessment. No conditions listed = the client meets all our criteria.
- Questions in that email = information the underwriter still lacked (extra source of truth).
- Competitor forms: map each with a confidence level of what is covered vs missing against our form.
- OCR must be highly accurate: many forms (ours included) arrive as scans.

## Relaxed requirements
- Some quotes relax our form's requirements. This is a mandate-based judgement call, driven by:
  - industry and sub-industry
  - cover limit requested
  - size of the business (turnover)
- Each case should record which conditions were relaxed and why, so the pattern can be learned.

## Compensating controls (case b1_02, 2026-10-15) · defensible positions, not hard rules
- Password policy: testing for known / easily guessable passwords is enough for a mid-size, lower-risk industry, even with short minimum length.
- MFA on remote access: judge by lateral movement. VPN-only remote access with no elevated rights on employee accounts can relax the MFA requirement for this type of business.

## Discretionary discount
- Competing directly against an incumbent policy (iTOO incumbent): 15% discretionary discount (underwriter,
  2026-10-16), entered in the workbook's MDR cell because the sheet has no discretionary column.

## MDR discount evidence (underwriter, 2026-10-16)
- Quick test for whether an MDR discount was passed: the quotation's Conditions of Cover carries a
  line referring to Sophos MDR, or a comparable MDR alternative the client must specify.
  Typical wording: "Sophos MDR Complete deployed on all access devices and entire network, with
  endpoints deployed, or comparative Managed, Detection and Response program in place; if so, please specify."
- An EDR / ETDR condition is NOT an MDR condition and is no evidence of an MDR discount.
- The quote's "Policy Disclosure: Do you have Sophos MDR in place?" answer is the client's current
  state, not the discount. It reads No on every batch 1 quote, including b1_07, which carries the condition.
- Batch 1 applied (quotation PDFs in casebook/quotes/):
  - b1_07 / b1_08 R50M: Sophos MDR Complete with endpoints condition, so MDR discount passed
    (public admin cap 15% applies).
  - b1_01, b1_04: EDR condition only, so no MDR discount.
  - b1_05 R15M: no MDR condition, so no MDR discount. Confirms the earlier 15% MDR brute-force fit was wrong.
  - b1_10 SEO Agency: SME quote, no conditions section.
  - b1_02 R5M/R10M: no MDR condition on the quote. RESOLVED (underwriter, 2026-10-16): the 15% was a
    discretionary discount to compete with the incumbent iTOO quote. The workbook has no discretionary column,
    so the underwriter used the pre-built MDR discount cell as a stand-in. No condition was ever required.
- Reading old workbook snapshots: an MDR discount in the sheet WITHOUT an MDR condition on the quote is a
  discretionary discount entered through the MDR cell. Record it as discretionary, not MDR.
- New quotes: the corporate rater has its own discretionary input (applied to the final premium, after MDR),
  as the SME rater does. MDR is selected only when the MDR condition goes on the quote; discretionary is entered
  separately, so the MDR-cell workaround does not carry over.

## Excess below R500k (underwriter, 2026-10-16)
- TRAINING AND GOAL-SEEK ONLY: the workbook's first excess tick is R500k, so a past quote with a smaller excess
  was rated at R0 or R500k. Try both when reproducing old quotes.
- NEW QUOTES: use the exact excess requested; the rater's any-amount excess credit already prices it. Do not
  round to R0 or R500k.

## Rating basis, RM fee and Aon bursary (underwriter, 2026-10-15)
- Relaxations and compensating controls are positions to argue from, not hard rules.
- Rate on the questionnaire posture only when the client answered (nearly) all of our questions: our form filled in completely, or a competitor form asking the same things. Otherwise rate Average (Moderate, x1.00), assuming the minimum conditions are in place.
- A question the form does not ask is never penalised in the band. It only feeds the conditions gate: find out whether the minimum requirement is met.
- Quotes are given WITHOUT the 6% RM fee (rater final / 1.06). Flag this clearly on every quote, as the SME rater does.
- Aon: quote the full premium (no RM fee) and show the risk bursary = 10% of net premium = full x 0.8 x 10% (workbook Summary E36). Wording: "This quotation includes a 10% risk bursary based on net premium."

## CORRECTION 2026-10-15: b1_02 reproduced exactly from the underwriter's workbook snapshot
Earlier entries said b1_02 was Very Weak less a 10% discretionary discount. That was wrong: it rested on the
wrong industry (the instruction email says Services > Miscellaneous; the workbook was rated Services > Hotels,
Rooming Houses, Camps And Other Lodging Places).
Actual rating basis, both options exact to the cent:
- Sub-industry: Services > Hotels. Turnover R1,137,000,000.
- Maturity: Moderate (Average), set manually by the underwriter after reading the form. The workbook's computed band (Very Strong on the snapshot) is meaningless: the questionnaire mapping in the spreadsheet was never completed, so the maturity is ALWAYS a manual override. Never read the workbook's computed posture as evidence.
- Excess rated: R500,000 on both options (the email states R100k / R200k).
- Funds Protect: standard (10% of cover). Computer Crime and PCI unticked.
- Discount: 15% discretionary (entered in the workbook's Sophos Essentials MDR cell, no MDR condition). In the
  rater: No MDR + 15% discretionary gives the same premium.
- R5M: final R161,408.22, without RM fee R152,271.91. R10M: final R201,142.58, without RM fee R189,757.15.
Lessons: take the industry from the form's business description, not the email label; the Average rule held.

## Maturity band source (underwriter, 2026-10-15)
- On the corporate workbook the maturity band is always a manual override from the underwriter reading the form. The spreadsheet's computed posture is unused because its questionnaire mapping was never finished.
- For training and goal-seek, compare the rater's band to the underwriter's override only, never to the workbook's computed band.

## PCI Fines and Penalties (underwriter, 2026-10-15)
- Not needed: the client says it stores or holds no card data (0 card records, or card number, expiry and security code all No) and the card-processing section is blank.
- Needed: the form shows stored card data (a storage question Yes, or a PCI merchant level).
- Anything else is a question to the client, never a silent decision. Typical case: card section left blank with no "no card data" statement, which looks like an oversight.
- Encoded in formdb/pci_rules.json and formdb/pci_check.py. Batch 1: b1_02 and b1_04 not needed; b1_07 ask (blank Annexure D); b1_01, b1_05 and the b1_04 competitor form ask (form not readable or not mapped).

## BI time excess (underwriter, 2026-10-15)
- Business Interruption and Contingent BI carry a time excess (waiting period) in 12-hour steps, not the rand excess.
- The workbook does not price the waiting period. BI's loading stays inside the rand-excess credit exactly as the workbook does it.
- Rating a longer waiting period is possible later, from BI's financial impact on the client, but needs the scanner wired in with a scan available. Not feasible now.
- Rater: BI shows "time" in the Excess column; BI and CBI waiting periods are recorded on the quote and PDF, with no price effect.

## PCI vs records held (underwriter, 2026-10-15)
- A client can hold records (PII) and still take cards through a merchant or processor without holding card data. That does not trigger PCI Fines and Penalties.
- Card storage answers decide it, not the record count. b1_04: 'less than 100' records, card number, expiry and security code all No; underwriter quoted PCI N/A on R50M and R60M.

## Contingent BI on SOEs (underwriter, 2026-10-15)
- Most state-owned enterprises (SOEs) are quoted WITHOUT Contingent Business Interruption.
- Reason: their revenue is government funding, so they do not depend on other service providers for revenue. CBI covers loss from a supplier or provider outage, which is not their exposure.
- Evidence: the annual financial statements often show it (government grants, transfers or allocations as the main revenue line).
- Position to argue from, not a hard rule. If the AFS shows material trading revenue that depends on third-party providers, CBI can still be offered. If revenue source is unclear, ask the client or broker.

## Revenue confirmation when the form is half-filled (underwriter, 2026-10-15)
- Some broker requests come with the financial section of the form blank but with AFS attached. Turnover must then be confirmed from another source before rating.
- Order: (1) total revenue from the attached AFS, stating the source and year on the quote; (2) a basic public search (annual or integrated report, municipal or treasury data); (3) if still not enough, flag it to confirm via BizPortal / CIPC or ask the broker.
- Check the AFS is for the trading entity. b1_07 attached its Provident Fund AFS, which cannot confirm the client's revenue.
- Scanned AFS need OCR first (rv_025).
- The AFS grant share also feeds the SOE Contingent BI position: mostly government-funded revenue supports quoting without CBI.
- Encoded in formdb/revenue_check.py.

## SOE turnover always checked (underwriter, 2026-10-15)
- SOEs sometimes understate turnover to get a better rate. Their turnover is ALWAYS checked against a documented figure (AFS or public annual report), even when the form is filled in.
- SOE signals: client name (SOC, water board, municipality, agency, authority, board), industry (Public Admin / government), or public-sector reporting in the AFS (GRAP, PFMA, MFMA, non-exchange transactions).
- If the form figure is more than 25% below the documented figure, rate on the documented figure or ask the broker to explain (underwriter set 25%, 2026-10-15).
- The public search runs as part of the routine on every case (required for SOEs and blank forms, recommended otherwise). The user is asked to confirm the figure with a separate search of their own until the routine has learned enough to run unattended.
- b1_07 test: form blank, AFS was the Provident Fund, public search gave R7.70bn (2023/24), which agrees with the R7.6B quoted on.
- Encoded in formdb/revenue_check.py.

## Contingent BI grant threshold (underwriter, 2026-10-15)
- A BI claim runs 15-30 days in practice and 3 months at most. The scanner agrees: 25 recovery days at 50% average revenue loss for ransomware and wipers, 1-5 days for acute outages and DDoS.
- So if government grants in the AFS cover more than about a month of revenue (30/365 = 8.2%, roughly 1/12), Contingent BI is not included automatically.
- Below that, CBI is included at its standard sublimit: 50% of the BI limit (policy wording). The 30-day threshold only decides WHETHER CBI is included; it never changes the CBI amount.
- Encoded in formdb/revenue_check.py (CBI_GRANT_DAYS = 30).

## Form-mapping rulings (underwriter, 2026-10-16)
Full table in formdb/uncertainty_register.md section A2; condition detail in formdb/security_controls_kb.md.
- Vulnerability remediation: needs a timely plan for identified vulnerabilities. Scan done / regular scans matter most; also remediation time and prioritisation (CVSS, exploitability). A policy alone does not meet it.
- EDR: a reasonable, active endpoint protection programme with supporting identifiers (malware blocking, heuristics). No named product required.
- Backups: regular backups at least weekly (the norm). Bi-weekly is an underwriter relaxation only for low-connectivity risks (e.g. manufacturing) or little PII / PHR / employee data, never assumed by the rater. Second level: a separate set removed from production or immutable (preferably both). iTOO immutable / air-gapped alone meets the second level. Regular backups alone never do, because attackers corrupt failsafe backups before striking. Strict on relaxing; depends on type and size.
- Firewall: IDS scores only; NGFW at breakout points meets the condition but does not score DMZ isolation.
- Awareness training: at least annually. No frequency given: ask, or put it in the conditions of cover.
- Pen test: no last-test date, or a date over a year old with no future test booked, does not count.
- Old-form downtime "Weeks" = 48 hours (no real BI claim risk).
- Industry stringency: never relax for public admin / government. Healthcare by type, size, revenue and PHR count (hospitals > practitioners > laboratories; large PHR base = high standard even at low turnover). Legal by PII count. Finance by PII, revenue and type. Payment processors, insurers, banks, trading platforms: highest standard regardless of size.

## BI / CBI time excess default (underwriter, 2026-10-16)
- BI and Contingent BI always carry the same waiting period unless the client asks otherwise.
- 12 hours if the client states 12 hours, or for a smaller business. Otherwise 24 hours is the norm, unless the client ticked 36 or 48 hours on our form.

## Blank minimum-condition questions (underwriter, 2026-10-16)
- A minimum-condition question left blank on a form that asks it is read as No.
- It goes on the quote as a condition of cover, and the client is asked to confirm it.
- The posture is NOT penalised: the row is scored as if the condition is met, like any other condition of cover.
- A question the form never asked stays "information required" (ask the broker); nothing is assumed.
- MDR conditions are never assumed from a blank, because MDR answers drive the discount.
- Encoded in Corporate Rating Engine/questionnaire.py: context left_blank (True for our own form, or a list of rows),
  result field confirm_with_client. Test: test_blank_minimum_condition_is_a_condition_of_cover_not_a_penalty.

## SME to corporate switch (underwriter, 2026-10-28)
- Funds Protect: the SME FP limit maps to the corporate AUTHORISED limit. The corporate unauthorised limit is double the authorised, at the standard FP rates. That doubling is the corporate differentiator, not an extra charge.
- Benefits: SME is a standard package (apart from FP); corporate benefits are selectable. Untick a benefit the client has no exposure to, e.g. PCI Fines and Penalties when no card data is stored. Do not carry PCI over just to match the SME schedule.
- Excess: set by the underwriter per client; for an Oct 2026 corporate renewal it was 0.5% of cover (R75,000 on R15M). Treat 0.5% of cover as a starting point to ask about, not a rule.
- Product fit: Software & Technology at R100M+ turnover is better placed on the corporate form and policy, even though it still fits the top of the SME range.
- Market softened (Oct 2026): renewal moving SME to corporate must price below the current premium.
- Brokers who only know the SME rater get the corporate price worked out by us.

## SME minimum requirements (underwriter, 2026-10-28)
- At the very least, especially for SME: weekly backups, one backup set immutable or completely removed from production, and MFA for privileged accounts.
- SME loadings for "No" answers apply only while the client has these main conditions of cover in place.

## Posture bands not yet calibrated (open)
- The questionnaire posture-to-band thresholds are untrained. Scored forms land in Weak / Very Weak far more often than underwriters rate in practice.
- Until the posture points are re-tuned, price corporate quotes at Moderate (Average) and record the scored band only as information.

## Incident response plan condition for small businesses
- Drop the "IR plan tested annually with executive participation" condition when the business is small enough that the executive sits close to day-to-day operations (e.g. a ~R100M turnover owner-run company). Executive participation is then implicit, so the condition adds nothing.

## Backup frequency left blank on the form
- When the form shows onsite and offsite backups and a set that is immutable or isolated from production, but the frequency question is blank, do not impose the full backup condition. Keep "Data backups are done at least weekly" and add "(please confirm the frequency, as it wasn't filled out on the form)" next to it.

## EDR condition on SME-to-corporate upgrades (existing clients)
- When an existing SME client renews onto the corporate product and the corporate form answers No to EDR/ETDR, keep the EDR condition, but add a note asking the team to confirm with the broker/client that the in-force SME minimum requirement is in place. The SME requirement (proposal Q1 / Q1.1) is: a comprehensive, paid-for internet security software subscription, installed and up to date on all computer systems and access devices, including antivirus/anti-malware with real-time endpoint detection and response (EDR).
- Reason: the client already had to meet the SME minimum requirements under the in-force policy, so endpoint protection is likely in place; the corporate form's No may reflect the stricter corporate wording (e.g. 75% coverage) rather than no protection at all.

## Cyber threat intelligence and vulnerability management conditions
- Do not impose "a cyber threat intelligence capability" as a condition of cover. Phishield will provide threat intelligence on the client's behalf through the scanner's continuous scans once those are in production.
- When the form says Yes to "a defined process for remediating vulnerabilities" but No to "a formal proactive vulnerability management program", the condition is: a formal, proactive vulnerability management program is in place, OR the client explains how the stated remediation process is quantified (e.g. scan frequency, time to patch critical vulnerabilities). Either is sufficient. Scanner reports can help the client meet this.

## Firewall evidence in the corporate form's vendor/security-tools table
- Before asking the broker to confirm a firewall, check the security tools / third-party vendor table on the corporate form (Section 10 area). A named next-generation firewall vendor listed there (e.g. "Firewall | Yes - {vendor}") counts as the firewall being in place and filtering both ways; do not add a broker confirmation for it. The same table may also show IPS/IDS and antivirus services, which supports the endpoint protection note.

## Quote instructions: repeat condition notes in the broker paragraph
- Any explanatory note attached to a condition of cover (e.g. "please confirm the frequency", "confirm the in-force SME requirement", "confirm how the process is quantified") must ALSO be repeated as a short bullet list in the paragraph addressed to the team member who liaises with the broker. That person confirms these points with the broker and mostly reads that paragraph, so the duplication is intentional. Keep the note in the conditions list as well.

## RDP / high-risk protocols answered No: clarify before imposing
- Our corporate form asks one Yes/No ("Are high-risk protocols (e.g. RDP, SMBv1) disabled externally?"). A client whose firewall only accepts RDP over VPN plus MFA has to answer No, although the risk is controlled.
- So a No here is not an automatic condition. Keep the condition, but add "(please confirm whether these can be reached from outside the network at all, and if so, whether only through VPN plus MFA)" and repeat it in the broker-liaison paragraph.
- If the broker confirms RDP/SMB is reachable only via VPN plus MFA, drop the condition. Cross-check the form's own remote-access answer (VPN and MFA for remote access) and the scanner's external port findings; a contradiction is a conflict to raise.
- iTOO forms split this into three questions: (1) FTP/SSH/SNMP/RDP/SMB only available via VPN plus MFA; (2) FTP/SSH/RDP/Telnet/SNMP/SMB/SMTP blocked on externally exposed systems; (3) remote-access tick list (RDP blocked externally, VPN, MFA, ZTNA, pre-login device check). Candidate questionnaire tweak.
- Open: compare AIG and Aon wording when their forms come up in the systematic quote review.
- Refinement: when the form answers No to BOTH "high-risk protocols disabled externally" AND "VPN and MFA used for remote access", RDP is unlikely to sit behind VPN plus MFA, so the condition is likely to stand. Keep the condition plain in the conditions list (no bracketed note) and put the clarifying question only in the broker-liaison paragraph, stating that both answers are No and the condition is likely to remain. Use the bracketed note in the conditions list only when the remote-access answer is Yes or unclear.

## SME to corporate conversion: public administration (underwriter, 2026-10-29)
- Quote every cover limit the broker requests as separate options (check the request itself; do not carry limits over from another open quote).
- Corporate limits are full benefits unless the client stipulates otherwise, except Contingent BI, which is 50% of the BI limit (policy wording). SOE rule still removes Contingent BI when grants dominate revenue.
- Funds Protect at the standard inclusion: 10% of the limit authorised, 20% unauthorised.
- Excess for public administration: at least 2% of the limit; the target is 5%+, but step up gradually when converting an existing SME policy.
- Rate on the documented turnover (AFS), not the SME band ticked on the form, and state the revenue in the quote instruction.
- Old SME community-rated premium was R921 pm (R11,052 p/a); a broker figure of 12x that is an annual-vs-monthly error.

## Government-owned entities priced as public admin: Sophos MDR first (underwriter, 2026-10-29)
- A client owned or funded by a national, provincial or local government body (e.g. a provincially owned theatre) carries the same risk profile as an SOE, even when its own industry looks like arts or services.
- Put the Sophos MDR condition on the quote: "Sophos MDR Complete deployed on all access devices and entire network, with endpoints deployed, or comparative Managed, Detection and Response program in place; if so, please specify." Price with the MDR discount, capped at 15% for public admin / SOE.
- Tell the broker-liaison team member that the MDR route is tried first and may be relaxed if the client pushes back; give the no-MDR rate as the fallback.
- Applied: an Oct 2026 public-administration SME-to-corporate conversion (R5M).

## Corporate quotes below the R250M revenue floor (hybrid rule)
- Scope (underwriter, 29.10.2026): this is a candidate method for a NEW below-floor quote, shown with the SME comparison for the underwriter to choose. It never overrides an instructed rate and is never used to reprice a quote already sent. Sent instructions are final and are the target to reproduce exactly when training on past quotes, using the attached forms and the underwriter's guidance.
- When a corporate quote is for a turnover below R250M, do not run the corporate rater on the actual turnover. Rate at R250M turnover with all the same inputs (industry, posture, benefits, Funds Protect, waiting periods, excess, MDR, discretionary) and take the final premium incl. RM (C36).
- When it applies (underwriter, 30.10.2026): only when the policy is to be issued on the corporate wording and benefits, but the turnover is too low to rate straight on the corporate rater. Mostly new quotes.
- Multiply by the ratio: SME annual premium on the client's ACTUAL turnover (SME rater, not the band top) / SME annual premium at R250M (band R200M-R250M), same cover limit, both with matching Funds Protect. The ratio measures how far the client sits below the corporate rater's R250M floor, where the corporate rater becomes accurate.
- Conversion of our own existing SME policy to corporate at renewal: a 15-20% increase over the current premium is usually defensible (higher Funds Protect where it differs, plus the broader corporate benefits). Compare the hybrid to the current premium: if the hybrid is 15-20% above it, use the hybrid; if not, use the SME rater +20% with benefits matched to the corporate quote (usually the Funds Protect change, but not always). No softening-market discount on a conversion; that applies only to a like-for-like SME renewal.
- Excl. RM = result / 1.06; monthly excl. RM = excl. RM / 12.
- Worked checks: R5M 55,609.74 x (33,396 / 37,368 = 0.8937) = 49,698.42; R15M 78,719.18 x (58,524 / 65,028 = 0.9000) = 70,847.26.
- Not yet encoded in corporate-engine.js; apply in the case pricing script. Source ledger: PROGRESS_hybrid_cases.md rule 3.
- Below R250M the straight corporate rater must NEVER be used for the quote; it reads too low. The hybrid was the method chosen for a group quote on 29.10.2026; for other below-floor quotes it is a candidate the underwriter chooses, not a fixed rule.
- The SME premiums used for the band ratio must carry the SAME Funds Protect as the corporate quote. The Standard Premium Tables include only the standard (minimum) FP: R250k (R3,144) at R5M, R1M (R9,108) at R10M, R1.5M (R15,756) at R15M. With corporate FP at 10% of limit, swap the table FP for the matching SME FP cost in BOTH bands before dividing (R5M: -3,144 +4,800 for R500k; R10M: no change).
- On every below-floor quote, run a comparison for context: SME rater price on actual turnover with matching FP, plus 15% and plus 20%; the hybrid; and the straight corporate run (reference only). All excl. the 6% RM fee, VAT incl. Flag hybrids well outside SME +15-20%. Note the SME rater applies Micro SME pricing at R1M-R5M for bands up to R50M, so show the standard figure as well.
- Micro exclusion: when a quote request includes any cover limit above the Micro band (R5M), every option on that request is rated on the standard SME band tables, including the options that would otherwise qualify for Micro.
- Sanity check (every corporate quote below the R250M revenue floor): compute three figures per option: SME rater price with matching Funds Protect (micro exclusion applied), the hybrid, and the straight corporate run on actual turnover. Show them side by side with SME +15% and SME +20% and the hybrid as % of SME +20%. For a conversion the deciding test is the hybrid against the current premium (above); for a new quote the hybrid is the method and the SME comparison is context. An Oct 2026 group quote was a new quote where the underwriter chose SME +20%. Never quote the straight run.
- An internal SOC together with a SIEM earns a Good equivalent posture rating and the posture discount, even where the questionnaire scores lower (precedent: group quote, Oct 2026).
- When a Good / Strong equivalent posture is granted, the SME posture discount equals the corporate Strong bracket discount (15%, i.e. the corporate x0.85 factor), not a free percentage (precedent: group quote, Oct 2026).
- Group / subsidiary quotes (corporate sanity check and SME quotes alike): when entities are rated together as one group quote, load the SME base premium (excl. Funds Protect) with the sub-industry Risk Factor from 'Look Up Tables_2026' column S, as the Standard premium Tables sheet does (V = 1 + W, X = (base x V) + FP), instead of the average industry modifier of 1.0. Single-entity quotes keep the average modifier, because each separate policy already carries its own Funds Protect and pricing. Posture and discretionary discounts apply after the loading (precedent: group quote, Oct 2026; Business/Legal Services RF 0.4452).

## Records loading (underwriter, 2026-10-29)
- When declared records are far above typical for the client's size, load only Third Party Claims and Data Restoration Costs, not the whole premium. Industry stays as rated.
- Typical = top of the form's record band for the size (or the rater's IBM SA average of ~23k breached records). Load sub-linearly (per-record cost falls with volume); method pending ruling.

## Condition wording (underwriter, 29.10.2026)
- Write conditions of cover in the exact wording of conditions_template.md. Never paraphrase a condition (e.g. "e-mail filtering" alone is wrong; use "An e-mail filtering solution that blocks malicious attachments and suspicious file types, including executables.").

## E-mail filtering condition: SPF + DKIM + DMARC satisfies it (underwriter, 29.10.2026)
- If the form shows SPF, DKIM and DMARC all in place, the e-mail filtering condition of cover is met. Do not impose "An e-mail filtering solution that blocks malicious attachments and suspicious file types, including executables." even when the separate "email security incl. URL rewriting / malware protection" question is No.
- Only impose the e-mail filtering condition when any of SPF, DKIM or DMARC is missing (and no filtering product is named).

## Remote access without MFA, and staff with admin rights (underwriter, 29.10.2026)
- When remote access is via VPN but "all remote connections require MFA" is not confirmed, check how many employees have system administrator privileges.
- If the form says all (or most) employees have admin privileges: ask the liaison to confirm it, state that these are privileged accounts so MFA is required on all their logins (including remote), and add the condition "Multifactor Authentication (MFA) is implemented for all privileged accounts." with that confirmation note.
- If only a few named admins have privileges (and MFA on privileged access is Yes), leave it as is; no remote-MFA condition.

## Contingent BI sublimit (underwriter, 29.10.2026)
- Contingent Business Interruption is 50% of the Business Interruption limit, as per the policy wording (e.g. BI R10M -> CBI R5M). Never give CBI the full limit unless the client asks for it.
- CBI is only included at all where the rules allow it (see the SOE and grant-threshold rules); otherwise state N/A.
- The corporate rater has no separate CBI benefit, so the 50% sublimit does not change the premium.

## Product classification for saved quotes
- A quote's product is the policy wording it is issued on, as stated in the instruction email ("on our corporate product/policy" or "on our SME product"). SME +20% and hybrid prices issued on the corporate wording are corporate quotes and are saved in the corporate quote store. Only options issued on the SME wording are saved in the SME rater's store.
- One instruction can carry both: a corporate option plus an "also quote on the SME product" fallback. Classify each option separately.
