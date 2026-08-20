# Outstanding Items — Phishield Scanner

**Last updated**: 2026-07-02
**Owner**: SML Consulting (engineering) + Phishield UMA (ops)
**Authoritative source** for items pending across the scanner project.
Consolidates open items from gap analysis SCN-* entries, memory files,
and session-level decisions. Update this file whenever a new
outstanding item lands.

**File pair:**
- `OUTSTANDING.md` (this file) is the live working version — edit here.
- `OUTSTANDING.docx` is a polished read-only snapshot for easy reading.
  Regenerate after each edit with `py -3 tooling/generate_outstanding_docx.py`
  (from the `security_scanner/` directory). The script applies Phishield
  branding and formats tables for printable / shareable output.

---

## 0. DEMO WINDOW — must be reversed when the demo ends (opened 2026-07-28)

A small group of external testers was given access to the live VM scanner. Three
temporary controls were put in place for that window. **All three are reversals,
not features** — work through this table before the scanner is treated as
production, and again the moment demo feedback is concluded.

| Item | Status | How to reverse | Notes |
|---|---|---|---|
| **Interim edge Basic auth on `/scanner`** | LIVE (Caddy, 2026-07-28) | The `basic_auth` block in `/etc/caddy/Caddyfile` is split into two labelled groups. **When the demo ends, delete only the lines under `# --- DEMO TESTERS ---`** and run `sudo systemctl reload caddy`; the internal-staff group stays. Remove the whole `@needs_auth` + `basic_auth` block to reopen access entirely. | Internal staff (keep): `sarel`, `zamani`, `inze`. Demo testers (remove at demo end): `demo1`–`demo4`. bcrypt hashes; one login each so access can be revoked individually and the access log attributes activity. `/health` and `/health/providers` are deliberately EXEMPT so the uptime monitor and the deploy's public-reachability check keep working; `/metrics` IS gated. **This is a shared-secret gate, not user auth** — no per-user identity inside the app, no session expiry, no audit trail beyond Caddy's access log. It does NOT satisfy the production auth requirement below. |
| **Encrypted credential export DISABLED** | Fails closed by default (2026-07-28) | Set `CREDENTIAL_EXPORT_ENABLED=1` in the VM `.env` and `sudo systemctl restart phishield-scanner`. Config only — no code change, no redeploy. | The export releases a client's **actual breached passwords**. What makes that lawful is the client's signed consent, and the `consent: true` field on the request is only a broker attestation — with demo testers who have signed nothing, it is not a control at all. Both the POST **and** the one-time download route are gated (gating only the POST would let a token minted before the flip still be redeemed). The dashboard shows the control as unavailable rather than letting a tester complete a consent attestation and then hit a 503. Everything else in the scan — which accounts are exposed, in which breaches, how recent — is unaffected. **Re-enable only once the consent/authorisation page ships.** |
| **Demo-facing manual in circulation** | Written 2026-07-28 | Withdraw the demo manual; the full manual stays internal. | `Phishield_Scanner_Demo_Guide.docx` deliberately omits scoring weights, calibration anchors, checker internals, data sources and thresholds. Do not circulate the full `Phishield_Cyber_Risk_Scanner_User_Manual.docx` to demo testers. |

**Also open (2026-07-28):** wire IntelX's **free** `/authenticate/info` endpoint
into the budget guard. The guard currently counts HTTP calls and estimates the
search quota from them (1 search = up to 4 calls); that endpoint reports remaining
*searches* authoritatively, at no credit cost, and would remove the estimate.

**Related, still open:** the production auth model (see *Enable API auth* in §1) is
unchanged by the demo gate — edge Basic auth is a stopgap in front of an app that
still has no authentication of its own.

### Deferred, flagged for review (not defects — decisions not yet taken)

| Item | Owner | Why it is parked |
|---|---|---|
| **Uptime monitor on `/scanner/health/providers`** | Owner (ops) | The readiness probe returns 503 when a provider key dies, the datastore falls back to SQLite, or a metered budget is exhausted — all silent failures otherwise. Nothing is watching it yet. A 2026-07-27 drill confirmed the 503 fires correctly; only the monitor is missing. |
| **Should lookalike mail-capability carry SEVERITY?** | Owner (calibration) | Lookalike posture probing (MX / SPF / parking / content) ships as **reporting-only**: the category score is still a flat penalty per resolved domain, so a mail-capable near-typo and a parked null-MX domain score identically. Weighting by capability means either replacing that channel or justifying a second one, plus the manual paragraph that locks it — a calibration decision under the no-double-count rule, not a code tweak. Options: weight the existing penalty by risk band, add a probability uplift, or keep reporting-only permanently. |

---

## 1. Hosting / infrastructure

| Item | Status | Owner | Target date |
|---|---|---|---|
| **Cloudflare / Hetzner proxy for `phishield.com/scanner-info`** | Pending hosting-company action | Hosting team | Tuesday 2026-05-19 (WordPress → HTML cutover). Handoff doc at `docs/scanner_info_proxy_setup.md`. Options: static copy (simplest), nginx reverse-proxy (cleanest), Cloudflare layer (long-term). |
| **User-Agent flip back to canonical `phishield.com/scanner-info`** | Blocked by proxy above | Engineering | After hosting team confirms `phishield.com/scanner-info` returns 200. Single-line change in `http_client.py` USER_AGENT constant. |
| **GCP migration of scanner backend** | **Largely DONE (2026-06).** Scanner runs live on the Google VM `veilguard-prod-jnb` (GCP project `rugged-sunbeam-492106-j1`, `africa-south1-a`, `n2-standard-8`) at `veilguard.phishield.com/scanner`, with a **dedicated Postgres 16** container (not the ephemeral Render SQLite). gunicorn under systemd, Caddy edge. Runbook: `docs/DEPLOYMENT.md`. | Phishield ops + engineering | **Remaining:** (a) **Vertex AI / LLM-augmented analysis** (the "protected environment + LLM" goal, not yet started). Render decommission is DONE in code (2026-07-06): the `phishield-scanner` block was removed from `render.yaml` and the scanner's self-identification (User-Agent + scanner-info page) repointed to the VM; only the Render-dashboard suspend/delete remains. The **persistent Postgres removes the ephemeral-`scans.db` risk to the encrypted-export enrichment (5k)** on the VM path. |
| **Eventual move to Hetzner self-hosted** | Future-future | TBD | After GCP/Vertex experience accumulated. |
| **Enable API auth (`SCANNER_API_KEY`)** | Code shipped 2026-06-11, env var NOT yet set (auth is opt-in / off) | Engineering + frontend | Set `SCANNER_API_KEY` on Render AND add the matching `X-Api-Key` header to the Vercel frontend's calls to `/api/scan`, `/api/preflight`, `/api/credential-export`, balance endpoints. Order matters: frontend first or simultaneously, else scans 401. Rate limiting (per-IP, env-tunable) is already live and needs nothing. |
| **`vendor_breaches.json` — Adobe/Marketo watch item** | 2021 `marketo` row PRUNED 2026-06-11 (aged out of the 5-yr lookback; decayed contribution was ~0.5%). | Engineering | WATCH: alleged Adobe breach early-April 2026 (UNC6783, ~13M support tickets via compromised BPO; Marketo Engage plausibly in scope). Confirmed-only DB discipline — add a fresh row with the 2026 date if/when Adobe confirms. Details in `vendor_breaches.json` `_pruned`. |

## 2. External API budget (Phase 2 unblockers)

| API | Current tier | Required tier for 4,000-cohort | Estimated monthly cost | Action by |
|---|---|---|---|---|
| Shodan | Free `oss` (0 query credits — confirmed via `/api-info` 2026-05-29) | **Freelancer ($69/mo, 10,000 query credits)** unlocks search + origin cert-search. One-time **Membership (~$49, 100 credits/mo)** is a low-volume stopgap. | ~$69/mo (≈R1,300) if per-IP vuln data stays on free InternetDB and only origin cert-search spends credits (~1 credit/scan). Higher only if per-IP `/shodan/host/{ip}` lookups are also moved to the paid API. | Before 1 July 2026 — **also gates origin IP discovery (see §5, item 4c), which is a scanner-breaking RDP false-negative on CDN-fronted targets** |
| SecurityTrails | Free (100/month; history endpoint works on current key — confirmed 2026-05-29, NOT paid-gated) | Paid tier for sustained usage | Similar order of magnitude | Before 1 July 2026 |
| VirusTotal | Free (4/min, 500/day) | No upgrade needed | — | n/a |
| IntelX | **CRITICAL.** Returning data in the 2026-05-29 live test (300 results: 260 leak + 40 paste mentions, with per-record dates) — the "expired 2026-04-08" note is stale, the configured key currently works. It is now **load-bearing**: the 4th signal (active forum/dump circulation + recency dates) in the **Credential Exposure Correlation**. | Confirm a sustainable IntelX subscription OR equivalent (Snusbase / LeakCheck Pro / SpyCloud) — must persist, not lapse | TBD | **CRITICAL — before shipping live.** Credential correlation degrades gracefully without it ("monitoring pending") but loses the active-circulation signal + its main recency source. |
| HIBP, Hudson Rock, OSV.dev | Free unlimited | No upgrade needed | — | n/a |

### Shodan origin cert-search — how to make it live

Origin IP discovery (`origin_discovery.py`) is **already wired and deployed**.
It works in two stages and the paid stage **auto-activates the moment a paid
key is in place — no code change or redeploy of logic is needed**:

1. **Free stage (live now):** `/shodan/host/count` returns how many internet
   hosts present the target's TLS certificate. Surfaced in the report as the
   "Origin IP Discovery" card. When that count exceeds the origins we confirm
   via DNS history, the report flags a likely **undiscovered exposed origin**.
2. **Paid stage (pending key):** `/shodan/host/search` returns the actual
   origin IPs. On the free `oss` plan it returns HTTP 403 and we fall back to
   count-only. On a paid plan it returns the IPs, which are then TLS-cert
   verified and scanned like any other origin.

**Go-live steps:**
1. Buy a Shodan plan — **Freelancer ($69/mo)** recommended (10,000 query
   credits/mo); or one-time **Membership (~$49)** for low volume. Buy it on
   the Shodan account **whose API key is already set in Render** (so credits
   attach to that key), or buy on a new account and update the key in step 2.
2. Set / confirm `SHODAN_API_KEY` in the Render environment for the scanner
   service (Render → service → Environment). No code change required.
3. (Optional) verify with `GET https://api.shodan.io/api-info?key=...` —
   `query_credits` should be > 0 and `plan` should read `dev`/`member`/etc.,
   not `oss`.
4. Next scan of a CDN-fronted domain will retrieve + verify + scan the real
   origin IPs automatically; the "Origin IP Discovery" card switches from a
   count-only hint to listing the verified origins.

Budget note: keep per-IP vulnerability data on the **free InternetDB** path
(current default) so Shodan credits are spent only on the ~1-credit-per-scan
cert-search. Moving `/shodan/host/{ip}` per-IP lookups onto the paid API is
the larger credit consumer (~1 credit per discovered IP per scan) and is a
separate decision.

### IntelX (free tier) — current state + Wednesday testing

Confirmed 2026-05-29: the configured IntelX key **works** (the "trial expired"
note was stale). **Verified 2026-05-31 via `/authenticate/info` + IntelX docs:**
the free tier's `/intelligent/search` cap is **`CreditMax = 50` per DAY, reset
at midnight UTC** (NOT ~500 — that was a wrong code comment), 1 credit/scan,
**max 3 concurrent searches**.

Planning implication: the cohort runs at **~25-30 scans/day** (§3), which fits
*under* 50/day with modest headroom — so the free daily tier is **borderline-
viable for the steady cohort rate**, NOT "10× too small" as first thought.
BUT: zero burst headroom, the 3-concurrent cap throttles throughput, and any
broker ad-hoc scans eat into the same 50. So a **paid replacement
(Snusbase / LeakCheck Pro / SpyCloud) is still recommended** for safety +
throughput + always-on use, but it is no longer an emergency blocker. Avoid
burning credits on test scans (`skip_intelx:true`; the smoke test is already
credit-free).

- **DONE (2026-06-01):** `INTELX_API_KEY` (and `SHODAN_API_KEY`) are set on
  Render — prod now carries the IntelX/forum signal. The *paid-tier upgrade
  decision* (Shodan Freelancer, IntelX replacement) remains open above.
- **DONE (2026-07-01):** `INTELX_API_KEY` is now also set on the **Google VM**
  `.env` (service restarted, balance active). The key is account-scoped, so the
  VM and Render **share the same 50-credit/day pool** (they do not each get 50).
- **Still seek a sustainable replacement** (Snusbase / LeakCheck Pro /
  SpyCloud) for the cohort-scale + always-on case; the free tier can remain a
  fallback for ad-hoc use. The credential-correlation circulation slot is
  provider-agnostic, so swapping is a checker change, not a correlation rewrite.

## 3. Peer benchmarking rollout (SCN-028)

| Phase | Status | Start date | Source tag |
|---|---|---|---|
| Phase 1 — public reference seed pool | **Live** (bi-weekly via `tooling/benchmark_runner.py`) | 2026-05-16 onwards | `benchmark_pool` |
| Phase 2 — lower-tier-upsell cohort (~4,000 clients) | Pending launch (1-July window now open; gated on the prerequisites below) | 1 July 2026 → ~Feb 2027 (6-9 months at ~25-30/day) | `lower_tier_upsell` |
| Phase 3 — broker opt-in via scan form checkbox | Future | When opt-in plumbing is added; no fixed date | `client_optin` |

**Phase 2 prerequisites** (must complete before 1 July):
- [ ] Export 4,000-client list to CSV (`domain, industry, sub_industry, annual_revenue_zar` columns)
- [ ] API tier upgrades (see section 2)
- [ ] Daily cron / Render scheduled job invoking `py -3 tooling/benchmark_runner.py --source lower_tier_upsell --input-csv ... --limit 25`
- [ ] Phase 2 upsell workflow definition (how to deliver PDFs to brokers / clients)

## 4. Deferred-to-continuous-monitoring track (SCN-026)

| Item | Status |
|---|---|
| Probe-cache SQLite-backed implementation | Interface defined in `http_client.ProbeCache`; default `_NullProbeCache` no-op. Real implementation lands with continuous-monitoring scheduler. |
| Continuous-monitoring scheduler | Open. Estimated 3-4 week build. Requires probe cache + per-tenant scheduling + delta-finding detection + alert-on-change pipeline. |

### 3b. Historical scans no longer reproduce their own score (OBSERVED, 2026-08-20)

**Found by a safety guard, not by looking for it.** The recommendation backfill
re-ran the scorer over every completed scan's STORED categories, making no
provider call, and refused to write any scan whose score moved. Twelve of
fifty-two moved.

| | |
|---|---|
| Scans re-scoring identically | 40 |
| Scans re-scoring differently | **12** |
| Typical movement | 14 to 28 points down; one moved +65 |

**Two causes confirmed, both legitimate:**

- `38da8562` phishield.com (218 -> 200): `http_headers` now grades as FAILED
  where it did not, because `unreachable` was added to `_FAILED_STATUSES` in the
  blocked-is-not-clean work. Excluded weight 0.045 -> 0.083, so the redistribution
  differs.
- `007f19d1` mip.co.za (117 -> 182): identical failed/skipped sets and identical
  excluded weight, so the movement is in the scoring maths itself, not exclusion.

Neither is a defect. Both are scoring improvements made after those scans ran.

**Why it is recorded here.** A stored scan is an underwriting artefact. A client
quoted off a 2026-07 score cannot have that number silently restated months
later, so the backfill deliberately left those twelve alone and only corrected
the ordering of the action list on the other forty. But it means **a re-quote off
an old scan is not comparable to a re-quote off a fresh one**, and nothing in the
product says so.

**OWNER DECISION, 2026-08-20: quotes must NOT be produced off earlier scans.**
A quote is derived from a fresh scan or it is not produced. That settles question
2 below and makes question 1 the enabling work rather than a nice-to-have: the
policy cannot be enforced, or even audited after the fact, unless a stored scan
records the model it was scored under.

**Remaining, to schedule:**

1. **Stamp the scoring model version onto every scan** so a stale score is
   visibly stale rather than silently stale. Cheap now, impossible to reconstruct
   later, and it is the mechanism the decision above depends on. Without it
   "is this scan current?" is answerable only by re-scoring and comparing, which
   is exactly the accident that surfaced this.
2. **Decide where the policy is enforced.** Recording it in a document does not
   stop anyone. Candidates: the scan record carries a freshness/model field the
   rating path refuses to quote against, or the report itself states the scan
   date and model prominently enough that quoting off a stale one is obvious.
3. All twelve divergent scans are phishield/takealot test scans or have a newer
   scan for the same domain, so there is no known live exposure today. That is
   luck, not design, and it is the reason this is schedulable rather than urgent.

Ties into 4a: a stable finding identity across re-scans is the same prerequisite.

### 4a. Risk-register workflow: analyst/client adjudication of findings (GAP, 2026-08-18)

**Owner-raised, explicitly NOT for now.** Recorded here so the continuous-monitoring
build does not get designed without it, because it changes the data model rather
than the UI, and retrofitting it later is far more expensive than allowing for it.

**The gap.** Today a finding has exactly one state: whatever the scanner decided.
There is no way to record what happened when a human looked at it. After a client
session the broker knows things the scan cannot: that an exposed service is a
decommissioned host awaiting teardown, that a "critical" database is a vendor's
shared platform (see 2026-08-18, `707418b`), that a lookalike domain is the
client's own marketing site. None of that survives anywhere. The next scan
re-raises the same finding at the same severity, and the client sees an
unchanged report after telling us it was wrong.

**What is wanted.** Selectable fields on each identified risk so a finding can be
adjudicated:

- a **status** drop-down (open / accepted / mitigated / false positive / vendor-owned / decommissioned)
- an **override severity** with the scanner's original severity retained alongside it, never overwritten
- a **mandatory comment** whenever the override differs from the scan verdict, so the escalation or de-escalation carries its own justification
- **attribution and timestamp** on every change, since this becomes the audit trail for why a quoted risk differed from a scanned one

**Reference UI.** The owner cites Darkivore's scan interface as the shape to aim
for (risk items managed in place, adjudicated rather than merely listed). Not
independently reviewed by me and NOT verified against their product; treat as a
directional pointer from the owner, not a specification, and confirm before
designing to it.

**Why it is a continuous-monitoring item and not a dashboard item.** Adjudication
only pays off across repeat scans. Its whole value is that scan N+1 remembers what
a human decided about scan N, which means the override must attach to a STABLE
FINDING IDENTITY that survives re-scanning, not to a row in one scan's results.
That identity does not exist yet and is a prerequisite for the delta-finding
detection already listed in section 4. Design them together.

**Underwriting caution, to settle before build.** An override that de-escalates a
finding changes the risk score a quote is derived from. That needs an explicit
decision: does an adjudicated score feed the premium, or does the scanner's own
score remain the rated one with the override shown alongside as broker context?
Silently letting a client talk a score down would be a serious defect in an
underwriting tool. Recommend the scanner's score stays authoritative for rating
and the adjudicated view is presented separately, but this is the owner's call.

**Ties into 5m (UI screening test).** 5m is about the dashboard faithfully
REPORTING what the scan found. This item adds a second, human-authored layer on
top. Doing 5m first is the right order: there is no point building adjudication
over a display that does not yet provably agree with the scoring path.

## 5. Open accuracy items (gap analysis roadmap)

Carried over from v9 / v10 gap analyses. Not blocking but worth flagging:

**Checker accuracy audit (2026-06-30 → 2026-07-02) — COMPLETE.** A ground-truth
sweep of every checker module (white-box plus credit-free live runs, since the
frozen golden fixture is stale). Seven fixes shipped, deployed, and sha256-verified
on the VM, each locked by an `adversarial_gate.py` ground-truth scenario (the gate
now runs 40 across socket / IP-attribution / CVE-gating / checker-FP cases):

- **Py3.10 scan-crash fixed** (the scan phase loops now catch the
  `concurrent.futures` timeout, not the builtin; live scans had crashed on
  high-IP targets) plus a blocking AST guard, now extended to all four checker
  modules.
- **IP attribution by who-operates-the-host** (`ip_classification.py`): own vs
  vendor vs internal (RFC1918). Directly mitigates the "reassigned / vendor IP
  scored as the insured's own exposure" risk flagged in 4c / 4c-ii below.
- **CVE-to-software evidence-gating** (port-template CVEs dropped when the banner
  names a different product) and two wrong-software CVE data errors removed.
- **Live and golden scoring unified** into `scoring_pipeline` (one calculator
  invocation shared by the live scan and the golden replay) plus a guard against
  re-divergence; this drift is how the RSI-revenue size-multiplier bug had hidden.
- **False-positive hardening:** TechStack end-of-life detection matched against
  response headers only (not incidental version mentions in the page body); the
  VPN apex RDP probe now tarpit-gated (`is_saturated_host`) so a SYN-ACK-everything
  host cannot fabricate an RDP exposure; Dehashed staff attribution boundary-matches
  the mailbox domain (no lookalike-domain leaked account counted as own-staff).
- **hudson_rock staff-vs-customer distinction made consistent** on the reporting
  credential-correlation card (customer-only infections cap below staff there).
  The RSI-driving credential tier (`CredentialRiskClassifier`) already floored
  customer-only to HIGH and staff to CRITICAL, so the RSI itself was unchanged;
  this was a reporting-consistency correction, not a scoring change.
- **Subdomain enumeration made reliable (#7):** crt.sh and certspotter queried in
  parallel and unioned, with a `low_coverage` flag when both fail, so a flaky
  crt.sh no longer collapses enumeration to brute-force-only.

**Deferred follow-ups from the audit:** (a) cache Certificate-Transparency results
per-domain (TTL) for even tighter reproducibility; (b) refresh the stale golden
fixture (`test_fixtures/takealot_baseline.json`) from a fresh scan, then re-run
`tooling/regression/golden.py --capture` after reviewing the drift.

| Phase | Item | Status |
|---|---|---|
| 4b | CMS admin path detection (dynamic from tech stack) | Open |
| 4c | CDN origin IP leakage / origin discovery | **Partial — implemented (`origin_discovery.py`, 2026-05-29):** SecurityTrails historical-DNS candidates + TLS cert-match verification live; verified origins scanned, candidates surfaced. Free Shodan cert-host count hint live. **Full Shodan cert-search IP retrieval pending paid key (see §2 go-live).** Also: RDP exposure now reconciled across all discovered IPs, not just the apex (was a false-negative on CDN-fronted targets). |
| 4d | MFA presence on VPN login pages | Open |
| 4c-ii | **Infrastructure-infection / C2-beaconing signal** (reinsurer "Infrastructure Infections — Malicious Connection Attempt" card). Distinct from credential/infostealer: it flags *org servers/hosts* observed connecting to malicious infra. We partially cover via DNSBL (reputation/blacklist), but lack infection-type + days-observed granularity. Would need a threat-intel feed (Spamhaus CSS/XBL, GreyNoise, abuse.ch Feodo). **Attribution caveat:** the reinsurer's example IP `152.111.191.48` reverse-resolves to `download.kalahari.com` (Kalahari merged into Takealot 2014) — a legacy/related-brand IP not in takealot.com's scope, so it would only surface via related-domain (S-1) discovery + cert-verification. The reassigned/legacy-IP attribution risk is now mitigated by the own-vs-vendor classification (`ip_classification.py`, 2026-06-30), which keeps vendor/legacy hosts out of the insured's own attack surface; the C2-beaconing signal itself still needs a threat-intel feed. | Open (signal not built; attribution risk mitigated) |
| 4e | WAF rate limiting / bot protection detection | Open |
| 4f | DNSSEC validation chain | Open |
| 4h | Exploit Window narrative enhancement | Open |
| 5a | Bug bounty programme detection (HackerOne / Bugcrowd) | Open |
| 5f | retire.js CVE cross-reference | Open |
| 5i-T1 | AI Threat Readiness Tier 1 (externally observable) | Glasswing done; rest open |
| 5i-T2 | AI Threat Readiness Tier 2 (self-reported) | Open |
| 5k | **Fresh-dump content-fetch (credit-gated tier)** | **Partial — done 2026-06-02:** the encrypted export now includes IntelX stealer-log postings as date-ordered `leak_reference` rows with a `match_type`→`confidence` label (`credential_export.py`; Manual §6.4). **Still open:** the **content-fetch tier** — on explicit client request, pull the named dump BODY (IntelX selector/view, costs credits) to confirm whether a real credential was exposed vs just a `History/` visit. The free listing classifies by path but cannot read the contents. |
| 5L | **Confidence-gate the p(breach) / RSI input (scoring decision — NOT done)** | Open, **calibration-gated** (scoring-change rule). The export/dashboard now expose a `match_type`→`confidence` model, but the *score* does not yet use it: a recent LOW-confidence reference (aggregated index, browser-History visit) can still pull credential signals the same as a HIGH-confidence password capture. Decision to make: gate any p(breach)/RSI uplift on HIGH-confidence (or content-fetch-confirmed) evidence, so low-confidence freshness alone does not inflate the probability. Builds on the §6 "Credential-risk scoring calibration" ticket. **Cat model is unaffected — this is purely the p(breach) input.** Until decided, the disclaimer + content-fetch prompt (5k) is the interim control. **Design pre-read for the 2026-06-03 FIN-9 calibration session: `docs/credential_confidence_pbreach_design.md`** (current wiring, the model, the K1-K7 calibration knobs, and the empirical anchors that set them). |

### 5m. UI screening test — validate every dashboard display against the PDF/scoring path (NEW, 2026-08-06)

**The gap.** The React dashboard is a SECOND rendering path over the same scan
results, and it has never been validated against the first. The PDF/scoring path
is well gated: `pdf_snapshot.py` (byte-level render baseline), `golden.py`
(scoring regression), `adversarial_gate.py` (now 100+ ground-truth scenarios),
plus the financial-wiring verifiers. The dashboard has almost none of that —
`tsc --noEmit`, a base-path link check, and the recently added built-bundle
prefix check. Nothing asserts that what the dashboard SAYS about a scan matches
what the PDF says about the same scan.

**Why this is now a named gap.** Three separate defects in ~36 hours, all of the
same shape — a rule taught to one layer and not the others:

1. **WAF `blocking_observed` (fixed `583dcca`).** Added to the scorer in
   `ba6b380`; NO renderer learned it. The PDF plain-language summary, the PDF
   category card, the RemediationSimulator recommendation list and the dashboard
   panel all still read `waf.detected` alone, so a site that refused 20 of 20
   probes was told it had "no protective filter, leaving it directly exposed".
2. **Risk Factors roll-up (`selectors.ts` `getRiskFactors`, OPEN).** Each
   dimension averages the `score` field of its categories, but several checkers
   (`exposed_admin`, `payment_security`, `vpn_remote`, `dns_infrastructure`,
   `high_risk_protocols`, `cloud_cdn`, `security_policy`, `waf`) never emit a
   per-category `score` at all — their contribution is computed downstream in
   `scoring_analytics`. The roll-up silently averages whatever subset happens to
   carry the field, while the label still claims the full dimension. Observed on
   excellentmeat.co.za `f0313b6a`: **Data Protection ran on 1 of 4 categories**
   (privacy_compliance=0, i.e. "no compliant privacy policy page found") and
   rendered "Critical +100"; **Network Exposure ran on 1 of 4** (shodan_vulns=100)
   and rendered **green "Low"**. A green verdict resting on one signal is the
   dangerous direction — nobody challenges green.
3. **Base-path build (fixed `5cdbaa9`).** The bundle shipped without
   `SCANNER_BASE_PATH`, so every dashboard API call missed the Caddy mount. The
   page still rendered and the timer still ticked, so a completed scan sat at
   "0 / 39 Scanning" indefinitely.

**Deferred deliberately, not overlooked.** The dashboard sits behind the demo
edge auth (§0) and the PDF is the client deliverable, so the exposure is
currently internal. That is what makes this schedulable rather than urgent.

**What the screening test should do** — for every display element in the
dashboard, trace what drives it and assert it agrees with the PDF/scoring path
for the same scan:

- Enumerate each panel/field and record its data source (category, derived
  selector, or computed-in-frontend), so "computed in the frontend" is a visible
  category rather than an accident. `getRiskFactors` and `getAttackPath` are
  known frontend-side derivations; there may be others.
- For a fixture scan, diff every dashboard-rendered verdict against the
  corresponding PDF statement. Any divergence is either a bug or a documented
  deliberate difference — currently there is no record of which.
- Assert coverage honesty per dimension: show the denominator ("1 of 4
  assessed"), and do not render green where the underlying coverage is thin.
- Add whatever survives as gate scenarios, so the dashboard gets the same
  "does not silently degrade" guarantee the PDF has.

**Also open from the same review:** the `+xx` impact figure reads as an additive
contribution to a score but is only `100 - dimension_score` (a display-only
inversion; the five values summed to 326 on a scan whose overall risk score was
251). Relabel. And "Data Protection" is currently driven by privacy-policy
presence, which the name does not convey.

## 6. Architectural follow-ups (low priority)

| Item | Status |
|---|---|
| Enforcement-discount % calibration per regulator | Statutory maxima used everywhere in cat stack. Expected-loss view uses heuristic. Compliance officer should set per-regulator discount %. |
| Civil exposure quantification (POPIA s99 / common-law delict) | Currently qualitative disclosure only. Quantification requires internal-contract data. |
| Tail recalibration with empirical SA cat data | 5× PERT upper bound on `mc_total_breach` is conservative. Calibrate against SABRIC + CISA + IBM SA-specific incident-type data when available. |
| WAF coverage-loading constant calibration (SCN-029) | `K_TAIL=1.20` in `_calculate_zar` sets how aggressively the catastrophe tail widens per unit of lost scan coverage. Heuristic — calibrate against rescan deltas (blinded scan vs allow-listed rescan of the same target) once continuous monitoring provides paired observations. Only the ZAR path is loaded; the dead USD path is not. |
| Bias correction on `lower_tier_upsell` benchmark cohort | Cohort may not be SA median; pool composition disclosed in report. Future: source-class weighting in percentile calculation. |
| GPD tail fit MLE upgrade (currently method-of-moments + pure numpy) | scipy.stats.genpareto provides MLE fit but adds dependency. Defer until scipy is acceptable on Render. |
| **Credential-risk scoring calibration** | **Structural tweaks DONE via the K1-K7 confidence-weighted rewrite of `CredentialRiskClassifier.classify` (FIN-9, 2026-06-03; checkers_threats.py).** Both landed: (1) IntelX paste/dark-web mentions are now **report-only (K7=0, "no score impact")**, not an uncapped per-mention deduction; (2) the Hudson Rock class FLOOR is **date-gated** (`L3_HR_STALE_DAYS=180`: a stale employee infection floors to HIGH, not CRITICAL), and a customer-only (`hr_users`, no employees) infection floors to HIGH while staff floors to CRITICAL. The K1-K7 *magnitudes/ranges* remain colleague-gated (see §6b and `docs/calibration_prep/02_credential_pbreach.md`). |

## 6b. FIN-9 calibration inputs — financial-loss impact of the 2026-06-03 accuracy waves

> **STATUS (2026-06-11):** the 2026-06-03/04 session RETIRED the FIN-9 Pareto
> widening; the #14 records-driven cat redesign was wired instead (see
> `calibration_prep/07_WIRING_SPEC_AND_HANDOFF.md` §7 and the FIN-9 memory
> memo). The dead-USD `COST_PER_RECORD` / `REGULATORY_FINE` tables listed
> below have since been **deleted** from `scoring_analytics.py`. Still
> genuinely open from this table: the `p_breach` base/curve sign-off, risk-band
> re-fit (200/400/600), TEF multipliers, K_TAIL, HIBP step thresholds,
> remediation caps — all colleague-gated.
>
> **UPDATE (2026-07-02):** the checker accuracy audit (§5) is complete — a further
> round of false-positive hardening (TechStack EOL, VPN RDP tarpit-gate, Dehashed
> attribution, evidence-gated CVEs) plus the live/golden scoring unification. These
> did **not** move the frozen golden fixture scores (they fixed FPs that were not
> firing on those fixtures), so the calibration baseline is stable; but the
> pre-session reference-loss-curve regeneration should run on the LATEST code.

**Why this matters for the FIN-9 session.** Wave 1 wired `cat_results["_overall_score"]`
into the FinancialImpactCalculator for the FIRST time in production — `vulnerability`
now couples to the real posture score (was permanently pinned at 0.5). Combined with
the de-inflation from the other waves (SSL no longer auto-"Invalid" −40, DNSBL no longer
auto-"blacklisted", Exposed-Admin 403-inversion gone, phantom F5-WAF and fabricated
CVE ASN/geo removed, HTTP-headers no longer false-penalised off a 403 block page), the
financial-loss **inputs changed materially**. Worked example: a fixed-code production
scan of phishield.com now scores **169 (Low)** vs **381 (Medium)** pre-fix, so its
`p_breach`, expected loss and every Monte-Carlo return-period tail shift accordingly.

**Consequence:** the FIN-9 Pareto widening (and the 5L credential-confidence work) must
anchor to the **corrected post-fix loss baseline**, not the old inflated one. The
downstream financial constants below were never empirically validated against *working*
coupling (the coupling was broken until Wave 1), so they now genuinely need calibration.

**Parameters to calibrate (anchor to DBIR / Mandiant M-Trends / IBM CoDB / Sophos SA + colleague judgement):**

| Parameter | Where | Why it now needs calibration |
|---|---|---|
| `vulnerability` ← `_overall_score` mapping, and the `0.3` in `p_breach = vulnerability × TEF × 0.3` | `scoring_analytics.py` (~L2099) | coupling is live for the first time; neither the curve nor the `0.3` was ever validated against real scores |
| credential → p(breach) contribution (replaces `dehashed_total × 2`, ~L669) | 5L / pre-read **K1–K7** | the confidence-weighted credential class (`docs/credential_confidence_pbreach_design.md`) |
| Pareto **alpha** + LGB **mixture weight** (FIN-9 core) | `_calculate_zar` | re-anchor to the corrected loss baseline + the MOVEit per-org curve |
| Remediation cap: `MAX_RSI_REDUCTION_FRACTION=0.15`, `RSI_RESIDUAL_FLOOR=0.05` | `scoring_analytics.py` (Wave 4) | set heuristically in Wave 4; the ~81% modelled loss-cut is now a calibration question, not a bug |
| TEF industry-targeting multipliers | `scoring_analytics.py` | how often each industry is targeted |
| HIBP scenario `p_breach` step thresholds (0.35 / 0.20 / 0.08) | `scoring_analytics.py:1664` | heuristic step function |
| `COST_PER_RECORD`, `REGULATORY_FINE` tables | `scoring_analytics.py` | per-industry SA values |
| `K_TAIL = 1.20` (catastrophe tail widening) | `_calculate_zar` | heuristic |
| Risk-level bands `200 / 400 / 600` (Low/Med/High/Crit on the 0-1000 score) | `scoring_analytics.py:806` | fixed even split, set against the OLD inflated distribution; de-inflation lowered scores (phishield 381->169) so they may now mis-bucket — re-fit to the corrected distribution + align to the calibrated p(breach) tiers |

**Pre-session action:** regenerate the reference loss curves on the FIXED code (a clean
post-fix scan of takealot + 1–2 references) so the calibration anchors to the corrected
baseline. `verify_supply_chain_financial_wiring.py` confirms wiring but INJECTS scores —
use a real fixed-code scan for the magnitudes. (A fixed-code phishield scan is already in
`test_fixtures/phishield_live.json`.)

## 7. Documentation / artifacts

| Item | Status |
|---|---|
| User Manual docx regeneration | `py -3 generate_manual.py` — now a **thin orchestrator** that assembles `manual_parts/part1-6` (each `build(doc)`); writes `Phishield_Cyber_Risk_Scanner_User_Manual.docx`. **Edit content in `manual_parts/`** (not the orchestrator). Helpers live in `manual_parts/helpers.py` (aliased by top-level `manual_helpers.py`); part1 uses `set_helpers()` injection, parts 2-6 import directly. The pre-2026-05-18 monolith is retired but preserved in git history (commit before the cutover) if ever needed. |
| Gap Analysis v10 regeneration | Regenerated via `node gen_gap_v10.cjs` **from the `security_scanner/` directory** (the script + its content live at `security_scanner/gen_gap_v10.cjs`, not a `generators/` subfolder). Outputs `security_scanner/Phishield_Scanner_Gap_Analysis_v10.docx`. This is hand-authored content in the `.cjs` (there is no markdown source); edit the `.cjs` then re-run. |
| FAIR Model Gap Analysis (legacy) | `security_scanner/generate_gap_analysis.cjs` produces `Phishield_FAIR_Model_Gap_Analysis.docx`. Pre-v10 artifact; check if still needed before next regeneration |
| Sensitivity analysis docs | `tooling/sensitivity/sensitivity_analysis*.py` + JSONs + `generators/gen_sensitivity_doc.cjs`. Pre-v10 calibration analysis; verify relevance before next regeneration |
| Legacy gap analysis v6/v7/v8 docx | Archived at `docs/archive/`. Kept for historical reference; not regenerated |

## 8. Document quality rules (cross-project)

Hard rules for all client-facing PDF / docx outputs live in
`C:\Users\sarel\.claude\projects\C--Users-sarel-Desktop-Sarel-Local-Only\memory\feedback_document_quality.md`.
Audit every output against the rules (now 16, numbered 0-15) before regeneration.
Pre-build audit gate is rule #0; rule #13 bans em-dashes; rule #14 requires font
embedding in every generated PDF.

---

## How to use this file

- Adding an outstanding item: append a row to the relevant section, note status / owner / target date
- Closing an item: remove the row (don't strike through — keep the file tight)
- Major architectural decisions: add a new section if a single line doesn't capture it
- Periodic review: scan this file before any big planning session or commit
