# Network & Exposure — Re-Test

Method: code verification across Waves 1-4 (`f0cf35e~1..f13ba11`) + free live re-checks (Shodan InternetDB keyless, no paid APIs). Cached `phishield_live.json` is PRE-FIX and was NOT trusted for output; fixes verified in code + live ground truth + isolated Python execution of the changed functions.

## Open Ports / High-Risk Protocols (DNS & Open Ports card)
- **Was:** GAP (attribution) — merged `open_ports` rendered under the apex (Cloudflare) IP header; on CDN-fronted targets FTP on a separate origin appeared to sit on the apex with no per-port IP attribution.
- **Now:** FIXED
- **Evidence:** HTML `templates/results.html:1349-1373` builds a `port_ip_map` from `dns.per_ip[ip].dns_infrastructure.open_ports` and renders a "Found on IP:" row per risky port; PDF `pdf_report.py:cat_dns` (≈797-808) adds the same "Found on IP" row. `scanner.py:295-333` confirms `_aggregate_ip_results` populates `dns.per_ip` with each IP's `dns_infrastructure.open_ports`, so the renderer reads real data. Live: InternetDB `34.76.113.116` (takealot) returns `ports:[21]` on Google Cloud (`*.googleusercontent.com`), NOT the apex — exactly the case now attributed correctly.

## Database / Service Exposure (High-Risk Protocol card)
- **Was:** PASS (with a dead 5432 `PORT_INTEL` hygiene entry in `dns_infrastructure`).
- **Now:** FIXED (no regression; hygiene addressed in Wave 4)
- **Evidence:** Detection path unchanged and correct. Live: InternetDB `213.133.105.171` returns `5432` open + `tags:["database"]` — phishield PostgreSQL exposure is real and still surfaces on the DB card. Wave 4 ("ghosts & hygiene") cleans the disjoint-port dead entry. No regression.

## VPN & Remote Access / RDP
- **Was:** BUG (VPN false-positive) — `Microsoft RDS Web` fired on the substring `"remote desktop"` with no status check; takealot rendered a false "VPN detected" badge. RDP path was PASS.
- **Now:** FIXED (VPN); PASS held (RDP)
- **Evidence:** `checkers_network.py:342-396` — `body_keywords` now require genuine RD Web tokens (`rdwebpage`, `domainusernamelabel`, `workspaceid`, `rdweb/pages`, `tswa_winauthcookie`); weak `"remote desktop"` removed; `require_200:True` + status gate added. Executed the match logic: soft-404 SPA mentioning "remote desktop" (HTTP 200) → no detection; 302+token → no detection; genuine RDWeb login form → detects. RDP reconciliation intact at `scanner.py:630-640` (`rdp_exposed`/`rdp_exposed_ips` set from any per-IP 3389) — no regression.

## Origin IP Discovery (Cloudflare-bypass)
- **Was:** PASS — cert-verified verified-vs-candidate separation, scan-only-verified posture.
- **Now:** PASS (no regression)
- **Evidence:** `origin_discovery.py` untouched in Waves 1-4 (not in the diff stat). Cert-match gating, renderer `status=='completed'` gating, and candidate/verified separation all unchanged. No regression introduced.

## CVE / Known Vulnerabilities (Shodan / external_ips card)
- **Was:** BUG — (1) ASN/Country fabricated as "1 ASN / 1 Country" + "Unknown" org on the free InternetDB path (`unique_asns = len(asns) or 1`); (2) latent >10-CVE undercount (`medium_count` bumped for CVEs 11+ without adding to `cves`).
- **Now:** (1) FIXED; (2) STILL-PRESENT (latent, unchanged — was a secondary/low-impact note, not in the committed fix set)
- **Evidence:** (1) `scoring_analytics.py:193-202` drops the `or 1` fallbacks, reports genuine `len(asns)`/`len(countries)`, and adds `asn_geo_unavailable`; HTML `results.html:1541-1542` renders `n/a` when the flag is set. Executed the aggregator: InternetDB path → `unique_asns=0, unique_countries=0, asn_geo_unavailable=True` (renders n/a); full-API path → genuine counts, flag False. Live: InternetDB `2a01:4f8:d0a:27c5::2` returns NO asn/org/country fields, confirming n/a is the correct output. (2) `checkers_threats.py:825-826` still does `for cve_id in raw_cves[10:]: result["medium_count"] += 1` while the aggregator recounts from the ≤10 `cves` list — unchanged. Low-impact (OSV.dev back-fill renders phishield's 19), and it was explicitly logged as a latent edge, not part of the 3 committed cluster fixes.

## Re-test summary
fixed=4 partial=1 still-broken=0 regressions=0 new=0; headline = all three committed Network & Exposure fixes (CVE ASN/geo fabrication, VPN RDWeb tokens+200, Open-Ports per-IP attribution) verified clean in code + live + execution; RDP and Origin Discovery held with no regression. The CVE card is PARTIAL only because the pre-existing latent >10-CVE undercount (a secondary back-test note, never in the fix scope) is untouched and stays low-impact.
