"""Local end-to-end test scan harness for Batch 1-4 verification.

Runs the full SecurityScanner.scan() pipeline against phishield.com with
Finance industry / R10M revenue / Insurance Agents sub-industry, plus
the pre-flight auto-detection step the broker form would invoke.
Caches the result JSON + generated PDF for further iteration.

Usage: py -3 run_test_scan.py
"""
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# Load .env from the main project (worktree has no separate .env)
env_path = Path("C:/Users/sarel/Desktop/Sarel/SML Consulting/PSQ/security_scanner/.env")
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

sys.path.insert(0, str(Path(__file__).parent))

from scanner import SecurityScanner
from flag_inference import run_preflight
from pdf_report import generate_pdf
from scoring_analytics import FinancialImpactCalculator, RansomwareIndex, RiskScorer, DataBreachIndex, RemediationSimulator

DOMAIN = "phishield.com"
INDUSTRY = "finance"
SUB_INDUSTRY = "Insurance Agents, Brokers, And Service"
ANNUAL_REVENUE_ZAR = 10_000_000


def main():
    print("=" * 80)
    print(f"TEST SCAN: {DOMAIN} | industry={INDUSTRY} | rev=R{ANNUAL_REVENUE_ZAR:,} | sub={SUB_INDUSTRY!r}")
    print("=" * 80)

    # --- Step 1: Pre-flight auto-detection ---
    t_pf_start = time.perf_counter()
    print(f"\n[1] Pre-flight auto-detection for {DOMAIN}...")
    preflight = run_preflight(DOMAIN, sub_industry=SUB_INDUSTRY, industry=INDUSTRY)
    t_pf = time.perf_counter() - t_pf_start
    print(f"    Wall time: {t_pf:.2f}s   Status: {preflight.get('status')}")
    print(f"    Detected flags:")
    for flag_name, info in (preflight.get("flags") or {}).items():
        marker = "[YES]" if info.get("auto_detected") else "[no ]"
        evidence = info.get("evidence", "")
        print(f"      {marker} {flag_name:30s} {evidence[:100]}")

    # --- Step 2: Build scanner with API keys from env ---
    print(f"\n[2] Building SecurityScanner with available API keys...")
    scanner = SecurityScanner(
        hibp_api_key=os.environ.get("HIBP_API_KEY"),
        dehashed_email=os.environ.get("DEHASHED_EMAIL"),
        dehashed_api_key=os.environ.get("DEHASHED_API_KEY"),
        virustotal_api_key=os.environ.get("VIRUSTOTAL_API_KEY"),
        securitytrails_api_key=os.environ.get("SECURITYTRAILS_API_KEY"),
        shodan_api_key=os.environ.get("SHODAN_API_KEY"),
        intelx_api_key=os.environ.get("INTELX_API_KEY"),
    )
    # Carry sub-industry + broker-confirmed regulatory flags through.
    # Simulate what the broker would tick in the form:
    #   accountable_institution = True (auto-detected, broker would confirm)
    #   b2c = True (auto-detected, broker would confirm)
    #   listed_company = False (not auto-detected; broker leaves unchecked)
    broker_flags = {
        "accountable_institution": True,
        "b2c": True,
        "_auto_detected": preflight.get("flags", {}),
    }
    scanner._regulatory_flags = broker_flags
    scanner._sub_industry = SUB_INDUSTRY

    # --- Step 3: Run scan with timing ---
    print(f"\n[3] Running scan against {DOMAIN}...")
    progress_log = []

    def on_progress(event):
        ev_type = event.get("status") or event.get("type") or "?"
        ev_name = event.get("checker") or "?"
        if ev_type in ("done", "complete"):
            score = event.get("score")
            score_str = f" score={score}" if score is not None else ""
            print(f"    [{ev_type:>8s}] {ev_name}{score_str}")
            progress_log.append((time.perf_counter(), ev_type, ev_name))

    t_scan_start = time.perf_counter()
    result = scanner.scan(
        DOMAIN,
        on_progress=on_progress,
        industry=INDUSTRY,
        annual_revenue=0,
        annual_revenue_zar=ANNUAL_REVENUE_ZAR,
        country="ZA",
        include_fraudulent_domains=False,
    )
    t_scan = time.perf_counter() - t_scan_start
    print(f"\n    Total scan wall time: {t_scan:.1f}s ({t_scan / 60:.2f} min)")

    # --- Step 4: Inspect output for new fields ---
    print(f"\n[4] Verifying new Batch 1-4 fields in result...")
    sc = result.get("_scan_completeness", {})
    print(f"    _scan_completeness.checkers_observed: {sc.get('checkers_observed', '?')}")
    print(f"    _scan_completeness.total_checker_seconds: {sc.get('total_checker_seconds', '?')}s")
    slowest = sc.get("slowest_checker", ("?", 0))
    print(f"    slowest checker: {slowest[0]} ({slowest[1]:.1f}s)")

    durations = sc.get("per_checker_seconds", {})
    print(f"\n    Per-checker timing (top 10):")
    items = sorted(durations.items(), key=lambda kv: kv[1], reverse=True)[:10]
    for name, secs in items:
        print(f"      {secs:7.2f}s  {name}")

    ins = result.get("insurance", {})
    fin = ins.get("financial_impact", {})
    print(f"\n    Financial impact module presence:")
    print(f"      currency: {fin.get('currency', '?')}")
    print(f"      score:    {fin.get('score', '?')}")

    le = fin.get("loss_exposure", {})
    if le:
        print(f"\n    Loss Exposure Scenarios (new in B1/B2):")
        for key, sc_row in (le.get("scenarios") or {}).items():
            print(f"      {sc_row['label']:25s}  R{sc_row['loss_zar']:>13,}  (annual_prob={sc_row.get('annual_prob')})")
    else:
        print(f"      WARNING: loss_exposure block missing from output")

    reg = fin.get("regulatory_exposure", {})
    cat = reg.get("catastrophe_stack", {})
    if cat:
        print(f"\n    Catastrophe Regulatory Stack (new in Phase C):")
        print(f"      capacity_factor:        {cat.get('capacity_factor')}")
        print(f"      revenue_band:           R{cat.get('revenue_band_zar', 0):,}")
        print(f"      popia_statutory_scaled: R{cat.get('popia_statutory_scaled_zar', 0):,}")
        print(f"      cpa_cat:                R{cat.get('cpa_cat_zar', 0):,}")
        print(f"      sector_cat_total:       R{cat.get('sector_cat_total_zar', 0):,}")
        print(f"      total_cat_stack:        R{cat.get('total_cat_stack_zar', 0):,}")
        for fw in cat.get("sector_frameworks", []):
            print(f"        + {fw['framework']}: R{fw['statutory_max_zar']:,} -> R{fw['cat_scaled_zar']:,}")
    else:
        print(f"      WARNING: catastrophe_stack missing from regulatory_exposure")

    mc = fin.get("monte_carlo", {})
    if mc:
        total = mc.get("total", {})
        print(f"\n    Monte Carlo output (B3 verification):")
        print(f"      iterations: {mc.get('iterations')} (expect 50,000)")
        print(f"      P95:    R{total.get('p95', 0):,}")
        print(f"      P99:    R{total.get('p99', 0):,}")
        print(f"      P99.5:  R{total.get('p99_5', 0):,}")
        print(f"      P99.6:  R{total.get('p99_6', 0):,}")
        print(f"      P99 raw vs fitted divergence:  {total.get('p99_fit_applied')}")
        print(f"      mode:   R{total.get('mode', 0):,}")

    rf = reg.get("flags", {})
    auto = rf.get("_auto_detected")
    print(f"\n    Regulatory flag audit trail:")
    print(f"      broker-confirmed flags: {[k for k in rf if not k.startswith('_')]}")
    print(f"      _auto_detected present: {auto is not None}")

    # --- Step 5: Cache result JSON + PDF for tinkering ---
    cache_dir = Path("test_fixtures")
    cache_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d")
    json_path = cache_dir / f"phishield_R10M_finance_{stamp}.json"
    pdf_path = cache_dir / f"phishield_R10M_finance_{stamp}.pdf"
    json_path.write_text(json.dumps(result, indent=2, default=str))
    print(f"\n[5] Cached result JSON to {json_path} ({json_path.stat().st_size // 1024} KB)")

    try:
        pdf_bytes = generate_pdf(result, report_type="full")
        pdf_path.write_bytes(pdf_bytes)
        print(f"    Generated full PDF to {pdf_path} ({pdf_path.stat().st_size // 1024} KB)")
    except Exception as e:
        print(f"    PDF generation FAILED: {e!r}")
        import traceback
        traceback.print_exc()

    print("\n" + "=" * 80)
    print(f"TEST SCAN COMPLETE  wall_time={t_scan:.1f}s  preflight={t_pf:.2f}s")
    print("=" * 80)


if __name__ == "__main__":
    main()
