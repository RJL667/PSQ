# Archived artifacts (2026-06-11)

Superseded files moved out of the active tree during the operational
hardening pass. Kept in-repo (not deleted) as audit trail / rollback
reference. Nothing here is imported or executed by the live scanner.

| Item | Why archived |
|---|---|
| `gen_gap_v9.cjs` | Superseded by `gen_gap_v10.cjs` (still active in root). |
| `generate_sensitivity_doc.cjs`, `sensitivity_analysis.py`, `sensitivity_results.json` | v1 sensitivity chain — superseded by the v2 chain (`sensitivity_analysis_v2.py` → `sensitivity_results_v2.json` → `gen_sensitivity_doc.cjs`), which received the 2026-06-08 fixture-fallback patch. |
| `_sub_ind_js.txt` | Raw sub-industry/SIC dump from an earlier ETL step; the live mapping is generated and guarded by `tooling/verify_subindustry_dropdown_mapping.py`. |
| `_spec_workspace/` | Multi-agent specification workbench from the 2026-04/05 design phase; superseded by `docs/` (BACKTEST/RETEST/HEURISTICS_AUDIT/calibration_prep). |
