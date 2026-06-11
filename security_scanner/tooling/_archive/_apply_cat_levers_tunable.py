# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (2026-06-08): hoist the cat-lever parameters to module level + make them
env-overridable, so the curve can be swept now and tuned in early-stage production
without a redeploy. Defaults = the current values (Lever 1 MIN=0.30 / HI=R2bn, Lever 2
floor=0.60). Removes the in-method local definitions so calculate() reads the globals.
CRLF-safe. NOT shipped by this script."""
import ast, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SA = os.path.join(ROOT, "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s
n = 0

# 1. Module-level, env-overridable constants (before _grade_probability).
OLD = "def _grade_probability(pct, bands):\n"
NEW = (
    "# Catastrophe-model calibration levers (env-overridable; defaults are the\n"
    "# colleague-reviewed values). Lever 1: small->large taper on the IBM-average C1\n"
    "# residual - CAT_RESIDUAL_TAPER_MIN is the residual weight at <=R10M revenue;\n"
    "# CAT_RESIDUAL_TAPER_HI_ZAR is the revenue at which the taper reaches 1.0 (no\n"
    "# taper, large-cap). Lever 2: FINE_CAPACITY_FLOOR floors the capacity factor used\n"
    "# for fixed-cap statutory fines (POPIA/ECTA/sector). Env-overridable so the cat\n"
    "# curve can be re-tuned in early-stage production WITHOUT a redeploy.\n"
    "import os as _os\n"
    "\n"
    "\n"
    "def _cat_env_float(key, default, lo, hi):\n"
    "    try:\n"
    "        return min(hi, max(lo, float(_os.environ.get(key, default))))\n"
    "    except (TypeError, ValueError):\n"
    "        return default\n"
    "\n"
    "\n"
    "CAT_RESIDUAL_TAPER_MIN    = _cat_env_float(\"CAT_RESIDUAL_TAPER_MIN\", 0.30, 0.0, 1.0)\n"
    "CAT_RESIDUAL_TAPER_HI_ZAR = _cat_env_float(\"CAT_RESIDUAL_TAPER_HI_ZAR\", 2_000_000_000.0, 1e7, 1e12)\n"
    "FINE_CAPACITY_FLOOR       = _cat_env_float(\"FINE_CAPACITY_FLOOR\", 0.60, 0.0, 1.0)\n"
    "\n"
    "\n"
    "def _grade_probability(pct, bands):\n"
)
assert s.count(OLD) == 1, ("grade_probability anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 2. Remove the in-method Lever-2 local (line ~2304).
OLD = "        FINE_CAPACITY_FLOOR = 0.60\n        fine_capacity_factor = max(capacity_factor, FINE_CAPACITY_FLOOR)\n"
NEW = "        fine_capacity_factor = max(capacity_factor, FINE_CAPACITY_FLOOR)\n"
assert s.count(OLD) == 1, ("fine floor local", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 3. Remove the in-method Lever-1 locals (line ~2418-2419).
OLD = "        CAT_RESIDUAL_TAPER_MIN = 0.30\n        CAT_RESIDUAL_TAPER_HI_ZAR = 2_000_000_000\n"
NEW = ""
assert s.count(OLD) == 1, ("taper locals", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

assert "_cat_env_float" in s and s.count("CAT_RESIDUAL_TAPER_MIN") >= 3
ast.parse(s)
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(SA, encoding="utf-8").read())
print(f"OK scoring_analytics.py: {n} edits (cat levers hoisted to module-level + env-overridable).")
