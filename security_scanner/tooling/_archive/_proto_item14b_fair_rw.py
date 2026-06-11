# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX PROTOTYPE (finding #6, NOT shipped): restore FAIR on the ransomware
channel. Today the 3 ransomware legs use rsi_score directly as a frequency (an
index, ~8x the breach LEF). Recast as a proper FAIR loss-event frequency:
   p_ransomware = rsi_score x RW_LEF                 # RW_LEF = 0.30 (reuse breach LEF)
   leg_i = p_ransomware x (ratio_i / sum_ratio)      # conditional shares sum to 1
rsi_score already carries a modest industry/size tilt, so NO extra TEF (would
double-count industry targeting). Severities, breach legs, ddos, cat tail
untouched. Applied to BOTH the central incidents dict AND the MC (prob-weighted
+ compound) ransomware legs. CRLF-preserving; restore from .item14bak after.
"""
import os

SA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

# 1. Define the FAIR ransomware frequency right after the split ratios R.
anchor_R = "        # ── Split ratios ──\n        R = self.INCIDENT_SPLIT_RATIOS\n"
assert s.count(anchor_R) == 1, ("R anchor", s.count(anchor_R))
s = s.replace(anchor_R, anchor_R +
    "\n"
    "        # ── FAIR-restore (SANDBOX PROTOTYPE, finding #6 - NOT shipped) ──\n"
    "        # Ransomware legs used rsi_score directly as a frequency (an index, not\n"
    "        # TEF x Vulnerability), running ~8x the breach LEF. Recast as a proper\n"
    "        # FAIR annual loss-event frequency p_ransomware = rsi_score x RW_LEF,\n"
    "        # partitioned across the 3 ransomware types by their conditional shares\n"
    "        # (so the legs sum to p_ransomware). rsi_score already carries a modest\n"
    "        # industry/size tilt, so NO extra TEF (avoids double-counting targeting).\n"
    "        # RW_LEF reuses the breach 0.3 LEF constant (colleague-gated lever).\n"
    "        RW_LEF = 0.30\n"
    "        _rw_share_sum = R[\"double_extortion\"] + R[\"ransomware_only\"] + R[\"wiper_destructive\"]\n"
    "        rsi_freq = rsi_score * RW_LEF / _rw_share_sum\n",
    1)

# 2. Define the MC counterpart right after mc_rsi is sampled.
anchor_mcrsi = ("        mc_rsi = np.clip(self._pert_sample(rsi_score * 0.5, rsi_score,"
                " min(1.0, rsi_score * 2.0), N), 0, 1)\n")
assert s.count(anchor_mcrsi) == 1, ("mc_rsi anchor", s.count(anchor_mcrsi))
s = s.replace(anchor_mcrsi, anchor_mcrsi +
    "        mc_rsi_freq = np.clip(mc_rsi * RW_LEF / _rw_share_sum, 0, 1)  # FAIR-restore (finding #6, sandbox)\n",
    1)

# 3. Swap the ransomware-leg driver: central (count 1 each) + MC prob-weighted &
#    compound (count 2 each). Severities/costs unchanged.
swaps = [
    ('rsi_score * R["double_extortion"]', 'rsi_freq * R["double_extortion"]', 1),
    ('rsi_score * R["ransomware_only"]',  'rsi_freq * R["ransomware_only"]',  1),
    ('rsi_score * R["wiper_destructive"]','rsi_freq * R["wiper_destructive"]', 1),
    ('mc_rsi * R["double_extortion"]',    'mc_rsi_freq * R["double_extortion"]', 2),
    ('mc_rsi * R["ransomware_only"]',     'mc_rsi_freq * R["ransomware_only"]',  2),
    ('mc_rsi * R["wiper_destructive"]',   'mc_rsi_freq * R["wiper_destructive"]', 2),
]
for old, new, want in swaps:
    got = s.count(old)
    assert got == want, (old, "expected", want, "got", got)
    s = s.replace(old, new)

# Post-conditions
assert "rsi_freq = rsi_score * RW_LEF / _rw_share_sum" in s
assert "mc_rsi_freq = np.clip(mc_rsi * RW_LEF" in s
assert s.count("mc_rsi_freq * R[") == 6
assert s.count("rsi_freq * R[") == 9  # 3 central + 6 mc (mc_rsi_freq contains rsi_freq)
assert "\r" not in s
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print("OK scoring_analytics.py: FAIR ransomware-LEF prototype applied (3 central + 6 MC legs).")
