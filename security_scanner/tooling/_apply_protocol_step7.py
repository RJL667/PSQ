# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (2026-06-08): add Step 7 (output-surface wiring + Attacker's-View kill-chain
placement) to docs/card_verification_protocol.md, after the supply-chain checkers were
found priced in the model but MISSING from the Attacker's View. CRLF-safe. NOT shipped
by this script."""
import os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = os.path.join(ROOT, "docs", "card_verification_protocol.md")
s = open(P, encoding="utf-8").read()
assert "\r" not in s
n = 0

for tag, old, new in [
    ("count 6->7 intro",
     "A card is not \"accurate\" until it passes this 6-step ground-truth check on a",
     "A card is not \"accurate\" until it passes this 7-step ground-truth check on a"),
    ("header 6->7",
     "## The 6 steps",
     "## The 7 steps"),
    ("insert step 7",
     "   `_probe` (200-only + body-sanity) is the reference pattern for response\n"
     "   handling.\n"
     "\n"
     "## Pass criteria\n",
     "   `_probe` (200-only + body-sanity) is the reference pattern for response\n"
     "   handling.\n"
     "\n"
     "7. **Output-surface wiring + Attacker's-View placement (run for every NEW checker).**\n"
     "   A checker is NOT \"done\" when its own card renders - it must be wired into every\n"
     "   output surface where its risk class belongs, and its kill-chain role decided:\n"
     "   - **All four tiers + the risk-class roll-up** - confirm the checker (or its\n"
     "     family roll-up) appears wherever that family is summarised, not only on its\n"
     "     own card (e.g. a supply-chain checker must surface in the Supply-Chain\n"
     "     Exposure slide, not just its individual card).\n"
     "   - **Attacker's View kill chain** - EXPLICITLY decide whether the finding is an\n"
     "     attacker step and, if so, wire it into `_assessment_kill_chain` (+\n"
     "     `_kill_chain_severities`) under the right phase (Recon / Initial Access /\n"
     "     Exploitation / Data & Impact). The kill chain is the SINGLE shared source for\n"
     "     the full, broker and exec-deck Attacker's View, so one edit covers all tiers.\n"
     "     **Default: an externally-observable finding IS an attacker step** - exclusion\n"
     "     is the exception and must carry a one-line written justification, not silence.\n"
     "   - **Consistency with the priced signal** - if the four-channel financial\n"
     "     anchoring routed the signal into p_breach / severity / tail, the Attacker's\n"
     "     View narrative must reflect it too. A signal that moves the number but never\n"
     "     appears in the \"how they break in\" story is an inconsistency.\n"
     "   - *Origin (2026-06-08): the six supply-chain checkers (S-1/2/3/4/5/10) were\n"
     "     priced via `supply_chain_vulnerability_uplift` but absent from the kill chain\n"
     "     - the exact failure mode this step exists to prevent.*\n"
     "\n"
     "## Pass criteria\n"),
    ("pass-criteria checkbox",
     "- [ ] **Every heuristic enumerated, screened against the failure modes, and classified (justified / fragile / arbitrary / calibration-gated) — no fabrication, no generic-response-as-signal, no boolean-as-count, no inversion, no stale table**\n",
     "- [ ] **Every heuristic enumerated, screened against the failure modes, and classified (justified / fragile / arbitrary / calibration-gated) — no fabrication, no generic-response-as-signal, no boolean-as-count, no inversion, no stale table**\n"
     "- [ ] **Wired into every relevant output surface, and an explicit Attacker's-View kill-chain placement (which phase) OR a written exclusion justification**\n"),
]:
    c = s.count(old)
    assert c == 1, (tag, c)
    s = s.replace(old, new, 1); n += 1

with open(P, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print(f"OK card_verification_protocol.md: {n} edits (Step 7 added; 6->7).")
