import io
p = r"C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\.claude\worktrees\blissful-chandrasekhar-0714c9\security_scanner\tooling\_build_dryrun_outcomes_docx.py"
s = io.open(p, encoding="utf-8", newline="").read()
start_anchor = '    ("C1 liability floors to 0 for high-revenue orgs. ",'
end_anchor = '"C3 be surfaced in cost_components?"),'
assert s.count(start_anchor) == 1, "start anchor count"
i = s.index(start_anchor)
j = s.index(end_anchor, i) + len(end_anchor)
new_block = (
    '    ("C1 liability — give it its own factor in the cat model, not the residual balance. ",\n'
    '     "Today C1 = max(0, severity − C2 − C3 − C4 − C5) is a residual/plug. C3/BI is independently "\n'
    '     "revenue-scaled, overruns the breach anchor, and floors C1 to 0 for big orgs (takealot C1=0; cost_components "\n'
    '     "also omits C3, so the visible ≈ R 30.8m understates the MC-derived ML R 124.0m). The residual is only the "\n'
    '     "symptom — a residual cannot carry its own tail, yet liability is the heaviest-tailed bucket in real cyber "\n'
    '     "cat (class actions / regulatory cascade). Direction: in the CAT model (mc_c1, :2521) model C1 as an "\n'
    '     "independent severity + tail; keep the residual in the central/point estimate (:2342 — a real central loss "\n'
    '     "can legitimately floor a bucket). Side effects: removes the floor artefact AND restores a non-zero C1+C2 "\n'
    '     "severity for FIN-9 (:2531) to widen. Candidate drivers: records × per-record liability (records already "\n'
    '     "estimated, currently disclosure-only) or an independent lognormal/Pareto anchor; demote the IBM total to a "\n'
    '     "coherence cap. Also surface C3 in cost_components (display fix)."),'
)
s2 = s[:i] + new_block + s[j:]
io.open(p, "w", encoding="utf-8", newline="").write(s2)
print("OK patched item5; char delta", len(s2)-len(s))
