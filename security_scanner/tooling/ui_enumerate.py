# -*- coding: utf-8 -*-
"""Enumerate every dashboard selector: what it READS, and what it DERIVES.

WHY (OUTSTANDING 5m). The React dashboard is a second rendering path over the
same scan results and has never been validated against the first. The PDF path
is gated by pdf_snapshot, golden and 100+ adversarial scenarios; the dashboard
has a typecheck and two link checks. Nothing asserts the two agree.

The first requirement of 5m is to make "computed in the frontend" a VISIBLE
category rather than an accident, because that is where the two paths can
silently disagree: a passthrough of a stored field cannot diverge from the PDF,
whereas a verdict computed in TypeScript is a second opinion nobody compares.

This tool reports, per selector:
  * the scan categories it reads
  * the top-level result fields it reads
  * DERIVATION MARKERS -- literal verdict strings, thresholds, arithmetic --
    which mean the selector forms its own opinion rather than relaying one

It deliberately does not try to decide correctness. It produces the inventory a
human adjudicates once, which then becomes the baseline a gate can hold.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SEL = os.path.join(HERE, "..", "frontend", "src", "data", "selectors.ts")

# Verdict words a selector should be RELAYING, not inventing.
VERDICT_LITERALS = re.compile(
    r"'(CRITICAL|HIGH|MEDIUM|LOW|Critical|High|Medium|Low|UNKNOWN|Unknown|"
    r"critical|high|medium|low|clean|Clean|PASS|FAIL|Pass|Fail)'")
# A numeric threshold that turns a number into a band.
THRESHOLD = re.compile(r"[<>]=?\s*\d+")
# Arithmetic that builds a new number from stored ones.
ARITH = re.compile(r"(?<![=!<>])[-+*/]\s*(?:\d|\w+\.)|\.reduce\(|Math\.(round|max|min|abs)")


def _bodies(src):
    """(name, body) per exported selector, body running to the next export."""
    marks = [(m.start(), m.group(1))
             for m in re.finditer(r"^export (?:function|const) ([A-Za-z_]+)", src, re.M)]
    out = []
    for i, (pos, name) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(src)
        out.append((name, src[pos:end], src[:pos].count("\n") + 1))
    return out


def main():
    src = open(os.path.normpath(SEL), encoding="utf-8").read()
    rows = []
    for name, body, line in _bodies(src):
        cats = sorted(set(re.findall(r"cat\(\s*r\s*,\s*'([a-z0-9_]+)'", body)))
        fields = sorted(set(re.findall(r"\br\.([A-Za-z_][A-Za-z0-9_]*)", body))
                        | set(re.findall(r"\br\[\s*'([A-Za-z_][A-Za-z0-9_]*)'", body)))
        verdicts = sorted(set(m.group(1) for m in VERDICT_LITERALS.finditer(body)))
        thresholds = len(THRESHOLD.findall(body))
        arith = len(ARITH.findall(body))
        guarded = "isConclusive" in body
        derived = bool(verdicts) or thresholds > 0 or arith > 0
        rows.append({
            "selector": name, "line": line, "categories": cats, "fields": fields,
            "verdict_literals": verdicts, "thresholds": thresholds,
            "arithmetic": arith, "uses_isConclusive": guarded,
            "derives": derived,
        })

    if "--json" in sys.argv:
        print(json.dumps(rows, indent=2))
        return 0

    print("DASHBOARD SELECTOR INVENTORY  (%s)" % os.path.basename(os.path.normpath(SEL)))
    print("=" * 108)
    print("%-26s %-5s %-9s %-6s %-6s %-9s %s"
          % ("selector", "line", "derives?", "thrsh", "arith", "guarded", "categories read"))
    print("-" * 108)
    derived_n = guarded_n = 0
    for r in rows:
        if r["derives"]:
            derived_n += 1
        if r["uses_isConclusive"]:
            guarded_n += 1
        print("%-26s %-5s %-9s %-6s %-6s %-9s %s"
              % (r["selector"], r["line"],
                 "DERIVES" if r["derives"] else "passthru",
                 r["thresholds"], r["arithmetic"],
                 "yes" if r["uses_isConclusive"] else "-",
                 ", ".join(r["categories"])[:44] or "-"))

    print()
    print("  selectors: %d   deriving their own verdict: %d   using isConclusive: %d"
          % (len(rows), derived_n, guarded_n))
    print()
    print("  A DERIVING selector forms an opinion the PDF forms separately in Python.")
    print("  Those are the ones that can disagree with the client's report, and the")
    print("  ones where an unguarded read of an unassessed checker becomes a verdict.")
    risky = [r for r in rows if r["derives"] and not r["uses_isConclusive"] and r["categories"]]
    if risky:
        print()
        print("  DERIVES a verdict from raw category reads with NO isConclusive guard:")
        for r in risky:
            print("     %-24s line %-5s %s" % (r["selector"], r["line"],
                                               ", ".join(r["categories"])[:60]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
