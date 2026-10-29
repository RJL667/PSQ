"""Accuracy of intake.py against the register and our sent instruction emails.

Usage: python3 casebook/pipeline/intake/eval_intake.py   (from workspace root)
Writes eval_rows.csv next to this file and prints per-field accuracy.
Ground truth:
  product route  -> product of the first instruction (issued-wording rule, build_backfill)
  new/renewal    -> register 'type' (rows with a blank type are skipped for this field)
  mailbox folder -> register product + filing_month
  limits         -> limits in the first instruction (scored: exact set, and any overlap)
  turnover       -> instruction turnover, within 10%
  main industry  -> instruction Main industry (first word match)
  insured        -> entity name on the issued quote files / subject (token overlap >= 0.5)
"""
import csv, glob, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
CB = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(CB, "tools"))
sys.path.insert(0, HERE)
import build_backfill as bb  # noqa: E402
import intake as it  # noqa: E402


def toks(s):
    return set(it.norm_entity(s).split())


def main():
    reg = list(csv.DictReader(open(os.path.join(CB, "quote-register.csv"))))
    by_msg = {r["message_id"]: r for r in reg}
    by_conv = {r["conversation_id"]: r for r in reg}
    rows = []
    for f in sorted(glob.glob(os.path.join(CB, "threads/*.json"))):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        if not isinstance(d, dict) or not d.get("messages"):
            continue
        msgs = sorted(d["messages"], key=it.ts)
        instr = None
        for m in msgs:
            if it.own(m):
                p = bb.parse_instruction(bb.body(m))
                if p:
                    instr = p
                    break
        if not instr or not any(not it.own(m) for m in msgs):
            continue
        r = next((by_msg[m["id"]] for m in msgs if m.get("id") in by_msg), None) or by_conv.get(d.get("id"))
        rec = it.intake(d)
        files = [x for m in msgs for x in bb.attachments(m)]
        truth_ent = bb.company_from(bb.headers(msgs[0]).get("Subject", ""), files)
        t_lim = sorted({l for l, _ in instr["limits"] if l})
        t_prod = instr["product"]
        row = {"file": os.path.relpath(f, CB)}

        def score(field, ok, got, want):
            row[field] = "" if ok is None else int(bool(ok))
            row[field + "_got"] = got
            row[field + "_want"] = want

        score("route", rec["product_route"] == t_prod, rec["product_route"], t_prod)
        score("wording", rec["issued_wording_likely"] == t_prod, rec["issued_wording_likely"], t_prod)
        score("type", (rec["type"] == r["type"]) if r and r.get("type") else None, rec["type"], r and r.get("type"))
        if r and r.get("filing_month"):
            want_f = ("Corporate Quotes/" if r["product"] == "Corporate" else "SME Quotes/") + r["filing_month"]
            score("folder", rec["mailbox_folder"] == want_f, rec["mailbox_folder"], want_f)
            score("folder_month", rec["mailbox_folder"][-7:] == r["filing_month"], rec["mailbox_folder"][-7:], r["filing_month"])
        else:
            score("folder", None, rec["mailbox_folder"], None)
            score("folder_month", None, None, None)
        got_l = sorted(rec["requested_limits"])
        score("limits_exact", (got_l == t_lim) if t_lim else None, got_l, t_lim)
        score("limits_cover", (set(t_lim) <= set(got_l)) if t_lim else None, got_l, t_lim)
        score("limits_overlap", (bool(set(got_l) & set(t_lim))) if t_lim else None, got_l, t_lim)
        tt = instr["turnover"]
        score("turnover", (rec["turnover"] is not None and abs(rec["turnover"] - tt) <= 0.1 * tt) if tt else None,
              rec["turnover"], tt)
        mi = (instr["main_industry"] or "").split()
        gi = " ".join(x or "" for x in rec["industry"].values()).lower()
        score("industry_main", (mi[0].lower() in gi) if mi else None, rec["industry"]["main"] or rec["industry"]["description"],
              instr["main_industry"])
        te, ge = toks(truth_ent), toks(rec["insured"])
        score("insured", (len(te & ge) / max(1, min(len(te), len(ge) or 1)) >= 0.6) if te else None, rec["insured"], truth_ent)
        row["questions"] = "; ".join(rec["open_questions"])
        rows.append(row)
    with open(os.path.join(HERE, "eval_rows.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"threads scored: {len(rows)}\n\n| Field | scored | correct | accuracy |\n|---|---|---|---|")
    for fld in ["route", "wording", "type", "folder", "folder_month", "limits_exact", "limits_cover", "limits_overlap", "turnover",
                "industry_main", "insured"]:
        xs = [x[fld] for x in rows if x[fld] != ""]
        print(f"| {fld} | {len(xs)} | {sum(xs)} | {100 * sum(xs) / len(xs):.0f}% |" if xs else f"| {fld} | 0 | - | - |")
    if "-v" in sys.argv:
        fld = sys.argv[sys.argv.index("-v") + 1]
        for x in rows:
            if x[fld] == 0:
                print(x["file"], "| got:", x[fld + "_got"], "| want:", x[fld + "_want"])


if __name__ == "__main__":
    main()
