"""Baseline: broker request received -> first instruction email sent, per thread.

Usage: python3 casebook/pipeline/intake/baseline.py  (run from workspace root)
Writes casebook/pipeline/intake/baseline.csv and prints the summary table.
"""
import csv, glob, json, os, re, sys
from statistics import median

HERE = os.path.dirname(os.path.abspath(__file__))
CB = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(CB, "tools"))
import build_backfill as bb  # noqa: E402

OWN = bb.OWN
REN_RE = re.compile(r"renewal|renew\b|\bCYB/R\d|R0000\d|existing (policy|cover)|expir", re.I)


def ts(m):
    return int(m.get("internalDate") or 0) / 1000.0


def load_register():
    reg = list(csv.DictReader(open(os.path.join(CB, "quote-register.csv"))))
    by_msg = {r["message_id"]: r for r in reg}
    by_conv = {r["conversation_id"]: r for r in reg}
    return by_msg, by_conv


def vg_threads():
    reg = json.load(open(os.path.join(CB, "quote_check/pending/register.json")))
    return {e["thread_id"] for e in reg}


def analyse(d, fname, by_msg, by_conv, vg):
    msgs = sorted(d.get("messages", []), key=ts)
    if not msgs:
        return None
    first_instr = None
    for i, m in enumerate(msgs):
        if OWN in bb.headers(m).get("From", ""):
            p = bb.parse_instruction(bb.body(m))
            if p:
                first_instr = (i, m, p)
                break
    if not first_instr:
        return None
    i, im, p = first_instr
    # the request = the latest external message before the instruction that is not our own
    # (first external message in the thread; forwards inside it carry older dates we ignore)
    ext = [m for m in msgs[:i] if OWN not in bb.headers(m).get("From", "")]
    if not ext:
        return None
    req = ext[0]
    subj = bb.headers(msgs[0]).get("Subject", "")
    reg = None
    for m in msgs:
        reg = reg or by_msg.get(m.get("id"))
    reg = reg or by_conv.get(d.get("id"))
    rtype = (reg or {}).get("type") or ""
    if not rtype:
        txt = subj + " " + bb.body(req)[:3000]
        rtype = "Renewal" if REN_RE.search(txt) else "New"
    product = "Corporate" if p["product"] == "corporate" else "SME"
    hours = (ts(im) - ts(req)) / 3600.0
    tid = d.get("id")
    is_vg = tid in vg or any(m.get("id") in vg for m in msgs) or "quote_check/pending" in fname
    return {
        "file": os.path.relpath(fname, CB), "subject": subj[:90], "product": product,
        "type": rtype, "veilguard": is_vg,
        "request_utc": bb.headers(req).get("Date", ""), "instruction_utc": bb.headers(im).get("Date", ""),
        "hours": round(hours, 2), "n_msgs_before": i, "register_product": (reg or {}).get("product", ""),
    }


def pct(xs, q):
    xs = sorted(xs)
    if not xs:
        return None
    k = (len(xs) - 1) * q
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def fmt(h):
    if h is None:
        return "-"
    return f"{h:.1f} h" if h < 48 else f"{h / 24:.1f} d"


def main():
    by_msg, by_conv = load_register()
    vg = vg_threads()
    rows, seen = [], set()
    files = sorted(glob.glob(os.path.join(CB, "threads/*.json"))) + \
        sorted(glob.glob(os.path.join(CB, "quote_check/pending/*.json")))
    for f in files:
        if f.endswith("register.json"):
            continue
        try:
            d = json.load(open(f))
        except Exception:
            continue
        if not isinstance(d, dict) or d.get("id") in seen:
            continue
        seen.add(d.get("id"))
        r = analyse(d, f, by_msg, by_conv, vg)
        if r:
            rows.append(r)
    with open(os.path.join(HERE, "baseline.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    neg = [r for r in rows if r["hours"] < 0]
    ok = [r for r in rows if r["hours"] >= 0]
    groups = []
    for label, flt in [
        ("All manual (pre-Veilguard)", lambda r: not r["veilguard"]),
        ("Manual Corporate New", lambda r: not r["veilguard"] and r["product"] == "Corporate" and r["type"] == "New"),
        ("Manual Corporate Renewal", lambda r: not r["veilguard"] and r["product"] == "Corporate" and r["type"] == "Renewal"),
        ("Manual SME New", lambda r: not r["veilguard"] and r["product"] == "SME" and r["type"] == "New"),
        ("Manual SME Renewal", lambda r: not r["veilguard"] and r["product"] == "SME" and r["type"] == "Renewal"),
        ("Veilguard-assisted (Oct 2026)", lambda r: r["veilguard"]),
    ]:
        xs = [r["hours"] for r in ok if flt(r)]
        groups.append((label, len(xs), median(xs) if xs else None, pct(xs, 0.75), max(xs) if xs else None))
    print("| Group | n | median | p75 | slowest |\n|---|---|---|---|---|")
    for g in groups:
        print(f"| {g[0]} | {g[1]} | {fmt(g[2])} | {fmt(g[3])} | {fmt(g[4])} |")
    print(f"\nthreads with request+instruction: {len(rows)}; negative/odd timings dropped: {len(neg)}")
    for r in neg:
        print("  NEG", r["file"], r["hours"], r["subject"])
    print("\nslowest 8:")
    for r in sorted(ok, key=lambda r: -r["hours"])[:8]:
        print(f"  {fmt(r['hours'])}  {r['product']} {r['type']} {r['file']} {r['subject']}")
    print("\nVeilguard rows:")
    for r in ok:
        if r["veilguard"]:
            print(f"  {fmt(r['hours'])}  {r['product']} {r['type']} {r['file']} {r['subject']}")


if __name__ == "__main__":
    main()
