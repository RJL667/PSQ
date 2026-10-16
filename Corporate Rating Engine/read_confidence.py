"""Confidence scoring for answers read from client documents and mapped onto our assessment form.

Every answer carries two confidences, each 0..1:
  read  - how sure we are of WHAT the document says (tick mark, typed field, OCR text)
  map   - how sure we are WHICH question on our form it answers (question-text match)
The answer's confidence is read x map, reported as a percentage.

The form gets three numbers:
  answer_confidence  - mean answer confidence, weighted by each question's weight in the posture
  posture_range      - 5th to 95th percentile posture when uncertain answers are allowed to flip
  band_confidence    - share of those simulations that land in the same maturity band
plus the uncertain answers that move the posture most, so the underwriter checks those first.

Source defaults (read confidence) when a reader gives none:
  fillable_form 1.00 (field values are exact), review 1.00 (underwriter), quote 1.00 (quote wording),
  visual 0.90 (read by eye from a crop), llm_text 0.75 (mapped from free text), tick_ocr computed.
"""
import random
import statistics

SOURCE_READ = {"fillable_form": 1.0, "review": 1.0, "quote": 1.0, "visual": 0.9, "llm_text": 0.75}

# ---------------------------------------------------------------------------------------------
# Calibration. A raw tick score is only a ranking. The percentage we report is the share of past
# reads with a similar raw score that turned out right, taken from labelled rows (answers a quote
# confirmed, and every underwriter correction saved in the casebook). It is stored per source in
# calibration.json and sharpens as more cases are reviewed. With few labels it leans on a prior.
# ---------------------------------------------------------------------------------------------
import json as _json
from pathlib import Path as _Path

CAL_PATH = _Path(__file__).resolve().parent / "calibration.json"
CAL_BINS = (0.0, 0.3, 0.45, 0.6, 0.75, 1.01)
CAL_PRIOR, CAL_PRIOR_WEIGHT = 0.8, 4.0


def _bin(x):
    for i in range(len(CAL_BINS) - 1):
        if CAL_BINS[i] <= x < CAL_BINS[i + 1]:
            return i
    return len(CAL_BINS) - 2


def load_calibration(path=CAL_PATH):
    try:
        return _json.loads(_Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def fit_calibration(labelled, source="tick_ocr", path=CAL_PATH):
    """labelled: [(raw_read, correct_bool)]. Adds to the stored counts and saves."""
    cal = load_calibration(path)
    src = cal.setdefault(source, {"bins": list(CAL_BINS), "right": [0] * (len(CAL_BINS) - 1),
                                  "total": [0] * (len(CAL_BINS) - 1), "labels": 0})
    for raw, ok in labelled:
        b = _bin(float(raw))
        src["total"][b] += 1
        src["right"][b] += 1 if ok else 0
        src["labels"] += 1
    _Path(path).write_text(_json.dumps(cal, indent=1), encoding="utf-8")
    return cal


def calibrated(raw, source="tick_ocr", cal=None):
    """Raw read score -> probability the read is right (0..1), smoothed toward the prior and kept
    monotonic (a higher raw score never gets a lower percentage)."""
    cal = load_calibration() if cal is None else cal
    src = cal.get(source)
    if not src:
        return raw
    probs = []
    for i in range(len(CAL_BINS) - 1):
        mid_prior = CAL_PRIOR * (0.75 + 0.5 * (i / (len(CAL_BINS) - 2)))   # gentle slope 0.6..1.0
        probs.append((src["right"][i] + CAL_PRIOR_WEIGHT * min(0.99, mid_prior))
                     / (src["total"][i] + CAL_PRIOR_WEIGHT))
    for i in range(1, len(probs)):                                         # monotonic
        probs[i] = max(probs[i], probs[i - 1])
    return round(min(0.99, probs[_bin(float(raw))]), 3)


def tick_confidence(f, neighbours=()):
    """Read confidence for one hand-ticked Y/N row from tick-reader features.

    f: {low, cx, yc, nc, mass, massY, massN, coreY?, coreN?, gap_above?, gap_below?}. Four signals vote:
    the tick's vertex (the call), its ink centroid, residual ink near each letter in a wide window, and
    the same on the question's own text line (core). Confidence rises with agreement, with how far the
    vertex sits from the Y/N midpoint and with how much ink there is. It drops when the row is crowded
    by its neighbours or shares its ink with a neighbouring row (the tick may belong to that row)."""
    if not f or f.get("yc") is None or f.get("low") is None or (f.get("mass") or 0) < 20:
        return {"call": "?", "read": 0.0, "why": "no tick found"}
    yc, nc = float(f["yc"]), float(f["nc"])
    mid, half = (yc + nc) / 2, max(1.0, (nc - yc) / 2)
    call = "Y" if f["low"] < mid else "N"
    votes = [call]
    if f.get("cx") is not None:
        votes.append("Y" if f["cx"] < mid else "N")
    my, mn = float(f.get("massY") or 0), float(f.get("massN") or 0)
    if my + mn > 0:
        votes.append("Y" if my > mn else "N")
    cy_, cn_ = float(f.get("coreY") or 0), float(f.get("coreN") or 0)
    core_margin = abs(cy_ - cn_) / (cy_ + cn_ + 1.0) if (cy_ + cn_) > 0 else None
    if core_margin is not None and core_margin >= 0.15:
        votes.append("Y" if cy_ > cn_ else "N")
    agree = votes.count(call) / len(votes)
    pos = min(1.0, abs(f["low"] - mid) / half)
    margin = abs(my - mn) / (my + mn + 1.0)
    strength = min(1.0, float(f["mass"]) / 150.0)
    lo_agree = 1.0 / len(votes)
    score = 0.45 * pos + 0.35 * ((agree - lo_agree) / (1 - lo_agree) if lo_agree < 1 else 1.0) + 0.20 * margin
    read = (0.15 + 0.85 * score) * (0.7 + 0.3 * strength)
    why = []
    if agree < 1:
        why.append("signals disagree (%d of %d agree)" % (votes.count(call), len(votes)))
    if pos < 0.3:
        why.append("tick sits between Y and N")
    if strength < 0.5:
        why.append("faint mark")
    if core_margin is not None and core_margin < 0.15:
        read *= 0.85
        why.append("own line shows ink at both Y and N")
    for nb in neighbours or ():
        if nb and nb.get("low") is not None and abs(nb["low"] - f["low"]) <= 3 \
                and nb.get("cx") is not None and f.get("cx") is not None and abs(nb["cx"] - f["cx"]) <= 6:
            read *= 0.7
            why.append("same ink as a neighbouring row")
            break
    read = max(0.0, min(0.99, read))
    return {"call": call, "read": round(read, 3), "why": "; ".join(why) or "clear tick"}


def answer_confidence(a):
    """a: {row, value, source, read?, map?} -> adds 'confidence' (0..1) and 'pct'."""
    read = a.get("read")
    if read is None:
        read = SOURCE_READ.get(a.get("source"), 0.5)
    elif a.get("source") == "tick_ocr" and not a.get("raw_only"):
        a = dict(a, raw_read=read)
        read = calibrated(read, "tick_ocr")
    mp = a.get("map")
    mp = 1.0 if mp is None else float(mp)
    c = max(0.0, min(1.0, float(read) * mp))
    return dict(a, read=round(float(read), 3), map=round(mp, 3), confidence=round(c, 3), pct=round(c * 100))


def _flip(value, q):
    opts = (q or {}).get("options") or []
    if value in ("Yes", "No"):
        return "No" if value == "Yes" else "Yes"
    others = [o for o in opts if o != value]
    return random.choice(others) if others else None


def assess_with_confidence(records, context=None, sims=400, seed=7):
    """records: list of answer dicts (see answer_confidence). Later records override earlier ones for
    the same row, so pass them in order of trust (OCR first, review last)."""
    import questionnaire as Q
    rows = {}
    for r in records:
        rows[int(r["row"])] = answer_confidence(r)
    answers = {k: v["value"] for k, v in rows.items() if v.get("value") is not None}
    base = Q.assess(answers, context)
    m = Q._model()
    qmeta = {q["row"]: q for q in m["questions"]}

    # Posture weight per row: section weight / scored questions in that section (an approximation
    # good enough to rank answers; the simulation below uses the exact workbook formulas).
    weight = {}
    sec_w = {s["section"]: s["weight"] for s in base["sections"] if isinstance(s.get("weight"), (int, float))}
    by_sec = {}
    for q in m["questions"]:
        if q.get("scored"):
            by_sec.setdefault(q.get("section"), []).append(q["row"])
    for sec, rs in by_sec.items():
        for r in rs:
            weight[r] = (sec_w.get(sec) or 0.0) / len(rs)
    scored = [r for r in rows if weight.get(r)]
    tw = sum(weight[r] for r in scored) or 1.0
    form_conf = sum(rows[r]["confidence"] * weight[r] for r in scored) / tw

    # Monte Carlo: each answer flips with probability (1 - confidence).
    rnd = random.Random(seed)
    random.seed(seed)
    band0 = base["maturity"]["band"]
    postures, same = [], 0
    for _ in range(sims):
        a = dict(answers)
        for r, rec in rows.items():
            if r in a and rnd.random() > rec["confidence"]:
                fv = _flip(a[r], qmeta.get(r))
                if fv is not None:
                    a[r] = fv
        res = Q.assess(a, context)
        if res.get("posture") is None:
            continue
        postures.append(res["posture"])
        same += res["maturity"]["band"] == band0
    postures.sort()
    pct = lambda p: postures[min(len(postures) - 1, int(p * len(postures)))] if postures else None  # noqa: E731

    # Which uncertain answers matter most: posture change if flipped x chance it is wrong.
    impact = []
    for r, rec in rows.items():
        if rec["confidence"] >= 0.95 or r not in answers:
            continue
        fv = _flip(answers[r], qmeta.get(r))
        if fv is None:
            continue
        d = Q.assess({**answers, r: fv}, context).get("posture")
        if d is None or base.get("posture") is None:
            continue
        delta = d - base["posture"]
        impact.append({"row": r, "question": (qmeta.get(r) or {}).get("text"), "read_as": answers[r],
                       "confidence_pct": rec["pct"], "why": rec.get("why"),
                       "posture_if_wrong": round(delta, 4),
                       "risk": round(abs(delta) * (1 - rec["confidence"]), 5)})
    impact.sort(key=lambda x: -x["risk"])

    buckets = {"high (90%+)": 0, "medium (70-89%)": 0, "low (<70%)": 0}
    for rec in rows.values():
        k = "high (90%+)" if rec["pct"] >= 90 else "medium (70-89%)" if rec["pct"] >= 70 else "low (<70%)"
        buckets[k] += 1
    base["read_confidence"] = {
        "answer_confidence_pct": round(form_conf * 100),
        "answers_by_confidence": buckets,
        "posture_range": {"p05": pct(0.05), "p50": pct(0.5), "p95": pct(0.95)},
        "band": band0,
        "band_confidence_pct": round(100 * same / len(postures)) if postures else None,
        "check_first": impact[:8],
        "answers": {str(r): rows[r] for r in sorted(rows)},
        "simulations": len(postures),
    }
    return base


def calibration(records, truth):
    """How well confidence predicts correctness on labelled rows. truth: {row: correct value}."""
    out = []
    for r in records:
        row = int(r["row"])
        if row in truth:
            a = answer_confidence(r)
            out.append({"row": row, "pct": a["pct"], "correct": a["value"] == truth[row]})
    out.sort(key=lambda x: x["pct"])
    bands = {}
    for x in out:
        k = "90+" if x["pct"] >= 90 else "70-89" if x["pct"] >= 70 else "<70"
        b = bands.setdefault(k, [0, 0])
        b[0] += x["correct"]
        b[1] += 1
    return {"rows": out, "accuracy_by_band": {k: "%d/%d" % tuple(v) for k, v in bands.items()},
            "mean_conf_correct": statistics.mean([x["pct"] for x in out if x["correct"]] or [0]),
            "mean_conf_wrong": statistics.mean([x["pct"] for x in out if not x["correct"]] or [0])}
