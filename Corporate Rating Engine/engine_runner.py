"""
Run the corporate rating engine (corporate-engine.js, the same file the browser uses)
inside the Python service, so every saved quote is recalculated on the server.

The JS context is built once per worker process and guarded by a lock (a V8 isolate is
not thread-safe, and gunicorn runs several threads per worker).
"""
import hashlib
import json
import re
import threading
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
_lock = threading.Lock()
_ctx = None
_version = None


def _racer():
    try:
        from py_mini_racer import MiniRacer
    except ImportError:  # newer package layout
        from mini_racer import MiniRacer
    return MiniRacer()


def _load():
    global _ctx, _version
    data = (BASE_DIR / "corporate-data.js").read_text(encoding="utf-8")
    engine = (BASE_DIR / "corporate-engine.js").read_text(encoding="utf-8")
    ctx = _racer()
    ctx.eval(data + "\n;globalThis.CORP_DATA = CORP_DATA;")
    ctx.eval(engine)
    _version = hashlib.sha256((data + engine).encode("utf-8")).hexdigest()[:12]
    _ctx = ctx


def version():
    with _lock:
        if _ctx is None:
            _load()
        return _version


_industries = None


def industries():
    """The engine's sub-industry labels, e.g. 'Services - Business Services'."""
    global _industries
    with _lock:
        if _ctx is None:
            _load()
        if _industries is None:
            _industries = json.loads(_ctx.eval(
                "JSON.stringify(CORP_DATA.INDUSTRIES.map(function (r) { return r.sub; }))"))
    return _industries


def _norm(s):
    s = (s or "").lower().replace("&", " and ")
    s = re.sub(r"\badmin\b", "administration", s)
    return re.sub(r"[^a-z0-9]+", " ", s).strip()


def resolve_industry(sub, main=""):
    """Map a sub-industry as written in an email or by a caller ('Business Services',
    'Software & Technology') to the engine's label. None when nothing fits."""
    if not sub:
        return None
    labels = industries()
    if sub in labels:
        return sub
    n = _norm(sub)
    for lab in labels:
        if _norm(lab) == n or _norm(lab) == _norm(f"{main} - {sub}"):
            return lab
    hits = []
    for lab in labels:
        head, _, tail = lab.partition("-")
        if _norm(tail) == n:
            hits.append((_norm(head), lab))
    if not hits:
        # 'Fabricated Metal Products' -> '... Fabricated Metal Products, Except Machinery ...';
        # 'Durable Goods' -> 'Wholesale Trade - Wholesale Trade-durable Goods'.
        for lab in labels:
            head, _, tail = lab.partition(" - ")
            t = _norm(tail)
            if len(n) >= 8 and (t.startswith(n + " ") or t.endswith(" " + n)) \
                    and not (t.endswith(" " + n) and ("non " + n) in t):
                hits.append((_norm(head), lab))
    if len(hits) > 1 and main:
        first = (_norm(main).split() or [""])[0]
        for head, lab in hits:
            if head.startswith(first):
                return lab
    return hits[0][1] if hits else None


def compute(inputs):
    """computePremium(inputs) -> result dict (ok, finalPremium, premiumExRM, steps, ...)."""
    inputs = dict(inputs)
    lab = resolve_industry(inputs.get("subIndustry"), inputs.get("mainIndustry") or "")
    if lab:
        inputs["subIndustry"] = lab
    with _lock:
        if _ctx is None:
            _load()
        out = _ctx.eval("JSON.stringify(CorpEngine.computePremium(%s))" % json.dumps(inputs))
    return json.loads(out)
