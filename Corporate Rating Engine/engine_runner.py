"""
Run the corporate rating engine (corporate-engine.js, the same file the browser uses)
inside the Python service, so every saved quote is recalculated on the server.

The JS context is built once per worker process and guarded by a lock (a V8 isolate is
not thread-safe, and gunicorn runs several threads per worker).
"""
import hashlib
import json
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


def compute(inputs):
    """computePremium(inputs) -> result dict (ok, finalPremium, premiumExRM, steps, ...)."""
    with _lock:
        if _ctx is None:
            _load()
        out = _ctx.eval("JSON.stringify(CorpEngine.computePremium(%s))" % json.dumps(inputs))
    return json.loads(out)
