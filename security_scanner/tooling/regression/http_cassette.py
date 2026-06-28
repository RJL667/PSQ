"""HTTP record/replay cassette — the checker-level regression gate's missing half.

Monkeypatches ``requests.sessions.Session.request`` — the single funnel that
``requests.get`` / ``post`` / ``head`` / ``request`` *and* ``HttpClient._request``
all pass through. An egress audit of the scanner (2026-06-28) confirmed there is
no other outbound transport: nothing uses a urllib3 PoolManager directly, httpx,
aiohttp, ``http.client``, or raw sockets for HTTP. So this one class attribute is
the universal interception point.

Why this matters: the scaling design (SCALE-00c / WS0, see
``docs/SCALING_DESIGN.md``) treats a checker-level golden gate as *blocked on WS0*
— the reasoning being that you cannot intercept every outbound call until it all
flows through WS0's single egress seam, yet WS0 itself needs that gate to be safe
(a chicken-and-egg the doc calls out explicitly). That premise is wrong: the
universal seam already exists one layer down, inside ``requests``. Recording there
gives a deterministic, offline re-run of the checkers **today**, before WS0 — which
means WS0's correctness evidence (a committed cassette + a frozen result blob) no
longer depends on durable infra to exist.

Modes
-----
* ``record``  — call the real ``Session.request``, snapshot the response to the
  cassette, and return the live response unchanged.
* ``replay``  — reconstruct a ``requests.Response`` from the cassette and return
  it with **zero network**. A request whose canonical key is not in the cassette
  raises :class:`CassetteMiss` — a changed request shape is exactly what a
  behaviour-preserving WS0 refactor must be caught doing.

Keying
------
Entries are keyed by a canonical ``(METHOD, url, body-signature)`` with **secrets
redacted** (``key`` / ``apikey`` / ``token`` / ``X-Key`` …). The key deliberately
**omits request headers and timeout**, so the one legitimate change WS0 introduces
— the seam adding an identifying ``User-Agent`` and a default timeout — does *not*
perturb the key. Request-fidelity (same logical calls before/after) is therefore
asserted for free, while the seam's header/timeout additions are permitted.

This module is imported by **no runtime code**. Activate it explicitly in tests or
tooling via the :func:`record` / :func:`replay` context managers.
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# requests is a hard dependency of the scanner; a missing import here should fail
# loudly (this is tooling, not the graceful-degradation runtime path).
import requests.sessions as _rsessions
from requests.models import Response as _Response
from requests.structures import CaseInsensitiveDict as _CIDict

CASSETTE_VERSION = 1

# Request params / headers whose values are credentials. Redacted from the key so
# (a) the cassette never persists an API key and (b) two otherwise-identical calls
# that differ only by a rotated key collapse to one logical request.
SECRET_PARAM_KEYS = frozenset({
    "key", "apikey", "api_key", "apiKey", "token", "auth", "access_token",
    "x-key", "secret", "password", "pass",
})


class CassetteMiss(LookupError):
    """Replay was asked for a request not present in the cassette."""

    def __init__(self, key: str, known: int = 0):
        super().__init__(
            f"no cassette entry for request:\n    {key}\n"
            f"({known} entries loaded). The request shape changed, or this is a "
            f"new outbound call — which a behaviour-preserving refactor should not "
            f"introduce.")
        self.key = key


# --- canonicalisation -----------------------------------------------------

def _redact(key: str, value) -> str:
    return "<redacted>" if str(key).lower() in SECRET_PARAM_KEYS else str(value)


def _canonical_url(url: str, params=None) -> str:
    """scheme://host[:port]/path?sorted-redacted-query — case-normalised host."""
    parsed = urlsplit(url or "")
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if params:
        if isinstance(params, dict):
            query += list(params.items())
        elif isinstance(params, (list, tuple)):
            query += [tuple(p) for p in params]
    norm = sorted((str(k), _redact(k, v)) for k, v in query)
    host = (parsed.hostname or "").lower()
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path,
                       urlencode(norm), ""))


def _body_signature(data=None, json_body=None) -> str:
    """A stable hash of the request body, secrets redacted. Empty for no body."""
    if json_body is not None:
        payload = _redact_structure(json_body)
        raw = json.dumps(payload, sort_keys=True, default=str)
    elif data is None:
        return ""
    elif isinstance(data, dict):
        raw = json.dumps({str(k): _redact(k, v) for k, v in data.items()},
                         sort_keys=True, default=str)
    elif isinstance(data, (list, tuple)):
        raw = json.dumps([str(x) for x in data], default=str)
    elif isinstance(data, bytes):
        return hashlib.sha256(data).hexdigest()[:16]
    else:
        raw = str(data)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _redact_structure(obj):
    if isinstance(obj, dict):
        return {k: ("<redacted>" if str(k).lower() in SECRET_PARAM_KEYS
                    else _redact_structure(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_structure(v) for v in obj]
    return obj


def canonical_key(method: str, url: str, params=None, data=None,
                  json_body=None) -> str:
    sig = _body_signature(data, json_body)
    base = f"{(method or 'GET').upper()} {_canonical_url(url, params)}"
    return f"{base} #{sig}" if sig else base


# --- response (de)serialisation -------------------------------------------

def _snapshot(resp) -> dict:
    """A JSON-able snapshot of a requests.Response (body base64'd to survive
    non-UTF8 payloads). ``elapsed`` is dropped — it is volatile by nature."""
    try:
        content = resp.content or b""
    except Exception:
        content = b""
    return {
        "status_code": int(getattr(resp, "status_code", 0) or 0),
        "reason": getattr(resp, "reason", None),
        "url": _canonical_url(getattr(resp, "url", "") or ""),
        "encoding": getattr(resp, "encoding", None),
        "headers": dict(getattr(resp, "headers", {}) or {}),
        "content_b64": base64.b64encode(content).decode("ascii"),
    }


def _build_response(snap: dict):
    r = _Response()
    r.status_code = snap.get("status_code", 0)
    r.reason = snap.get("reason")
    r._content = base64.b64decode(snap.get("content_b64", "") or "")
    r._content_consumed = True
    r.url = snap.get("url")
    r.encoding = snap.get("encoding")
    r.headers = _CIDict(snap.get("headers") or {})
    r.elapsed = timedelta(0)
    return r


# --- cassette -------------------------------------------------------------

class Cassette:
    """A record/replay tape over ``requests.sessions.Session.request``.

    Prefer the :func:`record` / :func:`replay` context managers; they install,
    save/load, and uninstall for you.
    """

    def __init__(self, mode: str, path: Optional[str] = None):
        if mode not in ("record", "replay"):
            raise ValueError("mode must be 'record' or 'replay'")
        self.mode = mode
        self.path = Path(path) if path else None
        self.entries: dict = {}
        self.request_log: list = []          # every key observed this run (with repeats)
        self.expected_request_log: list = []  # frozen at record time, read on load
        self._lock = threading.Lock()
        self._original = None

    # ---- patching --------------------------------------------------------
    def install(self) -> "Cassette":
        if self._original is not None:
            raise RuntimeError("cassette already installed")
        self._original = _rsessions.Session.request
        cassette = self

        def _patched(session_self, method, url, **kwargs):
            return cassette._handle(session_self, method, url, kwargs)

        _rsessions.Session.request = _patched
        return self

    def uninstall(self) -> None:
        if self._original is not None:
            _rsessions.Session.request = self._original
            self._original = None

    # ---- the intercept ---------------------------------------------------
    def _handle(self, session, method, url, kwargs):
        key = canonical_key(method, url, kwargs.get("params"),
                            kwargs.get("data"), kwargs.get("json"))
        if self.mode == "record":
            resp = self._original(session, method, url, **kwargs)
            with self._lock:
                self.entries[key] = _snapshot(resp)
                self.request_log.append(key)
            return resp
        # replay
        with self._lock:
            self.request_log.append(key)
            snap = self.entries.get(key)
            known = len(self.entries)
        if snap is None:
            raise CassetteMiss(key, known)
        return _build_response(snap)

    # ---- persistence -----------------------------------------------------
    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": CASSETTE_VERSION,
            "request_log": sorted(self.request_log),
            "entries": self.entries,
        }
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True),
                             encoding="utf-8")

    def load(self) -> None:
        if not self.path or not self.path.exists():
            raise FileNotFoundError(f"no cassette at {self.path}")
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        self.entries = payload.get("entries", {})
        self.expected_request_log = payload.get("request_log", [])

    # ---- request-fidelity ------------------------------------------------
    def fidelity_diff(self) -> dict:
        """After a replay run, compare the requests this run actually made to the
        frozen set recorded earlier. A behaviour-preserving refactor must keep
        these identical (the key already ignores the seam's UA/timeout additions).

        Returns ``{"missing": [...], "unexpected": [...]}`` — both empty == clean.
        """
        observed = sorted(self.request_log)
        expected = sorted(self.expected_request_log)
        from collections import Counter
        oc, ec = Counter(observed), Counter(expected)
        missing = sorted((ec - oc).elements())       # expected, not made this run
        unexpected = sorted((oc - ec).elements())    # made this run, not expected
        return {"missing": missing, "unexpected": unexpected}


# --- context managers -----------------------------------------------------

@contextmanager
def record(path: Optional[str] = None):
    """Record all outbound HTTP to ``path`` (saved on exit). Yields the Cassette."""
    cas = Cassette("record", path).install()
    try:
        yield cas
    finally:
        cas.uninstall()
        cas.save()


@contextmanager
def replay(path: str):
    """Serve all outbound HTTP from ``path`` with no network. Yields the Cassette."""
    cas = Cassette("replay", path)
    cas.load()
    cas.install()
    try:
        yield cas
    finally:
        cas.uninstall()
