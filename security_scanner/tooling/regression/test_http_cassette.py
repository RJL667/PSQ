"""Unit tests for http_cassette — runnable without pytest:  py test_http_cassette.py

Fully offline: a fake ``Session.request`` stands in for the network, so these
tests never make a real outbound call. They prove the cassette (a) canonicalises
and redacts request keys, (b) records and replays a response by key, (c) serves
replay with zero network and tolerates rotated secrets, (d) raises on a changed
request shape, (e) reports request-fidelity drift, and (f) is thread-safe.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import http_cassette as hc
import requests
import requests.sessions as _S

_passed = 0
_failed = 0


def check(name: str, cond: bool) -> None:
    global _passed, _failed
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if cond:
        _passed += 1
    else:
        _failed += 1


def expect_raises(name: str, exc, fn) -> None:
    try:
        fn()
        check(name, False)
    except exc:
        check(name, True)
    except Exception as e:  # noqa: BLE001
        print(f"        (wrong exception: {type(e).__name__})")
        check(name, False)


# --- a fake transport so nothing ever hits the network --------------------

def _make_fake(status=200, body=b'{"ok": true}', headers=None, record_calls=None):
    def fake(session_self, method, url, **kwargs):
        if record_calls is not None:
            record_calls.append((method, url, kwargs.get("params")))
        r = requests.models.Response()
        r.status_code = status
        r._content = body
        r._content_consumed = True
        r.url = url
        r.encoding = "utf-8"
        r.headers = requests.structures.CaseInsensitiveDict(headers or {"X-Test": "1"})
        return r
    return fake


def _boom(session_self, method, url, **kwargs):
    raise AssertionError(f"network hit during replay: {method} {url}")


# --- canonical key --------------------------------------------------------

k = hc.canonical_key
check("method is upper-cased in key",
      k("get", "https://x.io/a") == k("GET", "https://x.io/a"))

check("query param order does not change the key",
      k("GET", "https://x.io/a?b=2&a=1") == k("GET", "https://x.io/a?a=1&b=2"))

check("params kwarg and inline query produce the same key",
      k("GET", "https://x.io/a", params={"a": "1", "b": "2"})
      == k("GET", "https://x.io/a?b=2&a=1"))

check("host case is normalised",
      k("GET", "https://API.Example.IO/a") == k("GET", "https://api.example.io/a"))

check("a rotated secret param collapses to the same key",
      k("GET", "https://api.shodan.io/x", params={"key": "AAA", "q": "z"})
      == k("GET", "https://api.shodan.io/x", params={"key": "BBB", "q": "z"}))

check("the key never contains the secret value",
      "AAA" not in k("GET", "https://api.shodan.io/x", params={"key": "AAA"}))

check("different non-secret params produce different keys",
      k("GET", "https://x.io/a", params={"q": "one"})
      != k("GET", "https://x.io/a", params={"q": "two"}))

check("json body changes the key; redacted secret in body does not",
      (k("POST", "https://x.io/s", json_body={"q": "a"})
       != k("POST", "https://x.io/s", json_body={"q": "b"}))
      and (k("POST", "https://x.io/s", json_body={"q": "a", "token": "T1"})
           == k("POST", "https://x.io/s", json_body={"q": "a", "token": "T2"})))


# --- record then replay (round trip) --------------------------------------

TMP = Path(__file__).parent / "_cassette_test_tmp.json"
TMP.unlink(missing_ok=True)

_orig = _S.Session.request
try:
    # RECORD against the fake transport
    _S.Session.request = _make_fake(status=200, body=b'{"ok": true, "n": 7}')
    with hc.record(str(TMP)) as cas:
        r = requests.get("https://api.example.io/data?b=2&a=1",
                         params={"key": "SECRET-RECORD"})
        check("record returns the live response", r.status_code == 200)
    check("cassette file written", TMP.exists())
    check("one entry captured", len(cas.entries) == 1)

    # REPLAY with a transport that explodes if touched → proves zero network
    _S.Session.request = _boom
    with hc.replay(str(TMP)) as rcas:
        # same logical request, DIFFERENT secret value → must still hit
        r2 = requests.get("https://api.example.io/data?a=1&b=2",
                          params={"key": "DIFFERENT-REPLAY"})
        check("replay serves status from cassette", r2.status_code == 200)
        check("replay serves body from cassette", r2.json()["n"] == 7)
        check("replay tolerates a rotated secret (same key)", True)
        fid = rcas.fidelity_diff()
        check("fidelity clean for an identical replay",
              fid["missing"] == [] and fid["unexpected"] == [])

    # a request NOT in the cassette must raise CassetteMiss
    _S.Session.request = _boom
    with hc.replay(str(TMP)) as rcas2:
        expect_raises("unrecorded request raises CassetteMiss",
                      hc.CassetteMiss,
                      lambda: requests.get("https://api.example.io/OTHER"))

    # fidelity reports a recorded-but-not-replayed call as "missing"
    _S.Session.request = _make_fake(body=b'{"ok": true}')
    with hc.record(str(TMP)) as c2:
        requests.get("https://api.example.io/alpha")
        requests.get("https://api.example.io/beta")
    _S.Session.request = _boom
    with hc.replay(str(TMP)) as rcas3:
        requests.get("https://api.example.io/alpha")  # only one of the two
        fid = rcas3.fidelity_diff()
        check("fidelity flags a dropped call as missing",
              any("beta" in m for m in fid["missing"])
              and not fid["unexpected"])

    # repeated identical request is served every time on replay
    _S.Session.request = _make_fake(body=b'{"ok": true}')
    with hc.record(str(TMP)) as c3:
        requests.get("https://api.example.io/repeat")
    _S.Session.request = _boom
    with hc.replay(str(TMP)) as rcas4:
        a = requests.get("https://api.example.io/repeat")
        b = requests.get("https://api.example.io/repeat")
        check("repeated identical request served idempotently",
              a.status_code == 200 and b.status_code == 200)

    # thread-safety: concurrent record captures every distinct call
    _S.Session.request = _make_fake(body=b'{"ok": true}')
    with hc.record(str(TMP)) as c4:
        def hit(i):
            requests.get(f"https://api.example.io/t/{i}")
        threads = [threading.Thread(target=hit, args=(i,)) for i in range(25)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    check("concurrent record captured all 25 distinct calls",
          len(c4.entries) == 25)

finally:
    _S.Session.request = _orig
    TMP.unlink(missing_ok=True)


print(f"\n{_passed} passed, {_failed} failed")
sys.exit(1 if _failed else 0)
