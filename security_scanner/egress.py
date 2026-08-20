# -*- coding: utf-8 -*-
"""The scanner's OWN public egress address.

WHY THIS EXISTS. When a target's edge refuses the assessment, the report tells
the client the sections can only be covered by allow-listing the assessment
source -- and until now nothing told them WHAT to allow-list. Observed
2026-08-20 on bbgroup.co.za: TCP filtered on 80 and 443 from the scanner while
the same host answered 10 of 10 from an ordinary connection.

DETECTED, NOT HARDCODED. A literal address in the report goes stale silently the
first time the VM is rebuilt or moved region, and a client would then dutifully
allow-list an address we no longer use -- worse than saying nothing, because it
looks like it worked. So the value is discovered at runtime and cached briefly.

FAILS TO None, NEVER TO A GUESS. If detection fails and no override is set the
caller must omit the address entirely rather than print something plausible.
"""
import ipaddress
import json
import os
import time

_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "scans", "_egress_ip.json")
# Short enough that a rebuilt VM corrects itself within the hour, long enough
# that scan volume cannot turn this into a per-scan dependency.
TTL_S = float(os.environ.get("SCANNER_EGRESS_TTL_S", 3600))

# Two providers, both plain-text and free. Neither is a metered provider, so the
# gate's paid-egress guard is unaffected.
_SOURCES = ("https://api.ipify.org", "https://checkip.amazonaws.com")


def _valid_public(v):
    """A routable address, or None. Rejects private/loopback/junk outright: a
    report must never tell a client to allow-list 127.0.0.1."""
    try:
        obj = ipaddress.ip_address(str(v or "").strip())
    except ValueError:
        return None
    if obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved:
        return None
    return str(obj)


def _read_cache():
    try:
        with open(_CACHE, encoding="utf-8") as f:
            d = json.load(f)
        if (time.time() - float(d.get("at", 0))) <= TTL_S:
            return _valid_public(d.get("ip"))
    except Exception:
        pass
    return None


def _write_cache(ip):
    try:
        os.makedirs(os.path.dirname(_CACHE), exist_ok=True)
        tmp = _CACHE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"ip": ip, "at": round(time.time(), 3)}, f)
        os.replace(tmp, _CACHE)
    except Exception:
        pass                      # best-effort; never break a scan for a cache


def egress_ip(timeout=4.0):
    """The address a target sees us arrive from, or None if we cannot establish it.

    Order: explicit override, then a fresh cached value, then detection.
    """
    override = _valid_public(os.environ.get("SCANNER_EGRESS_IP"))
    if override:
        return override

    cached = _read_cache()
    if cached:
        return cached

    try:
        import requests
    except ImportError:
        return None
    for url in _SOURCES:
        try:
            r = requests.get(url, timeout=timeout)
            if r is not None and r.status_code == 200:
                ip = _valid_public(r.text)
                if ip:
                    _write_cache(ip)
                    return ip
        except Exception:
            continue
    return None
