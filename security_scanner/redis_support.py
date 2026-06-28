"""Shared Redis access + an in-process FakeRedis (WS5a/WS6/WS8 foundation).

`get_redis()` returns a real client from ``REDIS_URL`` (lazy, pooled by redis-py),
or None when unset — callers then fall back to their in-process default. The
distributed workstreams (rate limiter, result cache, progress bus) are written
against this interface so prod uses Redis and dev/tests use either the in-process
default or ``FakeRedis``.

``FakeRedis`` is a tiny, thread-safe, single-process stand-in implementing only the
ops these workstreams use (string get/set with NX/PX/EX + TTL expiry, delete,
incr, pub/sub, and Redis Streams xadd/xrange). It is NOT a full Redis — it exists
so the distributed code paths get real offline test coverage without a server.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Optional

_client = None
_tried = False


def get_redis():
    """Real Redis client from REDIS_URL, or None if unset/unavailable."""
    global _client, _tried
    if _client is not None:
        return _client
    if _tried:
        return None
    _tried = True
    url = os.environ.get("REDIS_URL")
    if not url:
        return None
    import redis  # redis-py is installed
    _client = redis.Redis.from_url(url, decode_responses=True)
    return _client


def reset_for_tests(client=None) -> None:
    global _client, _tried
    _client = client
    _tried = client is not None


class FakeRedis:
    """Minimal in-process Redis stand-in (thread-safe). Supports the subset used by
    WS5a/WS6/WS8. Keys expire lazily on access. ``decode_responses``-style: stores
    and returns str."""

    def __init__(self):
        self._d: dict = {}          # key -> (value, expire_epoch | None)
        self._streams: dict = {}    # key -> list[(id, {field:val})]
        self._channels: dict = {}   # channel -> list[callback]
        self._lock = threading.RLock()

    # ---- expiry helper ---------------------------------------------------
    def _live(self, key):
        v = self._d.get(key)
        if v is None:
            return None
        val, exp = v
        if exp is not None and time.time() >= exp:
            self._d.pop(key, None)
            return None
        return val

    # ---- strings ---------------------------------------------------------
    def set(self, key, value, nx=False, px=None, ex=None):
        with self._lock:
            if nx and self._live(key) is not None:
                return None
            exp = None
            if px is not None:
                exp = time.time() + px / 1000.0
            elif ex is not None:
                exp = time.time() + ex
            self._d[key] = (str(value), exp)
            return True

    def get(self, key):
        with self._lock:
            return self._live(key)

    def delete(self, *keys):
        with self._lock:
            n = 0
            for k in keys:
                if self._d.pop(k, None) is not None:
                    n += 1
            return n

    def exists(self, key):
        with self._lock:
            return 1 if self._live(key) is not None else 0

    def incr(self, key, amount=1):
        with self._lock:
            cur = self._live(key)
            new = (int(cur) if cur is not None else 0) + amount
            _, exp = self._d.get(key, (None, None))
            self._d[key] = (str(new), exp)
            return new

    def expire(self, key, seconds):
        with self._lock:
            v = self._d.get(key)
            if v is None:
                return False
            self._d[key] = (v[0], time.time() + seconds)
            return True

    def pttl(self, key):
        with self._lock:
            v = self._d.get(key)
            if v is None or v[1] is None:
                return -1
            return max(0, int((v[1] - time.time()) * 1000))

    # ---- pub/sub (synchronous, in-process) -------------------------------
    def publish(self, channel, message):
        with self._lock:
            subs = list(self._channels.get(channel, []))
        for cb in subs:
            cb(message)
        return len(subs)

    def subscribe_callback(self, channel, callback):
        """Test/in-process convenience — real code uses pubsub() objects."""
        with self._lock:
            self._channels.setdefault(channel, []).append(callback)

    # ---- streams (for WS8 replay) ----------------------------------------
    def xadd(self, key, fields: dict, maxlen=None):
        with self._lock:
            stream = self._streams.setdefault(key, [])
            seq = (len(stream) + 1)
            entry_id = f"{int(time.time()*1000)}-{seq}"
            stream.append((entry_id, {str(k): str(v) for k, v in fields.items()}))
            if maxlen is not None and len(stream) > maxlen:
                del stream[:-maxlen]
            return entry_id

    def xrange(self, key, min="-", max="+"):
        with self._lock:
            return list(self._streams.get(key, []))
