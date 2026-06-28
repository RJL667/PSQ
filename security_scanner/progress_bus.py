"""Cross-worker scan progress (WS8 / SCALE-11).

Today progress is an in-process ``queue.Queue`` the SSE endpoint reads from the same
process — the moment scans move to a separate worker (WS2) that breaks, and a
reconnecting client misses everything published before it subscribed. This replaces
it with an append-only event log (replay + tail), so a late/reconnecting subscriber
catches up:

  * ``InProcessProgressBus`` — single-process default (a per-scan capped event list +
    a condition var); same behaviour as today, plus replay.
  * ``RedisProgressBus`` — a capped Redis Stream per scan (XADD/XRANGE); workers
    publish, the SSE tier reads the backlog then tails. Survives the worker/web split.

Both: ``publish(scan_id, event)``, ``listen(scan_id, idle_timeout)`` (a generator
that replays the backlog then tails, stopping on a terminal event or idle timeout),
and ``recent(scan_id)`` (snapshot for ``GET /api/scan`` / late connect).
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Iterator

_TERMINAL = {"complete", "error"}
_MAXLEN = 500
_TTL_S = 3600


class InProcessProgressBus:
    def __init__(self):
        self._d: dict = {}   # scan_id -> {"events":[...], "cond":Condition, "ts":epoch}
        self._guard = threading.Lock()

    def _slot(self, scan_id):
        with self._guard:
            s = self._d.get(scan_id)
            if s is None:
                s = {"events": [], "cond": threading.Condition(), "ts": time.time()}
                self._d[scan_id] = s
            return s

    def publish(self, scan_id, event: dict):
        s = self._slot(scan_id)
        with s["cond"]:
            s["events"].append(event)
            if len(s["events"]) > _MAXLEN:
                del s["events"][:-_MAXLEN]
            s["cond"].notify_all()
        self._sweep()

    def recent(self, scan_id) -> list:
        s = self._d.get(scan_id)
        return list(s["events"]) if s else []

    def listen(self, scan_id, idle_timeout: float = 30.0) -> Iterator[dict]:
        s = self._slot(scan_id)
        idx = 0
        while True:
            with s["cond"]:
                while idx >= len(s["events"]):
                    if not s["cond"].wait(timeout=idle_timeout):
                        return  # idle: let the client reconnect
                batch = s["events"][idx:]
                idx = len(s["events"])
            for ev in batch:
                yield ev
                if ev.get("type") in _TERMINAL:
                    return

    def close(self, scan_id):
        with self._guard:
            self._d.pop(scan_id, None)

    def _sweep(self):
        cutoff = time.time() - _TTL_S
        with self._guard:
            for sid in [k for k, v in self._d.items() if v["ts"] < cutoff]:
                self._d.pop(sid, None)


class RedisProgressBus:
    def __init__(self, redis):
        self.r = redis

    def _key(self, scan_id):
        return f"progress:{scan_id}"

    def publish(self, scan_id, event: dict):
        self.r.xadd(self._key(scan_id), {"e": json.dumps(event)}, maxlen=_MAXLEN)
        self.r.expire(self._key(scan_id), _TTL_S)

    def recent(self, scan_id) -> list:
        return [json.loads(f["e"]) for _id, f in self.r.xrange(self._key(scan_id))]

    def listen(self, scan_id, idle_timeout: float = 30.0) -> Iterator[dict]:
        key = self._key(scan_id)
        last = "0-0"
        deadline = time.time() + idle_timeout
        while True:
            try:
                resp = self.r.xread({key: last}, count=50, block=int(idle_timeout * 1000))
            except (TypeError, AttributeError):
                resp = None  # backend without blocking xread -> poll xrange below
            entries = []
            if resp:
                for _stream, items in resp:
                    for _id, fields in items:
                        last = _id
                        entries.append(json.loads(fields["e"]))
            elif not entries:
                # fall back to polling xrange for backends without blocking xread
                for _id, fields in self.r.xrange(key):
                    if _id > last:
                        last = _id
                        entries.append(json.loads(fields["e"]))
            for ev in entries:
                yield ev
                if ev.get("type") in _TERMINAL:
                    return
            if not entries:
                if time.time() >= deadline:
                    return
                time.sleep(0.1)
            else:
                deadline = time.time() + idle_timeout

    def close(self, scan_id):
        self.r.delete(self._key(scan_id))


_BUS = None


def get_progress_bus():
    """Process-wide bus: Redis when REDIS_URL is set, else in-process."""
    global _BUS
    if _BUS is not None:
        return _BUS
    from redis_support import get_redis
    r = get_redis()
    _BUS = RedisProgressBus(r) if r is not None else InProcessProgressBus()
    return _BUS


def reset_for_tests(bus=None):
    global _BUS
    _BUS = bus
