"""Unit tests for progress_bus (WS8). py tooling/test_progress_bus.py (offline)"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import progress_bus as pb
from redis_support import FakeRedis

_p = _f = 0
def check(n, c):
    global _p, _f
    print(f"  {'PASS' if c else 'FAIL'}  {n}")
    _p += 1 if c else 0
    _f += 0 if c else 1


def suite(make_bus, label):
    print(f"--- {label} ---")
    bus = make_bus()
    bus.publish("s1", {"type": "running", "checker": "ssl"})
    bus.publish("s1", {"type": "done", "checker": "ssl"})
    check(f"[{label}] recent() returns backlog", len(bus.recent("s1")) == 2)

    # late subscriber replays backlog then sees terminal
    bus.publish("s1", {"type": "complete"})
    got = list(bus.listen("s1", idle_timeout=2))
    check(f"[{label}] listen replays backlog + stops at terminal",
          [e["type"] for e in got] == ["running", "done", "complete"])

    # live tail: a subscriber started before publish receives events
    bus2 = make_bus()
    received = []
    def consume():
        for ev in bus2.listen("s2", idle_timeout=3):
            received.append(ev)
    t = threading.Thread(target=consume, daemon=True)
    t.start()
    time.sleep(0.1)
    bus2.publish("s2", {"type": "running"})
    bus2.publish("s2", {"type": "complete"})
    t.join(timeout=4)
    check(f"[{label}] live subscriber tails to terminal",
          [e["type"] for e in received] == ["running", "complete"])


suite(lambda: pb.InProcessProgressBus(), "in-process")
suite(lambda: pb.RedisProgressBus(FakeRedis()), "redis(fake)")

# factory selection
import redis_support as rs
rs.reset_for_tests(FakeRedis()); pb.reset_for_tests()
check("get_progress_bus -> Redis when client present",
      isinstance(pb.get_progress_bus(), pb.RedisProgressBus))
rs.reset_for_tests(None); pb.reset_for_tests()
check("get_progress_bus -> in-process when no redis",
      isinstance(pb.get_progress_bus(), pb.InProcessProgressBus))
pb.reset_for_tests()

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
