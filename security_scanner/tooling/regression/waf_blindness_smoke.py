"""SMOKE TEST: put every HTTP-making checker behind a simulated WAF and see
which ones still report a clean, complete result.

For each checker: force every HTTP response to 403 (a blanket WAF deny), run
check(), and classify the outcome:

  HONEST  — non-conclusive status (unreachable/error/blocked/...)
  BLIND   — status "completed" AND no issues AND (score is absent or perfect)
            i.e. it read a block page as evidence of a clean estate
  n/a     — checker needs credentials / does not apply

This is the empirical version of the audit: it tests behaviour, not grep.
"""
import inspect, os, sys, json
from unittest import mock

SEC = "/opt/phishield-scanner/security_scanner" if os.path.isdir(
    "/opt/phishield-scanner/security_scanner") else \
    r"C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner"
os.chdir(SEC); sys.path.insert(0, SEC)

import checkers_core, checkers_network, checkers_threats, checkers_supply_chain
MODULES = [checkers_core, checkers_network, checkers_threats, checkers_supply_chain]

CODE = int(os.environ.get("SMOKE_CODE", "403"))


class Resp:
    def __init__(self, code=CODE):
        self.status_code = code
        self.text = "<html><body>Forbidden</body></html>"
        self.content = self.text.encode()
        self.headers = {}
        self.url = "https://example.com/"
        self.cookies = {}
    def json(self):
        return {}


def fake(*a, **kw):
    return Resp()


NONCONCLUSIVE = {"unreachable", "error", "timeout", "blocked", "no_api_key",
                 "auth_failed", "quota_exhausted", "subscription_required",
                 "skipped", "disabled"}

results = []
for mod in MODULES:
    for name, cls in sorted(vars(mod).items()):
        if not (inspect.isclass(cls) and name.endswith("Checker")):
            continue
        if not hasattr(cls, "check"):
            continue
        sig = inspect.signature(cls.check)
        params = [p for p in sig.parameters if p != "self"]
        # only single-required-arg checkers (domain); skip ones needing api keys
        required = [p for p in sig.parameters.values()
                    if p.name != "self" and p.default is inspect.Parameter.empty]
        if len(required) != 1:
            results.append((mod.__name__, name, "n/a", f"needs {len(required)} args"))
            continue
        patches = [mock.patch.object(m, "HTTP", create=True) for m in MODULES]
        try:
            with mock.patch("http_client.HTTP") as H, \
                 mock.patch("requests.get", side_effect=fake), \
                 mock.patch("requests.post", side_effect=fake), \
                 mock.patch("requests.head", side_effect=fake):
                for p in patches:
                    h = p.start()
                    h.get.side_effect = fake; h.head.side_effect = fake
                    h.post.side_effect = fake; h.discover.side_effect = fake
                    h.stop_probing.return_value = False
                    h.waf_status.return_value = {"blocked": True, "codes": {str(CODE): 20}}
                H.get.side_effect = fake; H.head.side_effect = fake
                H.post.side_effect = fake; H.discover.side_effect = fake
                H.stop_probing.return_value = False
                out = cls().check("example.com")
        except Exception as e:
            results.append((mod.__name__, name, "n/a", f"{type(e).__name__}"))
            continue
        finally:
            for p in patches:
                try: p.stop()
                except Exception: pass
        if not isinstance(out, dict):
            results.append((mod.__name__, name, "n/a", "non-dict"))
            continue
        st = out.get("status")
        issues = out.get("issues") or []
        score = out.get("score")
        clean_looking = (st == "completed" and not issues
                         and (score is None or score >= 95))
        verdict = "HONEST" if st in NONCONCLUSIVE else ("BLIND" if clean_looking else "partial")
        results.append((mod.__name__, name, verdict,
                        f"status={st} issues={len(issues)} score={score}"))

print(f"=== every checker behind a simulated HTTP {CODE} wall ===\n")
order = {"BLIND": 0, "partial": 1, "HONEST": 2, "n/a": 3}
for m, n, v, d in sorted(results, key=lambda r: (order.get(r[2], 9), r[1])):
    mark = "***" if v == "BLIND" else "   "
    print(f"{mark} {v:8s} {n:34s} {d}")
print()
for v in ("BLIND", "partial", "HONEST", "n/a"):
    print(f"   {v:8s} {sum(1 for r in results if r[2] == v)}")
