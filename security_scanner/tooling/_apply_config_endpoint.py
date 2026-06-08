# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (2026-06-08): add a lightweight /config endpoint to app.py so the effective
MAX_CONCURRENT_SCANS (and worker PID) can be verified from a URL without dashboard
access. No secrets exposed. CRLF-safe. NOT shipped by this script."""
import ast, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AP = os.path.join(ROOT, "app.py")
s = open(AP, encoding="utf-8").read()
assert "\r" not in s

OLD = (
    "@app.route(\"/health\")\n"
    "def health():\n"
    "    return jsonify({\"status\": \"ok\", \"timestamp\": datetime.now(timezone.utc).isoformat()})\n"
)
NEW = (
    "@app.route(\"/health\")\n"
    "def health():\n"
    "    return jsonify({\"status\": \"ok\", \"timestamp\": datetime.now(timezone.utc).isoformat()})\n"
    "\n"
    "\n"
    "@app.route(\"/config\")\n"
    "def config_info():\n"
    "    # Lightweight config-verification endpoint. Reports the effective\n"
    "    # MAX_CONCURRENT_SCANS the app booted with (so an env-var change can be\n"
    "    # confirmed from a URL) and the worker PID. Hit it a few times: a single\n"
    "    # repeating PID => 1 gunicorn worker; alternating PIDs => 2 workers.\n"
    "    # No secrets exposed.\n"
    "    return jsonify({\n"
    "        \"max_concurrent_scans\": MAX_CONCURRENT,\n"
    "        \"worker_pid\": os.getpid(),\n"
    "        \"timestamp\": datetime.now(timezone.utc).isoformat(),\n"
    "    })\n"
)
assert s.count(OLD) == 1, ("health anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1)
ast.parse(s)
with open(AP, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(AP, encoding="utf-8").read())
print("OK app.py: /config endpoint added (max_concurrent_scans + worker_pid).")
