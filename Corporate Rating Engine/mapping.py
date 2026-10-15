"""mapping.py — Phase 2 framework: map an ingested risk-assessment against our requirements.

Pipeline:  redact (PII out) -> map (Claude, or a keyless mock for local testing) -> rehydrate
           -> TIDE-style scorecard (families, favourable/deficient/missing, posture, completeness,
              and the minimum-requirements gate to rate & quote).

Engines:
  - "mock"   : deterministic keyword scan — runs fully offline/on-prem, no API key. (Local test system.)
  - "claude" : Anthropic API on the *redacted* text. Used automatically when ANTHROPIC_API_KEY is set
               and the `anthropic` SDK is installed; otherwise we fall back to "mock".

Deployment: set PII_PROXY_URL (default http://pii-proxy:4000/anthropic). The proxy owns both
PII redaction and the Claude credential — no ANTHROPIC_API_KEY or REDACTION_URL in the engine.
"""
import os
import re
import json
import urllib.request

import redaction

# --- Claude-via-proxy config ------------------------------------------------
# The Veilguard pii-proxy is Anthropic-compatible: POST {PII_PROXY_URL}/v1/messages
# with x-api-key: pii-proxy-managed. It redacts PII before the call reaches Claude
# and rehydrates the response, keyed by the per-request session id we pass.
PII_PROXY_URL = os.environ.get("PII_PROXY_URL", "http://pii-proxy:4000/anthropic").rstrip("/")

# [WORKSPACE_VM 2026-10-15] Inside the phishield-data workspace VM the proxy is reached through
# the host's /vm/anthropic bridge, which needs a short-lived Veilguard VM token. The host waker
# re-mints it into PII_PROXY_KEY_FILE every few hours, so it is read fresh on every call.
PII_PROXY_KEY_FILE = os.environ.get("PII_PROXY_KEY_FILE", "")


def _proxy_key() -> str:
    if PII_PROXY_KEY_FILE:
        try:
            with open(PII_PROXY_KEY_FILE) as fh:
                key = fh.read().strip()
            if key:
                return key
        except OSError:
            pass
    return "pii-proxy-managed"
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
# ON by default (container). Set CORP_USE_PII_PROXY=0 to force the offline mock.
USE_PII_PROXY = os.environ.get("CORP_USE_PII_PROXY", "1").strip().lower() not in ("0", "false", "no")

# ---------------------------------------------------------------------------
# Requirement schema — families of controls. `req=True` => a minimum requirement
# to rate & quote. `kw` / `neg` drive the offline mock; the Claude engine uses the
# control text directly. Grouped to mirror the TIDE "True View" family scorecard.
# ---------------------------------------------------------------------------
SCHEMA = [
    ("Privileged Access Management", [
        ("MFA on privileged / admin accounts", True, ["mfa", "multi-factor", "2fa", "two-factor"], []),
        ("Separate administrative credentials", False, ["separate admin", "separate credential", "dedicated admin"], []),
        ("Privileged credentials vaulted", False, ["password safe", "vault", "pam", "privileged access management"], []),
    ]),
    ("Access Control", [
        ("Password complexity & reuse policy", True, ["password policy", "password complexity", "complexity requirement"], []),
        ("Account inventory maintained", False, ["account inventory", "user inventory"], []),
    ]),
    ("Backups", [
        ("At least weekly backups", True, ["weekly backup", "daily backup", "backups are performed", "backup frequency"], ["no backup"]),
        ("Immutable / isolated backups", True, ["immutable", "air-gapped", "air gapped", "isolated from production", "offline backup"], []),
        ("Backups encrypted", False, ["backup", "encrypt"], []),
        ("Backup restoration tested", False, ["restoration drill", "restore test", "restoration test", "backup test"], []),
    ]),
    ("Configuration & Hardening", [
        ("Secure configuration baselines", False, ["baseline", "hardening", "cis benchmark"], []),
        ("Change control process", False, ["change control", "change management"], []),
    ]),
    ("BC / DR / IR Plans", [
        ("Incident response plan in place", False, ["incident response", "ir plan"], []),
        ("IR plan tested at least annually", True, ["tested annually", "tabletop", "annual test", "ir test"], []),
        ("Ransomware-specific playbook", False, ["ransomware playbook", "ransomware-specific"], []),
    ]),
    ("Data Encryption", [
        ("Encryption at rest", False, ["encryption at rest", "encrypted at rest", "disk encryption"], []),
        ("Cryptographic key management", False, ["key management", "key rotation", "encryption keys"], []),
    ]),
    ("Network, Perimeter & Email", [
        ("Email filtering / Secure Email Gateway", True, ["email gateway", "email filtering", "mimecast", "proofpoint", "secure email"], []),
        ("Web filtering", True, ["web filter", "web filtering", "web proxy", "url filtering"], []),
        ("High-risk protocols (RDP/SMBv1) restricted", False, ["rdp disabled", "smbv1", "rdp restricted", "rdp"], ["rdp open"]),
        ("SIEM / network monitoring", False, ["siem", "network monitoring", "log monitoring"], []),
    ]),
    ("Endpoint Security", [
        ("EDR / ETDR deployed", True, ["edr", "etdr", "endpoint detection", "crowdstrike", "sentinelone", "defender for endpoint", "carbon black"], []),
        ("Mobile device management", False, ["mdm", "mobile device management", "intune"], []),
    ]),
    ("Email & Messaging Auth", [
        ("DMARC / SPF / DKIM enforced", False, ["dmarc", "spf", "dkim"], []),
        ("BEC controls / external banners", False, ["bec", "business email compromise", "external banner"], []),
    ]),
    ("End-of-Life Management", [
        ("EOL systems isolated or decommissioned", False, ["end-of-life", "end of life", "eol", "decommission", "legacy system"], []),
    ]),
    ("Vulnerability Management", [
        ("Regular vulnerability scanning", False, ["vulnerability scan", "vuln scan", "vulnerability assessment"], []),
        ("Timely patching of critical vulnerabilities", True, ["patch", "patching", "patch management"], []),
        ("Penetration testing", False, ["penetration test", "pen test", "pentest"], []),
    ]),
    ("Security Operations (MDR)", [
        ("Managed Detection & Response (MDR)", False, ["mdr", "managed detection", "sophos mdr", "soc 24"], []),
    ]),
    ("Payment Fraud Controls", [
        ("Beneficiary verification process", True, ["beneficiary verification", "verify beneficiary", "verify new beneficiaries"], []),
        ("Dual authorisation for payments", False, ["dual authorisation", "dual authorization", "dual control", "two-person"], []),
        ("Bank account verification service", False, ["account verification", "bank account verification"], []),
    ]),
]

RATING = [(0.9, 5, "Strong"), (0.7, 4, "Good"), (0.5, 3, "Moderate"), (0.3, 2, "Poor"), (0.0, 1, "Critical")]


def _sentence_with(text, kw):
    for s in re.split(r"(?<=[.!?\n])\s+", text):
        if kw in s.lower():
            return s.strip()[:200]
    return ""


def mock_map(text):
    """Offline keyword mapper — per control: favourable / deficient / missing (+ evidence)."""
    low = (text or "").lower()
    families = []
    for fam, controls in SCHEMA:
        rows = []
        for name, req, kw, neg in controls:
            status, evidence = "missing", ""
            if any(n in low for n in neg):
                status = "deficient"; evidence = _sentence_with(text, next(n for n in neg if n in low))
            elif any(k in low for k in kw):
                status = "favorable"; evidence = _sentence_with(text, next(k for k in kw if k in low))
            rows.append({"name": name, "required": req, "status": status, "evidence": evidence})
        families.append({"name": fam, "controls": rows})
    return families


MAPPING_TOOL = {
    "name": "record_mapping",
    "description": "Record the status and evidence for every control in the schema.",
    "input_schema": {
        "type": "object",
        "properties": {"families": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "family": {"type": "string"},
                "controls": {"type": "array", "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "status": {"type": "string", "enum": ["favorable", "deficient", "missing"]},
                        "evidence": {"type": "string"},
                    },
                    "required": ["name", "status", "evidence"],
                }},
            },
            "required": ["family", "controls"],
        }}},
        "required": ["families"],
    },
}


def claude_map(assessment_text, extra_terms=None, sid=None, user_id=None):
    """Claude engine via the Veilguard pii-proxy.

    Sends RAW assessment text to the proxy, which redacts PII on egress to Claude and
    rehydrates the reply — so the engine never holds a Claude key and no raw text leaves
    the VM un-redacted. Returns a families list, or None when the proxy path is disabled
    or the proxy is unavailable (the caller decides whether to refuse or fall back to mock).

    Fails CLOSED: any non-200 / transport error returns None — never a raw-text fallback.
    """
    if not USE_PII_PROXY:
        return None
    vm_token = _proxy_key().startswith("vgvm.")
    if not user_id and not vm_token:
        # Seat admission needs the real Veilguard user; never guess one. Fail closed.
        # (Inside the workspace VM the signed vgvm. token itself names the user.)
        return None
    schema_for_prompt = [{"family": fam, "controls": [c[0] for c in cs]} for fam, cs in SCHEMA]
    sysmsg = ("You map a third-party cyber risk-assessment onto a fixed control schema. For every control return "
              "status ∈ {favorable, deficient, missing} and a short verbatim evidence quote (or empty). "
              "favorable = control is present/operating; deficient = present but inadequate/negative; "
              "missing = not addressed. Output ONLY JSON: {\"families\":[{\"family\":..,\"controls\":"
              "[{\"name\":..,\"status\":..,\"evidence\":..}]}]}.")
    body = json.dumps({
        "model": CLAUDE_MODEL,
        "max_tokens": 8000,
        "system": sysmsg,
        # [2026-10-15] Forced tool call: the API returns the mapping as parsed JSON, so a stray
        # bracket or raw newline in free text can no longer make the whole reply unreadable.
        "tools": [MAPPING_TOOL],
        "tool_choice": {"type": "tool", "name": MAPPING_TOOL["name"]},
        "messages": [{"role": "user", "content":
            "SCHEMA:\n" + json.dumps(schema_for_prompt) +
            "\n\nASSESSMENT:\n" + (assessment_text or "")[:120000]}],
    }).encode("utf-8")
    headers = {
        "content-type": "application/json",
        "x-api-key": _proxy_key(),  # proxy owns the real Claude credential
        "anthropic-version": "2023-06-01",
        "x-redact-org": "1",                     # org mode: force-redact company / people names
    }
    # x-user-id = the real Veilguard user (Claude seat admission + budget);
    # x-conversation-id = the redaction/rehydration session so the reply comes back with real values.
    if user_id:
        headers["x-user-id"] = str(user_id)
    headers["x-conversation-id"] = str(sid or user_id or "corp-rating")
    req = urllib.request.Request(PII_PROXY_URL + "/v1/messages", data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:  # non-200 raises -> fail closed
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None
    parsed = next((b.get("input") for b in (data.get("content") or [])
                   if b.get("type") == "tool_use" and isinstance(b.get("input"), dict)), None)
    if parsed is None:
        raw = "".join(b.get("text", "") for b in (data.get("content") or []) if b.get("type") == "text")
        start, end = raw.find("{"), raw.rfind("}")
        if start < 0 or end < 0:
            return None
        try:
            # strict=False: evidence quotes often carry raw newlines from the source document.
            parsed = json.loads(raw[start:end + 1], strict=False)
        except Exception:
            return None
    if not parsed.get("families"):
        return None
    # re-attach the `required` flags from our schema
    reqmap = {c[0]: c[1] for _, cs in SCHEMA for c in cs}
    fams = []
    for f in parsed.get("families", []):
        rows = [{"name": c.get("name"), "required": reqmap.get(c.get("name"), False),
                 "status": c.get("status", "missing"), "evidence": c.get("evidence", "")}
                for c in f.get("controls", [])]
        fams.append({"name": f.get("family"), "controls": rows})
    return fams


def _score(fav, total):
    pct = (fav / total) if total else 0.0
    for thr, sc, label in RATING:
        if pct >= thr:
            return pct, sc, label
    return pct, 1, "Critical"


def assemble(families):
    """Build the TIDE-style scorecard + minimum-requirements gate from per-control statuses."""
    all_controls = [c for f in families for c in f["controls"]]
    fav = [c for c in all_controls if c["status"] == "favorable"]
    defi = [c for c in all_controls if c["status"] == "deficient"]
    miss = [c for c in all_controls if c["status"] == "missing"]
    addressed = len(fav) + len(defi)
    total = len(all_controls)

    fam_out = []
    for f in families:
        cs = f["controls"]
        favc = sum(1 for c in cs if c["status"] == "favorable")
        addressedc = sum(1 for c in cs if c["status"] != "missing")
        if addressedc == 0:
            fam_out.append({"name": f["name"], "rating": "N/A", "score": 0, "favorablePct": 0.0,
                            "completeness": 0.0, "controls": cs})
        else:
            pct, sc, label = _score(favc, len(cs))
            fam_out.append({"name": f["name"], "rating": label, "score": sc, "favorablePct": pct,
                            "completeness": addressedc / len(cs), "controls": cs})

    posture = len(fav) / total if total else 0.0
    pct, overall_score, overall_label = _score(len(fav), total)
    req = [c for c in all_controls if c["required"]]
    req_met = [c["name"] for c in req if c["status"] == "favorable"]
    req_unmet = [c["name"] for c in req if c["status"] != "favorable"]
    return {
        "posture": round(posture, 4),
        "overallScore": overall_score, "overallLabel": overall_label,
        "favorablePct": round(pct, 4),
        "completeness": round(addressed / total, 4) if total else 0.0,
        "counts": {"favorable": len(fav), "deficient": len(defi), "missing": len(miss), "total": total},
        "families": fam_out,
        "favorable": [c["name"] for c in fav],
        "deficient": [c["name"] for c in defi],
        "missing": [c["name"] for c in miss],
        "minimumRequirements": {"met": req_met, "unmet": req_unmet, "ready": len(req_unmet) == 0},
    }


def map_assessment(text, extra_terms=None, prefer="auto", sid=None, user_id=None):
    """Full pipeline. prefer ∈ {auto, claude, mock}. Returns the scorecard result dict.

    Claude path: RAW text -> pii-proxy (redacts -> Claude -> rehydrates) -> scorecard. The
    proxy owns redaction + the Claude credential, so the engine adds no local redaction here.
    Mock path: local redaction stand-in -> keyword map -> rehydrate, fully offline.
    """
    text = text or ""
    engine = "mock"
    families = None
    redaction_mode = None

    if prefer in ("auto", "claude"):
        families = claude_map(text, extra_terms=extra_terms, sid=sid, user_id=user_id)
        if families is not None:
            engine = "claude"
            redaction_mode = "pii-proxy"

    if families is None:
        if prefer == "claude":
            # Fail closed — do NOT fall back to raw text or fabricated figures.
            if not user_id:
                return {"ok": False, "error": "Claude engine needs the calling Veilguard user "
                                              "(x-user-id header) — refused (fail-closed)."}
            return {"ok": False, "error": "Claude engine (pii-proxy) unavailable — refused (fail-closed)."}
        # Offline mock: local redaction stand-in so no raw text is scanned in the clear.
        redacted, token_map = redaction.apply_redaction(text, extra_terms)
        families = mock_map(redacted)
        redaction_mode = redaction.mode()
        for f in families:
            for c in f["controls"]:
                if c.get("evidence"):
                    c["evidence"] = redaction.rehydrate(c["evidence"], token_map)

    result = assemble(families)
    result["ok"] = True
    result["engine"] = engine
    result["redaction"] = redaction_mode
    return result
