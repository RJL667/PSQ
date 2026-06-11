#!/usr/bin/env python3
"""SANDBOX one-off (item 0.5 / task #5): replace the confidence-BLIND credential
ladder with the K1-K7 weighted-confidence model + L3 HR hard floor.

Two anchored edits (fail-safe; assert count==1; CRLF-preserving):
  (1) checkers_threats.py CredentialRiskClassifier:
        - insert class-level K-constants after KNOWN_BREACH_DATES
        - rewrite classify() (per-record w = K1 x K2 x (K3 if combo) -> W ->
          class K4 -> contributions K5; IntelX report-only K7=0; HR floor L3)
        - new output field `pbreach_contribution` (0-100 posture slot)
  (2) scoring_analytics.py L677:
        - dehashed_risk now READS credential_risk.pbreach_contribution
          instead of the confidence-blind total_entries*2.

Run from security_scanner/.  NOT shipped (calibration prep, FIN-9 2026-06-03).
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SEC = os.path.dirname(HERE)

# ---------------------------------------------------------------------------
# Edit 1: checkers_threats.py
# ---------------------------------------------------------------------------
CT = os.path.join(SEC, "checkers_threats.py")
s = open(CT, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer (CT)"

KCLOSE = '        "rockyou2021": "2021-06-01",\n    }\n'
assert s.count(KCLOSE) == 1, ("KCLOSE", s.count(KCLOSE))

K_CONSTANTS = '''
    # --- Credential-confidence model (K1-K7) - FIN-9 / 5L calibration -------
    # Per-record weight  w = K1[confidence] x K2[recency] x (K3 if combo),
    # summed to W; W -> class (K4); class -> p(breach) posture slot (K5) +
    # report-only risk_score (K5b). Replaces the confidence-blind
    # `total_entries x 2`. PROPOSED (SANDBOX, FIN-9 2026-06-03); ranges and
    # colleague-gated items in docs/calibration_prep/02_credential_pbreach.md.
    K1_CONFIDENCE = {"high": 1.0, "med": 0.4, "low": 0.1}  # plaintext / hash / email-only
    K2_RECENCY_BANDS = ((90, 1.0), (180, 0.8), (360, 0.6), (730, 0.4))  # (max_age_d, mult)
    K2_FLOOR = 0.25  # >2yr or undated (IBM CoDB 292d dwell -> slow decay, no cliff)
    K3_COMBO_DISCOUNT = 0.3  # combo/aggregator lists (COLLEAGUE-GATED Q-A; band 0.25-0.4)
    K4_THRESHOLDS = ((4.0, "CRITICAL"), (2.0, "HIGH"), (0.8, "MEDIUM"), (0.2, "LOW"))  # else NONE
    K5_PBREACH_CONTRIBUTION = {"CRITICAL": 100, "HIGH": 70, "MEDIUM": 35, "LOW": 10, "NONE": 0}
    K5_RISK_SCORE = {"CRITICAL": 0, "HIGH": 25, "MEDIUM": 55, "LOW": 85, "NONE": 100}  # report-only, higher=safer
    L3_HR_STALE_DAYS = 180  # confirmed HR infection older than this decays CRITICAL->HIGH (gated 180-365)
    COMBO_SOURCE_TOKENS = (
        "combo", "collection #", "alien txtbase", "naz.api", "rockyou",
        "exploit.in", "anti public", "apollo", "socradar", "bureau van dijk",
        "telegram", "stealer log", "compilation",
    )
'''
s = s.replace(KCLOSE, KCLOSE + K_CONSTANTS, 1)

START = ("    @staticmethod\n"
         "    def classify(dehashed: dict, hudson_rock: dict, intelx: dict = None, hibp_enriched: dict = None) -> dict:\n")
END_MARK = ("\n\n\n# ---------------------------------------------------------------------------\n"
            "# 27. IntelX Dark Web Monitoring (free tier)\n")
assert s.count(START) == 1, ("START", s.count(START))
assert s.count(END_MARK) == 1, ("END_MARK", s.count(END_MARK))

NEW_METHOD = '''    @staticmethod
    def classify(dehashed: dict, hudson_rock: dict, intelx: dict = None, hibp_enriched: dict = None) -> dict:
        """Confidence-weighted credential-risk classification (K1-K7 model).

        Replaces the old confidence-blind deduction ladder (darkweb x-10 /
        paste x-3, uncapped) with a per-record weighted sum: every DeHashed
        record scores w = K1[confidence] x K2[recency] x (K3 if combo). The
        records sum to W; W maps to a class (K4); the class maps to a
        p(breach) posture contribution (K5) and the report-only risk_score.
        A confirmed Hudson Rock infostealer infection is a hard class FLOOR
        (L3) the weighted sum can never lower. IntelX dark-web mentions are
        report-only (K7=0): aggregated-index / browser-history noise must not
        score as credential theft. See
        docs/calibration_prep/02_credential_pbreach.md.
        """
        from datetime import datetime, timezone
        cls_self = CredentialRiskClassifier
        K1 = cls_self.K1_CONFIDENCE
        today = datetime.now(timezone.utc).date()

        def _is_combo(source):
            s = (source or "").strip().lower()
            return any(tok in s for tok in cls_self.COMBO_SOURCE_TOKENS)

        def _recency_mult(date_str):
            if not date_str or str(date_str).strip().lower() in ("", "unknown", "none"):
                return cls_self.K2_FLOOR
            try:
                d = datetime.strptime(str(date_str)[:10], "%Y-%m-%d").date()
            except (ValueError, TypeError):
                return cls_self.K2_FLOOR
            age = max(0, (today - d).days)
            for max_age, mult in cls_self.K2_RECENCY_BANDS:
                if age <= max_age:
                    return mult
            return cls_self.K2_FLOOR

        # Per-source breach date: prefer HIBP enrichment, fall back to the
        # KNOWN_BREACH_DATES table for sources HIBP does not track.
        src_date = {}
        for src in (dehashed.get("enriched_sources", []) or []):
            nm = (src.get("name") or "").strip().lower()
            if nm:
                src_date[nm] = src.get("breach_date", "Unknown")

        def _date_for(source):
            s = (source or "").strip().lower()
            dt = src_date.get(s)
            if dt and dt not in ("Unknown", ""):
                return dt
            return cls_self.KNOWN_BREACH_DATES.get(s, "Unknown")

        # ---- K1-K3: weight every DeHashed record by what it actually carries.
        records = dehashed.get("breach_details", []) or []
        W = 0.0
        high_records = med_records = 0
        password_sources = set()
        recent_pw_sources = set()
        for r in records:
            has_pw = bool(r.get("has_password"))
            has_hash = bool(r.get("has_hash"))
            if has_pw:
                k1 = K1["high"]; high_records += 1
            elif has_hash:
                k1 = K1["med"]; med_records += 1
            else:
                k1 = K1["low"]
            src = r.get("database", "") or ""
            k2 = _recency_mult(_date_for(src))
            k3 = cls_self.K3_COMBO_DISCOUNT if _is_combo(src) else 1.0
            W += k1 * k2 * k3
            if has_pw or has_hash:
                password_sources.add(src or "unknown")
                if k2 >= 0.6:
                    recent_pw_sources.add(src or "unknown")

        # ---- K4: summed weight -> class.
        cls = "NONE"
        for min_w, name in cls_self.K4_THRESHOLDS:
            if W >= min_w:
                cls = name
                break

        # ---- L3: a confirmed Hudson Rock infection is a hard class FLOOR that
        # can only RAISE the class, never lower it (the weighted sum governs the
        # DeHashed/IntelX corpus and must never down-grade a real infection).
        hr_employees = hudson_rock.get("compromised_employees", 0) or 0
        hr_users = hudson_rock.get("compromised_users", 0) or 0
        hr_days = hudson_rock.get("days_since_compromise")
        active_compromise = bool(hr_employees or hr_users)
        order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

        def _raise_to(current, floor):
            return floor if order.index(floor) > order.index(current) else current

        stale_infection = isinstance(hr_days, (int, float)) and hr_days > cls_self.L3_HR_STALE_DAYS
        if hr_employees > 0:
            cls = _raise_to(cls, "HIGH" if stale_infection else "CRITICAL")
        elif hr_users > 0:
            cls = _raise_to(cls, "HIGH")

        # ---- K5: class -> contributions. risk_level stays display-compatible
        # (CRITICAL/HIGH/MEDIUM/LOW); NONE collapses to LOW for display but
        # contributes 0 to the posture channel.
        pbreach_contribution = cls_self.K5_PBREACH_CONTRIBUTION[cls]
        risk_score = cls_self.K5_RISK_SCORE[cls]
        risk_level = "LOW" if cls == "NONE" else cls

        # ---- Factors (human-readable; IntelX lines are report-only). ----------
        factors = []
        if hr_employees > 0:
            if stale_infection:
                factors.append(f"INFOSTEALER (stale): {hr_employees} employee device(s) infected, last seen ~{int(hr_days)}d ago")
            else:
                factors.append(f"ACTIVE INFOSTEALER: {hr_employees} employee device(s) infected - credentials may be exfiltrating in real time")
        if hr_users > 0:
            factors.append(f"{hr_users} user account(s) compromised via infostealer malware")
        total_records = len(records)
        if high_records or med_records:
            factors.append(
                f"{high_records} plaintext-password and {med_records} hashed-credential record(s) "
                f"of {total_records} exposed (confidence-weighted W={W:.2f}); "
                f"source(s): {', '.join(sorted(password_sources)) or 'n/a'}"
            )
        elif total_records:
            n_src = len({(r.get('database') or '') for r in records})
            factors.append(
                f"{total_records} email-only breach record(s) across {n_src} source(s) - "
                f"no password/hash on record (confidence-weighted W={W:.2f})"
            )
        if recent_pw_sources:
            factors.append("Recent (<=1yr) credential exposure: " + ", ".join(sorted(recent_pw_sources)))
        if intelx and isinstance(intelx, dict):
            dw = intelx.get("darkweb_count", 0) or 0
            pst = intelx.get("paste_count", 0) or 0
            if dw or pst:
                factors.append(
                    f"IntelX: {dw} dark-web and {pst} paste mention(s) - monitoring signal, "
                    "not confirmed credential theft (no score impact)"
                )

        summary_by_level = {
            "CRITICAL": ("CRITICAL credential risk - active infostealer infection or fresh password "
                         "capture. Force resets, enable MFA, isolate infected devices, engage IR."),
            "HIGH": ("HIGH credential risk - confirmed credential exposure (passwords/hashes) or a "
                     "stale infostealer infection. Force resets, enable MFA, monitor for stuffing."),
            "MEDIUM": ("MEDIUM credential risk - some confidence-weighted credential exposure. "
                       "Review affected accounts, enforce MFA, monitor."),
            "LOW": ("LOW credential risk - exposure is historical and/or email-only (no fresh, "
                    "high-confidence passwords; no active infection)."),
        }

        return {
            "risk_level": risk_level,
            "credential_class": cls,
            "risk_score": risk_score,
            "pbreach_contribution": pbreach_contribution,
            "weighted_exposure": round(W, 3),
            "active_compromise": active_compromise,
            "factors": factors,
            "summary": summary_by_level[risk_level],
        }'''

i = s.index(START)
j = s.index(END_MARK, i)  # j sits at the first \n right after the old "return result"
s = s[:i] + NEW_METHOD + s[j:]

# Sanity: old confidence-blind ladder gone; new model present.
for dead in ("result[\"risk_score\"] = max(0, result[\"risk_score\"] - darkweb * 10)",
             "pastes * 3",
             '"risk_score": 100,'):
    assert dead not in s, ("residual ladder", dead)
for need in ("K1_CONFIDENCE", "K4_THRESHOLDS", "pbreach_contribution",
             "weighted_exposure", "def _recency_mult"):
    assert need in s, ("missing", need)
assert "\r" not in s, "unexpected CR (CT)"
with open(CT, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print("OK checkers_threats.py: K-model classify() applied")

# ---------------------------------------------------------------------------
# Edit 2: scoring_analytics.py L677 wiring
# ---------------------------------------------------------------------------
SA = os.path.join(SEC, "scoring_analytics.py")
t = open(SA, encoding="utf-8").read()
assert "\r" not in t, "expected text-mode normalised buffer (SA)"

OLD = (
    "        # Dehashed credential leak risk\n"
    "        dehashed = results.get(\"dehashed\", {})\n"
    "        dehashed_total = dehashed.get(\"total_entries\", 0)\n"
    "        dehashed_risk = min(100, dehashed_total * 2) if dehashed.get(\"status\") not in (\"no_api_key\", \"auth_failed\") else 0\n"
)
assert t.count(OLD) == 1, ("SA OLD", t.count(OLD))

NEW = (
    "        # Credential-leak posture contribution. CredentialRiskClassifier\n"
    "        # (checkers_threats.py) turns the DeHashed/IntelX/Hudson-Rock corpus\n"
    "        # into a confidence-weighted class (K1-K7) and maps it to a 0-100\n"
    "        # posture slot (pbreach_contribution). Replaces the confidence-blind\n"
    "        # `total_entries * 2`, which moved 13 stale email-only appearances as\n"
    "        # hard as 13 fresh passwords. Falls back to 0 when DeHashed returned\n"
    "        # no usable result. (Weight key stays \"dehashed\".)\n"
    "        dehashed = results.get(\"dehashed\", {})\n"
    "        if dehashed.get(\"status\") in (\"no_api_key\", \"auth_failed\"):\n"
    "            dehashed_risk = 0\n"
    "        else:\n"
    "            dehashed_risk = results.get(\"credential_risk\", {}).get(\"pbreach_contribution\", 0)\n"
)
t = t.replace(OLD, NEW, 1)
assert "min(100, dehashed_total * 2)" not in t, "old blind dehashed_risk still present"
assert "pbreach_contribution" in t, "new wiring missing"
assert "\r" not in t, "unexpected CR (SA)"
with open(SA, "wb") as f:
    f.write(t.replace("\n", "\r\n").encode("utf-8"))
print("OK scoring_analytics.py: dehashed_risk now reads pbreach_contribution")
