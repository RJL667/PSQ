"""
Cyber Insurance External Security Scanner
Passive, read-only assessment of external-facing infrastructure.
All checks use only publicly available information.
"""

import ssl
import socket
import json
import re
import time
import threading
from datetime import datetime, timezone
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

DEFAULT_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 CyberInsuranceScanner/1.0 (passive assessment)"


# ---------------------------------------------------------------------------
# 1. SSL / TLS Assessment
# ---------------------------------------------------------------------------

class SSLChecker:
    def check(self, domain: str) -> dict:
        result = {
            "status": "completed", "certificate": {}, "tls_versions": {},
            "cipher_suite": {}, "hsts": False, "grade": "F", "score": 0, "issues": [],
        }
        try:
            result["certificate"] = self._get_certificate(domain)
            result["tls_versions"] = self._check_tls_versions(domain)
            result["cipher_suite"] = self._get_cipher_suite(domain)
            result["hsts"] = self._check_hsts(domain)
            grade, score, issues = self._calculate_grade(
                result["certificate"], result["tls_versions"],
                result["cipher_suite"], result["hsts"]
            )
            result["grade"] = grade
            result["score"] = score
            result["issues"] = issues
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
            result["issues"] = [f"SSL check error: {e}"]
        return result

    def _get_certificate(self, domain: str) -> dict:
        info = {"valid": False}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=DEFAULT_TIMEOUT) as raw:
                with ctx.wrap_socket(raw, server_hostname=domain) as s:
                    cert = s.getpeercert()
                    not_after = cert.get("notAfter", "")
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (expiry - now).days
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                    info = {
                        "valid": True,
                        "subject": subject.get("commonName", domain),
                        "issuer": issuer.get("organizationName", "Unknown"),
                        "issuer_cn": issuer.get("commonName", "Unknown"),
                        "expiry_date": not_after,
                        "days_until_expiry": days_left,
                        "is_expired": days_left < 0,
                        "expiring_soon": 0 <= days_left <= 30,
                        "san_count": len(sans),
                    }
        except ssl.SSLCertVerificationError as e:
            info = {"valid": False, "error": str(e)}
        except Exception as e:
            info = {"valid": False, "error": str(e)}
        return info

    def _check_tls_versions(self, domain: str) -> dict:
        versions = {"TLS 1.0": False, "TLS 1.1": False, "TLS 1.2": False, "TLS 1.3": False}
        checks = {
            "TLS 1.2": ("TLSv1_2", True), "TLS 1.3": ("TLSv1_3", True),
            "TLS 1.0": ("TLSv1", False), "TLS 1.1": ("TLSv1_1", False),
        }
        for label, (attr, verify) in checks.items():
            if not hasattr(ssl.TLSVersion, attr):
                continue
            try:
                ver = getattr(ssl.TLSVersion, attr)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = ver; ctx.maximum_version = ver
                ctx.check_hostname = verify
                ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
                with socket.create_connection((domain, 443), timeout=DEFAULT_TIMEOUT) as raw:
                    with ctx.wrap_socket(raw, server_hostname=domain):
                        versions[label] = True
            except Exception:
                pass
        return versions

    def _get_cipher_suite(self, domain: str) -> dict:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=DEFAULT_TIMEOUT) as raw:
                with ctx.wrap_socket(raw, server_hostname=domain) as s:
                    c = s.cipher()
                    if c:
                        weak = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON"]
                        return {"name": c[0], "protocol": c[1], "bits": c[2] or 0,
                                "is_weak": any(w in c[0].upper() for w in weak)}
        except Exception as e:
            return {"name": "Unknown", "bits": 0, "is_weak": True, "error": str(e)}
        return {"name": "Unknown", "bits": 0, "is_weak": True}

    def _check_hsts(self, domain: str) -> bool:
        if not REQUESTS_AVAILABLE:
            return False
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            return "strict-transport-security" in r.headers
        except Exception:
            return False

    def _calculate_grade(self, cert, tls, cipher, hsts) -> tuple:
        issues, ded = [], 0
        if not cert.get("valid"):
            ded += 40; issues.append("Invalid or unverifiable SSL certificate")
        elif cert.get("is_expired"):
            ded += 40; issues.append("SSL certificate has EXPIRED")
        elif cert.get("expiring_soon"):
            ded += 20; issues.append(f"Certificate expiring in {cert.get('days_until_expiry')} days")
        if tls.get("TLS 1.0"):
            ded += 20; issues.append("TLS 1.0 supported — deprecated and insecure")
        if tls.get("TLS 1.1"):
            ded += 10; issues.append("TLS 1.1 supported — deprecated")
        if not tls.get("TLS 1.2") and not tls.get("TLS 1.3"):
            ded += 30; issues.append("No modern TLS version (1.2/1.3) detected")
        if cipher.get("is_weak"):
            ded += 20; issues.append(f"Weak cipher: {cipher.get('name', 'Unknown')}")
        if not hsts:
            ded += 10; issues.append("HSTS header missing")
        score = max(0, 100 - ded)
        grade = "A+" if score >= 95 else "A" if score >= 80 else "B" if score >= 70 else "C" if score >= 60 else "D" if score >= 50 else "F"
        return grade, score, issues


# ---------------------------------------------------------------------------
# 2. Email Security (DNS-based)
# ---------------------------------------------------------------------------

class EmailSecurityChecker:
    DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "mail", "dkim", "k1", "smtp"]

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "spf": {"present": False, "valid": False, "record": None},
            "dmarc": {"present": False, "policy": None, "record": None},
            "dkim": {"selectors_found": []},
            "mx": {"records": []},
            "score": 0, "issues": [],
        }
        if not DNS_AVAILABLE:
            result["status"] = "error"; result["error"] = "dnspython not installed"; return result
        try:
            result["spf"] = self._check_spf(domain)
            result["dmarc"] = self._check_dmarc(domain)
            result["dkim"] = self._check_dkim(domain)
            result["mx"] = self._check_mx(domain)
            result["score"], result["issues"] = self._calculate_score(
                result["spf"], result["dmarc"], result["dkim"])
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result

    def _check_spf(self, domain: str) -> dict:
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=DEFAULT_TIMEOUT)
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
                if txt.startswith("v=spf1"):
                    valid = "all" in txt
                    return {"present": True, "valid": valid, "record": txt,
                            "dangerous": "+all" in txt}
        except Exception:
            pass
        return {"present": False, "valid": False, "record": None, "dangerous": False}

    def _check_dmarc(self, domain: str) -> dict:
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=DEFAULT_TIMEOUT)
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
                if "v=DMARC1" in txt:
                    match = re.search(r"p=(\w+)", txt)
                    policy = match.group(1) if match else "none"
                    return {"present": True, "policy": policy, "record": txt}
        except Exception:
            pass
        return {"present": False, "policy": None, "record": None}

    def _check_dkim(self, domain: str) -> dict:
        found = []
        for selector in self.DKIM_SELECTORS:
            try:
                dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT", lifetime=5)
                found.append(selector)
            except Exception:
                pass
        return {"selectors_found": found}

    def _check_mx(self, domain: str) -> dict:
        records = []
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=DEFAULT_TIMEOUT)
            records = sorted([{"preference": r.preference, "exchange": str(r.exchange)} for r in answers],
                             key=lambda x: x["preference"])
        except Exception:
            pass
        return {"records": records}

    def _calculate_score(self, spf, dmarc, dkim) -> tuple:
        score, issues = 10, []
        if not spf["present"]:
            score -= 3; issues.append("No SPF record — spoofing risk")
        elif spf.get("dangerous"):
            score -= 3; issues.append("SPF uses '+all' — allows any server to send on your behalf")
        elif not spf["valid"]:
            score -= 1; issues.append("SPF record may be invalid")
        if not dmarc["present"]:
            score -= 4; issues.append("No DMARC record — phishing risk")
        elif dmarc["policy"] == "none":
            score -= 2; issues.append("DMARC policy is 'none' — no enforcement")
        elif dmarc["policy"] == "quarantine":
            score -= 1; issues.append("DMARC policy is 'quarantine' — consider upgrading to 'reject'")
        if not dkim["selectors_found"]:
            score -= 2; issues.append("No DKIM selectors found for common selector names")
        return max(0, score), issues


# ---------------------------------------------------------------------------
# 3. Email Hardening (MTA-STS, DANE, BIMI)
# ---------------------------------------------------------------------------

class EmailHardeningChecker:
    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "mta_sts": {"present": False, "mode": None},
            "bimi": {"present": False, "has_vmc": False},
            "dane": {"present": False},
            "issues": [], "score": 0,
        }
        if not DNS_AVAILABLE or not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result
        try:
            result["mta_sts"] = self._check_mta_sts(domain)
            result["bimi"] = self._check_bimi(domain)
            result["dane"] = self._check_dane(domain)
            result["score"], result["issues"] = self._calculate_score(
                result["mta_sts"], result["bimi"], result["dane"])
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result

    def _check_mta_sts(self, domain: str) -> dict:
        try:
            answers = dns.resolver.resolve(f"_mta-sts.{domain}", "TXT", lifetime=5)
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
                if "v=STSv1" in txt:
                    # Also try to fetch the policy file
                    mode = None
                    try:
                        r = requests.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                                         timeout=5, headers={"User-Agent": USER_AGENT})
                        m = re.search(r"mode:\s*(\w+)", r.text)
                        mode = m.group(1) if m else "unknown"
                    except Exception:
                        mode = "unknown"
                    return {"present": True, "mode": mode}
        except Exception:
            pass
        return {"present": False, "mode": None}

    def _check_bimi(self, domain: str) -> dict:
        try:
            answers = dns.resolver.resolve(f"default._bimi.{domain}", "TXT", lifetime=5)
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
                if "v=BIMI1" in txt:
                    has_vmc = "a=https" in txt.lower()
                    return {"present": True, "has_vmc": has_vmc}
        except Exception:
            pass
        return {"present": False, "has_vmc": False}

    def _check_dane(self, domain: str) -> dict:
        # Check TLSA record for primary MX
        try:
            mx_answers = dns.resolver.resolve(domain, "MX", lifetime=5)
            if mx_answers:
                mx_host = str(sorted(mx_answers, key=lambda r: r.preference)[0].exchange).rstrip(".")
                try:
                    dns.resolver.resolve(f"_25._tcp.{mx_host}", "TLSA", lifetime=5)
                    return {"present": True}
                except Exception:
                    pass
        except Exception:
            pass
        return {"present": False}

    def _calculate_score(self, mta_sts, bimi, dane) -> tuple:
        score, issues = 0, []
        if mta_sts["present"]:
            score += 4
            if mta_sts["mode"] == "enforce":
                score += 2
        else:
            issues.append("No MTA-STS policy — inbound email susceptible to TLS downgrade attacks")
        if bimi["present"]:
            score += 2
            if bimi["has_vmc"]:
                score += 1
        if dane["present"]:
            score += 1
        else:
            issues.append("DANE/TLSA not configured for mail servers")
        return min(score, 10), issues


# ---------------------------------------------------------------------------
# 4. HTTP Security Headers
# ---------------------------------------------------------------------------

class HTTPHeaderChecker:
    HEADERS = {
        "content-security-policy": ("Content-Security-Policy", 20),
        "x-frame-options": ("X-Frame-Options", 15),
        "x-content-type-options": ("X-Content-Type-Options", 15),
        "strict-transport-security": ("Strict-Transport-Security", 20),
        "referrer-policy": ("Referrer-Policy", 15),
        "permissions-policy": ("Permissions-Policy", 15),
    }

    def check(self, domain: str) -> dict:
        result = {"status": "completed", "headers": {}, "score": 0, "issues": []}
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; result["error"] = "requests not installed"; return result
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            total_weight, earned = 0, 0
            for key, (label, weight) in self.HEADERS.items():
                present = key in headers_lower
                result["headers"][label] = {"present": present, "value": headers_lower.get(key)}
                total_weight += weight
                if present:
                    earned += weight
                else:
                    result["issues"].append(f"Missing security header: {label}")
            result["score"] = round((earned / total_weight) * 100) if total_weight else 0
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 5. WAF Detection
# ---------------------------------------------------------------------------

class WAFChecker:
    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": ["cf-ray", "cf-cache-status"],
            "cookies": ["__cfduid", "cf_clearance"],
            "body": ["cloudflare"],
        },
        "AWS WAF / CloudFront": {
            "headers": ["x-amz-cf-id", "x-amzn-requestid", "x-cache"],
            "cookies": ["awselb", "awsalb"],
            "body": [],
        },
        "Imperva / Incapsula": {
            "headers": ["x-iinfo", "x-cdn"],
            "cookies": ["visid_incap", "_incap_ses"],
            "body": ["incap_ses", "visid_incap"],
        },
        "Akamai": {
            "headers": ["x-akamai-transformed", "akamai-origin-hop", "x-check-cacheable"],
            "cookies": ["ak_bmsc", "bm_sz"],
            "body": [],
        },
        "Sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "cookies": [],
            "body": ["sucuri"],
        },
        "F5 BIG-IP ASM": {
            "headers": ["x-wa-info", "x-frame-options"],
            "cookies": ["ts", "f5avr"],
            "body": [],
        },
        "Barracuda": {
            "headers": [],
            "cookies": ["barra_counter_session"],
            "body": [],
        },
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "detected": False,
            "waf_name": None,
            "all_detected": [],
            "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
            cookies_lower = {k.lower(): v.lower() for k, v in r.cookies.items()}
            body_lower = r.text[:5000].lower()

            detected = []
            for waf_name, sigs in self.WAF_SIGNATURES.items():
                matched = False
                for h in sigs["headers"]:
                    if h in headers_lower:
                        matched = True; break
                if not matched:
                    for c in sigs["cookies"]:
                        if c in cookies_lower:
                            matched = True; break
                if not matched:
                    for b in sigs["body"]:
                        if b in body_lower:
                            matched = True; break
                if matched:
                    detected.append(waf_name)

            if detected:
                result["detected"] = True
                result["waf_name"] = detected[0]
                result["all_detected"] = detected
            else:
                result["issues"].append("No WAF detected — web application firewall recommended")
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 6. Cloud & CDN Provider Detection
# ---------------------------------------------------------------------------

class CloudCDNChecker:
    CLOUD_CNAMES = {
        "Cloudflare": [".cloudflare.com", ".cloudflare.net"],
        "AWS CloudFront": [".cloudfront.net"],
        "AWS": [".amazonaws.com", ".awsglobalaccelerator.com", ".elb.amazonaws.com"],
        "Azure": [".azurewebsites.net", ".trafficmanager.net", ".azure-api.net", ".cloudapp.azure.com"],
        "GCP": [".appspot.com", ".run.app", ".googleapis.com"],
        "Akamai": [".akamaiedge.net", ".akamaihd.net", ".akamaistream.net"],
        "Fastly": [".fastly.net", ".fastlylb.net"],
        "Vercel": [".vercel.app", ".vercel-dns.com"],
        "Netlify": [".netlify.app", ".netlify.com"],
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "provider": None,
            "cdn_detected": False,
            "ip_addresses": [],
            "hosting_type": "unknown",
            "issues": [],
        }
        if not DNS_AVAILABLE:
            result["status"] = "error"; return result
        try:
            # Resolve IPs
            try:
                ips = [str(r) for r in dns.resolver.resolve(domain, "A", lifetime=DEFAULT_TIMEOUT)]
                result["ip_addresses"] = ips
            except Exception:
                pass

            # Chase CNAME chain
            cname_chain = []
            try:
                target = domain
                for _ in range(5):
                    try:
                        answers = dns.resolver.resolve(target, "CNAME", lifetime=5)
                        cname = str(answers[0].target)
                        cname_chain.append(cname)
                        target = cname
                    except Exception:
                        break
            except Exception:
                pass

            all_cnames = " ".join(cname_chain).lower()

            for provider, patterns in self.CLOUD_CNAMES.items():
                if any(p in all_cnames for p in patterns):
                    result["provider"] = provider
                    result["cdn_detected"] = True
                    result["hosting_type"] = "cloud/cdn"
                    break

            if not result["provider"] and result["ip_addresses"]:
                result["hosting_type"] = "self-hosted or undetected cloud"

        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 7. Domain Intelligence (WHOIS)
# ---------------------------------------------------------------------------

class DomainIntelChecker:
    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "registrar": None,
            "creation_date": None,
            "expiry_date": None,
            "domain_age_days": None,
            "privacy_protected": False,
            "issues": [],
        }
        try:
            import whois
            w = whois.whois(domain)
            creation = w.creation_date
            expiry = w.expiration_date
            if isinstance(creation, list):
                creation = creation[0]
            if isinstance(expiry, list):
                expiry = expiry[0]

            result["registrar"] = str(w.registrar) if w.registrar else None

            if creation:
                age = (datetime.now() - creation.replace(tzinfo=None)).days
                result["creation_date"] = str(creation.date()) if hasattr(creation, 'date') else str(creation)
                result["domain_age_days"] = age
                if age < 365:
                    result["issues"].append(f"Domain is less than 1 year old ({age} days) — higher fraud risk")
                elif age < 730:
                    result["issues"].append(f"Domain is less than 2 years old ({age} days)")

            if expiry:
                result["expiry_date"] = str(expiry.date()) if hasattr(expiry, 'date') else str(expiry)
                days_to_expiry = (expiry.replace(tzinfo=None) - datetime.now()).days
                if days_to_expiry < 30:
                    result["issues"].append(f"Domain expires in {days_to_expiry} days — renewal risk")

            # Detect privacy protection
            whois_raw = str(w).lower()
            privacy_keywords = ["redacted", "privacy", "withheld", "protected", "proxy"]
            result["privacy_protected"] = any(k in whois_raw for k in privacy_keywords)

        except ImportError:
            result["status"] = "skipped"
            result["error"] = "python-whois not installed"
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 8. Subdomain Discovery (Certificate Transparency)
# ---------------------------------------------------------------------------

class SubdomainChecker:
    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "subdomains": [],
            "risky_subdomains": [],
            "total_count": 0,
            "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result

        RISKY_KEYWORDS = ["dev", "staging", "test", "admin", "api", "old", "beta",
                          "backup", "db", "database", "internal", "vpn", "remote",
                          "jenkins", "gitlab", "jira", "grafana", "kibana", "phpmyadmin"]
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=20, headers={"User-Agent": USER_AGENT}
            )
            if r.status_code == 200:
                entries = r.json()
                seen = set()
                subdomains = []
                for entry in entries:
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lower().lstrip("*.")
                        if name and name != domain and domain in name and name not in seen:
                            seen.add(name)
                            subdomains.append(name)

                subdomains = subdomains[:100]  # cap at 100
                result["subdomains"] = subdomains
                result["total_count"] = len(subdomains)

                risky = [s for s in subdomains if any(k in s for k in RISKY_KEYWORDS)]
                result["risky_subdomains"] = risky

                if risky:
                    result["issues"].append(
                        f"{len(risky)} risky subdomain(s) found in public CT logs: {', '.join(risky[:5])}"
                    )
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 9. Exposed Admin Panels & Sensitive Paths
# ---------------------------------------------------------------------------

class ExposedAdminChecker:
    PATHS = {
        "critical": [
            "/.env", "/.git/HEAD", "/.git/config", "/wp-config.php",
            "/config.php", "/database.yml", "/.htpasswd", "/backup.sql",
            "/dump.sql", "/db.sql", "/backup.zip", "/backup.tar.gz",
        ],
        "high": [
            "/admin", "/administrator", "/wp-admin", "/wp-login.php",
            "/phpmyadmin", "/cpanel", "/whm", "/webmail",
            "/jenkins", "/grafana", "/kibana", "/portainer",
            "/jira", "/confluence", "/gitlab", "/rancher",
            "/.well-known/", "/api/v1/users", "/api/v2/users",
        ],
        "medium": [
            "/server-status", "/server-info", "/status", "/health",
            "/metrics", "/actuator", "/actuator/health", "/actuator/env",
            "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/openapi.json",
            "/robots.txt", "/sitemap.xml", "/phpinfo.php",
        ],
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "exposed": [],
            "critical_count": 0,
            "high_count": 0,
            "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result

        exposed = []

        def probe(path, risk):
            try:
                r = requests.get(
                    f"https://{domain}{path}", timeout=4,
                    allow_redirects=False, headers={"User-Agent": USER_AGENT}
                )
                # 200 = exposed, 401/403 = exists but auth required (still noteworthy for critical)
                if r.status_code == 200 or (risk == "critical" and r.status_code in [401, 403]):
                    return {"path": path, "status": r.status_code, "risk": risk}
            except Exception:
                pass
            return None

        all_paths = [(p, "critical") for p in self.PATHS["critical"]] + \
                    [(p, "high") for p in self.PATHS["high"]] + \
                    [(p, "medium") for p in self.PATHS["medium"]]

        with ThreadPoolExecutor(max_workers=15) as ex:
            futures = {ex.submit(probe, path, risk): (path, risk) for path, risk in all_paths}
            for f in as_completed(futures, timeout=25):
                try:
                    r = f.result()
                    if r:
                        exposed.append(r)
                except Exception:
                    pass

        result["exposed"] = sorted(exposed, key=lambda x: ["critical", "high", "medium"].index(x["risk"]))
        result["critical_count"] = sum(1 for e in exposed if e["risk"] == "critical")
        result["high_count"] = sum(1 for e in exposed if e["risk"] == "high")

        for e in exposed:
            if e["risk"] == "critical":
                result["issues"].append(f"CRITICAL: Sensitive file exposed — {e['path']} (HTTP {e['status']})")
            elif e["risk"] == "high":
                result["issues"].append(f"Admin panel accessible — {e['path']} (HTTP {e['status']})")

        return result


# ---------------------------------------------------------------------------
# 10. VPN / Remote Access Detection
# ---------------------------------------------------------------------------

class VPNRemoteAccessChecker:
    VPN_SIGNATURES = {
        "Cisco AnyConnect": {
            "paths": ["/+CSCOE+/logon.html", "/+webvpn+/"],
            "body_keywords": ["anyconnect", "cisco ssl vpn"],
        },
        "Fortinet FortiGate SSL VPN": {
            "paths": ["/remote/login", "/remote/logincheck"],
            "body_keywords": ["fortinet", "fortigate", "ssl-vpn"],
        },
        "Pulse Secure / Ivanti": {
            "paths": ["/dana-na/auth/url_default/welcome.cgi"],
            "body_keywords": ["pulse secure", "ivanti"],
        },
        "Palo Alto GlobalProtect": {
            "paths": ["/global-protect/getsoftware.esp", "/ssl-vpn/"],
            "body_keywords": ["globalprotect", "palo alto"],
        },
        "Citrix Gateway": {
            "paths": ["/citrix/xenapp", "/Citrix/XenApp", "/vpn/index.html"],
            "body_keywords": ["citrix gateway", "netscaler"],
        },
        "Microsoft RDS Web": {
            "paths": ["/RDWeb/Pages/en-US/login.aspx", "/RDWeb/"],
            "body_keywords": ["remote desktop", "rdweb"],
        },
        "OpenVPN Access Server": {
            "paths": ["/"],
            "body_keywords": ["openvpn access server", "openvpn-as"],
        },
        "SonicWall SSL VPN": {
            "paths": ["/cgi-bin/sslvpnclient", "/prx/000/http/localhost/cgi-bin/welcome"],
            "body_keywords": ["sonicwall", "netextender"],
        },
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "vpn_detected": False,
            "vpn_name": None,
            "rdp_exposed": False,
            "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result

        # Check RDP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            rdp_open = s.connect_ex((domain, 3389)) == 0
            s.close()
            result["rdp_exposed"] = rdp_open
            if rdp_open:
                result["issues"].append("RDP (port 3389) is exposed — directly accessible from internet")
        except Exception:
            pass

        # Probe VPN login pages
        for vpn_name, sigs in self.VPN_SIGNATURES.items():
            for path in sigs["paths"]:
                try:
                    r = requests.get(
                        f"https://{domain}{path}", timeout=5,
                        allow_redirects=True, headers={"User-Agent": USER_AGENT}
                    )
                    body = r.text[:3000].lower()
                    if any(kw in body for kw in sigs["body_keywords"]):
                        result["vpn_detected"] = True
                        result["vpn_name"] = vpn_name
                        break
                except Exception:
                    pass
            if result["vpn_detected"]:
                break

        if not result["vpn_detected"]:
            result["issues"].append("No VPN/remote access gateway detected — remote access method unknown")

        return result


# ---------------------------------------------------------------------------
# 11. DNS & Infrastructure
# ---------------------------------------------------------------------------

class DNSInfrastructureChecker:
    HIGH_RISK_PORTS = {21: "FTP", 23: "Telnet", 3306: "MySQL", 3389: "RDP", 5900: "VNC"}
    MEDIUM_RISK_PORTS = {22: "SSH", 25: "SMTP", 110: "POP3", 143: "IMAP"}
    INFO_PORTS = {80: "HTTP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"}
    ALL_PORTS = {**HIGH_RISK_PORTS, **MEDIUM_RISK_PORTS, **INFO_PORTS}

    # Maps each port to exploit context relevant for cyber insurance underwriting
    PORT_EXPLOIT_MAP = {
        21: {
            "service": "FTP",
            "exploits": "Anonymous login, credential brute-force, cleartext credential theft (CVE-2015-3306, CVE-2019-12815)",
            "typical_cves": ["CVE-2015-3306", "CVE-2019-12815", "CVE-2010-4221"],
            "typical_cvss": 9.8, "typical_severity": "critical",
            "typical_epss": 0.85, "in_kev": True,
            "insurance_risk": "Data exfiltration via unencrypted file transfer; ransomware initial access vector",
            "severity": "high",
            "underwriting_impact": "Increases likelihood of data breach claim; cleartext credentials enable lateral movement",
        },
        23: {
            "service": "Telnet",
            "exploits": "Cleartext session hijacking, credential sniffing, brute-force attacks (Mirai botnet family)",
            "typical_cves": ["CVE-2018-10561", "CVE-2019-7256"],
            "typical_cvss": 9.8, "typical_severity": "critical",
            "typical_epss": 0.95, "in_kev": True,
            "insurance_risk": "Full remote command execution with stolen credentials; botnet recruitment",
            "severity": "critical",
            "underwriting_impact": "Critical indicator of poor security hygiene; highly exploitable for ransomware deployment",
        },
        22: {
            "service": "SSH",
            "exploits": "Brute-force attacks, key-based auth bypass (CVE-2024-6387 regreSSHion, CVE-2023-48795 Terrapin)",
            "typical_cves": ["CVE-2024-6387", "CVE-2023-48795", "CVE-2016-20012"],
            "typical_cvss": 8.1, "typical_severity": "high",
            "typical_epss": 0.35, "in_kev": False,
            "insurance_risk": "Remote command execution if compromised; privilege escalation",
            "severity": "medium",
            "underwriting_impact": "Common but manageable with key-based auth; outdated versions significantly increase risk",
        },
        25: {
            "service": "SMTP",
            "exploits": "Open relay abuse, email spoofing, buffer overflow (CVE-2019-15846 Exim, CVE-2021-21315)",
            "typical_cves": ["CVE-2019-15846", "CVE-2021-21315", "CVE-2020-28017"],
            "typical_cvss": 9.8, "typical_severity": "critical",
            "typical_epss": 0.60, "in_kev": True,
            "insurance_risk": "Email-based fraud, phishing campaigns from compromised mail server, BEC attacks",
            "severity": "medium",
            "underwriting_impact": "Exposed SMTP increases business email compromise claim probability",
        },
        110: {
            "service": "POP3",
            "exploits": "Cleartext credential theft, brute-force, buffer overflow attacks",
            "typical_cves": ["CVE-2011-1720"],
            "typical_cvss": 7.5, "typical_severity": "high",
            "typical_epss": 0.15, "in_kev": False,
            "insurance_risk": "Email account takeover via credential interception",
            "severity": "medium",
            "underwriting_impact": "Unencrypted email retrieval exposes credentials; migrate to POP3S (995)",
        },
        143: {
            "service": "IMAP",
            "exploits": "Cleartext credential interception, brute-force, injection attacks",
            "typical_cves": ["CVE-2021-33515", "CVE-2019-11500"],
            "typical_cvss": 7.5, "typical_severity": "high",
            "typical_epss": 0.12, "in_kev": False,
            "insurance_risk": "Email account compromise leading to BEC or data theft",
            "severity": "medium",
            "underwriting_impact": "Unencrypted IMAP exposes email credentials in transit; upgrade to IMAPS (993)",
        },
        80: {
            "service": "HTTP",
            "exploits": "XSS, SQL injection, CSRF, directory traversal, unencrypted data exposure",
            "typical_cves": [],
            "typical_cvss": 0.0, "typical_severity": "info",
            "typical_epss": 0.0, "in_kev": False,
            "insurance_risk": "Web application attacks; data exposure if sensitive content served over HTTP",
            "severity": "info",
            "underwriting_impact": "Standard web port; risk depends on whether HTTPS redirect is enforced",
        },
        443: {
            "service": "HTTPS",
            "exploits": "TLS downgrade attacks, certificate vulnerabilities, web app exploits (OWASP Top 10)",
            "typical_cves": [],
            "typical_cvss": 0.0, "typical_severity": "info",
            "typical_epss": 0.0, "in_kev": False,
            "insurance_risk": "Primary attack surface for web applications",
            "severity": "info",
            "underwriting_impact": "Expected to be open; risk depends on TLS configuration and web app security",
        },
        3306: {
            "service": "MySQL",
            "exploits": "Authentication bypass (CVE-2012-2122), SQL injection, credential brute-force, data dumping",
            "typical_cves": ["CVE-2012-2122", "CVE-2016-6662", "CVE-2020-14812"],
            "typical_cvss": 9.8, "typical_severity": "critical",
            "typical_epss": 0.92, "in_kev": True,
            "insurance_risk": "Direct database access enables mass data theft; ransomware encryption of data",
            "severity": "critical",
            "underwriting_impact": "Publicly exposed database is a critical underwriting red flag; high probability of data breach claim",
        },
        3389: {
            "service": "RDP",
            "exploits": "BlueKeep (CVE-2019-0708), credential brute-force, NLA bypass, DejaBlue (CVE-2019-1181)",
            "typical_cves": ["CVE-2019-0708", "CVE-2019-1181", "CVE-2019-1182"],
            "typical_cvss": 9.8, "typical_severity": "critical",
            "typical_epss": 0.97, "in_kev": True,
            "insurance_risk": "Primary ransomware entry point; #1 initial access vector in insurance claims",
            "severity": "critical",
            "underwriting_impact": "Exposed RDP is the single highest risk factor in cyber insurance; dramatically increases ransomware claim probability",
        },
        5900: {
            "service": "VNC",
            "exploits": "Authentication bypass, password brute-force, unencrypted sessions (CVE-2019-15678, CVE-2006-2369)",
            "typical_cves": ["CVE-2019-15678", "CVE-2006-2369", "CVE-2019-15679"],
            "typical_cvss": 9.8, "typical_severity": "critical",
            "typical_epss": 0.70, "in_kev": False,
            "insurance_risk": "Full graphical remote control; often used with weak or no authentication",
            "severity": "critical",
            "underwriting_impact": "Remote desktop without encryption; high-risk indicator for unauthorised access claims",
        },
        8080: {
            "service": "HTTP-Alt",
            "exploits": "Same as HTTP; often hosts dev/staging/admin interfaces with weaker security",
            "typical_cves": [],
            "typical_cvss": 5.0, "typical_severity": "medium",
            "typical_epss": 0.05, "in_kev": False,
            "insurance_risk": "Alternative HTTP port often exposes admin panels, APIs, or development environments",
            "severity": "medium",
            "underwriting_impact": "May indicate exposed management interfaces; review what service is running",
        },
        8443: {
            "service": "HTTPS-Alt",
            "exploits": "Same as HTTPS; commonly used for management consoles (VMware, network devices)",
            "typical_cves": [],
            "typical_cvss": 0.0, "typical_severity": "info",
            "typical_epss": 0.0, "in_kev": False,
            "insurance_risk": "Often hosts administrative interfaces for infrastructure management",
            "severity": "info",
            "underwriting_impact": "Low risk if properly secured; verify it's not an exposed admin console",
        },
        993: {
            "service": "IMAPS",
            "exploits": "TLS-protected email retrieval; significantly lower risk than plaintext IMAP",
            "typical_cves": [],
            "typical_cvss": 0.0, "typical_severity": "info",
            "typical_epss": 0.0, "in_kev": False,
            "insurance_risk": "Encrypted email access; standard configuration",
            "severity": "info",
            "underwriting_impact": "Good practice — encrypted email retrieval",
        },
        995: {
            "service": "POP3S",
            "exploits": "TLS-protected email retrieval; significantly lower risk than plaintext POP3",
            "typical_cves": [],
            "typical_cvss": 0.0, "typical_severity": "info",
            "typical_epss": 0.0, "in_kev": False,
            "insurance_risk": "Encrypted email access; standard configuration",
            "severity": "info",
            "underwriting_impact": "Good practice — encrypted email retrieval",
        },
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed", "dns_records": {}, "reverse_dns": None,
            "open_ports": [], "server_info": {}, "issues": [], "risk_score": 0,
        }
        try:
            if DNS_AVAILABLE:
                result["dns_records"] = self._get_dns_records(domain)
                result["reverse_dns"] = self._get_reverse_dns(domain)
            result["open_ports"] = self._scan_ports(domain)
            result["server_info"] = self._fingerprint_server(domain)
            result["risk_score"], result["issues"] = self._assess_risk(result["open_ports"])
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result

    def _get_dns_records(self, domain: str) -> dict:
        records = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=DEFAULT_TIMEOUT)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
        return records

    def _get_reverse_dns(self, domain: str) -> Optional[str]:
        try:
            ip = socket.gethostbyname(domain)
            rev = dns.reversename.from_address(ip)
            answer = dns.resolver.resolve(rev, "PTR", lifetime=DEFAULT_TIMEOUT)
            return str(answer[0])
        except Exception:
            return None

    def _scan_ports(self, domain: str) -> list:
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            return []

        open_ports = []

        def probe(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                if s.connect_ex((ip, port)) == 0:
                    risk = "high" if port in self.HIGH_RISK_PORTS else "medium" if port in self.MEDIUM_RISK_PORTS else "info"
                    entry = {"port": port, "service": self.ALL_PORTS.get(port, "Unknown"), "risk": risk}
                    exploit_info = self.PORT_EXPLOIT_MAP.get(port)
                    if exploit_info:
                        entry["exploits"] = exploit_info["exploits"]
                        entry["insurance_risk"] = exploit_info["insurance_risk"]
                        entry["underwriting_impact"] = exploit_info["underwriting_impact"]
                        entry["typical_cves"] = exploit_info.get("typical_cves", [])
                        entry["typical_cvss"] = exploit_info.get("typical_cvss", 0.0)
                        entry["typical_severity"] = exploit_info.get("typical_severity", "info")
                        entry["typical_epss"] = exploit_info.get("typical_epss", 0.0)
                        entry["in_kev"] = exploit_info.get("in_kev", False)
                    return entry
            except Exception:
                pass
            finally:
                try: s.close()
                except: pass
            return None

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(probe, p): p for p in self.ALL_PORTS}
            for f in as_completed(futures, timeout=30):
                try:
                    r = f.result()
                    if r:
                        open_ports.append(r)
                except Exception:
                    pass
        return sorted(open_ports, key=lambda x: x["port"])

    def _fingerprint_server(self, domain: str) -> dict:
        if not REQUESTS_AVAILABLE:
            return {}
        info = {}
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            for h in ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"]:
                if h in r.headers:
                    info[h] = r.headers[h]
        except Exception:
            pass
        return info

    def _assess_risk(self, open_ports: list) -> tuple:
        issues, score = [], 0
        for p in open_ports:
            exploit_ctx = p.get("insurance_risk", "")
            if p["risk"] == "high":
                score += 40
                issues.append(f"High-risk port open: {p['port']} ({p['service']}) — {exploit_ctx}" if exploit_ctx
                              else f"High-risk port open: {p['port']} ({p['service']})")
            elif p["risk"] == "medium":
                score += 15
                issues.append(f"Medium-risk port open: {p['port']} ({p['service']}) — {exploit_ctx}" if exploit_ctx
                              else f"Medium-risk port open: {p['port']} ({p['service']})")
        return min(score, 150), issues


# ---------------------------------------------------------------------------
# 12. High-Risk Protocol & Database Exposure
# ---------------------------------------------------------------------------

class HighRiskProtocolChecker:
    CRITICAL_SERVICES = {
        445: "SMB (file sharing)",
        161: "SNMP",
        27017: "MongoDB",
        6379: "Redis",
        9200: "Elasticsearch",
        5432: "PostgreSQL",
        1433: "MSSQL",
        5984: "CouchDB",
        7001: "Oracle WebLogic",
        8888: "Jupyter Notebook",
        11211: "Memcached",
        2375: "Docker API (unencrypted)",
        2376: "Docker API",
        9092: "Kafka",
        4848: "GlassFish Admin",
        8069: "Odoo ERP",
    }

    # Exploit and insurance underwriting context for each critical service
    SERVICE_EXPLOIT_MAP = {
        445: {
            "exploits": "EternalBlue (CVE-2017-0144), WannaCry, NotPetya, SMBGhost (CVE-2020-0796)",
            "typical_cves": ["CVE-2017-0144", "CVE-2020-0796", "CVE-2017-0145"],
            "typical_cvss": 10.0, "typical_severity": "critical",
            "typical_epss": 0.97, "in_kev": True,
            "insurance_risk": "Primary ransomware propagation vector; enables network-wide encryption within minutes",
            "underwriting_impact": "Exposed SMB is a critical deal-breaker for cyber insurance; associated with the largest ransomware claims globally",
        },
        161: {
            "exploits": "Community string brute-force, SNMP reflection DDoS, information disclosure (CVE-2017-6742)",
            "typical_cves": ["CVE-2017-6742", "CVE-2017-6744", "CVE-2018-0161"],
            "typical_cvss": 8.8, "typical_severity": "high",
            "typical_epss": 0.45, "in_kev": True,
            "insurance_risk": "Network reconnaissance and configuration theft; DDoS amplification",
            "underwriting_impact": "Enables attackers to map entire internal network; significant pre-attack intelligence gathering",
        },
        27017: {
            "exploits": "Default no-auth access, Meow ransomware, data theft bots, CVE-2019-2386",
            "typical_cves": ["CVE-2019-2386", "CVE-2015-7882", "CVE-2013-1892"],
            "typical_cvss": 9.8, "typical_severity": "critical",
            "typical_epss": 0.88, "in_kev": False,
            "insurance_risk": "Mass data exfiltration; databases often ransomed directly without deploying malware",
            "underwriting_impact": "Publicly exposed MongoDB frequently results in immediate data breach notification requirements",
        },
        6379: {
            "exploits": "No-auth RCE via SLAVEOF/MODULE, credential-less data dump, cryptomining (CVE-2022-0543)",
            "typical_cves": ["CVE-2022-0543", "CVE-2015-4335", "CVE-2015-8080"],
            "typical_cvss": 10.0, "typical_severity": "critical",
            "typical_epss": 0.90, "in_kev": False,
            "insurance_risk": "Remote code execution without authentication; data theft and server compromise",
            "underwriting_impact": "Redis exposed without auth is near-guaranteed compromise; major breach claim indicator",
        },
        9200: {
            "exploits": "Unauthenticated data access, Groovy script RCE (CVE-2015-1427), Log4Shell via logging",
            "typical_cves": ["CVE-2015-1427", "CVE-2014-3120", "CVE-2021-44228"],
            "typical_cvss": 9.8, "typical_severity": "critical",
            "typical_epss": 0.95, "in_kev": True,
            "insurance_risk": "Full database content exposure; often contains PII, logs, and business data",
            "underwriting_impact": "Elasticsearch exposure frequently triggers data breach notification obligations",
        },
        5432: {
            "exploits": "Credential brute-force, privilege escalation (CVE-2023-5868), SQL injection chaining",
            "typical_cves": ["CVE-2023-5868", "CVE-2019-9193", "CVE-2023-39417"],
            "typical_cvss": 8.8, "typical_severity": "high",
            "typical_epss": 0.40, "in_kev": False,
            "insurance_risk": "Direct access to structured business data; credential reuse attacks",
            "underwriting_impact": "Exposed PostgreSQL significantly increases data breach claim probability",
        },
        1433: {
            "exploits": "SA account brute-force, xp_cmdshell RCE, CVE-2020-0618, lateral movement via linked servers",
            "typical_cves": ["CVE-2020-0618", "CVE-2019-1068", "CVE-2020-1350"],
            "typical_cvss": 9.8, "typical_severity": "critical",
            "typical_epss": 0.80, "in_kev": True,
            "insurance_risk": "Full OS command execution via database; often used for ransomware deployment",
            "underwriting_impact": "MSSQL exposure is a top-tier risk; enables both data theft and ransomware in single attack chain",
        },
        5984: {
            "exploits": "Default admin access, Futon admin panel, RCE via replication (CVE-2017-12635/12636)",
            "typical_cves": ["CVE-2017-12635", "CVE-2017-12636", "CVE-2022-24706"],
            "typical_cvss": 9.8, "typical_severity": "critical",
            "typical_epss": 0.92, "in_kev": True,
            "insurance_risk": "Full database access and remote code execution without authentication",
            "underwriting_impact": "CouchDB often runs unauthenticated; high probability of data compromise",
        },
        7001: {
            "exploits": "Deserialization RCE (CVE-2020-14882, CVE-2023-21839), T3 protocol attacks",
            "typical_cves": ["CVE-2020-14882", "CVE-2023-21839", "CVE-2020-14883"],
            "typical_cvss": 9.8, "typical_severity": "critical",
            "typical_epss": 0.97, "in_kev": True,
            "insurance_risk": "Remote code execution on application server; gateway to internal network",
            "underwriting_impact": "WebLogic has extensive CVE history; exposed instances are actively targeted",
        },
        8888: {
            "exploits": "Unauthenticated code execution, token brute-force, arbitrary file access",
            "typical_cves": ["CVE-2019-9644"],
            "typical_cvss": 9.8, "typical_severity": "critical",
            "typical_epss": 0.50, "in_kev": False,
            "insurance_risk": "Direct server-side code execution; full system compromise",
            "underwriting_impact": "Jupyter Notebook allows arbitrary code execution; critical exposure if public-facing",
        },
        11211: {
            "exploits": "DDoS amplification (51,000x factor), data cache theft, no authentication",
            "typical_cves": ["CVE-2019-11596", "CVE-2019-15026"],
            "typical_cvss": 7.5, "typical_severity": "high",
            "typical_epss": 0.65, "in_kev": False,
            "insurance_risk": "Massive DDoS amplification; cached data exposure including session tokens",
            "underwriting_impact": "Memcached is the largest known DDoS amplification vector; targeted for reflection attacks",
        },
        2375: {
            "exploits": "Unauthenticated container escape, host filesystem access, cryptomining deployment",
            "typical_cves": ["CVE-2019-5736", "CVE-2020-15257"],
            "typical_cvss": 9.8, "typical_severity": "critical",
            "typical_epss": 0.85, "in_kev": True,
            "insurance_risk": "Full host system compromise via container escape; cryptomining and data theft",
            "underwriting_impact": "Unencrypted Docker API is equivalent to root shell access; critical finding",
        },
        2376: {
            "exploits": "Certificate-based auth bypass, container escape if misconfigured",
            "typical_cves": ["CVE-2019-5736"],
            "typical_cvss": 8.6, "typical_severity": "high",
            "typical_epss": 0.40, "in_kev": True,
            "insurance_risk": "Container orchestration compromise; potential host takeover",
            "underwriting_impact": "Encrypted Docker API still poses risk if certificates are weak or leaked",
        },
        9092: {
            "exploits": "Unauthenticated message consumption, data injection, CVE-2023-25194",
            "typical_cves": ["CVE-2023-25194", "CVE-2024-31141"],
            "typical_cvss": 8.8, "typical_severity": "high",
            "typical_epss": 0.30, "in_kev": False,
            "insurance_risk": "Access to real-time data streams; message injection for data manipulation",
            "underwriting_impact": "Kafka often carries sensitive business data streams; exposure enables data theft",
        },
        4848: {
            "exploits": "Default credentials, admin console RCE (CVE-2011-4358), deployment of malicious apps",
            "typical_cves": ["CVE-2011-4358", "CVE-2017-1000028"],
            "typical_cvss": 9.8, "typical_severity": "critical",
            "typical_epss": 0.65, "in_kev": False,
            "insurance_risk": "Full application server control via admin console",
            "underwriting_impact": "GlassFish admin consoles frequently use default credentials; easy target",
        },
        8069: {
            "exploits": "Default admin access, CVE-2023-1434, business logic manipulation",
            "typical_cves": ["CVE-2023-1434", "CVE-2017-10803"],
            "typical_cvss": 8.8, "typical_severity": "high",
            "typical_epss": 0.35, "in_kev": False,
            "insurance_risk": "Full ERP system compromise; financial data theft, invoice fraud",
            "underwriting_impact": "ERP exposure enables financial fraud and business data theft at scale",
        },
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "exposed_services": [],
            "critical_count": 0,
            "issues": [],
        }
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            return result

        exposed = []

        def probe(port, service):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                if s.connect_ex((ip, port)) == 0:
                    entry = {"port": port, "service": service}
                    exploit_info = self.SERVICE_EXPLOIT_MAP.get(port)
                    if exploit_info:
                        entry["exploits"] = exploit_info["exploits"]
                        entry["insurance_risk"] = exploit_info["insurance_risk"]
                        entry["underwriting_impact"] = exploit_info["underwriting_impact"]
                        entry["typical_cves"] = exploit_info.get("typical_cves", [])
                        entry["typical_cvss"] = exploit_info.get("typical_cvss", 0.0)
                        entry["typical_severity"] = exploit_info.get("typical_severity", "critical")
                        entry["typical_epss"] = exploit_info.get("typical_epss", 0.0)
                        entry["in_kev"] = exploit_info.get("in_kev", False)
                    return entry
            except Exception:
                pass
            finally:
                try: s.close()
                except: pass
            return None

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(probe, port, svc): port for port, svc in self.CRITICAL_SERVICES.items()}
            for f in as_completed(futures, timeout=30):
                try:
                    r = f.result()
                    if r:
                        exposed.append(r)
                except Exception:
                    pass

        result["exposed_services"] = sorted(exposed, key=lambda x: x["port"])
        result["critical_count"] = len(exposed)

        for e in exposed:
            insurance_ctx = e.get("insurance_risk", "database/service should never be publicly accessible")
            result["issues"].append(
                f"CRITICAL: {e['service']} (port {e['port']}) exposed to internet — {insurance_ctx}"
            )

        return result


# ---------------------------------------------------------------------------
# 13. Security Policy (security.txt + VDP)
# ---------------------------------------------------------------------------

class SecurityPolicyChecker:
    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "security_txt": {"present": False, "path": None, "has_contact": False, "has_pgp": False},
            "robots_txt": {"present": False, "disallows_count": 0},
            "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result

        # Check security.txt
        for path in ["/.well-known/security.txt", "/security.txt"]:
            try:
                r = requests.get(f"https://{domain}{path}", timeout=5,
                                 headers={"User-Agent": USER_AGENT})
                if r.status_code == 200 and "Contact:" in r.text:
                    result["security_txt"] = {
                        "present": True, "path": path,
                        "has_contact": "Contact:" in r.text,
                        "has_pgp": "Encryption:" in r.text or "-----BEGIN PGP" in r.text,
                    }
                    break
            except Exception:
                pass

        if not result["security_txt"]["present"]:
            result["issues"].append("No security.txt found — no vulnerability disclosure policy (VDP) detected")

        # Check robots.txt
        try:
            r = requests.get(f"https://{domain}/robots.txt", timeout=5,
                             headers={"User-Agent": USER_AGENT})
            if r.status_code == 200:
                disallows = r.text.lower().count("disallow:")
                result["robots_txt"] = {"present": True, "disallows_count": disallows}
        except Exception:
            pass

        return result


# ---------------------------------------------------------------------------
# 14. DNSBL / IP Reputation
# ---------------------------------------------------------------------------

class DNSBLChecker:
    IP_DNSBLS = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org",
        "dnsbl-1.uceprotect.net",
    ]
    DOMAIN_DNSBLS = [
        "dbl.spamhaus.org",
        "uribl.com",
    ]

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "ip_listings": [],
            "domain_listings": [],
            "blacklisted": False,
            "issues": [],
        }
        if not DNS_AVAILABLE:
            result["status"] = "error"; return result

        try:
            ip = socket.gethostbyname(domain)
            reversed_ip = ".".join(reversed(ip.split(".")))

            # IP-based checks
            for dnsbl in self.IP_DNSBLS:
                try:
                    dns.resolver.resolve(f"{reversed_ip}.{dnsbl}", "A", lifetime=5)
                    result["ip_listings"].append(dnsbl)
                except Exception:
                    pass

            # Domain-based checks
            for dnsbl in self.DOMAIN_DNSBLS:
                try:
                    dns.resolver.resolve(f"{domain}.{dnsbl}", "A", lifetime=5)
                    result["domain_listings"].append(dnsbl)
                except Exception:
                    pass

            all_listings = result["ip_listings"] + result["domain_listings"]
            result["blacklisted"] = len(all_listings) > 0

            if all_listings:
                result["issues"].append(
                    f"Domain/IP listed on {len(all_listings)} blacklist(s): {', '.join(all_listings)}"
                )

        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)

        return result


# ---------------------------------------------------------------------------
# 15. Technology Stack & EOL/CVE Check
# ---------------------------------------------------------------------------

class TechStackChecker:
    EOL_SIGNATURES = {
        "PHP/5": {"risk": "critical", "note": "PHP 5.x — end-of-life Dec 2018, no security patches"},
        "PHP/7.0": {"risk": "critical", "note": "PHP 7.0 — end-of-life Dec 2019"},
        "PHP/7.1": {"risk": "critical", "note": "PHP 7.1 — end-of-life Dec 2019"},
        "PHP/7.2": {"risk": "high", "note": "PHP 7.2 — end-of-life Nov 2020"},
        "PHP/7.3": {"risk": "high", "note": "PHP 7.3 — end-of-life Dec 2021"},
        "PHP/7.4": {"risk": "medium", "note": "PHP 7.4 — end-of-life Nov 2022"},
        "ASP.NET/1": {"risk": "critical", "note": "ASP.NET 1.x — end-of-life"},
        "ASP.NET/2": {"risk": "critical", "note": "ASP.NET 2.0 — end-of-life Jul 2011"},
        "ASP.NET/3": {"risk": "critical", "note": "ASP.NET 3.x — end-of-life"},
        "Apache/2.2": {"risk": "high", "note": "Apache 2.2 — end-of-life Dec 2017"},
        "nginx/1.14": {"risk": "medium", "note": "nginx 1.14 — legacy stable branch"},
        "nginx/1.12": {"risk": "high", "note": "nginx 1.12 — end-of-life"},
        "nginx/1.10": {"risk": "critical", "note": "nginx 1.10 — end-of-life"},
        "OpenSSL/1.0": {"risk": "critical", "note": "OpenSSL 1.0.x — end-of-life Dec 2019"},
        "OpenSSL/1.1.0": {"risk": "high", "note": "OpenSSL 1.1.0 — end-of-life Sep 2019"},
    }

    CMS_SIGNATURES = {
        "WordPress": ["/wp-content/", "/wp-includes/", "wp-json"],
        "Joomla": ["/components/com_", "Joomla!", "/media/jui/"],
        "Drupal": ["/sites/default/", "Drupal.settings", "/modules/system/"],
        "Wix": ["wixsite.com", "wix-code"],
        "Shopify": ["cdn.shopify.com", "Shopify.theme"],
        "Squarespace": ["squarespace.com", "data-squarespace"],
        "Magento": ["Mage.Cookies", "/skin/frontend/", "magento"],
        "PrestaShop": ["prestashop", "/themes/default-bootstrap/"],
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "server_software": [],
            "cms": {"detected": None, "version": None},
            "eol_detected": [],
            "issues": [],
            "score": 100,
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            body = r.text[:100000]
            all_headers_str = str(r.headers)

            # Collect disclosed software versions from headers
            for h in ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"]:
                if h in r.headers:
                    result["server_software"].append(f"{h}: {r.headers[h]}")

            # Check for EOL versions
            combined = (all_headers_str + body).lower()
            for sig, info in self.EOL_SIGNATURES.items():
                if sig.lower() in combined:
                    result["eol_detected"].append({**info, "software": sig})
                    result["issues"].append(f"EOL software detected: {info['note']}")
                    if info["risk"] == "critical":
                        result["score"] -= 40
                    elif info["risk"] == "high":
                        result["score"] -= 25
                    elif info["risk"] == "medium":
                        result["score"] -= 10

            # CMS detection
            for cms, sigs in self.CMS_SIGNATURES.items():
                if any(sig in body or sig in all_headers_str for sig in sigs):
                    version = None
                    if cms == "WordPress":
                        m = re.search(r"wp-includes/js/wp-emoji-release\.min\.js\?ver=([\d.]+)", body)
                        if not m:
                            m = re.search(r'content="WordPress ([\d.]+)"', body)
                        version = m.group(1) if m else None
                    result["cms"] = {"detected": cms, "version": version}
                    break

            result["score"] = max(0, result["score"])

        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 16. Breach / Credential Exposure (HIBP)
# ---------------------------------------------------------------------------

class BreachChecker:
    HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"

    def check(self, domain: str, api_key: Optional[str] = None) -> dict:
        result = {
            "status": "completed", "breach_count": 0, "breaches": [],
            "most_recent_breach": None, "data_classes": [], "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; result["error"] = "requests not installed"; return result
        try:
            headers = {"User-Agent": USER_AGENT}
            if api_key:
                headers["hibp-api-key"] = api_key
            r = requests.get(self.HIBP_URL, params={"domain": domain},
                             headers=headers, timeout=DEFAULT_TIMEOUT)
            if r.status_code == 200:
                breaches = r.json()
                if breaches:
                    result["breach_count"] = len(breaches)
                    dates, all_classes = [], set()
                    for b in breaches:
                        dates.append(b.get("BreachDate", ""))
                        all_classes.update(b.get("DataClasses", []))
                        result["breaches"].append({
                            "name": b.get("Name"),
                            "date": b.get("BreachDate"),
                            "pwn_count": b.get("PwnCount"),
                            "data_classes": b.get("DataClasses", []),
                        })
                    dates = [d for d in dates if d]
                    if dates:
                        result["most_recent_breach"] = max(dates)
                    result["data_classes"] = sorted(all_classes)
                    result["issues"].append(f"Domain found in {len(breaches)} known data breach(es)")
            elif r.status_code == 401:
                result["status"] = "requires_api_key"
                result["error"] = "HIBP API key required"
            elif r.status_code == 404:
                pass
            else:
                result["status"] = "error"
                result["error"] = f"HIBP API returned {r.status_code}"
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 17. HTTP Security Headers
# ---------------------------------------------------------------------------

class HTTPHeaderChecker:
    HEADERS = {
        "content-security-policy": ("Content-Security-Policy", 20),
        "x-frame-options": ("X-Frame-Options", 15),
        "x-content-type-options": ("X-Content-Type-Options", 15),
        "strict-transport-security": ("Strict-Transport-Security", 20),
        "referrer-policy": ("Referrer-Policy", 15),
        "permissions-policy": ("Permissions-Policy", 15),
    }

    def check(self, domain: str) -> dict:
        result = {"status": "completed", "headers": {}, "score": 0, "issues": []}
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; result["error"] = "requests not installed"; return result
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            total_weight, earned = 0, 0
            for key, (label, weight) in self.HEADERS.items():
                present = key in headers_lower
                result["headers"][label] = {"present": present, "value": headers_lower.get(key)}
                total_weight += weight
                if present:
                    earned += weight
                else:
                    result["issues"].append(f"Missing security header: {label}")
            result["score"] = round((earned / total_weight) * 100) if total_weight else 0
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 18. Website Security Basics
# ---------------------------------------------------------------------------

class WebsiteSecurityChecker:
    CMS_SIGNATURES = {
        "WordPress": ["/wp-content/", "/wp-includes/", "wp-json"],
        "Joomla": ["/components/com_", "Joomla!", "/media/jui/"],
        "Drupal": ["/sites/default/", "Drupal.settings", "/modules/system/"],
        "Wix": ["wixsite.com", "X-Wix-"],
        "Shopify": ["cdn.shopify.com", "Shopify.theme"],
        "Squarespace": ["squarespace.com", "data-squarespace"],
        "Magento": ["Mage.Cookies", "/skin/frontend/"],
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed", "https_enforced": False,
            "cookies": {"secure": True, "httponly": True, "samesite": True, "details": []},
            "mixed_content": False, "cms": {"detected": None, "version": None},
            "issues": [], "score": 0,
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; result["error"] = "requests not installed"; return result
        try:
            result["https_enforced"] = self._check_https_redirect(domain)
            result["cookies"] = self._check_cookies(domain)
            result["mixed_content"] = self._check_mixed_content(domain)
            result["cms"] = self._detect_cms(domain)
            result["score"], result["issues"] = self._calculate_score(
                result["https_enforced"], result["cookies"], result["mixed_content"])
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result

    def _check_https_redirect(self, domain: str) -> bool:
        try:
            r = requests.get(f"http://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            return r.url.startswith("https://")
        except Exception:
            return False

    def _check_cookies(self, domain: str) -> dict:
        info = {"secure": True, "httponly": True, "samesite": True, "details": []}
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            for cookie in r.cookies:
                detail = {
                    "name": cookie.name, "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("HttpOnly") or
                                getattr(cookie, "_rest", {}).get("HttpOnly") is not None,
                    "samesite": cookie.get_nonstandard_attr("SameSite"),
                }
                info["details"].append(detail)
                if not detail["secure"]:
                    info["secure"] = False
                if not detail["httponly"]:
                    info["httponly"] = False
                if not detail["samesite"]:
                    info["samesite"] = False
        except Exception:
            pass
        return info

    def _check_mixed_content(self, domain: str) -> bool:
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            return bool(re.search(r'<(?:script|img|link|iframe)[^>]+src=["\']http://', r.text[:50000], re.I))
        except Exception:
            return False

    def _detect_cms(self, domain: str) -> dict:
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            combined = r.text[:100000] + str(r.headers)
            for cms, sigs in self.CMS_SIGNATURES.items():
                if any(sig in combined for sig in sigs):
                    version = None
                    if cms == "WordPress":
                        m = re.search(r"ver=([\d.]+)", r.text)
                        version = m.group(1) if m else None
                    return {"detected": cms, "version": version}
        except Exception:
            pass
        return {"detected": None, "version": None}

    def _calculate_score(self, https, cookies, mixed) -> tuple:
        score, issues = 100, []
        if not https:
            score -= 40; issues.append("HTTPS not enforced — HTTP does not redirect to HTTPS")
        if not cookies.get("secure", True):
            score -= 20; issues.append("Cookies missing Secure flag")
        if not cookies.get("httponly", True):
            score -= 15; issues.append("Cookies missing HttpOnly flag — XSS risk")
        if mixed:
            score -= 25; issues.append("Mixed content detected")
        return max(0, score), issues


# ---------------------------------------------------------------------------
# 19. Payment Security
# ---------------------------------------------------------------------------

class PaymentSecurityChecker:
    PAYMENT_PROVIDERS = {
        "Stripe": ["js.stripe.com", "stripe.com/v3"],
        "PayPal": ["paypalobjects.com", "paypal.com/sdk"],
        "PayFast": ["payfast.co.za"],
        "PayGate": ["paygate.co.za"],
        "Peach Payments": ["peachpayments.com"],
        "Ozow": ["ozow.com"],
        "Square": ["squareup.com", "squarecdnjs.net"],
        "Braintree": ["braintreepayments.com", "braintree-api.com"],
        "Adyen": ["adyen.com"],
    }
    PAYMENT_PATHS = ["/cart", "/checkout", "/payment", "/pay", "/order",
                     "/shop/cart", "/basket", "/buy", "/purchase"]

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "has_payment_page": False,
            "payment_provider": None,
            "self_hosted_payment_form": False,
            "payment_page_https": False,
            "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result

        payment_page_found = None
        for path in self.PAYMENT_PATHS:
            try:
                r = requests.get(f"https://{domain}{path}", timeout=4,
                                 allow_redirects=True, headers={"User-Agent": USER_AGENT})
                if r.status_code == 200:
                    body = r.text[:50000].lower()
                    # Check if this looks like a payment page
                    payment_keywords = ["credit card", "card number", "checkout", "payment",
                                        "billing", "cvv", "expiry", "pay now", "place order"]
                    if any(kw in body for kw in payment_keywords):
                        payment_page_found = (path, r.url, r.text[:50000])
                        break
            except Exception:
                pass

        if payment_page_found:
            path, final_url, body = payment_page_found
            result["has_payment_page"] = True
            result["payment_page_https"] = final_url.startswith("https://")

            # Check for third-party payment providers
            for provider, scripts in self.PAYMENT_PROVIDERS.items():
                if any(s in body.lower() for s in scripts):
                    result["payment_provider"] = provider
                    break

            # Detect self-hosted card form (high risk)
            if not result["payment_provider"]:
                if re.search(r'<input[^>]+(?:card.?number|cardnumber|cc.?num)', body, re.I):
                    result["self_hosted_payment_form"] = True
                    result["issues"].append(
                        "Self-hosted payment card form detected — PCI DSS compliance risk. "
                        "Card data may be processed directly on your servers."
                    )

            if not result["payment_page_https"]:
                result["issues"].append("Payment page not served over HTTPS — critical security risk")

        return result


# ---------------------------------------------------------------------------
# 20. Shodan InternetDB Vulnerability Checker (free, no API key)
# ---------------------------------------------------------------------------

class ShodanVulnChecker:
    """
    Queries Shodan's free InternetDB for CVEs associated with the domain's IP.
    Enriches top CVEs with CVSS scores from NVD, EPSS from FIRST.org, and
    checks against the CISA KEV (Known Exploited Vulnerabilities) catalog.
    """
    INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
    NVD_URL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_URL       = "https://api.first.org/data/v1/epss"
    KEV_URL        = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def _cvss_severity(self, score: float) -> str:
        if score >= 9.0: return "critical"
        if score >= 7.0: return "high"
        if score >= 4.0: return "medium"
        return "low"

    def _fetch_cvss(self, cve_id: str) -> dict:
        try:
            r = requests.get(self.NVD_URL, params={"cveId": cve_id},
                             headers={"User-Agent": USER_AGENT}, timeout=8)
            if r.status_code != 200:
                return {}
            data = r.json()
            vuln = data.get("vulnerabilities", [{}])[0].get("cve", {})
            desc = next((d["value"] for d in vuln.get("descriptions", [])
                         if d.get("lang") == "en"), "")
            metrics = vuln.get("metrics", {})
            # Try CVSS v3.1, then v3.0, then v2
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                m = metrics.get(key)
                if m:
                    base = m[0].get("cvssData", {})
                    score = base.get("baseScore", 0.0)
                    return {
                        "cve_id": cve_id,
                        "description": desc[:200],
                        "cvss_score": score,
                        "severity": self._cvss_severity(score),
                        "vector": base.get("vectorString", ""),
                    }
            return {"cve_id": cve_id, "description": desc[:200], "cvss_score": 0.0, "severity": "unknown", "vector": ""}
        except Exception:
            return {"cve_id": cve_id, "description": "", "cvss_score": 0.0, "severity": "unknown", "vector": ""}

    def _fetch_epss_batch(self, cve_ids: list) -> dict:
        """Batch-query FIRST.org EPSS API. Returns {cve_id: {epss, percentile}}."""
        if not cve_ids:
            return {}
        try:
            r = requests.get(self.EPSS_URL,
                             params={"cve": ",".join(cve_ids)},
                             headers={"User-Agent": USER_AGENT}, timeout=10)
            if r.status_code != 200:
                return {}
            data = r.json().get("data", [])
            return {
                item["cve"]: {
                    "epss_score": float(item.get("epss", 0)),
                    "epss_percentile": float(item.get("percentile", 0)),
                }
                for item in data
            }
        except Exception:
            return {}

    def _fetch_kev_set(self) -> dict:
        """Fetch CISA KEV catalog. Returns {cve_id: {due_date, ...}}."""
        try:
            r = requests.get(self.KEV_URL,
                             headers={"User-Agent": USER_AGENT}, timeout=12)
            if r.status_code != 200:
                return {}
            vulns = r.json().get("vulnerabilities", [])
            return {
                v["cveID"]: {
                    "kev_due_date": v.get("dueDate", ""),
                    "kev_ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                }
                for v in vulns if "cveID" in v
            }
        except Exception:
            return {}

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "ip": None,
            "open_ports": [],
            "cves": [],
            "cpe_list": [],
            "tags": [],
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "max_epss": 0.0,
            "avg_epss": 0.0,
            "high_epss_count": 0,
            "kev_count": 0,
            "score": 100,
            "issues": [],
        }
        try:
            ip = socket.gethostbyname(domain)
            result["ip"] = ip

            r = requests.get(self.INTERNETDB_URL.format(ip=ip),
                             headers={"User-Agent": USER_AGENT}, timeout=10)
            if r.status_code == 404:
                result["status"] = "completed"
                return result
            if r.status_code != 200:
                result["status"] = "error"
                return result

            data = r.json()
            result["open_ports"] = data.get("ports", [])
            result["cpe_list"]   = data.get("cpes", [])[:10]
            result["tags"]       = data.get("tags", [])

            raw_cves = data.get("vulns", [])[:20]  # cap at 20 CVEs

            # Enrich top 10 CVEs with CVSS via NVD (rate-limited to avoid 503)
            enriched = []
            for cve_id in raw_cves[:10]:
                info = self._fetch_cvss(cve_id)
                if info:
                    enriched.append(info)
                    sev = info.get("severity", "unknown")
                    if sev == "critical":   result["critical_count"] += 1
                    elif sev == "high":     result["high_count"] += 1
                    elif sev == "medium":   result["medium_count"] += 1
                    else:                   result["low_count"] += 1

            # Count severity for any CVEs beyond the enriched 10
            for cve_id in raw_cves[10:]:
                result["medium_count"] += 1  # conservative estimate

            # --- EPSS enrichment (batch query all CVE IDs) ---
            all_cve_ids = [c.get("cve_id") for c in enriched if c.get("cve_id")]
            epss_data = self._fetch_epss_batch(all_cve_ids)
            for cve in enriched:
                cve_id = cve.get("cve_id", "")
                if cve_id in epss_data:
                    cve["epss_score"] = epss_data[cve_id]["epss_score"]
                    cve["epss_percentile"] = epss_data[cve_id]["epss_percentile"]
                else:
                    cve["epss_score"] = None
                    cve["epss_percentile"] = None

            # --- CISA KEV enrichment ---
            kev_data = self._fetch_kev_set()
            for cve in enriched:
                cve_id = cve.get("cve_id", "")
                if cve_id in kev_data:
                    cve["kev_exploited"] = True
                    cve["kev_due_date"] = kev_data[cve_id].get("kev_due_date", "")
                    cve["kev_ransomware"] = kev_data[cve_id].get("kev_ransomware", "Unknown")
                else:
                    cve["kev_exploited"] = False
                    cve["kev_due_date"] = None
                    cve["kev_ransomware"] = None

            # --- Aggregate EPSS / KEV stats ---
            epss_scores = [c["epss_score"] for c in enriched if c.get("epss_score") is not None]
            result["max_epss"] = round(max(epss_scores), 4) if epss_scores else 0.0
            result["avg_epss"] = round(sum(epss_scores) / len(epss_scores), 4) if epss_scores else 0.0
            result["high_epss_count"] = sum(1 for s in epss_scores if s >= 0.1)
            result["kev_count"] = sum(1 for c in enriched if c.get("kev_exploited"))

            result["cves"] = enriched

            # Build issues
            if result["critical_count"] > 0:
                result["issues"].append(
                    f"CRITICAL: {result['critical_count']} critical CVE(s) found on this IP — patch immediately"
                )
            if result["high_count"] > 0:
                result["issues"].append(
                    f"{result['high_count']} high-severity CVE(s) detected — review and patch urgently"
                )
            if result["medium_count"] > 0:
                result["issues"].append(
                    f"{result['medium_count']} medium-severity CVE(s) detected — schedule patching"
                )
            if result["kev_count"] > 0:
                result["issues"].append(
                    f"CRITICAL: {result['kev_count']} CVE(s) listed in CISA KEV — confirmed actively exploited in the wild"
                )
            if result["high_epss_count"] > 0:
                result["issues"].append(
                    f"{result['high_epss_count']} CVE(s) with EPSS ≥ 10% — high probability of near-term exploitation"
                )

            # Score: 100 minus penalty per severity + EPSS/KEV penalties
            penalty = (result["critical_count"] * 30 +
                       result["high_count"] * 15 +
                       result["medium_count"] * 5)
            # Extra penalty for KEV-listed CVEs (confirmed exploitation)
            penalty += result["kev_count"] * 25
            # Extra penalty for high-EPSS CVEs (likely to be exploited)
            penalty += result["high_epss_count"] * 10
            result["score"] = max(0, 100 - min(100, penalty))

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

        return result


# ---------------------------------------------------------------------------
# 21. External IP Discovery & Per-IP Vulnerability Scanner
# ---------------------------------------------------------------------------

class ExternalIPDiscoveryChecker:
    """
    Discovers all external IP addresses linked to a domain (A, AAAA, MX, NS,
    SPF, subdomains), enriches each with geo/ASN info from ip-api.com, then
    scans each IP through Shodan InternetDB for CVEs (enriched with CVSS,
    EPSS, and CISA KEV).
    """
    INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
    NVD_URL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_URL       = "https://api.first.org/data/v1/epss"
    KEV_URL        = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    IP_API_BATCH   = "http://ip-api.com/batch"
    CRT_SH_URL     = "https://crt.sh/?q=%.{domain}&output=json"
    MAX_IPS_TO_SCAN = 20
    MAX_SUBDOMAINS  = 30

    # ---- IP Discovery helpers ------------------------------------------------

    def _resolve_a(self, domain: str) -> dict:
        """Resolve A and AAAA records for a hostname. Returns {ip: [sources]}."""
        ips = {}
        for rtype in ("A", "AAAA"):
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                for r in answers:
                    ip = str(r)
                    ips.setdefault(ip, [])
                    ips[ip].append(f"{rtype} record")
            except Exception:
                pass
        return ips

    def _discover_mx_ips(self, domain: str) -> dict:
        ips = {}
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=5)
            for mx in answers:
                host = str(mx.exchange).rstrip(".")
                for rtype in ("A", "AAAA"):
                    try:
                        a = dns.resolver.resolve(host, rtype, lifetime=5)
                        for r in a:
                            ip = str(r)
                            ips.setdefault(ip, [])
                            ips[ip].append(f"MX: {host}")
                    except Exception:
                        pass
        except Exception:
            pass
        return ips

    def _discover_ns_ips(self, domain: str) -> dict:
        ips = {}
        try:
            answers = dns.resolver.resolve(domain, "NS", lifetime=5)
            for ns in answers:
                host = str(ns.target).rstrip(".")
                try:
                    a = dns.resolver.resolve(host, "A", lifetime=5)
                    for r in a:
                        ip = str(r)
                        ips.setdefault(ip, [])
                        ips[ip].append(f"NS: {host}")
                except Exception:
                    pass
        except Exception:
            pass
        return ips

    def _parse_spf_ips(self, domain: str) -> dict:
        ips = {}
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
            for txt in answers:
                val = str(txt).strip('"')
                if not val.startswith("v=spf1"):
                    continue
                parts = val.split()
                for p in parts:
                    p_lower = p.lower()
                    if p_lower.startswith("ip4:") or p_lower.startswith("+ip4:"):
                        addr = p.split(":", 1)[1].split("/")[0]
                        ips.setdefault(addr, []).append("SPF ip4")
                    elif p_lower.startswith("ip6:") or p_lower.startswith("+ip6:"):
                        addr = p.split(":", 1)[1].split("/")[0]
                        ips.setdefault(addr, []).append("SPF ip6")
        except Exception:
            pass
        return ips

    def _discover_subdomain_ips(self, domain: str) -> dict:
        ips = {}
        if not REQUESTS_AVAILABLE:
            return ips
        try:
            r = requests.get(
                self.CRT_SH_URL.format(domain=domain),
                timeout=15, headers={"User-Agent": USER_AGENT}
            )
            if r.status_code != 200:
                return ips
            entries = r.json()
            seen = set()
            subs = []
            for entry in entries:
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lower().lstrip("*.")
                    if name and name != domain and domain in name and name not in seen:
                        seen.add(name)
                        subs.append(name)
                        if len(subs) >= self.MAX_SUBDOMAINS:
                            break
                if len(subs) >= self.MAX_SUBDOMAINS:
                    break

            def resolve_sub(sub):
                results = {}
                try:
                    a = dns.resolver.resolve(sub, "A", lifetime=3)
                    for rec in a:
                        ip = str(rec)
                        results.setdefault(ip, []).append(f"subdomain: {sub}")
                except Exception:
                    pass
                return results

            with ThreadPoolExecutor(max_workers=10) as ex:
                futures = {ex.submit(resolve_sub, s): s for s in subs}
                for f in as_completed(futures, timeout=30):
                    try:
                        sub_ips = f.result()
                        for ip, sources in sub_ips.items():
                            ips.setdefault(ip, []).extend(sources)
                    except Exception:
                        pass
        except Exception:
            pass
        return ips

    # ---- IP Enrichment -------------------------------------------------------

    def _enrich_ips_geo(self, ip_list: list) -> dict:
        """Batch query ip-api.com for geo/ASN info. Returns {ip: info_dict}."""
        enriched = {}
        if not REQUESTS_AVAILABLE or not ip_list:
            return enriched
        # ip-api.com batch supports up to 100 IPs
        batch = [{"query": ip, "fields": "query,org,as,isp,country,city,hosting,reverse"}
                 for ip in ip_list[:100]]
        try:
            r = requests.post(self.IP_API_BATCH, json=batch, timeout=10,
                              headers={"User-Agent": USER_AGENT})
            if r.status_code == 200:
                for item in r.json():
                    ip = item.get("query", "")
                    enriched[ip] = {
                        "org": item.get("org", ""),
                        "asn": item.get("as", "").split()[0] if item.get("as") else "",
                        "isp": item.get("isp", ""),
                        "country": item.get("country", ""),
                        "city": item.get("city", ""),
                        "hosting": item.get("hosting", False),
                        "reverse_dns": item.get("reverse", ""),
                    }
        except Exception:
            pass
        return enriched

    # ---- Per-IP Vulnerability Scanning (reuse ShodanVulnChecker logic) -------

    def _cvss_severity(self, score: float) -> str:
        if score >= 9.0: return "critical"
        if score >= 7.0: return "high"
        if score >= 4.0: return "medium"
        return "low"

    def _fetch_cvss(self, cve_id: str) -> dict:
        try:
            r = requests.get(self.NVD_URL, params={"cveId": cve_id},
                             headers={"User-Agent": USER_AGENT}, timeout=8)
            if r.status_code != 200:
                return {}
            data = r.json()
            vuln = data.get("vulnerabilities", [{}])[0].get("cve", {})
            desc = next((d["value"] for d in vuln.get("descriptions", [])
                         if d.get("lang") == "en"), "")
            metrics = vuln.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                m = metrics.get(key)
                if m:
                    base = m[0].get("cvssData", {})
                    score = base.get("baseScore", 0.0)
                    return {
                        "cve_id": cve_id, "description": desc[:200],
                        "cvss_score": score, "severity": self._cvss_severity(score),
                        "vector": base.get("vectorString", ""),
                    }
            return {"cve_id": cve_id, "description": desc[:200], "cvss_score": 0.0,
                    "severity": "unknown", "vector": ""}
        except Exception:
            return {"cve_id": cve_id, "description": "", "cvss_score": 0.0,
                    "severity": "unknown", "vector": ""}

    def _fetch_epss_batch(self, cve_ids: list) -> dict:
        if not cve_ids:
            return {}
        try:
            r = requests.get(self.EPSS_URL, params={"cve": ",".join(cve_ids)},
                             headers={"User-Agent": USER_AGENT}, timeout=10)
            if r.status_code != 200:
                return {}
            data = r.json().get("data", [])
            return {
                item["cve"]: {
                    "epss_score": float(item.get("epss", 0)),
                    "epss_percentile": float(item.get("percentile", 0)),
                }
                for item in data
            }
        except Exception:
            return {}

    def _fetch_kev_set(self) -> dict:
        try:
            r = requests.get(self.KEV_URL, headers={"User-Agent": USER_AGENT}, timeout=12)
            if r.status_code != 200:
                return {}
            vulns = r.json().get("vulnerabilities", [])
            return {
                v["cveID"]: {
                    "kev_due_date": v.get("dueDate", ""),
                    "kev_ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                }
                for v in vulns if "cveID" in v
            }
        except Exception:
            return {}

    def _build_ip_remediation(self, vuln: dict) -> str:
        """Generate remediation text for a single IP based on its vulnerability profile."""
        parts = []
        if vuln.get("kev_count", 0) > 0:
            parts.append(f"URGENT: {vuln['kev_count']} CVE(s) confirmed exploited in the wild (CISA KEV) — patch within 48 hours.")
        if vuln.get("critical_count", 0) > 0:
            parts.append(f"Patch {vuln['critical_count']} critical CVE(s) immediately.")
        if vuln.get("high_count", 0) > 0:
            parts.append(f"Review and patch {vuln['high_count']} high-severity CVE(s) within 30 days.")
        if vuln.get("medium_count", 0) > 0:
            parts.append(f"Schedule patching of {vuln['medium_count']} medium-severity CVE(s).")
        high_epss = sum(1 for c in vuln.get("cves", []) if (c.get("epss_score") or 0) >= 0.1)
        if high_epss > 0:
            parts.append(f"Prioritise {high_epss} CVE(s) with EPSS ≥ 10% — high exploitation probability.")
        # Check for risky open ports
        risky_ports = {21: "FTP", 23: "Telnet", 3306: "MySQL", 3389: "RDP",
                       5900: "VNC", 27017: "MongoDB", 6379: "Redis"}
        exposed = [f"{risky_ports[p]} ({p})" for p in vuln.get("open_ports", []) if p in risky_ports]
        if exposed:
            parts.append(f"Restrict access to exposed services: {', '.join(exposed)}.")
        if not parts and vuln.get("cve_count", 0) == 0:
            return "No known vulnerabilities detected. Continue monitoring."
        if not parts:
            return "Low-severity issues only. Schedule routine review."
        return " ".join(parts)

    def _calculate_ip_risk_score(self, vuln: dict) -> int:
        """Calculate 0-100 risk score for a single IP (100=clean, 0=critical)."""
        penalty = 0
        penalty += vuln.get("critical_count", 0) * 30
        penalty += vuln.get("high_count", 0) * 15
        penalty += vuln.get("medium_count", 0) * 5
        penalty += vuln.get("kev_count", 0) * 25
        high_epss = sum(1 for c in vuln.get("cves", []) if (c.get("epss_score") or 0) >= 0.1)
        penalty += high_epss * 10
        return max(0, 100 - min(100, penalty))

    def _ip_risk_label(self, score: int) -> str:
        if score >= 80: return "Low"
        if score >= 50: return "Medium"
        if score >= 20: return "High"
        return "Critical"

    def _scan_ip_vulns(self, ip: str, kev_data: dict) -> dict:
        """Query Shodan InternetDB for a single IP and enrich CVEs."""
        vuln_result = {
            "open_ports": [], "cve_count": 0, "cves": [],
            "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
            "max_cvss": 0.0, "max_epss": 0.0, "kev_count": 0,
            "risk_score": 100, "risk_label": "Low", "remediation": "",
        }
        try:
            r = requests.get(self.INTERNETDB_URL.format(ip=ip),
                             headers={"User-Agent": USER_AGENT}, timeout=8)
            if r.status_code == 404:
                return vuln_result
            if r.status_code != 200:
                return vuln_result
            data = r.json()
            vuln_result["open_ports"] = data.get("ports", [])
            raw_cves = data.get("vulns", [])
            vuln_result["cve_count"] = len(raw_cves)

            # Enrich top 5 CVEs per IP (keep scan time reasonable)
            enriched = []
            for cve_id in raw_cves[:5]:
                info = self._fetch_cvss(cve_id)
                if info:
                    enriched.append(info)
                    sev = info.get("severity", "unknown")
                    if sev == "critical":   vuln_result["critical_count"] += 1
                    elif sev == "high":     vuln_result["high_count"] += 1
                    elif sev == "medium":   vuln_result["medium_count"] += 1
                    else:                   vuln_result["low_count"] += 1

            # Count remaining CVEs conservatively
            vuln_result["medium_count"] += max(0, len(raw_cves) - 5)

            # EPSS enrichment
            cve_ids = [c["cve_id"] for c in enriched if c.get("cve_id")]
            epss_data = self._fetch_epss_batch(cve_ids)
            for cve in enriched:
                cid = cve.get("cve_id", "")
                if cid in epss_data:
                    cve["epss_score"] = epss_data[cid]["epss_score"]
                    cve["epss_percentile"] = epss_data[cid]["epss_percentile"]
                else:
                    cve["epss_score"] = None
                    cve["epss_percentile"] = None

            # KEV enrichment
            for cve in enriched:
                cid = cve.get("cve_id", "")
                if cid in kev_data:
                    cve["kev_exploited"] = True
                    cve["kev_due_date"] = kev_data[cid].get("kev_due_date", "")
                    cve["kev_ransomware"] = kev_data[cid].get("kev_ransomware", "Unknown")
                else:
                    cve["kev_exploited"] = False
                    cve["kev_due_date"] = None
                    cve["kev_ransomware"] = None

            vuln_result["cves"] = enriched

            # Aggregate stats
            cvss_scores = [c["cvss_score"] for c in enriched if c.get("cvss_score")]
            epss_scores = [c["epss_score"] for c in enriched if c.get("epss_score") is not None]
            vuln_result["max_cvss"] = round(max(cvss_scores), 1) if cvss_scores else 0.0
            vuln_result["max_epss"] = round(max(epss_scores), 4) if epss_scores else 0.0
            vuln_result["kev_count"] = sum(1 for c in enriched if c.get("kev_exploited"))

            # Per-IP risk score and remediation
            vuln_result["risk_score"] = self._calculate_ip_risk_score(vuln_result)
            vuln_result["risk_label"] = self._ip_risk_label(vuln_result["risk_score"])
            vuln_result["remediation"] = self._build_ip_remediation(vuln_result)

        except Exception:
            pass
        return vuln_result

    # ---- Main check ----------------------------------------------------------

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "total_unique_ips": 0,
            "ipv4_count": 0,
            "ipv6_count": 0,
            "ip_addresses": [],
            "aggregate_vulns": {
                "total_cves": 0, "critical_count": 0, "high_count": 0,
                "medium_count": 0, "max_cvss": 0.0, "max_epss": 0.0,
                "kev_count": 0, "ips_with_vulns": 0,
            },
            "unique_asns": 0,
            "unique_countries": 0,
            "issues": [],
            "score": 100,
        }
        try:
            # --- Phase 1: Discover all IPs ---
            all_ips = {}  # {ip: [list of sources]}

            # Get primary domain IP to skip (already scanned by ShodanVulnChecker)
            primary_ip = None
            try:
                primary_ip = socket.gethostbyname(domain)
            except Exception:
                pass

            # Collect IPs from all sources
            for discovery_fn in (
                lambda: self._resolve_a(domain),
                lambda: self._discover_mx_ips(domain),
                lambda: self._discover_ns_ips(domain),
                lambda: self._parse_spf_ips(domain),
                lambda: self._discover_subdomain_ips(domain),
            ):
                try:
                    found = discovery_fn()
                    for ip, sources in found.items():
                        all_ips.setdefault(ip, []).extend(sources)
                except Exception:
                    pass

            # Deduplicate sources per IP
            for ip in all_ips:
                all_ips[ip] = list(dict.fromkeys(all_ips[ip]))

            unique_ips = list(all_ips.keys())
            result["total_unique_ips"] = len(unique_ips)
            result["ipv4_count"] = sum(1 for ip in unique_ips if ":" not in ip)
            result["ipv6_count"] = sum(1 for ip in unique_ips if ":" in ip)

            # --- Phase 2: Geo/ASN enrichment ---
            # Only enrich IPv4 (ip-api.com doesn't reliably handle IPv6)
            ipv4_list = [ip for ip in unique_ips if ":" not in ip]
            geo_data = self._enrich_ips_geo(ipv4_list)

            # --- Phase 3: Per-IP vulnerability scanning ---
            # Fetch KEV once for all IPs
            kev_data = self._fetch_kev_set()

            # Select IPs to scan (skip primary, cap at MAX_IPS_TO_SCAN)
            ips_to_scan = [ip for ip in ipv4_list if ip != primary_ip][:self.MAX_IPS_TO_SCAN]

            ip_vuln_results = {}
            for ip in ips_to_scan:
                ip_vuln_results[ip] = self._scan_ip_vulns(ip, kev_data)
                time.sleep(0.3)  # rate-limit Shodan queries

            # --- Phase 4: Build result objects ---
            ip_entries = []
            agg = result["aggregate_vulns"]
            asns = set()
            countries = set()
            no_rdns_count = 0
            residential_found = False

            for ip in unique_ips:
                geo = geo_data.get(ip, {})
                vuln = ip_vuln_results.get(ip, {})

                entry = {
                    "ip": ip,
                    "version": "ipv6" if ":" in ip else "ipv4",
                    "sources": all_ips[ip],
                    "reverse_dns": geo.get("reverse_dns", ""),
                    "org": geo.get("org", ""),
                    "asn": geo.get("asn", ""),
                    "isp": geo.get("isp", ""),
                    "country": geo.get("country", ""),
                    "city": geo.get("city", ""),
                    "hosting": geo.get("hosting", None),
                    "is_primary": ip == primary_ip,
                    "shodan": vuln if vuln else None,
                }
                ip_entries.append(entry)

                if geo.get("asn"):
                    asns.add(geo["asn"])
                if geo.get("country"):
                    countries.add(geo["country"])
                if geo.get("hosting") is False and ":" not in ip:
                    residential_found = True
                if not geo.get("reverse_dns") and ":" not in ip:
                    no_rdns_count += 1

                # Aggregate vulnerability counts
                if vuln:
                    agg["total_cves"] += vuln.get("cve_count", 0)
                    agg["critical_count"] += vuln.get("critical_count", 0)
                    agg["high_count"] += vuln.get("high_count", 0)
                    agg["medium_count"] += vuln.get("medium_count", 0)
                    agg["kev_count"] += vuln.get("kev_count", 0)
                    if vuln.get("max_cvss", 0) > agg["max_cvss"]:
                        agg["max_cvss"] = vuln["max_cvss"]
                    if vuln.get("max_epss", 0) > agg["max_epss"]:
                        agg["max_epss"] = vuln["max_epss"]
                    if vuln.get("cve_count", 0) > 0:
                        agg["ips_with_vulns"] += 1

            result["ip_addresses"] = ip_entries
            result["unique_asns"] = len(asns)
            result["unique_countries"] = len(countries)

            # --- Phase 5: Risk scoring ---
            penalty = 0
            penalty += agg["critical_count"] * 25
            penalty += agg["high_count"] * 10
            penalty += agg["medium_count"] * 3
            penalty += agg["kev_count"] * 25
            # High EPSS across all IPs
            high_epss = 0
            for ip_entry in ip_entries:
                vuln = ip_entry.get("shodan") or {}
                for cve in vuln.get("cves", []):
                    if (cve.get("epss_score") or 0) >= 0.1:
                        high_epss += 1
            penalty += high_epss * 10
            if residential_found:
                penalty += 10
            penalty += min(15, no_rdns_count * 5)
            if len(unique_ips) > 20:
                penalty += 5

            result["score"] = max(0, 100 - min(100, penalty))

            # --- Phase 6: Build issues ---
            if agg["critical_count"] > 0:
                result["issues"].append(
                    f"CRITICAL: {agg['critical_count']} critical CVE(s) found across external IPs — patch immediately"
                )
            if agg["high_count"] > 0:
                result["issues"].append(
                    f"{agg['high_count']} high-severity CVE(s) across external IPs — review urgently"
                )
            if agg["kev_count"] > 0:
                result["issues"].append(
                    f"CRITICAL: {agg['kev_count']} CVE(s) listed in CISA KEV across external IPs"
                )
            if high_epss > 0:
                result["issues"].append(
                    f"{high_epss} CVE(s) with EPSS ≥ 10% across external IPs"
                )
            if residential_found:
                result["issues"].append(
                    "Residential (non-hosting) IP detected — possible shadow IT or misconfiguration"
                )
            if no_rdns_count > 2:
                result["issues"].append(
                    f"{no_rdns_count} IP(s) without reverse DNS — poor infrastructure hygiene"
                )
            if len(unique_ips) > 20:
                result["issues"].append(
                    f"Large external IP footprint ({len(unique_ips)} IPs) — increased attack surface"
                )

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

        return result


# ---------------------------------------------------------------------------
# 22. Dehashed Credential Leak Checker (optional API key)
# ---------------------------------------------------------------------------

class DehashedChecker:
    """
    Queries Dehashed for credential leaks associated with the domain.
    Requires DEHASHED_EMAIL + DEHASHED_API_KEY env vars (paid subscription).
    Falls back gracefully with status='no_api_key' when credentials are absent.
    """
    API_URL = "https://api.dehashed.com/search"

    def check(self, domain: str, email: str = None, api_key: str = None) -> dict:
        result = {
            "status": "completed",
            "total_entries": 0,
            "unique_emails": 0,
            "has_passwords": False,
            "sample_emails": [],
            "score": 100,
            "issues": [],
        }

        if not email or not api_key:
            result["status"] = "no_api_key"
            return result

        try:
            r = requests.get(
                self.API_URL,
                params={"query": f"domain:{domain}", "size": 100},
                auth=(email, api_key),
                headers={"Accept": "application/json", "User-Agent": USER_AGENT},
                timeout=15,
            )

            if r.status_code == 401:
                result["status"] = "auth_failed"
                result["issues"].append("Dehashed authentication failed — check API credentials")
                return result

            if r.status_code == 302 or r.status_code == 403:
                result["status"] = "subscription_required"
                return result

            if r.status_code != 200:
                result["status"] = "error"
                result["error"] = f"HTTP {r.status_code}"
                return result

            data = r.json()
            entries = data.get("entries") or []
            total   = data.get("total", len(entries))

            result["total_entries"] = total

            emails_seen = set()
            has_pw = False
            for entry in entries:
                em = entry.get("email", "")
                if em:
                    emails_seen.add(em)
                if entry.get("password") or entry.get("hashed_password"):
                    has_pw = True

            result["unique_emails"] = len(emails_seen)
            result["has_passwords"] = has_pw
            # Show up to 5 sample emails (truncated for display)
            result["sample_emails"] = [
                e[:40] + ("…" if len(e) > 40 else "") for e in list(emails_seen)[:5]
            ]

            if total > 0:
                result["issues"].append(
                    f"{total} credential record(s) found in Dehashed for this domain — "
                    "notify affected users and enforce password reset"
                )
            if has_pw:
                result["issues"].append(
                    "Plaintext or hashed passwords found in leaked records — "
                    "enforce immediate password reset and review authentication systems"
                )

            penalty = min(100, total * 2)
            result["score"] = max(0, 100 - penalty)

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

        return result


# ---------------------------------------------------------------------------
# 22. Fraudulent Domain Detection (Typosquat / Lookalike)
# ---------------------------------------------------------------------------

class FraudulentDomainChecker:
    """Detects typosquat and lookalike domains via crt.sh certificate transparency."""

    HOMOGLYPHS = {'a': ['@', 'à', 'á', 'â', 'ã', 'ä'], 'e': ['è', 'é', 'ê', 'ë', '3'],
                  'i': ['í', 'ì', 'î', 'ï', '1', 'l'], 'o': ['ò', 'ó', 'ô', 'õ', 'ö', '0'],
                  'l': ['1', 'i', '|'], 's': ['$', '5'], 't': ['7'], 'g': ['9', 'q']}
    TLD_SWAPS = ['.net', '.org', '.co', '.io', '.co.za', '.info', '.biz', '.xyz', '.online']

    def _generate_variants(self, domain: str) -> list:
        parts = domain.rsplit('.', 1)
        if len(parts) != 2:
            return []
        name, tld = parts[0], '.' + parts[1]
        variants = set()

        # Character omission
        for i in range(len(name)):
            v = name[:i] + name[i+1:]
            if v:
                variants.add(v + tld)

        # Adjacent character swap
        for i in range(len(name) - 1):
            v = list(name)
            v[i], v[i+1] = v[i+1], v[i]
            variants.add(''.join(v) + tld)

        # Character substitution (common typos)
        QWERTY_NEIGHBOURS = {
            'q': 'wa', 'w': 'qeas', 'e': 'wrds', 'r': 'etfs', 't': 'rygs',
            'y': 'tuhs', 'u': 'yijs', 'i': 'uoks', 'o': 'ipls', 'p': 'ol',
            'a': 'qwsz', 's': 'awedxz', 'd': 'serfcx', 'f': 'drtgvc',
            'g': 'ftyhbv', 'h': 'gyujnb', 'j': 'huiknm', 'k': 'jiolm',
            'l': 'kop', 'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb',
            'b': 'vghn', 'n': 'bhjm', 'm': 'njk',
        }
        for i in range(len(name)):
            for neighbour in QWERTY_NEIGHBOURS.get(name[i].lower(), ''):
                v = name[:i] + neighbour + name[i+1:]
                variants.add(v + tld)

        # Homoglyph substitution
        for i in range(len(name)):
            for h in self.HOMOGLYPHS.get(name[i].lower(), []):
                variants.add(name[:i] + h + name[i+1:] + tld)

        # Character doubling
        for i in range(len(name)):
            variants.add(name[:i+1] + name[i] + name[i+1:] + tld)

        # TLD swap
        for alt_tld in self.TLD_SWAPS:
            if alt_tld != tld:
                variants.add(name + alt_tld)

        # Prefix/suffix
        for affix in ['my-', 'login-', 'secure-', 'mail-', '-login', '-secure', '-mail']:
            if affix.startswith('-'):
                variants.add(name + affix + tld)
            else:
                variants.add(affix + name + tld)

        # Remove the original domain
        variants.discard(domain)
        return list(variants)[:20]

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "variants_checked": 0,
            "fraudulent_domains_found": 0,
            "domains": [],
            "issues": [],
            "score": 100,
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"
            return result

        variants = self._generate_variants(domain)
        result["variants_checked"] = len(variants)
        found = []

        for variant in variants:
            try:
                r = requests.get(
                    f"https://crt.sh/?q={variant}&output=json",
                    timeout=10, headers={"User-Agent": USER_AGENT}
                )
                if r.status_code == 200:
                    entries = r.json()
                    if entries:
                        issuer = entries[0].get("issuer_name", "Unknown")
                        first_seen = entries[0].get("not_before", "")[:10]
                        # Determine variant type
                        vtype = "lookalike"
                        name_v = variant.rsplit('.', 1)[0] if '.' in variant else variant
                        name_o = domain.rsplit('.', 1)[0] if '.' in domain else domain
                        tld_v = '.' + variant.rsplit('.', 1)[1] if '.' in variant else ''
                        tld_o = '.' + domain.rsplit('.', 1)[1] if '.' in domain else ''
                        if tld_v != tld_o and name_v == name_o:
                            vtype = "TLD swap"
                        elif len(name_v) == len(name_o) - 1:
                            vtype = "character omission"
                        elif len(name_v) == len(name_o) + 1:
                            vtype = "character doubling"
                        elif len(name_v) == len(name_o):
                            vtype = "character swap/substitution"
                        elif '-' in name_v:
                            vtype = "prefix/suffix"

                        found.append({
                            "domain": variant,
                            "type": vtype,
                            "has_certificate": True,
                            "cert_issuer": issuer[:60],
                            "first_seen": first_seen,
                            "risk": "high",
                        })
                time.sleep(0.3)
            except Exception:
                continue

        result["domains"] = found
        result["fraudulent_domains_found"] = len(found)

        if found:
            result["issues"].append(
                f"{len(found)} lookalike domain(s) with active certificates detected"
            )
        result["score"] = max(0, 100 - len(found) * 15)
        return result


# ---------------------------------------------------------------------------
# 23. Web Ranking (Tranco List)
# ---------------------------------------------------------------------------

class WebRankingChecker:
    """Checks domain popularity via the Tranco top-1M list."""

    TRANCO_API = "https://tranco-list.eu/api/ranks/domain/{domain}"

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "ranked": False,
            "rank": None,
            "rank_label": "Unranked",
            "popularity": "Unranked",
            "issues": [],
            "score": 40,
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"
            return result

        # Try the exact domain first, then apex
        domains_to_try = [domain]
        parts = domain.split('.')
        if len(parts) > 2:
            apex = '.'.join(parts[-2:])
            domains_to_try.append(apex)

        for d in domains_to_try:
            try:
                r = requests.get(
                    self.TRANCO_API.format(domain=d),
                    timeout=10, headers={"User-Agent": USER_AGENT}
                )
                if r.status_code == 200:
                    data = r.json()
                    ranks = data.get("ranks", [])
                    if ranks:
                        rank = ranks[0].get("rank", 0)
                        if rank > 0:
                            result["ranked"] = True
                            result["rank"] = rank
                            if rank <= 1000:
                                result["rank_label"] = "Top 1K"
                                result["popularity"] = "Very High"
                                result["score"] = 100
                            elif rank <= 10000:
                                result["rank_label"] = "Top 10K"
                                result["popularity"] = "High"
                                result["score"] = 95
                            elif rank <= 50000:
                                result["rank_label"] = "Top 50K"
                                result["popularity"] = "Moderate"
                                result["score"] = 85
                            elif rank <= 100000:
                                result["rank_label"] = "Top 100K"
                                result["popularity"] = "Moderate"
                                result["score"] = 75
                            elif rank <= 500000:
                                result["rank_label"] = "Top 500K"
                                result["popularity"] = "Low"
                                result["score"] = 65
                            else:
                                result["rank_label"] = "Top 1M"
                                result["popularity"] = "Low"
                                result["score"] = 55
                            break
            except Exception:
                continue

        return result


# ---------------------------------------------------------------------------
# 24. Ransomware Susceptibility Index (RSI) — Post-scan aggregator
# ---------------------------------------------------------------------------

# South African industry breach cost data (IBM 2025, translated to ZAR)
# Easily updatable when actual SA data becomes available.
SA_INDUSTRY_COSTS = {
    "Public Sector":              {"breach_cost_zar": 76_730_000, "cost_per_record": 3273, "multiplier": 1.74},
    "Healthcare":                 {"breach_cost_zar": 73_650_000, "cost_per_record": 3141, "multiplier": 1.67},
    "Financial Services":         {"breach_cost_zar": 70_120_000, "cost_per_record": 2992, "multiplier": 1.59},
    "Hospitality":                {"breach_cost_zar": 57_330_000, "cost_per_record": 2445, "multiplier": 1.30},
    "Services":                   {"breach_cost_zar": 56_890_000, "cost_per_record": 2426, "multiplier": 1.29},
    "Industrial / Manufacturing": {"breach_cost_zar": 49_390_000, "cost_per_record": 2107, "multiplier": 1.12},
    "Energy":                     {"breach_cost_zar": 48_070_000, "cost_per_record": 2051, "multiplier": 1.09},
    "Technology":                 {"breach_cost_zar": 47_630_000, "cost_per_record": 2032, "multiplier": 1.08},
    "Pharmaceuticals":            {"breach_cost_zar": 45_860_000, "cost_per_record": 1956, "multiplier": 1.04},
    "Entertainment":              {"breach_cost_zar": 44_100_000, "cost_per_record": 1881, "multiplier": 1.00},
    "Media":                      {"breach_cost_zar": 41_900_000, "cost_per_record": 1787, "multiplier": 0.95},
    "Transportation":             {"breach_cost_zar": 39_690_000, "cost_per_record": 1693, "multiplier": 0.90},
    "Education":                  {"breach_cost_zar": 37_490_000, "cost_per_record": 1599, "multiplier": 0.85},
    "Research":                   {"breach_cost_zar": 37_490_000, "cost_per_record": 1599, "multiplier": 0.85},
    "Communications":             {"breach_cost_zar": 37_040_000, "cost_per_record": 1580, "multiplier": 0.84},
    "Consumer":                   {"breach_cost_zar": 37_040_000, "cost_per_record": 1580, "multiplier": 0.84},
    "Retail":                     {"breach_cost_zar": 35_280_000, "cost_per_record": 1505, "multiplier": 0.80},
    "Agriculture":                {"breach_cost_zar": 28_670_000, "cost_per_record": 1223, "multiplier": 0.65},
    "Other":                      {"breach_cost_zar": 44_100_000, "cost_per_record": 1881, "multiplier": 1.00},
}


class RansomwareRiskChecker:
    """Computes RSI (0.0–1.0) from existing scan results + industry/revenue context."""

    def calculate(self, results: dict, industry: str = "Other", annual_revenue_zar: int = 0) -> dict:
        rsi = 0.0
        factors = []

        # RDP exposed → +0.35
        vpn = results.get("vpn_remote", {})
        if vpn.get("rdp_exposed"):
            rsi += 0.35
            factors.append({"factor": "RDP exposed to internet", "impact": 0.35})

        # High-risk protocol exposure → +0.15 each, cap 0.30
        hrp = results.get("high_risk_protocols", {})
        exposed_count = hrp.get("critical_count", 0)
        hrp_impact = min(0.30, exposed_count * 0.15)
        if hrp_impact > 0:
            rsi += hrp_impact
            factors.append({"factor": f"{exposed_count} exposed high-risk service(s)", "impact": round(hrp_impact, 2)})

        # CISA KEV CVEs → +0.10 each, cap 0.25
        ext_agg = results.get("external_ips", {}).get("aggregate_vulns", {})
        kev_count = ext_agg.get("kev_count", 0) + results.get("shodan_vulns", {}).get("kev_count", 0)
        kev_impact = min(0.25, kev_count * 0.10)
        if kev_impact > 0:
            rsi += kev_impact
            factors.append({"factor": f"{kev_count} CISA KEV vulnerabilit{'y' if kev_count == 1 else 'ies'}", "impact": round(kev_impact, 2)})

        # High EPSS (≥0.5) → +0.05 each, cap 0.15
        shodan = results.get("shodan_vulns", {})
        high_epss = sum(1 for c in shodan.get("cves", []) if (c.get("epss_score") or 0) >= 0.5)
        epss_impact = min(0.15, high_epss * 0.05)
        if epss_impact > 0:
            rsi += epss_impact
            factors.append({"factor": f"{high_epss} CVE(s) with EPSS ≥ 50%", "impact": round(epss_impact, 2)})

        # Breach + leaked passwords → +0.10
        breaches = results.get("breaches", {})
        dehashed = results.get("dehashed", {})
        if breaches.get("breach_count", 0) > 0 and dehashed.get("has_passwords"):
            rsi += 0.10
            factors.append({"factor": "Breached credentials with leaked passwords", "impact": 0.10})

        # Weak email security → +0.05
        email_sec = results.get("email_security", {})
        if email_sec.get("score", 10) < 5:
            rsi += 0.05
            factors.append({"factor": "Weak email security (DMARC/SPF)", "impact": 0.05})

        # No WAF → +0.05
        waf = results.get("waf", {})
        if not waf.get("detected"):
            rsi += 0.05
            factors.append({"factor": "No WAF detected", "impact": 0.05})

        # Poor SSL → +0.05
        ssl_grade = results.get("ssl", {}).get("grade", "")
        if ssl_grade in ("F", "D", "T"):
            rsi += 0.05
            factors.append({"factor": f"SSL grade {ssl_grade}", "impact": 0.05})

        # Apply industry multiplier
        industry_data = SA_INDUSTRY_COSTS.get(industry, SA_INDUSTRY_COSTS["Other"])
        industry_mult = industry_data["multiplier"]
        rsi *= industry_mult

        # Apply revenue multiplier
        if annual_revenue_zar > 0:
            if annual_revenue_zar < 50_000_000:
                rev_mult = 1.2
            elif annual_revenue_zar <= 500_000_000:
                rev_mult = 1.0
            else:
                rev_mult = 0.9
            rsi *= rev_mult

        # Cap at 1.0
        rsi = min(1.0, round(rsi, 2))

        # Label
        if rsi >= 0.8:
            label = "Critical"
        elif rsi >= 0.5:
            label = "High"
        elif rsi >= 0.25:
            label = "Medium"
        else:
            label = "Low"

        return {
            "status": "completed",
            "rsi_score": rsi,
            "rsi_label": label,
            "contributing_factors": sorted(factors, key=lambda x: x["impact"], reverse=True),
            "industry": industry,
            "annual_revenue_zar": annual_revenue_zar,
            "issues": [f"Ransomware susceptibility: {label} ({rsi})"] if rsi >= 0.5 else [],
            "score": max(0, round(100 - rsi * 100)),
        }


# ---------------------------------------------------------------------------
# 25. Data Breach Index (DBI) — Post-scan aggregator
# ---------------------------------------------------------------------------

class DataBreachIndexChecker:
    """Computes DBI (0–100) from breach history and credential leak data."""

    def calculate(self, results: dict) -> dict:
        breaches = results.get("breaches", {})
        dehashed = results.get("dehashed", {})

        dbi = 0
        breach_count = breaches.get("breach_count", 0)
        most_recent = breaches.get("most_recent_breach")
        data_classes = breaches.get("data_classes", [])
        credential_leaks = dehashed.get("total_entries", 0)

        # Breach count component (0–30)
        if breach_count == 0:
            dbi += 30
        elif breach_count <= 3:
            dbi += 15
        # else: 0

        # Recency component (0–20)
        if most_recent:
            try:
                breach_date = datetime.strptime(most_recent[:10], "%Y-%m-%d")
                years_ago = (datetime.now() - breach_date).days / 365.25
                if years_ago > 3:
                    dbi += 20
                elif years_ago > 1:
                    dbi += 10
                # else: <1yr = 0
            except (ValueError, TypeError):
                dbi += 10  # Unknown date, assume moderate
        else:
            dbi += 20  # No breach date = no known breach

        # Data classes severity (0–15)
        sensitive_classes = {"Passwords", "Credit cards", "Bank account numbers",
                           "Social security numbers", "Financial data", "Payment histories"}
        has_sensitive = bool(sensitive_classes & set(data_classes))
        if not has_sensitive:
            dbi += 15

        # Credential leak volume (0–20)
        if credential_leaks == 0 or dehashed.get("status") in ("no_api_key", "auth_failed"):
            dbi += 20
        elif credential_leaks <= 100:
            dbi += 10
        # else: 0

        # Breach trend (0–10) — improving if no recent breaches
        if breach_count > 0 and most_recent:
            try:
                breach_date = datetime.strptime(most_recent[:10], "%Y-%m-%d")
                if (datetime.now() - breach_date).days > 730:  # >2 years since last
                    dbi += 10
            except (ValueError, TypeError):
                pass
        elif breach_count == 0:
            dbi += 10

        dbi = min(100, max(0, dbi))

        if dbi >= 75:
            label = "Low"
        elif dbi >= 50:
            label = "Medium"
        elif dbi >= 25:
            label = "High Risk"
        else:
            label = "Critical"

        issues = []
        if breach_count > 0:
            issue_parts = [f"{breach_count} historical breach(es)"]
            if has_sensitive:
                issue_parts.append("with sensitive data exposure")
            if credential_leaks > 0:
                issue_parts.append(f"and {credential_leaks} credential leaks")
            issues.append(" ".join(issue_parts))

        return {
            "status": "completed",
            "dbi_score": dbi,
            "dbi_label": label,
            "breach_count": breach_count,
            "most_recent_breach": most_recent,
            "has_sensitive_data": has_sensitive,
            "credential_leaks": credential_leaks,
            "issues": issues,
            "score": dbi,
        }


# ---------------------------------------------------------------------------
# 26. Financial Impact Calculator (FAIR-inspired) — Post-scan aggregator
# ---------------------------------------------------------------------------

class FinancialImpactCalculator:
    """
    Estimates monetary loss in ZAR across three scenarios:
    data breach, ransomware, business interruption.
    """

    def calculate(self, results: dict, rsi_result: dict, dbi_result: dict,
                  overall_score: int, industry: str = "Other",
                  annual_revenue_zar: int = 0) -> dict:

        if annual_revenue_zar <= 0:
            return {
                "status": "skipped",
                "reason": "Annual revenue not provided",
                "issues": [],
                "score": 50,
            }

        industry_data = SA_INDUSTRY_COSTS.get(industry, SA_INDUSTRY_COSTS["Other"])
        rsi_score = rsi_result.get("rsi_score", 0)

        # --- Scenario 1: Data Breach ---
        p_breach = ((100 - overall_score / 10) / 100) * industry_data["multiplier"] * 0.3
        p_breach = min(1.0, max(0.0, p_breach))
        estimated_records = max(100, annual_revenue_zar // 50_000)
        cost_per_record = industry_data["cost_per_record"]
        regulatory_fine = annual_revenue_zar * 0.02  # POPIA max ~2%
        data_breach_loss = p_breach * (estimated_records * cost_per_record + regulatory_fine)

        # --- Scenario 2: Ransomware ---
        avg_downtime_days = 22
        daily_revenue = annual_revenue_zar / 365
        # Ransom estimate scaled by revenue
        if annual_revenue_zar < 50_000_000:
            ransom_estimate = 500_000
            ir_cost = 500_000
        elif annual_revenue_zar < 200_000_000:
            ransom_estimate = 2_500_000
            ir_cost = 1_500_000
        elif annual_revenue_zar < 500_000_000:
            ransom_estimate = 10_000_000
            ir_cost = 3_000_000
        else:
            ransom_estimate = 50_000_000
            ir_cost = 5_000_000
        ransomware_loss = rsi_score * (avg_downtime_days * daily_revenue * 0.5 + ransom_estimate + ir_cost)

        # --- Scenario 3: Business Interruption ---
        waf_detected = results.get("waf", {}).get("detected", False)
        cdn_detected = results.get("cloud_cdn", {}).get("cdn_detected", False)
        dns_info = results.get("dns_infrastructure", {})
        single_asn = results.get("external_ips", {}).get("unique_asns", 1) <= 1

        p_interruption = 0.05
        if not waf_detected:
            p_interruption += 0.05
        if not cdn_detected:
            p_interruption += 0.05
        if single_asn:
            p_interruption += 0.05
        p_interruption = min(0.5, p_interruption)

        impact_factor = 0.3
        if not waf_detected:
            impact_factor += 0.15
        if not cdn_detected:
            impact_factor += 0.15
        if single_asn:
            impact_factor += 0.1
        impact_factor = min(0.8, impact_factor)

        bi_downtime_days = 5
        bi_loss = p_interruption * (bi_downtime_days * daily_revenue * impact_factor)

        # --- Aggregate ---
        most_likely = round(data_breach_loss + ransomware_loss + bi_loss)
        minimum = round(most_likely * 0.15)
        maximum = round(most_likely * 3.5)

        # Insurance recommendation
        recommended_cover = round(maximum * 1.2, -5)  # 20% above max, rounded to nearest R100K
        minimum_cover = round(most_likely, -5)

        if rsi_score >= 0.7 or overall_score >= 500:
            premium_tier = "Very High"
        elif rsi_score >= 0.5 or overall_score >= 350:
            premium_tier = "High"
        elif rsi_score >= 0.25 or overall_score >= 200:
            premium_tier = "Medium"
        else:
            premium_tier = "Low"

        # Score (0–100, higher = better / lower financial risk)
        # Based on most_likely loss as % of revenue
        loss_pct = most_likely / annual_revenue_zar if annual_revenue_zar > 0 else 0
        if loss_pct >= 0.10:
            score = 10
        elif loss_pct >= 0.05:
            score = 30
        elif loss_pct >= 0.02:
            score = 50
        elif loss_pct >= 0.01:
            score = 70
        else:
            score = 90

        return {
            "status": "completed",
            "currency": "ZAR",
            "industry": industry,
            "annual_revenue_zar": annual_revenue_zar,
            "estimated_annual_loss": {
                "minimum": minimum,
                "most_likely": most_likely,
                "maximum": maximum,
            },
            "scenarios": {
                "data_breach": {
                    "probability": round(p_breach, 3),
                    "estimated_loss": round(data_breach_loss),
                    "cost_per_record": cost_per_record,
                    "estimated_records": estimated_records,
                    "regulatory_fine": round(regulatory_fine),
                },
                "ransomware": {
                    "rsi_score": rsi_score,
                    "estimated_loss": round(ransomware_loss),
                    "avg_downtime_days": avg_downtime_days,
                    "ransom_estimate": ransom_estimate,
                },
                "business_interruption": {
                    "probability": round(p_interruption, 3),
                    "estimated_loss": round(bi_loss),
                },
            },
            "insurance_recommendation": {
                "minimum_cover_zar": max(500_000, minimum_cover),
                "recommended_cover_zar": max(1_000_000, recommended_cover),
                "premium_risk_tier": premium_tier,
            },
            "issues": [],
            "score": score,
        }


# ---------------------------------------------------------------------------
# Risk Scoring Engine
# ---------------------------------------------------------------------------

class RiskScorer:
    """
    Weighted 0-1000 risk score.
    All weights must sum to 100 when WAF bonus excluded.
    """
    WEIGHTS = {
        "ssl":                  0.09,
        "email_security":       0.05,
        "email_hardening":      0.03,
        "breaches":             0.08,
        "http_headers":         0.04,
        "website_security":     0.04,
        "exposed_admin":        0.08,
        "high_risk_protocols":  0.08,
        "dnsbl":                0.05,
        "tech_stack":           0.05,
        "payment_security":     0.03,
        "vpn_remote":           0.04,
        "subdomains":           0.03,
        "shodan_vulns":         0.06,
        "dehashed":             0.02,
        "external_ips":         0.03,
        "fraudulent_domains":   0.03,
        "web_ranking":          0.02,
        "ransomware_risk":      0.06,
        "data_breach_index":    0.03,
        "financial_impact":     0.02,
    }

    RECOMMENDATIONS = {
        "SSL certificate has EXPIRED": "Renew your SSL certificate immediately — an expired cert causes browser warnings and erodes user trust.",
        "TLS 1.0 supported — deprecated and insecure": "Disable TLS 1.0 on your web server. Set minimum TLS version to 1.2.",
        "TLS 1.1 supported — deprecated": "Disable TLS 1.1. Modern clients support TLS 1.2+.",
        "No SPF record — spoofing risk": "Add an SPF record (e.g. 'v=spf1 include:_spf.google.com -all') to prevent email spoofing.",
        "SPF uses '+all'": "Change SPF to use '-all' (hard fail) or '~all' (soft fail) — '+all' is extremely dangerous.",
        "No DMARC record — phishing risk": "Add a DMARC record: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com'.",
        "DMARC policy is 'none'": "Upgrade DMARC policy from 'none' to 'quarantine' or 'reject' to enforce email authentication.",
        "No DKIM selectors found": "Configure DKIM signing for outbound email and publish the public key in DNS.",
        "No MTA-STS policy": "Implement MTA-STS to force TLS for inbound email and prevent downgrade attacks.",
        "HTTPS not enforced": "Configure your web server to redirect all HTTP traffic to HTTPS (301 redirect).",
        "HSTS header missing": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        "Missing security header: Content-Security-Policy": "Implement a Content Security Policy to mitigate XSS attacks.",
        "Missing security header: X-Frame-Options": "Add 'X-Frame-Options: DENY' to prevent clickjacking.",
        "Missing security header: X-Content-Type-Options": "Add 'X-Content-Type-Options: nosniff' to prevent MIME sniffing.",
        "No WAF detected": "Deploy a Web Application Firewall (e.g. Cloudflare, AWS WAF, Imperva) to filter malicious traffic.",
        "RDP (port 3389) is exposed": "Block RDP from public internet immediately. Use VPN or Zero Trust access for remote desktop.",
        "No VPN/remote access gateway detected": "Implement a VPN or Zero Trust Network Access (ZTNA) solution for remote workers.",
        "No security.txt found": "Create a security.txt file at /.well-known/security.txt to establish a vulnerability disclosure policy.",
        "CRITICAL: Sensitive file exposed": "Immediately restrict access to sensitive files. Audit your web server configuration and .htaccess rules.",
        "CRITICAL:": "Immediately investigate and remediate the critically exposed service.",
        "EOL software detected": "Update all end-of-life software immediately — unpatched software is a leading cause of breaches.",
        "Domain/IP listed on": "Investigate blacklist listings — likely indicates past spam, malware distribution, or compromise.",
        "Self-hosted payment card form": "Migrate to a PCI-compliant payment provider (Stripe, PayFast, Peach Payments) to avoid storing card data.",
        "No known breaches found": "",
        "CRITICAL: 1 critical CVE": "Patch critical CVEs on your public-facing servers immediately — attackers actively exploit these.",
        "critical CVE(s) found": "Patch critical CVEs on your public-facing servers immediately — attackers actively exploit these.",
        "high-severity CVE(s) detected": "Review and patch high-severity CVEs — schedule remediation within 30 days.",
        "medium-severity CVE(s) detected": "Review medium-severity CVEs and schedule patching within 90 days.",
        "listed in CISA KEV": "URGENT: Vulnerabilities confirmed exploited in the wild (CISA KEV). Patch these within 48 hours — attackers are actively targeting them.",
        "EPSS ≥ 10%": "Prioritise patching CVEs with high EPSS scores — these have a significant probability of exploitation within 30 days.",
        "credential record(s) found in Dehashed": "Notify affected users and enforce mandatory password reset for all leaked accounts.",
        "Plaintext or hashed passwords found": "Enforce immediate password reset and review authentication systems for all affected accounts.",
        "critical CVE(s) found across external IPs": "Patch critical CVEs on all external-facing servers — not just the primary domain IP.",
        "high-severity CVE(s) across external IPs": "Review and patch high-severity CVEs across your entire external IP footprint.",
        "CVE(s) listed in CISA KEV across external IPs": "URGENT: Confirmed exploited vulnerabilities found on secondary IPs — patch within 48 hours.",
        "EPSS ≥ 10% across external IPs": "Prioritise patching high-EPSS CVEs across all external IPs — high probability of near-term exploitation.",
        "Residential (non-hosting) IP detected": "Investigate residential IPs in your infrastructure — may indicate shadow IT, misconfigured services, or compromised devices.",
        "IP(s) without reverse DNS": "Configure reverse DNS (PTR records) for all external IPs — improves email deliverability and security posture.",
        "Large external IP footprint": "Review and consolidate your external IP footprint — a large attack surface increases exposure to threats.",
        "lookalike domain(s) with active certificates": "Investigate and report fraudulent lookalike domains — consider domain monitoring and takedown services.",
        "Ransomware susceptibility: Critical": "URGENT: Critical ransomware risk — immediately remediate RDP exposure, patch KEV vulnerabilities, and enforce MFA.",
        "Ransomware susceptibility: High": "High ransomware risk — prioritise patching known exploited vulnerabilities and reducing attack surface exposure.",
        "historical breach(es)": "Review historical breach exposure — notify affected users, enforce credential rotation, and enhance monitoring.",
    }

    def calculate(self, results: dict) -> tuple:
        def inv(score_0_100):
            return 100 - score_0_100

        # Per-category risk (0-100 scale, higher = more risky)
        ssl_risk = inv(results.get("ssl", {}).get("score", 50))
        email_risk = inv((results.get("email_security", {}).get("score", 5) / 10) * 100)
        email_hard_risk = inv((results.get("email_hardening", {}).get("score", 0) / 10) * 100)

        breach_count = results.get("breaches", {}).get("breach_count", 0)
        breach_risk = min(100, breach_count * 15)

        header_risk = inv(results.get("http_headers", {}).get("score", 50))
        website_risk = inv(results.get("website_security", {}).get("score", 50))

        # Exposed admin panels
        crit = results.get("exposed_admin", {}).get("critical_count", 0)
        high = results.get("exposed_admin", {}).get("high_count", 0)
        admin_risk = min(100, crit * 50 + high * 20)

        # High-risk protocols (database/service exposure)
        hrisky = results.get("high_risk_protocols", {}).get("critical_count", 0)
        hrisk = min(100, hrisky * 35)

        # DNSBL
        listed = len(results.get("dnsbl", {}).get("ip_listings", [])) + \
                 len(results.get("dnsbl", {}).get("domain_listings", []))
        dnsbl_risk = min(100, listed * 50)

        # Tech stack (EOL)
        tech_risk = inv(results.get("tech_stack", {}).get("score", 100))

        # Payment
        pay = results.get("payment_security", {})
        pay_risk = 0
        if pay.get("self_hosted_payment_form"):
            pay_risk = 80
        elif pay.get("has_payment_page") and not pay.get("payment_page_https"):
            pay_risk = 60

        # VPN/remote
        vpn = results.get("vpn_remote", {})
        vpn_risk = 40 if vpn.get("rdp_exposed") else (20 if not vpn.get("vpn_detected") else 0)

        # Subdomains
        risky_subs = len(results.get("subdomains", {}).get("risky_subdomains", []))
        sub_risk = min(100, risky_subs * 15)

        # Shodan CVE risk
        shodan = results.get("shodan_vulns", {})
        shodan_risk = inv(shodan.get("score", 100))

        # Dehashed credential leak risk
        dehashed = results.get("dehashed", {})
        dehashed_total = dehashed.get("total_entries", 0)
        dehashed_risk = min(100, dehashed_total * 2) if dehashed.get("status") not in ("no_api_key", "auth_failed") else 0

        # External IP discovery risk
        ext_ip_risk = inv(results.get("external_ips", {}).get("score", 100))

        # Fraudulent domains
        fraud_risk = inv(results.get("fraudulent_domains", {}).get("score", 100))

        # Web ranking
        rank_risk = inv(results.get("web_ranking", {}).get("score", 50))

        # RSI (already 0–100 inverted via score field)
        rsi_risk = inv(results.get("ransomware_risk", {}).get("score", 100))

        # DBI
        dbi_risk = inv(results.get("data_breach_index", {}).get("score", 100))

        # Financial impact
        fin_risk = inv(results.get("financial_impact", {}).get("score", 50))

        weighted = (
            ssl_risk         * self.WEIGHTS["ssl"] +
            email_risk       * self.WEIGHTS["email_security"] +
            email_hard_risk  * self.WEIGHTS["email_hardening"] +
            breach_risk      * self.WEIGHTS["breaches"] +
            header_risk      * self.WEIGHTS["http_headers"] +
            website_risk     * self.WEIGHTS["website_security"] +
            admin_risk       * self.WEIGHTS["exposed_admin"] +
            hrisk            * self.WEIGHTS["high_risk_protocols"] +
            dnsbl_risk       * self.WEIGHTS["dnsbl"] +
            tech_risk        * self.WEIGHTS["tech_stack"] +
            pay_risk         * self.WEIGHTS["payment_security"] +
            vpn_risk         * self.WEIGHTS["vpn_remote"] +
            sub_risk         * self.WEIGHTS["subdomains"] +
            shodan_risk      * self.WEIGHTS["shodan_vulns"] +
            dehashed_risk    * self.WEIGHTS["dehashed"] +
            ext_ip_risk      * self.WEIGHTS["external_ips"] +
            fraud_risk       * self.WEIGHTS["fraudulent_domains"] +
            rank_risk        * self.WEIGHTS["web_ranking"] +
            rsi_risk         * self.WEIGHTS["ransomware_risk"] +
            dbi_risk         * self.WEIGHTS["data_breach_index"] +
            fin_risk         * self.WEIGHTS["financial_impact"]
        )

        risk_score = round(weighted * 10)

        # WAF bonus — reduce score by up to 50 points
        if results.get("waf", {}).get("detected"):
            risk_score = max(0, risk_score - 50)

        risk_score = min(1000, risk_score)

        risk_level = (
            "Critical" if risk_score >= 600 else
            "High"     if risk_score >= 400 else
            "Medium"   if risk_score >= 200 else
            "Low"
        )

        # Build recommendations from all issues
        all_issues = []
        for cat in results.values():
            if isinstance(cat, dict):
                all_issues.extend(cat.get("issues", []))

        recommendations = []
        seen = set()
        for issue in all_issues:
            for key, rec in self.RECOMMENDATIONS.items():
                if key in issue and key not in seen and rec:
                    recommendations.append(rec)
                    seen.add(key)

        if breach_count > 0 and "breach_rec" not in seen:
            recommendations.append(
                f"Domain found in {breach_count} breach(es). Enforce strong passwords, "
                "implement credential monitoring, and review affected user accounts."
            )

        return risk_score, risk_level, recommendations


# ---------------------------------------------------------------------------
# Main Scanner Orchestrator
# ---------------------------------------------------------------------------

class SecurityScanner:
    def __init__(self, hibp_api_key: Optional[str] = None,
                 dehashed_email: Optional[str] = None,
                 dehashed_api_key: Optional[str] = None):
        self.hibp_api_key      = hibp_api_key
        self.dehashed_email    = dehashed_email
        self.dehashed_api_key  = dehashed_api_key

    def scan(self, domain: str, industry: str = "Other",
             annual_revenue_zar: int = 0,
             include_fraudulent_domains: bool = False) -> dict:
        domain = domain.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]
        results = {
            "domain_scanned": domain,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "industry": industry,
            "annual_revenue_zar": annual_revenue_zar,
            "overall_risk_score": 0,
            "risk_level": "Unknown",
            "categories": {},
            "recommendations": [],
        }

        checkers = {
            "ssl":                 (SSLChecker().check,               domain),
            "email_security":      (EmailSecurityChecker().check,      domain),
            "email_hardening":     (EmailHardeningChecker().check,     domain),
            "http_headers":        (HTTPHeaderChecker().check,         domain),
            "waf":                 (WAFChecker().check,                domain),
            "cloud_cdn":           (CloudCDNChecker().check,           domain),
            "domain_intel":        (DomainIntelChecker().check,        domain),
            "subdomains":          (SubdomainChecker().check,          domain),
            "exposed_admin":       (ExposedAdminChecker().check,       domain),
            "vpn_remote":          (VPNRemoteAccessChecker().check,    domain),
            "dns_infrastructure":  (DNSInfrastructureChecker().check,  domain),
            "high_risk_protocols": (HighRiskProtocolChecker().check,   domain),
            "security_policy":     (SecurityPolicyChecker().check,     domain),
            "dnsbl":               (DNSBLChecker().check,              domain),
            "tech_stack":          (TechStackChecker().check,          domain),
            "breaches":            (BreachChecker().check,             domain),
            "website_security":    (WebsiteSecurityChecker().check,    domain),
            "payment_security":    (PaymentSecurityChecker().check,    domain),
            "shodan_vulns":        (ShodanVulnChecker().check,         domain),
            "external_ips":        (ExternalIPDiscoveryChecker().check, domain),
            "dehashed":            (DehashedChecker().check,           domain),
            "web_ranking":         (WebRankingChecker().check,         domain),
        }

        if include_fraudulent_domains:
            checkers["fraudulent_domains"] = (FraudulentDomainChecker().check, domain)

        cat_results = {}
        with ThreadPoolExecutor(max_workers=12) as ex:
            futures = {}
            for name, (fn, arg) in checkers.items():
                if name == "breaches":
                    futures[ex.submit(fn, arg, self.hibp_api_key)] = name
                elif name == "dehashed":
                    futures[ex.submit(fn, arg, self.dehashed_email, self.dehashed_api_key)] = name
                else:
                    futures[ex.submit(fn, arg)] = name

            try:
                for future in as_completed(futures, timeout=300):
                    name = futures[future]
                    try:
                        cat_results[name] = future.result(timeout=DEFAULT_TIMEOUT * 2)
                    except Exception as e:
                        cat_results[name] = {"status": "error", "error": str(e), "issues": []}
            except TimeoutError:
                # Some checkers didn't finish — record them as timed out
                for future, name in futures.items():
                    if name not in cat_results:
                        cat_results[name] = {"status": "error", "error": "timeout", "issues": []}

        # --- Post-scan aggregators (depend on live checker results) ---

        # 1. Data Breach Index
        dbi_checker = DataBreachIndexChecker()
        cat_results["data_breach_index"] = dbi_checker.calculate(cat_results)

        # 2. Ransomware Susceptibility Index
        rsi_checker = RansomwareRiskChecker()
        cat_results["ransomware_risk"] = rsi_checker.calculate(
            cat_results, industry=industry, annual_revenue_zar=annual_revenue_zar
        )

        # 3. Financial Impact (needs RSI + DBI + preliminary score)
        # Compute a preliminary technical score for the financial model
        scorer = RiskScorer()
        prelim_score, _, _ = scorer.calculate(cat_results)

        fin_calc = FinancialImpactCalculator()
        cat_results["financial_impact"] = fin_calc.calculate(
            cat_results,
            rsi_result=cat_results["ransomware_risk"],
            dbi_result=cat_results["data_breach_index"],
            overall_score=prelim_score,
            industry=industry,
            annual_revenue_zar=annual_revenue_zar,
        )

        # --- Final scoring (includes all categories) ---
        results["categories"] = cat_results
        risk_score, risk_level, recommendations = scorer.calculate(cat_results)
        results["overall_risk_score"] = risk_score
        results["risk_level"] = risk_level
        results["recommendations"] = recommendations
        return results


if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    scanner = SecurityScanner()
    result = scanner.scan(domain)
    print(json.dumps(result, indent=2, default=str))
