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
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError

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
    """Passive SSL/TLS certificate and configuration assessment."""

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "certificate": {},
            "tls_versions": {},
            "cipher_suite": {},
            "hsts": False,
            "grade": "F",
            "score": 0,
            "issues": [],
        }
        try:
            result["certificate"] = self._get_certificate(domain)
            result["tls_versions"] = self._check_tls_versions(domain)
            result["cipher_suite"] = self._get_cipher_suite(domain)
            result["hsts"] = self._check_hsts(domain)
            grade, score, issues = self._calculate_grade(
                result["certificate"],
                result["tls_versions"],
                result["cipher_suite"],
                result["hsts"],
            )
            result["grade"] = grade
            result["score"] = score
            result["issues"] = issues
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
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
            "TLS 1.2": ("TLSv1_2", True),
            "TLS 1.3": ("TLSv1_3", True),
            "TLS 1.0": ("TLSv1", False),
            "TLS 1.1": ("TLSv1_1", False),
        }
        for label, (attr, verify) in checks.items():
            if not hasattr(ssl.TLSVersion, attr):
                continue
            try:
                ver = getattr(ssl.TLSVersion, attr)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = ver
                ctx.maximum_version = ver
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
                        return {
                            "name": c[0],
                            "protocol": c[1],
                            "bits": c[2] or 0,
                            "is_weak": any(w in c[0].upper() for w in weak),
                        }
        except Exception as e:
            return {"name": "Unknown", "bits": 0, "is_weak": True, "error": str(e)}
        return {"name": "Unknown", "bits": 0, "is_weak": True}

    def _check_hsts(self, domain: str) -> bool:
        if not REQUESTS_AVAILABLE:
            return False
        try:
            r = requests.get(
                f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                allow_redirects=True, headers={"User-Agent": USER_AGENT}
            )
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
            ded += 20; issues.append(f"Weak cipher: {cipher.get('name','Unknown')}")
        if not hsts:
            ded += 10; issues.append("HSTS header missing")
        score = max(0, 100 - ded)
        grade = "A+" if score >= 95 else "A" if score >= 80 else "B" if score >= 70 else "C" if score >= 60 else "D" if score >= 50 else "F"
        return grade, score, issues


# ---------------------------------------------------------------------------
# 2. Email Security (DNS-based)
# ---------------------------------------------------------------------------

class EmailSecurityChecker:
    """SPF, DKIM, DMARC, MX assessment."""

    DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "mail", "dkim", "k1", "smtp"]

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "spf": {"present": False, "valid": False, "record": None},
            "dmarc": {"present": False, "policy": None, "record": None},
            "dkim": {"selectors_found": []},
            "mx": {"records": []},
            "score": 0,
            "issues": [],
        }
        if not DNS_AVAILABLE:
            result["status"] = "error"
            result["error"] = "dnspython not installed"
            return result
        try:
            result["spf"] = self._check_spf(domain)
            result["dmarc"] = self._check_dmarc(domain)
            result["dkim"] = self._check_dkim(domain)
            result["mx"] = self._check_mx(domain)
            result["score"], result["issues"] = self._calculate_score(
                result["spf"], result["dmarc"], result["dkim"]
            )
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
        return result

    def _check_spf(self, domain: str) -> dict:
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=DEFAULT_TIMEOUT)
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
                if txt.startswith("v=spf1"):
                    valid = "all" in txt or "-all" in txt or "~all" in txt
                    return {"present": True, "valid": valid, "record": txt}
        except Exception:
            pass
        return {"present": False, "valid": False, "record": None}

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
            records = sorted([{"preference": r.preference, "exchange": str(r.exchange)} for r in answers], key=lambda x: x["preference"])
        except Exception:
            pass
        return {"records": records}

    def _calculate_score(self, spf, dmarc, dkim) -> tuple:
        score, issues = 10, []
        if not spf["present"]:
            score -= 3; issues.append("No SPF record — spoofing risk")
        elif not spf["valid"]:
            score -= 1; issues.append("SPF record exists but may be invalid")
        if not dmarc["present"]:
            score -= 4; issues.append("No DMARC record — phishing risk")
        elif dmarc["policy"] == "none":
            score -= 2; issues.append("DMARC policy is 'none' — monitoring only, no enforcement")
        elif dmarc["policy"] == "quarantine":
            score -= 1; issues.append("DMARC policy is 'quarantine' — consider upgrading to 'reject'")
        if not dkim["selectors_found"]:
            score -= 2; issues.append("No DKIM selectors found for common selector names")
        return max(0, score), issues


# ---------------------------------------------------------------------------
# 3. HTTP Security Headers
# ---------------------------------------------------------------------------

class HTTPHeaderChecker:
    """Checks for presence of security-related HTTP response headers."""

    HEADERS = {
        "content-security-policy": ("Content-Security-Policy", 20),
        "x-frame-options": ("X-Frame-Options", 15),
        "x-content-type-options": ("X-Content-Type-Options", 15),
        "strict-transport-security": ("Strict-Transport-Security", 20),
        "referrer-policy": ("Referrer-Policy", 15),
        "permissions-policy": ("Permissions-Policy", 15),
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "headers": {},
            "score": 0,
            "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"
            result["error"] = "requests not installed"
            return result
        try:
            r = requests.get(
                f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                allow_redirects=True, headers={"User-Agent": USER_AGENT}
            )
            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            total_weight, earned = 0, 0
            for key, (label, weight) in self.HEADERS.items():
                present = key in headers_lower
                result["headers"][label] = {
                    "present": present,
                    "value": headers_lower.get(key, None),
                }
                total_weight += weight
                if present:
                    earned += weight
                else:
                    result["issues"].append(f"Missing security header: {label}")
            result["score"] = round((earned / total_weight) * 100) if total_weight else 0
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 4. DNS & Infrastructure
# ---------------------------------------------------------------------------

class DNSInfrastructureChecker:
    """DNS records, reverse DNS, open ports, server fingerprinting."""

    HIGH_RISK_PORTS = {
        21: "FTP", 23: "Telnet", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
    }
    MEDIUM_RISK_PORTS = {
        22: "SSH", 25: "SMTP", 110: "POP3", 143: "IMAP",
    }
    INFO_PORTS = {
        80: "HTTP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    }
    ALL_PORTS = {**HIGH_RISK_PORTS, **MEDIUM_RISK_PORTS, **INFO_PORTS}

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "dns_records": {},
            "reverse_dns": None,
            "open_ports": [],
            "server_info": {},
            "issues": [],
            "risk_score": 0,
        }
        try:
            if DNS_AVAILABLE:
                result["dns_records"] = self._get_dns_records(domain)
                result["reverse_dns"] = self._get_reverse_dns(domain)
            result["open_ports"] = self._scan_ports(domain)
            result["server_info"] = self._fingerprint_server(domain)
            result["risk_score"], result["issues"] = self._assess_risk(result["open_ports"])
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
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
                    return {"port": port, "service": self.ALL_PORTS.get(port, "Unknown"), "risk": risk}
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
            r = requests.get(
                f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                allow_redirects=True, headers={"User-Agent": USER_AGENT}
            )
            for h in ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"]:
                if h in r.headers:
                    info[h] = r.headers[h]
        except Exception:
            pass
        return info

    def _assess_risk(self, open_ports: list) -> tuple:
        issues, score = [], 0
        for p in open_ports:
            if p["risk"] == "high":
                score += 40
                issues.append(f"High-risk port open: {p['port']} ({p['service']})")
            elif p["risk"] == "medium":
                score += 15
                issues.append(f"Medium-risk port open: {p['port']} ({p['service']})")
        return min(score, 150), issues


# ---------------------------------------------------------------------------
# 5. Breach / Credential Exposure
# ---------------------------------------------------------------------------

class BreachChecker:
    """Check Have I Been Pwned for domain breach exposure."""

    HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"

    def check(self, domain: str, api_key: Optional[str] = None) -> dict:
        result = {
            "status": "completed",
            "breach_count": 0,
            "breaches": [],
            "most_recent_breach": None,
            "data_classes": [],
            "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"
            result["error"] = "requests not installed"
            return result
        try:
            headers = {"User-Agent": USER_AGENT}
            if api_key:
                headers["hibp-api-key"] = api_key
            # Public endpoint — filter by domain
            r = requests.get(
                self.HIBP_URL, params={"domain": domain},
                headers=headers, timeout=DEFAULT_TIMEOUT
            )
            if r.status_code == 200:
                breaches = r.json()
                if breaches:
                    result["breach_count"] = len(breaches)
                    dates = []
                    all_classes = set()
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
                result["error"] = "HIBP API key required for detailed lookup"
            elif r.status_code == 404:
                pass  # No breaches found
            else:
                result["status"] = "error"
                result["error"] = f"HIBP API returned status {r.status_code}"
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 6. Website Security Basics
# ---------------------------------------------------------------------------

class WebsiteSecurityChecker:
    """HTTPS enforcement, cookies, mixed content, CMS detection."""

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
            "status": "completed",
            "https_enforced": False,
            "cookies": {"secure": True, "httponly": True, "samesite": True, "details": []},
            "mixed_content": False,
            "cms": {"detected": None, "version": None},
            "issues": [],
            "score": 0,
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"
            result["error"] = "requests not installed"
            return result
        try:
            result["https_enforced"] = self._check_https_redirect(domain)
            result["cookies"] = self._check_cookies(domain)
            result["mixed_content"] = self._check_mixed_content(domain)
            result["cms"] = self._detect_cms(domain)
            result["score"], result["issues"] = self._calculate_score(
                result["https_enforced"], result["cookies"], result["mixed_content"]
            )
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
        return result

    def _check_https_redirect(self, domain: str) -> bool:
        try:
            r = requests.get(
                f"http://{domain}", timeout=DEFAULT_TIMEOUT,
                allow_redirects=True, headers={"User-Agent": USER_AGENT}
            )
            return r.url.startswith("https://")
        except Exception:
            return False

    def _check_cookies(self, domain: str) -> dict:
        info = {"secure": True, "httponly": True, "samesite": True, "details": []}
        try:
            r = requests.get(
                f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                allow_redirects=True, headers={"User-Agent": USER_AGENT}
            )
            for cookie in r.cookies:
                detail = {
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("HttpOnly") or getattr(cookie, "_rest", {}).get("HttpOnly") is not None,
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
            r = requests.get(
                f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                allow_redirects=True, headers={"User-Agent": USER_AGENT}
            )
            content = r.text[:50000]
            return bool(re.search(r'<(?:script|img|link|iframe)[^>]+src=["\']http://', content, re.I))
        except Exception:
            return False

    def _detect_cms(self, domain: str) -> dict:
        try:
            r = requests.get(
                f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                allow_redirects=True, headers={"User-Agent": USER_AGENT}
            )
            text = r.text[:100000]
            all_headers = str(r.headers)
            combined = text + all_headers
            for cms, sigs in self.CMS_SIGNATURES.items():
                if any(sig in combined for sig in sigs):
                    version = None
                    if cms == "WordPress":
                        m = re.search(r'ver=(\d+\.\d+[\.\d]*)', text)
                        if m:
                            version = m.group(1)
                    return {"detected": cms, "version": version}
        except Exception:
            pass
        return {"detected": None, "version": None}

    def _calculate_score(self, https, cookies, mixed) -> tuple:
        score, issues = 100, []
        if not https:
            score -= 40; issues.append("HTTPS not enforced — HTTP does not redirect to HTTPS")
        if not cookies.get("secure", True):
            score -= 20; issues.append("Cookies missing Secure flag — transmitted over HTTP")
        if not cookies.get("httponly", True):
            score -= 15; issues.append("Cookies missing HttpOnly flag — XSS risk")
        if mixed:
            score -= 25; issues.append("Mixed content detected — HTTP resources loaded over HTTPS")
        return max(0, score), issues


# ---------------------------------------------------------------------------
# 7. Risk Scoring Engine
# ---------------------------------------------------------------------------

class RiskScorer:
    """Aggregates category results into a weighted 0-1000 risk score."""

    WEIGHTS = {
        "ssl": 0.25,
        "email": 0.20,
        "breaches": 0.20,
        "ports": 0.15,
        "headers": 0.10,
        "website": 0.10,
    }

    RECOMMENDATIONS = {
        "SSL certificate has EXPIRED": "Renew your SSL certificate immediately — an expired cert will cause browser warnings and erodes user trust.",
        "TLS 1.0 supported — deprecated and insecure": "Disable TLS 1.0 on your web server. Configure minimum TLS version to 1.2.",
        "TLS 1.1 supported — deprecated": "Disable TLS 1.1 on your web server. Modern clients support TLS 1.2+.",
        "No SPF record — spoofing risk": "Add an SPF record (e.g. 'v=spf1 include:_spf.google.com ~all') to prevent email spoofing.",
        "No DMARC record — phishing risk": "Add a DMARC record starting with 'v=DMARC1; p=quarantine' and monitor reports.",
        "DMARC policy is 'none' — monitoring only, no enforcement": "Upgrade DMARC policy from 'none' to 'quarantine' or 'reject' to block spoofed emails.",
        "No DKIM selectors found for common selector names": "Configure DKIM signing for outbound email and publish the public key in DNS.",
        "HTTPS not enforced — HTTP does not redirect to HTTPS": "Configure your web server to redirect all HTTP traffic to HTTPS (301 redirect).",
        "HSTS header missing": "Add Strict-Transport-Security header: 'max-age=31536000; includeSubDomains'.",
        "Missing security header: Content-Security-Policy": "Implement a Content Security Policy to mitigate XSS and data injection attacks.",
        "Missing security header: X-Frame-Options": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
        "Missing security header: X-Content-Type-Options": "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
        "Cookies missing Secure flag — transmitted over HTTP": "Set the Secure flag on all session cookies to prevent transmission over HTTP.",
        "Cookies missing HttpOnly flag — XSS risk": "Set the HttpOnly flag on all session cookies to prevent JavaScript access.",
        "Mixed content detected — HTTP resources loaded over HTTPS": "Update all embedded resource URLs to use HTTPS.",
    }

    def calculate(self, results: dict) -> tuple:
        """Returns (risk_score 0-1000, risk_level, recommendations)."""
        def normalise_risk(raw_score, max_raw):
            """Convert a raw score (higher=worse) to 0-100 risk scale."""
            return min(100, (raw_score / max_raw) * 100) if max_raw else 0

        # SSL: score is 0-100 quality → invert
        ssl_risk = 100 - results.get("ssl", {}).get("score", 50)

        # Email: score is 0-10 → invert to risk
        email_score = results.get("email_security", {}).get("score", 5)
        email_risk = (1 - email_score / 10) * 100

        # Breaches: scale by count
        breach_count = results.get("breaches", {}).get("breach_count", 0)
        breach_risk = min(100, breach_count * 20)

        # Ports: raw risk score capped at 150
        port_risk = normalise_risk(results.get("dns_infrastructure", {}).get("risk_score", 0), 150)

        # Headers: 0-100 quality → invert
        header_risk = 100 - results.get("http_headers", {}).get("score", 50)

        # Website: 0-100 quality → invert
        website_risk = 100 - results.get("website_security", {}).get("score", 50)

        weighted = (
            ssl_risk * self.WEIGHTS["ssl"] +
            email_risk * self.WEIGHTS["email"] +
            breach_risk * self.WEIGHTS["breaches"] +
            port_risk * self.WEIGHTS["ports"] +
            header_risk * self.WEIGHTS["headers"] +
            website_risk * self.WEIGHTS["website"]
        )

        risk_score = round(weighted * 10)  # Scale to 0-1000

        if risk_score >= 600:
            risk_level = "Critical"
        elif risk_score >= 400:
            risk_level = "High"
        elif risk_score >= 200:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # Gather all issues for recommendations
        all_issues = []
        for cat in results.values():
            if isinstance(cat, dict):
                all_issues.extend(cat.get("issues", []))

        recommendations = []
        seen = set()
        for issue in all_issues:
            for key, rec in self.RECOMMENDATIONS.items():
                if key in issue and key not in seen:
                    recommendations.append(rec)
                    seen.add(key)

        if breach_count > 0 and "breach_rec" not in seen:
            recommendations.append(
                f"Domain found in {breach_count} breach(es). Enforce strong password policies, "
                "consider credential monitoring, and notify affected users."
            )

        return risk_score, risk_level, recommendations


# ---------------------------------------------------------------------------
# Main Scanner
# ---------------------------------------------------------------------------

class SecurityScanner:
    """Orchestrates all checks and returns unified results."""

    def __init__(self, hibp_api_key: Optional[str] = None):
        self.hibp_api_key = hibp_api_key
        self.ssl_checker = SSLChecker()
        self.email_checker = EmailSecurityChecker()
        self.header_checker = HTTPHeaderChecker()
        self.dns_checker = DNSInfrastructureChecker()
        self.breach_checker = BreachChecker()
        self.website_checker = WebsiteSecurityChecker()
        self.scorer = RiskScorer()

    def scan(self, domain: str) -> dict:
        domain = domain.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]
        results = {
            "domain_scanned": domain,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_risk_score": 0,
            "risk_level": "Unknown",
            "categories": {},
            "recommendations": [],
        }

        checks = {
            "ssl": (self.ssl_checker.check, domain),
            "email_security": (self.email_checker.check, domain),
            "http_headers": (self.header_checker.check, domain),
            "dns_infrastructure": (self.dns_checker.check, domain),
            "breaches": (self.breach_checker.check, domain),
            "website_security": (self.website_checker.check, domain),
        }

        cat_results = {}
        with ThreadPoolExecutor(max_workers=6) as ex:
            futures = {}
            for name, (fn, arg) in checks.items():
                if name == "breaches":
                    futures[ex.submit(fn, arg, self.hibp_api_key)] = name
                else:
                    futures[ex.submit(fn, arg)] = name

            for future in as_completed(futures, timeout=120):
                name = futures[future]
                try:
                    cat_results[name] = future.result(timeout=DEFAULT_TIMEOUT * 2)
                except Exception as e:
                    cat_results[name] = {"status": "error", "error": str(e), "issues": []}

        results["categories"] = cat_results
        risk_score, risk_level, recommendations = self.scorer.calculate(cat_results)
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
