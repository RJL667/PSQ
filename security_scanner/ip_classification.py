# -*- coding: utf-8 -*-
"""Classify a discovered IP by WHO OPERATES THE HOST, so the scanner attributes
exposures to the right party.

WHY THIS EXISTS (checker audit, 2026-06-30 — real takealot.com scan):
    IPs reach the port/protocol/CVE checkers from four sources (apex A-records,
    broker client_ips, subdomain-resolved IPs, origin candidates). Only the
    ORIGIN source was ever classified (cert-match in origin_discovery). The
    subdomain-IP expansion (939cfe4, 2026-03-31) and the apex A-records went in
    RAW. When subdomain discovery widened (8d2663b, 2026-06-02), 41 third-party
    IPs got port-scanned and attributed to takealot as its OWN exposure —
    including a HostRocket shared host (FTP + "exposed Jupyter Notebook") behind
    success-network.takealot.com, plus RFC1918 internal hosts leaked in DNS.

POLICY (broker-confirmed 2026-06-30): attribute on WHO OPERATES THE HOST.
    - INSURED-OPERATED -> OWNED, scanned + attributed as the insured's exposure:
      dedicated IPs, cert-verified origins, and IaaS VMs the insured runs
      (AWS EC2, GCE, Azure VM). An exposed Jenkins/DB/admin on the insured's own
      cloud VM IS their risk — exactly what an external scan must catch.
    - VENDOR-OPERATED -> THIRD-PARTY, surfaced under supply-chain, NOT scanned:
      CDN edges (CloudFront/Akamai/Cloudflare/Fastly), managed SaaS
      (Zendesk/WP Engine/Salesforce), shared hosting (HostRocket), managed load
      balancers (AWS ELB). The provider patches the host; its exposure is the
      provider's risk and a supply-chain dependency for the insured.
    - PRIVATE (RFC1918) -> never scanned; an info-disclosure finding (public DNS
      exposing internal infrastructure).

Signals, strongest first: reverse-DNS suffix (PTR is set by the IP owner), HTTP
Server banner, Shodan org/isp. Default is OWNED — a host is only re-homed to
third-party on a POSITIVE vendor signal, so the insured's own infra (including
no-PTR hosts) is never silently dropped from coverage.

review-by: 2026-12-30  (provider tables are point-in-time; re-confirm)
"""
import ipaddress

# Buckets. OWNED is the only scannable / own-attributed bucket.
OWNED = "owned"
PRIVATE = "private"
CDN = "cdn"      # vendor-operated edge / managed LB
SAAS = "saas"    # vendor-operated SaaS / shared hosting
THIRD_PARTY_BUCKETS = (CDN, SAAS)

# --- VENDOR-operated reverse-DNS suffixes -> (bucket, label). Checked first. ---
_CDN_RDNS = {
    "cloudfront.net": "Amazon CloudFront",
    "akamaitechnologies.com": "Akamai", "akamai.net": "Akamai",
    "akamaized.net": "Akamai", "akamaihd.net": "Akamai",
    "edgekey.net": "Akamai", "edgesuite.net": "Akamai",
    "fastly.net": "Fastly",
}
_SAAS_RDNS = {
    "exacttarget.com": "Salesforce Marketing Cloud",
    "zendesk.com": "Zendesk",
    "wpengine.com": "WP Engine",
    "directorysecure.com": "HostRocket (shared host)",
    "herokuapp.com": "Heroku", "herokudns.com": "Heroku",
    "vercel.app": "Vercel", "netlify.app": "Netlify",
    "myshopify.com": "Shopify", "github.io": "GitHub Pages",
    "squarespace.com": "Squarespace", "wixsite.com": "Wix",
}

# --- INSURED-operated IaaS reverse-DNS markers -> OWNED (scanned). Checked AFTER
# the vendor suffixes so a CloudFront/ELB host on AWS is never mistaken for the
# insured's own EC2 instance. ---
_IAAS_RDNS = (
    "compute.amazonaws.com", "compute-1.amazonaws.com",   # AWS EC2
    "googleusercontent.com",                              # GCE
    "cloudapp.azure.com",                                 # Azure VM
)

# --- HTTP Server banner -> vendor-operated (managed edge / LB). ---
_VENDOR_BANNER = (
    ("cloudflare", (CDN, "Cloudflare")),
    ("cloudfront", (CDN, "Amazon CloudFront")),
    ("akamaighost", (CDN, "Akamai")),
    ("awselb", (CDN, "AWS ELB (managed LB)")),
)

# --- Shodan org/isp substring -> (bucket, label) for VENDOR-operated only. ---
_VENDOR_ORG = (
    ("cloudflare", (CDN, "Cloudflare")),
    ("akamai", (CDN, "Akamai")),
    ("fastly", (CDN, "Fastly")),
    ("zendesk", (SAAS, "Zendesk")),
    ("wpengine", (SAAS, "WP Engine")),
    ("wp engine", (SAAS, "WP Engine")),
    ("salesforce", (SAAS, "Salesforce")),
    ("exacttarget", (SAAS, "Salesforce Marketing Cloud")),
    ("hostrocket", (SAAS, "HostRocket (shared host)")),
    ("shopify", (SAAS, "Shopify")),
)

# --- Shodan org substrings for IaaS providers -> OWNED (insured runs the VM). ---
_IAAS_ORG = ("amazon", "google", "microsoft", "azure", "digitalocean",
             "linode", "hetzner", "ovh", "vultr")


def _suffix_match(host, suffix):
    return host == suffix or host.endswith("." + suffix)


def classify_ip(ip, reverse_dns=None, org=None, banner=None,
                default_cert_names=None, insured_domain=None):
    """Classify *ip* by who operates the host.

    Returns (bucket, provider_label). bucket is OWNED / PRIVATE / CDN / SAAS.
    Only OWNED is port-scanned and attributed as the insured's own exposure.
    """
    # 1. private / reserved — never scan, never attribute.
    try:
        obj = ipaddress.ip_address(str(ip))
    except ValueError:
        return (OWNED, "")
    if obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved or obj.is_multicast:
        return (PRIVATE, "internal")

    rdns = (reverse_dns or "").strip().rstrip(".").lower()
    orgl = (org or "").strip().lower()
    bannerl = (banner or "").strip().lower()

    # 2. reverse-DNS VENDOR suffixes (CDN, then SaaS / shared hosting).
    if rdns:
        for suf, label in _CDN_RDNS.items():
            if _suffix_match(rdns, suf):
                return (CDN, label)
        for suf, label in _SAAS_RDNS.items():
            if _suffix_match(rdns, suf):
                return (SAAS, label)

    # 3. HTTP Server banner — managed edge / LB. Checked BEFORE the IaaS
    #    reverse-DNS rule so a managed AWS ELB (banner 'awselb', but an
    #    ec2-*.compute.amazonaws.com PTR) is not mistaken for an insured EC2 VM.
    for kw, (bucket, label) in _VENDOR_BANNER:
        if kw in bannerl:
            return (bucket, label)

    # 3b. SHARED / MANAGED HOSTING, by the box's DEFAULT certificate.
    #     Must run BEFORE the IaaS rules: providers like Hetzner sell both
    #     customer-operated servers AND managed hosting under the same rDNS and
    #     the same org string, so those rules would otherwise claim it as the
    #     insured's own. Only fires on a POSITIVE reading; unknown falls through.
    if looks_multi_tenant(default_cert_names, insured_domain) is True:
        _sample = sorted(default_cert_names)[0] if default_cert_names else "?"
        return (SAAS, "shared/managed hosting (default cert %s)" % _sample)

    # 4. INSURED-operated IaaS VMs by reverse-DNS -> OWNED (scanned).
    if rdns:
        for suf in _IAAS_RDNS:
            if _suffix_match(rdns, suf):
                return (OWNED, "cloud IaaS (insured-operated)")

    # 5. Shodan org/isp: VENDOR SaaS/CDN first, then IaaS providers (OWNED).
    for kw, (bucket, label) in _VENDOR_ORG:
        if kw in orgl:
            return (bucket, label)
    if any(kw in orgl for kw in _IAAS_ORG):
        return (OWNED, "cloud IaaS (insured-operated)")

    # 5. no vendor signal -> OWNED (conservatively scanned; coverage preserved).
    return (OWNED, "")


def is_scannable(bucket):
    """Only the insured's own infrastructure is actively port-scanned."""
    return bucket == OWNED


def is_third_party(bucket):
    return bucket in THIRD_PARTY_BUCKETS


# --- shared / managed hosting detection -----------------------------------
#
# THE PROBLEM THIS SOLVES (phishield.com, 2026-08-18). 213.133.105.171 serves
# phishield.com and exposes MySQL 3306 + PostgreSQL 5432 to the internet. It was
# attributed to the insured as OWNED, "cloud IaaS (insured-operated)", so the
# report told a broker the client had an internet-facing database and advised
# closing a port the client cannot reach. It is a Hetzner MANAGED SHARED box and
# the client is one tenant on it.
#
# Reverse DNS cannot separate the two: Hetzner sells both customer-operated
# servers and managed hosting, and both live under your-server.de. A provider
# name list cannot either -- it is point-in-time and every provider is different.
#
# THE SIGNAL THAT ACTUALLY SEPARATES THEM is the certificate the box serves when
# you connect with NO SNI. That is the platform's own identity:
#   * a single-tenant server you operate presents YOUR certificate either way;
#   * a multi-tenant platform presents the PROVIDER's default (here
#     CN=*.your-server.de) and only serves your cert once SNI names you.
# Only the platform operator controls the default vhost, so it is hard to spoof,
# it needs no API or subscription, and it generalises to every shared host
# instead of the ones we happened to list.
def _cert_covers(names, domain):
    """Does a certificate name set cover *domain* (wildcards honoured)?"""
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        return False
    for n in names or ():
        n = (n or "").strip().lower().rstrip(".")
        if not n:
            continue
        if n == d:
            return True
        if n.startswith("*."):
            # RFC 6125: one label only. *.a.com covers x.a.com, not y.x.a.com.
            base = n[2:]
            if d.endswith("." + base) and d.count(".") == base.count(".") + 1:
                return True
    return False


def probe_default_cert(ip, timeout=5.0, port=443):
    """Certificate names the host serves with NO SNI, or None if unavailable.

    Returns a set of lowercase names (CN + subjectAltName DNS entries). None
    means "could not tell" -- the caller must then fall back to the existing
    behaviour rather than guessing, because absence of evidence is not evidence
    of single tenancy.
    """
    import socket, ssl as _ssl
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False              # we WANT the default vhost's cert
    ctx.verify_mode = _ssl.CERT_NONE        # self-signed defaults are still evidence
    try:
        with socket.create_connection((str(ip), port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock) as ss:   # deliberately no server_hostname
                der = ss.getpeercert(binary_form=True)
        if not der:
            return None
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.serialization import Encoding
            cert = x509.load_der_x509_certificate(der)
            names = set()
            for a in cert.subject:
                if a.oid._name in ("commonName", "common_name"):
                    names.add(str(a.value).lower())
            try:
                san = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName).value
                names.update(n.lower() for n in san.get_values_for_type(x509.DNSName))
            except Exception:
                pass
            return names or None
        except ImportError:
            # No cryptography: fall back to the stdlib decoded form, which needs
            # a verifying context. Better to report "unknown" than to guess.
            return None
    except Exception:
        return None


def looks_multi_tenant(default_cert_names, insured_domain):
    """True when the box's DEFAULT identity does not include the insured.

    None (unknown) whenever we could not read a default certificate, so the
    caller keeps its existing behaviour instead of inventing a verdict.
    """
    if not default_cert_names or not insured_domain:
        return None
    return not _cert_covers(default_cert_names, insured_domain)
