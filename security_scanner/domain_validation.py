"""Scan-target input handling: normalise, validate syntax, prove existence.

Three separate questions, deliberately kept apart:

  normalize_domain()  what did the user actually mean?
  valid_domain()      is that a syntactically legal domain?
  domain_exists()     is it registered at all?

They were previously one syntax regex in app.py, and both other questions went
unasked. That produced two real failures:

  * A broker pasting a target out of a submission form got "Invalid or missing
    domain" for a domain that looked perfectly correct on screen, because the
    paste carried a zero-width character, a full URL, or an email address.
  * morgancarco.com (a typo of morgancargo.com) passed the syntax check and
    scanned to completion against nothing: 266 "Medium", 77% coverage, zero
    discovered IPs, and headline findings of "No SPF record" and "No DMARC
    record" that are vacuously true of a domain which does not exist.

Kept free of Flask so the regression gate can import it directly.
"""
import re

__all__ = ["normalize_domain", "valid_domain", "domain_exists"]

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

# Characters that survive a copy out of a PDF, a Word table or a web form and
# are invisible in the input box. U+200B/C/D and U+FEFF are the usual culprits;
# str.strip() does not remove them, so the regex rejects a domain the broker can
# see is correct. U+00A0 IS stripped by str.strip() but is listed for clarity.
_INVISIBLE = dict.fromkeys(map(ord,
    "​‌‍⁠﻿­‎‏‪‫‬"
    "‭‮⁦⁧⁨⁩"), None)


def normalize_domain(raw: str) -> str:
    """Best-effort extraction of the domain the user meant.

    Handles, in order: invisible characters, surrounding whitespace and quotes,
    a scheme, userinfo or a pasted email address, a path/query/fragment, a port,
    and a trailing root dot. Returns "" when nothing usable is left.

    Deliberately does NOT strip a leading "www.": that is a real hostname and
    the caller may genuinely mean it. Deciding apex-vs-www is a product choice,
    not an input-cleaning one.
    """
    if not raw:
        return ""
    s = str(raw).translate(_INVISIBLE).strip().strip("\"'<>").strip()
    if not s:
        return ""
    s = s.lower()
    # Scheme, including the ones a broker might paste out of a mail client.
    for scheme in ("https://", "http://", "ftp://", "//", "mailto:"):
        if s.startswith(scheme):
            s = s[len(scheme):]
    # An email address is an extremely common paste from a submission form;
    # the domain is the part the scan wants. Also covers URL userinfo.
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    # Path, query, fragment.
    for sep in ("/", "?", "#"):
        s = s.split(sep, 1)[0]
    # Port.
    if ":" in s:
        s = s.split(":", 1)[0]
    # A fully-qualified name may carry the root dot.
    return s.strip().rstrip(".")


def valid_domain(domain: str) -> bool:
    """Syntax only. Says nothing about whether the domain exists."""
    d = normalize_domain(domain)
    return bool(_DOMAIN_RE.match(d)) and len(d) <= 253


def domain_exists(domain: str, *, timeout: float = 5.0) -> bool:
    """Is this domain REGISTERED? (NXDOMAIN => no.)

    Deliberately narrow: this asks ONLY whether the name exists in DNS, not
    whether it serves anything. A registered domain with NS records but no A or
    MX is a thin but legitimate target -- parked brand-protection domains are a
    real part of an attack surface -- so it must still scan. Only NXDOMAIN,
    meaning the name is not registered at all, is rejected.

    Fails OPEN on resolver trouble. Refusing real work because our own DNS
    hiccupped is worse than the occasional scan of a dead name.
    """
    d = normalize_domain(domain)
    if not d:
        return False
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        # Without dnspython the stdlib cannot tell NXDOMAIN from "no A record",
        # so only a clean resolution proves existence and everything else is
        # let through rather than guessed at.
        import socket
        try:
            socket.gethostbyname(d)
        except Exception:
            pass
        return True

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    # NS first: it is the record that proves delegation, and it is present for
    # registered domains publishing neither A nor MX.
    for rdtype in ("NS", "A", "MX", "SOA"):
        try:
            resolver.resolve(d, rdtype)
            return True
        except dns.resolver.NXDOMAIN:
            return False            # authoritative: the name does not exist
        except dns.resolver.NoAnswer:
            continue                # exists, just not this record type
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            return True             # resolver trouble: fail open
        except Exception:
            return True
    return True
