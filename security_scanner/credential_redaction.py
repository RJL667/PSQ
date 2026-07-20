"""Mask breached-credential identifiers (emails) at every point a scan result is
served to the browser or a downloadable report.

The credential checkers surface raw email addresses (DeHashed sample_emails /
breach_details, Hudson Rock, IntelX, ...). Manual 6.4 requires the dashboard and
the PDF reports to show only PARTIALLY-MASKED accounts (e.g. "jo***n@example.com")
so an organisation can recognise its own accounts while an outsider cannot
reconstruct them. The complete unmasked list (incl. actual passwords) is delivered
ONLY through the encrypted credential export, which re-queries DeHashed live at the
moment of export — so nothing here is needed for that path.

`redact_credentials` returns a REDACTED COPY; the stored scan is never mutated, and
it is applied at the serving boundary (JSON export, dashboard injection, PDF render)
so both new and already-stored scans are covered without a data migration.
"""
import re

# The negative lookbehind on '*' (and local-part chars) means an already-masked
# address like "jo***n@example.com" is left alone — only genuinely raw addresses
# match. Requires a normal char before the local part.
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-*])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# Categories that can carry breached-credential identifiers.
_CREDENTIAL_CATEGORIES = (
    "dehashed", "hudson_rock", "intelx", "credential_risk",
    "credential_correlation", "breaches", "info_disclosure",
)


def mask_email(email: str) -> str:
    """'john.doe@example.com' -> 'jo***e@example.com'. Short local parts fully
    masked ('ab@x.com' -> '***@x.com')."""
    local, sep, domain = email.partition("@")
    if not sep:
        return email
    if len(local) <= 3:
        return "***@" + domain
    return local[:2] + "***" + local[-1] + "@" + domain


def _mask(obj):
    if isinstance(obj, str):
        return _EMAIL_RE.sub(lambda m: mask_email(m.group(0)), obj)
    if isinstance(obj, list):
        return [_mask(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _mask(v) for k, v in obj.items()}
    return obj


def redact_credentials(results):
    """Return a copy of ``results`` with breached-credential emails masked in the
    credential-bearing categories. No-op when categories are absent. The original
    dict is not mutated (credential categories are replaced with masked copies)."""
    if not isinstance(results, dict):
        return results
    cats = results.get("categories")
    if not isinstance(cats, dict):
        return results
    out = dict(results)
    out_cats = dict(cats)
    for k in _CREDENTIAL_CATEGORIES:
        if k in out_cats:
            out_cats[k] = _mask(out_cats[k])
    out["categories"] = out_cats
    return out
