"""
Free webmail providers.

An address on one of these says nothing about the target's own
infrastructure, so their domains are never scanned unless the user asks for
one explicitly with --domain. The orchestrator applies this rule in one place
for every finding, whichever module or input it comes from.
"""
from __future__ import annotations

FREEMAIL_DOMAINS: frozenset[str] = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.gr", "ymail.com",
    "hotmail.com", "hotmail.gr", "outlook.com", "outlook.com.gr", "live.com",
    "msn.com", "icloud.com", "me.com", "mac.com", "aol.com", "proton.me",
    "protonmail.com", "pm.me", "gmx.com", "gmx.de", "gmx.net", "yandex.com",
    "yandex.ru", "mail.ru", "zoho.com", "tutanota.com", "tuta.io", "otenet.gr",
    "windowslive.com",
})

# finding types that name a domain and would be scanned as one
DOMAIN_TYPES = frozenset({"domain", "subdomain", "host"})


def _norm(value: str) -> str:
    return value.strip().lower().rstrip(".")


def is_under(value: str, domain: str) -> bool:
    """value == domain, or a subdomain of it."""
    v, d = _norm(value), _norm(domain)
    return v == d or v.endswith("." + d)


def is_webmail(value: str) -> bool:
    """gmail.com, mail.gmail.com, ... (case-insensitive)."""
    return any(is_under(value, d) for d in FREEMAIL_DOMAINS)
