"""
Normalizer: cleans the user's raw inputs and guesses their type.

Example: the user enters "user@example.com" -> detected as EMAIL, and
"example.com" is added automatically as a separate DOMAIN seed.
"""
from __future__ import annotations

import ipaddress
import logging
import re

from .models import EntityType, Finding

log = logging.getLogger("osint")

# Free webmail providers. An email on one of these says nothing about the
# target's own infrastructure, so its domain is NOT added as a seed (that would
# make theHarvester/recon-ng/SpiderFoot scan e.g. all of gmail.com).
# An explicit --domain is still scanned.
FREEMAIL_DOMAINS: frozenset[str] = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.gr", "ymail.com",
    "hotmail.com", "hotmail.gr", "outlook.com", "outlook.com.gr", "live.com",
    "msn.com", "icloud.com", "me.com", "mac.com", "aol.com", "proton.me",
    "protonmail.com", "pm.me", "gmx.com", "gmx.de", "gmx.net", "yandex.com",
    "yandex.ru", "mail.ru", "zoho.com", "tutanota.com", "tuta.io", "otenet.gr",
    "windowslive.com",
})

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$", re.I)
PHONE_RE = re.compile(r"^\+?[\d\s().-]{7,}$")
URL_RE = re.compile(r"^https?://", re.I)


def detect_type(value: str) -> str:
    """Guess the type of a raw string."""
    v = value.strip()
    if not v:
        return EntityType.UNKNOWN

    if URL_RE.match(v):
        return EntityType.PROFILE_URL
    if EMAIL_RE.match(v):
        return EntityType.EMAIL
    # IP (v4 or v6)
    try:
        ipaddress.ip_address(v)
        return EntityType.IP
    except ValueError:
        pass
    if DOMAIN_RE.match(v):
        return EntityType.DOMAIN
    if PHONE_RE.match(v) and sum(c.isdigit() for c in v) >= 7:
        return EntityType.PHONE
    if " " in v:
        return EntityType.NAME
    # anything left (a single word with no spaces or dots) is treated as a username
    return EntityType.USERNAME


def normalize(raw_inputs: dict[str, str]) -> list[Finding]:
    """
    Takes a dict from the CLI (e.g. {"email": "..", "username": ".."})
    and returns a list of seeds. Empty fields are ignored.
    If the user declares the type explicitly it is kept; otherwise it is guessed.
    """
    seeds: list[Finding] = []
    seen: set[str] = set()

    def push(type_: str, value: str) -> None:
        value = value.strip()
        if not value:
            return
        f = Finding(type=type_, value=value, source="input", confidence=1.0, depth=0)
        if f.key in seen:
            return
        seen.add(f.key)
        seeds.append(f)

    for declared_type, value in raw_inputs.items():
        value = (value or "").strip()
        if not value:
            continue
        # if the key is a known type, trust it; otherwise auto-detect
        t = declared_type if declared_type in EntityType._value2member_map_ else detect_type(value)
        push(t, value)

        # auto-derive: email -> domain (not for free webmail providers)
        if t == EntityType.EMAIL and "@" in value:
            domain = value.split("@", 1)[1]
            if domain.lower() in FREEMAIL_DOMAINS:
                log.info("Not scanning webmail domain %s (from %s)", domain, value)
            else:
                push(EntityType.DOMAIN, domain)
        # auto-derive: email local-part -> candidate username (low confidence)
        if t == EntityType.EMAIL and "@" in value:
            local = value.split("@", 1)[0]
            if local and "." not in local:
                f = Finding(
                    type=EntityType.USERNAME, value=local, source="input:derived",
                    parent=value, confidence=0.4, depth=0,
                )
                if f.key not in seen:
                    seen.add(f.key)
                    seeds.append(f)

    return seeds
