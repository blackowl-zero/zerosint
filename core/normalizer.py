"""
Normalizer: cleans the user's raw inputs and guesses their type.

Example: the user enters "user@example.com" -> detected as EMAIL, and
"example.com" is added automatically as a separate DOMAIN seed.
"""
from __future__ import annotations

import ipaddress
import re

from .models import EntityType, Finding

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

    def push(type_: str, value: str, derived_from: str | None = None) -> None:
        value = value.strip()
        if not value:
            return
        # derived_from marks a seed the user did not type themselves (the
        # orchestrator uses it to skip webmail domains)
        meta = {"derived_from": derived_from} if derived_from else {}
        f = Finding(type=type_, value=value, source="input", confidence=1.0, depth=0, meta=meta)
        if f.key in seen:
            if not derived_from:  # typed explicitly too: it is a real request
                for s in seeds:
                    if s.key == f.key:
                        s.meta.pop("derived_from", None)
                        if s.source == "input:derived":  # e.g. --username bob after --email bob@x
                            s.source, s.parent, s.confidence = "input", None, 1.0
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

        # auto-derive: email -> domain (webmail domains are dropped by the orchestrator)
        if t == EntityType.EMAIL and "@" in value:
            push(EntityType.DOMAIN, value.split("@", 1)[1], derived_from=value)
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
