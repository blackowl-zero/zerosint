"""
BreachModule: PASSIVE breach-exposure check.

WHAT IT DOES (legal, passive):
- email/username -> asks HaveIBeenPwned whether it appears in known breaches.
  It does not test anything anywhere; it only queries a database of past leaks.
  Returns breach NAMES, NOT passwords.

WHAT IT DOES NOT DO (and never will):
- Does not test creds on login forms (credential stuffing = unauthorized access).

The HIBP account API needs an API key (HIBP_API_KEY in .env). Without a key it
degrades gracefully. There is also a standalone utility `check_password_pwned()`
that uses k-anonymity to check YOUR OWN password without ever sending it.
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from urllib.parse import quote

import requests

from core.models import EntityType, Finding
from .base import BaseModule

log = logging.getLogger("osint")

HIBP_API = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
PWNED_PW_API = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "zerosint-research/0.1"

# HIBP 429 handling: up to MAX_RETRIES retries, waiting Retry-After seconds when
# the header is a number, otherwise BACKOFF_BASE * 2**n. Every wait is capped.
MAX_RETRIES = 3
BACKOFF_BASE = 1
MAX_RETRY_WAIT = 10  # seconds


def check_password_pwned(password: str) -> int:
    """
    Standalone utility. Checks whether a password has leaked, using k-anonymity:
    only the first 5 chars of the SHA-1 hash are sent. The full password never
    leaves the machine. Returns how many times it appeared (0 = clean).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(
            PWNED_PW_API.format(prefix=prefix),
            headers={"User-Agent": USER_AGENT},
            timeout=15,
        )
        r.raise_for_status()
    except requests.RequestException as e:
        log.warning("[breach] pwned-passwords error: %s", e)
        return -1
    for line in r.text.splitlines():
        h, sep, count = line.partition(":")
        if not sep:
            continue  # not a "HASH:COUNT" line
        if h.strip() == suffix:
            return int(count)
    return 0


class BreachModule(BaseModule):
    name = "breach"
    accepts = {EntityType.EMAIL, EntityType.USERNAME}
    requires_binary = None  # pure python

    def __init__(self) -> None:
        self.api_key = os.getenv("HIBP_API_KEY", "").strip()

    def available(self) -> bool:
        return bool(self.api_key)

    def _get(self, account: str) -> requests.Response | None:
        """GET with bounded retries on 429. None = failure (already logged)."""
        url = HIBP_API.format(account=quote(account, safe="@"))
        for attempt in range(MAX_RETRIES + 1):
            try:
                r = requests.get(
                    url,
                    headers={"hibp-api-key": self.api_key, "User-Agent": USER_AGENT},
                    params={"truncateResponse": "false"},
                    timeout=20,
                )
            except requests.RequestException as e:
                log.warning("[breach] request error: %s", e)
                return None
            if r.status_code != 429:
                return r
            if attempt == MAX_RETRIES:
                break
            try:
                wait = int(r.headers.get("retry-after", ""))
            except ValueError:
                wait = BACKOFF_BASE * 2 ** attempt
            wait = max(0, min(wait, MAX_RETRY_WAIT))
            log.info("[breach] 429 rate limited, retry %d/%d in %ss",
                     attempt + 1, MAX_RETRIES, wait)
            time.sleep(wait)

        log.error("[breach] HIBP still rate limited for %s after %d retries, skipping",
                  account, MAX_RETRIES)
        return None

    def run(self, seed: Finding) -> list[Finding]:
        if not self.api_key:
            log.info("[breach] no HIBP_API_KEY, skipping %s", seed.value)
            return []

        r = self._get(seed.value)
        if r is None:
            return []
        if r.status_code == 404:
            return []  # clean, no breach
        if r.status_code != 200:
            log.warning("[breach] HTTP %s for %s", r.status_code, seed.value)
            return []

        findings: list[Finding] = []
        for b in r.json():
            name = b.get("Name", "unknown")
            findings.append(
                Finding(
                    type=EntityType.BREACH,
                    value=name,
                    source=self.name,
                    parent=seed.value,
                    confidence=0.9,  # HIBP is a reliable source
                    depth=seed.depth + 1,
                    meta={
                        "domain": b.get("Domain"),
                        "breach_date": b.get("BreachDate"),
                        "data_classes": b.get("DataClasses", []),
                        "account": seed.value,
                    },
                )
            )
        return findings
