"""
XposedModule: PASSIVE breach-exposure check via XposedOrNot (free, no key).

WHAT IT DOES (legal, passive):
- email -> asks XposedOrNot whether it appears in known breaches.
  Returns ONLY breach names, NOT passwords or other data.

Why it exists: an alternative to BreachModule (HIBP), which needs a paid key.
If both run, the orchestrator dedups by Finding.key, and the same breach from
two sources just raises the confidence in the correlator.

Public API rate limits (per IP): 2 req/sec, 25/hour, 100/day.
So: one request per email, at most one retry on 429.
"""
from __future__ import annotations

import logging
import time
from urllib.parse import quote

import requests

from core.models import EntityType, Finding
from .base import BaseModule

log = logging.getLogger("osint")

XPOSED_API = "https://api.xposedornot.com/v1/check-email/{email}"
USER_AGENT = "zerosint/0.1"
TIMEOUT = 20
MAX_RETRY_WAIT = 10  # seconds, upper bound for Retry-After


def _flatten(breaches) -> list[str]:
    """
    The API returns a nested list: [["Adobe", "LinkedIn"]]. Flatten it, keep
    only non-empty strings and drop duplicates (in arrival order).
    """
    out: list[str] = []
    stack = [breaches]
    while stack:
        item = stack.pop()
        if isinstance(item, list):
            stack.extend(reversed(item))  # reversed -> keeps the order
        elif isinstance(item, str) and item.strip() and item.strip() not in out:
            out.append(item.strip())
    return out


class XposedModule(BaseModule):
    name = "xposedornot"
    accepts = {EntityType.EMAIL}
    requires_binary = None  # pure python

    def available(self) -> bool:
        # needs no key and no binary
        return True

    def _get(self, email: str) -> requests.Response | None:
        """GET with one retry on 429. None = failure (already logged)."""
        for attempt in range(2):
            try:
                r = requests.get(
                    XPOSED_API.format(email=quote(email, safe="@")),
                    headers={"User-Agent": USER_AGENT},
                    timeout=TIMEOUT,
                )
            except requests.RequestException as e:
                log.warning("[%s] request error: %s", self.name, e)
                return None

            if r.status_code != 429:
                return r
            if attempt == 0:
                # rate limit -> wait as long as Retry-After says (capped) and retry ONCE
                try:
                    wait = int(r.headers.get("retry-after", "2"))
                except ValueError:
                    wait = 2
                wait = max(0, min(wait, MAX_RETRY_WAIT))
                log.info("[%s] 429 rate limited, retrying in %ss", self.name, wait)
                time.sleep(wait)

        log.warning("[%s] still rate limited for %s, giving up", self.name, email)
        return None

    def run(self, seed: Finding) -> list[Finding]:
        r = self._get(seed.value)
        if r is None:
            return []

        try:
            data = r.json()
        except ValueError:
            data = None

        # clean: {"Error": "Not found"} (may come with 404 or 200)
        if isinstance(data, dict) and str(data.get("Error", "")).lower() == "not found":
            return []
        if r.status_code != 200:
            log.warning("[%s] HTTP %s for %s", self.name, r.status_code, seed.value)
            return []
        if not isinstance(data, dict):
            log.warning("[%s] bad JSON for %s", self.name, seed.value)
            return []

        findings: list[Finding] = []
        for name in _flatten(data.get("breaches", [])):
            findings.append(
                Finding(
                    type=EntityType.BREACH,
                    value=name,
                    source=self.name,
                    parent=seed.value,
                    confidence=0.85,  # reliable, slightly below HIBP
                    depth=seed.depth + 1,
                    # the correlator needs "account" for the breach cross-link
                    meta={"account": seed.value},
                )
            )
        return findings
