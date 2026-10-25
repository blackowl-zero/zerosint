"""
SpiderfootModule: broad scan of domain/email/ip via the SpiderFoot CLI.

Runs SpiderFoot's CLI with `-s <target> -o json` and parses the JSON. It is
found as, in order: sf.py on PATH, SPIDERFOOT_PATH/sf.py, or the `spiderfoot`
command (the Kali/Debian package's wrapper around sf.py). SpiderFoot is
heavy, so we set a timeout and a limited set of passive modules, and only
run it on the user's own inputs. Degrades gracefully if missing.

Output shape (SpiderFoot 4.x, -o json): a JSON array of
    {"generated": int, "type": "Internet Name", "data": str, "module": str, "source": str}

WARNING: a full scan can take hours. Here we use passive-only modules and a
short timeout so the pipeline is not blocked.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil

from core.models import EntityType, Finding
from .base import BaseModule

log = logging.getLogger("osint")

# map SpiderFoot event types -> our EntityType
SF_EVENT_MAP = {
    "EMAILADDR": EntityType.EMAIL,
    "DOMAIN_NAME": EntityType.DOMAIN,
    "INTERNET_NAME": EntityType.SUBDOMAIN,
    "IP_ADDRESS": EntityType.IP,
    "USERNAME": EntityType.USERNAME,
    "SOCIAL_MEDIA": EntityType.PROFILE_URL,
    "ACCOUNT_EXTERNAL_OWNED": EntityType.PROFILE_URL,
}

# `sf.py -o json` writes the human-readable name in "type" (e.g. "Internet Name",
# from tbl_event_types.event_descr), not the code. Accept both.
SF_DESCR_TO_CODE = {
    "Email Address": "EMAILADDR",
    "Domain Name": "DOMAIN_NAME",
    "Internet Name": "INTERNET_NAME",
    "IP Address": "IP_ADDRESS",
    "Username": "USERNAME",
    "Social Media Presence": "SOCIAL_MEDIA",
    "Account on External Site": "ACCOUNT_EXTERNAL_OWNED",
}

# passive, key-less modules (safe default)
SF_MODULES = "sfp_dnsresolve,sfp_crt,sfp_email,sfp_names,sfp_social,sfp_whois"

SFURL_RE = re.compile(r"<SFURL>(.*?)</SFURL>", re.S)


def clean_sf_data(data: str) -> str:
    """SpiderFoot wraps URLs: 'Twitter: <SFURL>https://..</SFURL>' -> 'https://..'."""
    m = SFURL_RE.search(data)
    return m.group(1).strip() if m else data


class SpiderfootModule(BaseModule):
    name = "spiderfoot"
    accepts = {EntityType.DOMAIN, EntityType.EMAIL, EntityType.IP}
    requires_binary = "spiderfoot"  # informational: available() also accepts sf.py

    def _locate(self) -> str | None:
        exe = shutil.which("sf.py")
        if exe:
            return exe
        base = os.getenv("SPIDERFOOT_PATH", "").strip()
        if base:
            cand = os.path.join(base, "sf.py")
            if os.path.exists(cand):
                return cand
        # Kali/Debian package: /usr/bin/spiderfoot, a wrapper that runs sf.py "$@"
        return shutil.which("spiderfoot")

    def _command(self) -> list[str] | None:
        """How to start SpiderFoot: sf.py through python3, the wrapper directly."""
        sf = self._locate()
        if not sf:
            return None
        return ["python3", sf] if sf.endswith("sf.py") else [sf]

    def available(self) -> bool:
        return self._locate() is not None

    def handles(self, seed: Finding) -> bool:
        # SpiderFoot is the slowest module (up to 600s per target), so it only
        # runs on the user's own inputs, never on pivoted findings.
        return seed.depth == 0 and super().handles(seed)

    def run(self, seed: Finding) -> list[Finding]:
        base_cmd = self._command()
        if not base_cmd:
            log.info("[spiderfoot] spiderfoot not found (no `spiderfoot` or sf.py on PATH, "
                     "SPIDERFOOT_PATH not set), skip %s", seed.value)
            return []

        cmd = [
            *base_cmd,
            "-s", seed.value,
            "-m", SF_MODULES,
            "-o", "json",
            "-q",  # quiet
        ]
        rc, out, _err = self._exec(cmd, timeout=600)
        if rc == -1 or not out.strip():
            return []

        try:
            rows = json.loads(out)
        except json.JSONDecodeError:
            log.warning("[spiderfoot] could not parse JSON output")
            return []

        findings: list[Finding] = []
        seen: set[str] = set()
        for row in rows:
            event_type = row.get("type") if isinstance(row, dict) else None
            data = row.get("data") if isinstance(row, dict) else None
            if not event_type or not data:
                continue
            data = clean_sf_data(str(data))
            event_type = SF_DESCR_TO_CODE.get(event_type, event_type)
            mapped = SF_EVENT_MAP.get(event_type)
            if not mapped:
                continue
            k = f"{mapped}:{data}".lower()
            if k in seen:
                continue
            seen.add(k)
            findings.append(Finding(
                type=mapped, value=str(data), source=self.name,
                parent=seed.value, confidence=0.6, depth=seed.depth + 1,
                meta={"sf_event": event_type},
            ))
        return findings
