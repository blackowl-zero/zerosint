"""
MaigretModule: username -> profiles on hundreds of sites.

Runs the maigret CLI with JSON output and parses it. Degrades gracefully if
maigret is not installed.

Note on confidence: Maigret produces a fair number of false positives. The
same username on 50 sites does NOT mean the same person, so we start with a
medium confidence and the correlator raises it if other sources agree.
"""
from __future__ import annotations

import glob
import json
import logging
import os
import tempfile

from core.models import EntityType, Finding
from .base import BaseModule

log = logging.getLogger("osint")


class MaigretModule(BaseModule):
    name = "maigret"
    accepts = {EntityType.USERNAME}
    requires_binary = "maigret"

    def run(self, seed: Finding) -> list[Finding]:
        if not self.available():
            log.info("[maigret] binary missing, skip %s", seed.value)
            return []

        outdir = tempfile.mkdtemp(prefix="maigret_")
        cmd = [
            "maigret", seed.value,
            "--json", "simple",
            "--folderoutput", outdir,
            "--no-progressbar",
            "--timeout", "15",
        ]
        rc, _out, _err = self._exec(cmd, timeout=300)
        if rc == -1:
            return []

        # maigret writes <username>_simple.json to outdir
        matches = glob.glob(os.path.join(outdir, f"*{seed.value}*.json"))
        if not matches:
            return []

        findings: list[Finding] = []
        try:
            with open(matches[0], encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            log.warning("[maigret] parse error: %s", e)
            return []

        for site, info in data.items():
            status = info.get("status", {})
            # keep only claimed/found
            if (status.get("status") or "").lower() not in ("claimed", "found"):
                continue
            url = info.get("url_user") or status.get("url") or ""
            if not url:
                continue
            findings.append(
                Finding(
                    type=EntityType.PROFILE_URL,
                    value=url,
                    source=self.name,
                    parent=seed.value,
                    confidence=0.55,   # medium, see note above
                    depth=seed.depth + 1,
                    meta={"site": site, "username": seed.value},
                )
            )
        return findings
