"""
HarvesterModule: domain -> emails, subdomains, hosts.

Runs theHarvester with -f JSON output and parses it. Degrades gracefully if missing.
Emails it finds become new seeds (pivot), so the breach check runs on them.

Notes (checked against theHarvester 4.11.1):
- One unsupported name in -b makes theHarvester print "Invalid source" and exit
  without writing any file. `bing` was removed upstream, so it is not used here.
- With `-f <dir>/out.json` it writes <dir>/out.xml and <dir>/out.json.
  JSON shape: {"cmd": str, "hosts": ["host" or "host:ip", ...],
  "emails": [...], "ips": [...], "shodan": [...], ...}; keys appear only when
  there is data.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import tempfile

from core.models import EntityType, Finding
from .base import BaseModule

log = logging.getLogger("osint")

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z]{2,63}$", re.I)


def clean_host(raw: str) -> str | None:
    """'host:ip' -> 'host'. Fix URL-encoding leftovers ('2Fdocs.x.com' from '%2Fdocs.x.com')."""
    host = str(raw).split(":")[0].strip().strip(".")
    # only the uppercase "2F" of an encoded "/"; a real name like "2fa.x.com" is kept
    if host.startswith("2F") and HOST_RE.match(host[2:]):
        host = host[2:]
    host = host.lower()
    return host if HOST_RE.match(host) else None


class HarvesterModule(BaseModule):
    name = "theharvester"
    accepts = {EntityType.DOMAIN}
    requires_binary = "theHarvester"

    # sources that need no API key (safe default). All must be valid for the
    # installed version, or theHarvester rejects the whole run.
    SOURCES = "crtsh,duckduckgo,hackertarget,rapiddns,otx"

    def available(self) -> bool:
        # the binary may be named theHarvester or theharvester
        import shutil
        return bool(shutil.which("theHarvester") or shutil.which("theharvester"))

    def _binary(self) -> str:
        import shutil
        return shutil.which("theHarvester") or shutil.which("theharvester") or "theHarvester"

    def run(self, seed: Finding) -> list[Finding]:
        if not self.available():
            log.info("[theharvester] binary missing, skip %s", seed.value)
            return []

        outdir = tempfile.mkdtemp(prefix="harvest_")
        try:
            return self._run_in(seed, outdir)
        finally:
            shutil.rmtree(outdir, ignore_errors=True)

    def _run_in(self, seed: Finding, outdir: str) -> list[Finding]:
        # give the file an extension: theHarvester derives .xml/.json by
        # splitting on the last dot of the whole path
        json_path = os.path.join(outdir, "out.json")
        cmd = [
            self._binary(),
            "-d", seed.value,
            "-b", self.SOURCES,
            "-f", json_path,
        ]
        rc, out, _err = self._exec(cmd, timeout=300)
        if rc == -1:
            return []
        if not os.path.exists(json_path):
            # theHarvester prints its errors on stdout ("[!] Invalid source.")
            tail = " | ".join(line.strip() for line in out.strip().splitlines()[-3:])
            log.warning("[theharvester] no output file (rc=%s): %s", rc, tail or "no message")
            return []

        try:
            with open(json_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            log.warning("[theharvester] parse error: %s", e)
            return []
        if not isinstance(data, dict):
            log.warning("[theharvester] unexpected JSON shape: %s", type(data).__name__)
            return []

        findings: list[Finding] = []
        seen: set[str] = set()
        for email in data.get("emails", []) or []:
            findings.append(Finding(
                type=EntityType.EMAIL, value=email, source=self.name,
                parent=seed.value, confidence=0.7, depth=seed.depth + 1,
            ))
        for host in data.get("hosts", []) or []:
            host_val = clean_host(host)
            if not host_val or host_val in seen:
                continue
            seen.add(host_val)
            findings.append(Finding(
                type=EntityType.SUBDOMAIN, value=host_val, source=self.name,
                parent=seed.value, confidence=0.75, depth=seed.depth + 1,
            ))
        for ip in data.get("ips", []) or []:
            findings.append(Finding(
                type=EntityType.IP, value=str(ip), source=self.name,
                parent=seed.value, confidence=0.7, depth=seed.depth + 1,
            ))
        return findings
