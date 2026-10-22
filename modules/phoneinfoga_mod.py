"""
PhoneInfogaModule: phone -> offline info + Google dork links.

`phoneinfoga scan` (v2.11) only prints text and has no JSON flag.
JSON is only available from the REST API, so we:
  1. briefly start `phoneinfoga serve --no-client` on a random port,
  2. call only the offline scanners `local` and `googlesearch`,
  3. stop the server.
Scanners that send the number to third parties (numverify, ovh, googlecse)
are disabled with -D.

Dead-link filtering: from each dork we keep ONLY the `site:DOMAIN`, send a
HEAD request to the bare domain (https://domain) and drop links whose domain
does not respond. We NEVER open the Google URLs and NEVER put the number in an
outbound request. The dorks stay as clickable links in the report.

Carrier and line type: the offline `local` scanner does not return them. They
need PhoneInfoga's `numverify` scanner plus a NUMVERIFY_API_KEY, and numverify
sends the number to a third-party API, so this module keeps it disabled.
Missing fields are left out of meta and listed under meta["unavailable"].

Dedup: the result uses PhoneInfoFinding, whose key includes the source. Without
that, a seed already in E164 form has the same key as the result, the
orchestrator keeps the input seed, and the scan reports 0 findings.
"""
from __future__ import annotations

import logging
import os
import re
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlparse

import requests

from core.models import EntityType, Finding
from .base import BaseModule

log = logging.getLogger("osint")

# phoneinfoga category -> our name
CATEGORY_MAP = {
    "social_media": "social",
    "reputation": "reputation",
    "individuals": "individuals",
    "disposable_providers": "disposable",
    "general": "general",
}
# scanners that talk to third parties; disabled
DISABLED_SCANNERS = ("numverify", "ovh", "googlecse")

SITE_RE = re.compile(r"site:([A-Za-z0-9.-]+)", re.I)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)

UNAVAILABLE = "unavailable (needs numverify scanner + NUMVERIFY_API_KEY)"

LIVENESS_TIMEOUT = 5
LIVENESS_WORKERS = 10


def extract_site_domains(dork_url: str) -> list[str]:
    """Extract the `site:` domains from a Google search URL (URL-decoded)."""
    try:
        q = " ".join(parse_qs(urlparse(dork_url).query).get("q", []))
    except ValueError:
        return []
    out = []
    for d in SITE_RE.findall(q):
        d = d.strip(".").lower()
        if DOMAIN_RE.match(d) and d not in out:
            out.append(d)
    return out


def _domain_alive(domain: str) -> bool:
    """HEAD to the bare domain. Any HTTP response = alive."""
    for scheme in ("https", "http"):
        try:
            requests.head(f"{scheme}://{domain}", timeout=LIVENESS_TIMEOUT,
                          allow_redirects=False)
            return True
        except requests.RequestException:
            continue
    return False


def check_domains(domains: list[str], number_digits: str) -> dict[str, bool]:
    """Threaded liveness check. Returns {domain: alive}."""
    # safety net: nothing that looks like the number leaves the machine
    safe = [d for d in domains
            if DOMAIN_RE.match(d) and not (number_digits and number_digits in d)]
    if not safe:
        return {}
    with ThreadPoolExecutor(max_workers=min(LIVENESS_WORKERS, len(safe))) as ex:
        return dict(zip(safe, ex.map(_domain_alive, safe)))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class PhoneInfoFinding(Finding):
    """PHONE finding with its own dedup key, so it is not merged into the input seed."""

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value.strip().lower()}#{self.source}"


class PhoneInfogaModule(BaseModule):
    name = "phoneinfoga"
    accepts = {EntityType.PHONE}
    requires_binary = "phoneinfoga"

    # ---- phoneinfoga REST API (localhost subprocess) ----
    def _query_api(self, digits: str) -> dict | None:
        """
        Run local + googlesearch through the REST API.
        Return {"local": {...}, "googlesearch": {...}} or None on failure.
        """
        port = _free_port()
        base = f"http://127.0.0.1:{port}/api/v2"
        cmd = ["phoneinfoga", "serve", "--no-client", "-p", str(port)]
        for s in DISABLED_SCANNERS:
            cmd += ["-D", s]
        workdir = tempfile.mkdtemp(prefix="phoneinfoga_")  # so it does not read our .env
        try:
            proc = subprocess.Popen(cmd, cwd=workdir, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        except (OSError, ValueError) as e:
            log.warning("[phoneinfoga] could not start: %s", e)
            return None
        try:
            deadline = time.monotonic() + 15
            while True:
                if proc.poll() is not None:
                    log.warning("[phoneinfoga] server exited early (rc=%s)", proc.returncode)
                    return None
                try:
                    requests.get(f"{base}/scanners", timeout=1)
                    break
                except requests.RequestException:
                    if time.monotonic() > deadline:
                        log.warning("[phoneinfoga] server did not start in time")
                        return None
                    time.sleep(0.3)

            out = {}
            for scanner in ("local", "googlesearch"):
                r = requests.post(f"{base}/scanners/{scanner}/run",
                                  json={"number": digits}, timeout=30)
                data = r.json()
                if "result" not in data:
                    log.warning("[phoneinfoga] %s: %s", scanner, data.get("error", data))
                    return None
                out[scanner] = data["result"]
            return out
        except (requests.RequestException, ValueError) as e:
            log.warning("[phoneinfoga] API/JSON error: %s", e)
            return None
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    # ---- dorks + dead-link filtering ----
    def _clean_dorks(self, gs: dict, digits: str) -> tuple[dict, dict]:
        """Group dorks by category, drop dead target domains. Return (dorks, filter_info)."""
        grouped: dict[str, list[dict]] = {v: [] for v in CATEGORY_MAP.values()}
        for raw_cat, items in (gs or {}).items():
            cat = CATEGORY_MAP.get(raw_cat, raw_cat)
            for it in items or []:
                url = (it or {}).get("url")
                if not url:
                    continue
                grouped.setdefault(cat, []).append({
                    "url": url,
                    "dork": it.get("dork", ""),
                    "domains": extract_site_domains(url),
                })

        domains = sorted({d for items in grouped.values() for it in items for d in it["domains"]})
        info = {"status": "skipped", "checked": len(domains), "dead_domains": [], "reason": ""}
        try:
            alive = check_domains(domains, digits)
        except Exception as e:  # noqa: BLE001 - filtering must not break the module
            alive = {}
            info["reason"] = f"liveness check error: {e}"

        if domains and alive and any(alive.values()):
            dead = {d for d, ok in alive.items() if not ok}
            info.update(status="filtered", dead_domains=sorted(dead))
            for cat, items in grouped.items():
                # keep a link if it has no site: (general) or any of its domains is alive
                grouped[cat] = [it for it in items
                                if not it["domains"] or any(d not in dead for d in it["domains"])]
        elif domains:
            # everything "dead" = probably offline -> keep them all
            info["reason"] = info["reason"] or "no domain reachable (offline?), links kept unfiltered"
            log.warning("[phoneinfoga] dead-link filtering skipped: %s", info["reason"])
        else:
            info.update(status="filtered", reason="no site: domains to check")
        return grouped, info

    def run(self, seed: Finding) -> list[Finding]:
        if not self.available():
            log.info("[phoneinfoga] binary missing, skip %s", seed.value)
            return []
        # our own output is a PHONE finding; do not rescan the same number
        if seed.source == self.name:
            return []

        digits = re.sub(r"\D", "", seed.value)
        if len(digits) < 7:
            log.warning("[phoneinfoga] not a valid number: %s", seed.value)
            return []

        data = self._query_api(digits)
        if not data:
            return []
        local = data.get("local") or {}
        e164 = local.get("e164")
        if not e164:
            log.warning("[phoneinfoga] no e164 in result")
            return []

        dorks, filter_info = self._clean_dorks(data.get("googlesearch") or {}, digits)
        info = {
            "e164": e164,
            "international": local.get("international"),
            "local_format": local.get("local"),
            "country_code": local.get("country_code"),
            "country": local.get("country"),
            "carrier": local.get("carrier"),
            "line_type": local.get("line_type"),
        }
        # store only real values; never silent nulls
        meta = {k: v for k, v in info.items() if v not in (None, "")}
        missing = {k: UNAVAILABLE for k in ("carrier", "line_type") if k not in meta}
        if missing:
            meta["unavailable"] = missing
        meta["dorks"] = dorks
        meta["dork_filter"] = filter_info
        return [PhoneInfoFinding(
            type=EntityType.PHONE,
            value=e164,
            source=self.name,
            parent=seed.value,
            confidence=0.8,
            depth=seed.depth + 1,
            meta=meta,
        )]
