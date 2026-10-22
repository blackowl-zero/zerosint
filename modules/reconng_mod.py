"""
ReconngModule: domain/email -> extra data via recon-ng modules.

Strategy: run recon-cli with a resource script in its own workspace, then read
the results DIRECTLY from the workspace SQLite database (more reliable than
parsing stdout).

Degrades gracefully if recon-cli is missing. Many modules need API keys, so
only key-less modules are used as a safe default.

One-time setup: recon-ng ships with NO modules. Install the ones used here:
    recon-cli -C "marketplace install recon/domains-hosts/hackertarget"
If a module is missing, recon-cli prints "Invalid module name" and still exits
0, so this wrapper checks stdout and logs the install command.

Email seeds are not handled: recon-ng has no key-less module that takes an
email as input. (recon/contacts-domains/migrate_contacts, used before, ignores
SOURCE and only reads the workspace's own contacts table.)

Each run uses a fresh workspace that is deleted afterwards, so results from
earlier runs are never re-reported.
"""
from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import uuid

from core.models import EntityType, Finding
from .base import BaseModule

log = logging.getLogger("osint")

# key-less modules per seed type
MODULES_FOR = {
    EntityType.DOMAIN: ["recon/domains-hosts/hackertarget"],
}


class ReconngModule(BaseModule):
    name = "recon-ng"
    accepts = {EntityType.DOMAIN}
    requires_binary = "recon-cli"

    def run(self, seed: Finding) -> list[Finding]:
        if not self.available():
            log.info("[recon-ng] recon-cli missing, skip %s", seed.value)
            return []

        mods = MODULES_FOR.get(seed.type, [])
        if not mods:
            return []

        workspace = f"osint_{seed.node_id}_{uuid.uuid4().hex[:8]}"
        try:
            return self._run_in(seed, mods, workspace)
        finally:
            shutil.rmtree(os.path.dirname(self._db_path(workspace)), ignore_errors=True)

    @staticmethod
    def _db_path(workspace: str) -> str:
        return os.path.expanduser(f"~/.recon-ng/workspaces/{workspace}/data.db")

    def _run_in(self, seed: Finding, mods: list[str], workspace: str) -> list[Finding]:
        findings: list[Finding] = []

        for module in mods:
            # recon-cli -w <ws> -m <module> -o SOURCE=<value> -x
            cmd = [
                "recon-cli",
                "-w", workspace,
                "-m", module,
                "-o", f"SOURCE={seed.value}",
                "-x",
            ]
            rc, out, _err = self._exec(cmd, timeout=240)
            if rc == -1:
                continue
            if "Invalid module name" in out:
                log.warning('[recon-ng] module not installed: %s. Run: '
                            'recon-cli -C "marketplace install %s"', module, module)

        # read the workspace SQLite
        db_path = self._db_path(workspace)
        if not os.path.exists(db_path):
            return findings

        try:
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            # hosts table
            for row in cur.execute("SELECT host, ip_address FROM hosts"):
                if row["host"]:
                    findings.append(Finding(
                        type=EntityType.SUBDOMAIN, value=row["host"],
                        source=self.name, parent=seed.value,
                        confidence=0.7, depth=seed.depth + 1,
                    ))
                if row["ip_address"]:
                    findings.append(Finding(
                        type=EntityType.IP, value=row["ip_address"],
                        source=self.name, parent=seed.value,
                        confidence=0.65, depth=seed.depth + 1,
                    ))
            # contacts (emails)
            try:
                for row in cur.execute("SELECT email FROM contacts WHERE email IS NOT NULL"):
                    findings.append(Finding(
                        type=EntityType.EMAIL, value=row["email"],
                        source=self.name, parent=seed.value,
                        confidence=0.7, depth=seed.depth + 1,
                    ))
            except sqlite3.OperationalError:
                pass
            con.close()
        except sqlite3.Error as e:
            log.warning("[recon-ng] db read error: %s", e)

        return findings
