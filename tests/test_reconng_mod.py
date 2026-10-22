"""
Offline tests for ReconngModule. recon-cli is mocked: the fake _exec creates
the workspace SQLite with recon-ng 5.1.2's real hosts/contacts schema (sample
rows from a real hackertarget run against github.com).

    python tests/test_reconng_mod.py
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import EntityType, Finding  # noqa: E402
from modules.reconng_mod import ReconngModule  # noqa: E402

# recon-ng 5.1.2 workspace schema (columns read from a real data.db)
SCHEMA = """
CREATE TABLE hosts (host TEXT, ip_address TEXT, region TEXT, country TEXT,
                    latitude TEXT, longitude TEXT, notes TEXT, module TEXT);
CREATE TABLE contacts (first_name TEXT, middle_name TEXT, last_name TEXT, email TEXT,
                       title TEXT, region TEXT, country TEXT, phone TEXT, notes TEXT, module TEXT);
"""
HOSTS = [
    ("github.com", "140.82.114.3"),
    ("accelerator.github.com", "185.199.110.153"),
    ("accessibility.github.com", None),
]
RUN_OK_STDOUT = "SUMMARY\n[*] 3 total (3 new) hosts found.\n"
NOT_INSTALLED_STDOUT = "[*] Version check disabled.\nWORKSPACE => x\n[!] Invalid module name.\n"


class ReconngModuleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = ReconngModule()
        self.seed = Finding(type=EntityType.DOMAIN, value="github.com", depth=0)
        self.tmp = tempfile.mkdtemp(prefix="reconng_test_")
        self.calls = []
        mock.patch.object(ReconngModule, "available", return_value=True).start()
        mock.patch.object(ReconngModule, "_db_path",
                          side_effect=lambda ws: os.path.join(self.tmp, ws, "data.db")).start()

    def tearDown(self) -> None:
        mock.patch.stopall()

    def _fake_exec(self, stdout=RUN_OK_STDOUT, with_db=True, contacts=()):
        def _exec(cmd, timeout=0):
            self.calls.append(cmd)
            if with_db:
                ws = cmd[cmd.index("-w") + 1]
                os.makedirs(os.path.join(self.tmp, ws), exist_ok=True)
                con = sqlite3.connect(os.path.join(self.tmp, ws, "data.db"))
                con.executescript(SCHEMA)
                con.executemany("INSERT INTO hosts(host, ip_address, module) VALUES (?,?,'hackertarget')", HOSTS)
                con.executemany("INSERT INTO contacts(email) VALUES (?)", [(c,) for c in contacts])
                con.commit()
                con.close()
            return 0, stdout, ""
        return _exec

    def test_parses_hosts_and_contacts(self):
        with mock.patch.object(ReconngModule, "_exec",
                               side_effect=self._fake_exec(contacts=["security@github.com"])):
            out = self.mod.run(self.seed)
        subs = sorted(f.value for f in out if f.type == EntityType.SUBDOMAIN)
        ips = sorted(f.value for f in out if f.type == EntityType.IP)
        emails = [f.value for f in out if f.type == EntityType.EMAIL]
        self.assertEqual(subs, ["accelerator.github.com", "accessibility.github.com", "github.com"])
        self.assertEqual(ips, ["140.82.114.3", "185.199.110.153"])
        self.assertEqual(emails, ["security@github.com"])
        self.assertTrue(all(f.source == "recon-ng" and f.parent == "github.com" for f in out))

    def test_command_shape(self):
        with mock.patch.object(ReconngModule, "_exec", side_effect=self._fake_exec()):
            self.mod.run(self.seed)
        cmd = self.calls[0]
        self.assertEqual(cmd[0], "recon-cli")
        self.assertEqual(cmd[cmd.index("-m") + 1], "recon/domains-hosts/hackertarget")
        self.assertIn("SOURCE=github.com", cmd)
        self.assertIn("-x", cmd)

    def test_module_not_installed_warns_with_install_command(self):
        with mock.patch.object(ReconngModule, "_exec",
                               side_effect=self._fake_exec(stdout=NOT_INSTALLED_STDOUT, with_db=False)), \
             self.assertLogs("osint", level="WARNING") as logs:
            self.assertEqual(self.mod.run(self.seed), [])
        self.assertIn("marketplace install recon/domains-hosts/hackertarget", "\n".join(logs.output))

    def test_fresh_workspace_each_run_and_removed(self):
        with mock.patch.object(ReconngModule, "_exec", side_effect=self._fake_exec()):
            first = self.mod.run(self.seed)
            second = self.mod.run(self.seed)
        ws1 = self.calls[0][self.calls[0].index("-w") + 1]
        ws2 = self.calls[1][self.calls[1].index("-w") + 1]
        self.assertNotEqual(ws1, ws2)
        self.assertEqual(len(first), len(second))   # no stale rows piling up
        self.assertEqual(os.listdir(self.tmp), [])  # workspaces deleted

    def test_email_not_accepted(self):
        self.assertFalse(self.mod.handles(Finding(type=EntityType.EMAIL, value="a@b.com")))
        self.assertTrue(self.mod.handles(self.seed))

    def test_timeout_returns_empty(self):
        with mock.patch.object(ReconngModule, "_exec", return_value=(-1, "", "timeout")):
            self.assertEqual(self.mod.run(self.seed), [])

    def test_binary_missing(self):
        with mock.patch.object(ReconngModule, "available", return_value=False):
            self.assertEqual(self.mod.run(self.seed), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
