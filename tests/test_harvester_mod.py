"""
Offline tests for HarvesterModule. theHarvester itself is mocked: the fake
_exec writes a JSON file in the shape theHarvester 4.11.1 produces (sample
values taken from a real run against github.com).

    python tests/test_harvester_mod.py
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import EntityType, Finding  # noqa: E402
from modules.harvester_mod import HarvesterModule, clean_host  # noqa: E402

# real shape: keys only present when there is data; hosts may be "host:ip"
REAL_JSON = {
    "cmd": "-d github.com -b crtsh,duckduckgo,hackertarget,rapiddns,otx -f /tmp/x/out.json",
    "hosts": [
        "2Fbrand.github.com",          # URL-encoding leftover seen in real output
        "brand.github.com",
        "docs.github.com",
        "api.github.com:140.82.112.6",
        "github.com",
    ],
    "emails": ["security@github.com"],
    "ips": ["140.82.112.6"],
    "shodan": [],
}
INVALID_SOURCE_STDOUT = (
    "* theHarvester 4.11.1 *\n"
    "The following engines are not supported: {'bing'}\n"
    "\n[!] Invalid source.\n"
)


def _fake_exec_writing(payload, calls):
    def _exec(cmd, timeout=0):
        calls.append(cmd)
        path = cmd[cmd.index("-f") + 1]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(payload if isinstance(payload, str) else json.dumps(payload))
        return 0, "[*] Hosts found: 5\n", ""
    return _exec


class HarvesterModuleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = HarvesterModule()
        self.seed = Finding(type=EntityType.DOMAIN, value="github.com", depth=0)
        mock.patch.object(HarvesterModule, "available", return_value=True).start()

    def tearDown(self) -> None:
        mock.patch.stopall()

    def test_parses_real_shape(self):
        calls = []
        with mock.patch.object(HarvesterModule, "_exec", side_effect=_fake_exec_writing(REAL_JSON, calls)):
            out = self.mod.run(self.seed)
        by_type = {}
        for f in out:
            by_type.setdefault(f.type, []).append(f.value)
        self.assertEqual(sorted(by_type["subdomain"]),
                         ["api.github.com", "brand.github.com", "docs.github.com", "github.com"])
        self.assertEqual(by_type["email"], ["security@github.com"])
        self.assertEqual(by_type["ip"], ["140.82.112.6"])
        for f in out:
            self.assertEqual(f.source, "theharvester")
            self.assertEqual(f.parent, "github.com")
            self.assertEqual(f.depth, 1)

    def test_command_uses_valid_sources_and_json_path(self):
        calls = []
        with mock.patch.object(HarvesterModule, "_exec", side_effect=_fake_exec_writing(REAL_JSON, calls)):
            self.mod.run(self.seed)
        cmd = calls[0]
        sources = cmd[cmd.index("-b") + 1].split(",")
        self.assertNotIn("bing", sources)          # removed upstream; breaks the whole run
        self.assertTrue(cmd[cmd.index("-f") + 1].endswith(".json"))

    def test_invalid_source_logs_reason_not_parse_error(self):
        with mock.patch.object(HarvesterModule, "_exec", return_value=(1, INVALID_SOURCE_STDOUT, "")), \
             self.assertLogs("osint", level="WARNING") as logs:
            self.assertEqual(self.mod.run(self.seed), [])
        text = "\n".join(logs.output)
        self.assertIn("Invalid source", text)
        self.assertNotIn("parse error", text)

    def test_corrupt_json_returns_empty(self):
        with mock.patch.object(HarvesterModule, "_exec", side_effect=_fake_exec_writing("{not json", [])), \
             self.assertLogs("osint", level="WARNING"):
            self.assertEqual(self.mod.run(self.seed), [])

    def test_temp_dir_removed(self):
        calls = []
        with mock.patch.object(HarvesterModule, "_exec", side_effect=_fake_exec_writing(REAL_JSON, calls)):
            self.mod.run(self.seed)
        outdir = os.path.dirname(calls[0][calls[0].index("-f") + 1])
        self.assertFalse(os.path.exists(outdir))

    def test_timeout_returns_empty(self):
        with mock.patch.object(HarvesterModule, "_exec", return_value=(-1, "", "timeout")):
            self.assertEqual(self.mod.run(self.seed), [])

    def test_binary_missing(self):
        with mock.patch.object(HarvesterModule, "available", return_value=False):
            self.assertEqual(self.mod.run(self.seed), [])

    def test_clean_host(self):
        self.assertEqual(clean_host("2Fdocs.github.com"), "docs.github.com")
        self.assertEqual(clean_host("api.github.com:1.2.3.4"), "api.github.com")
        self.assertEqual(clean_host("2fa.example.com"), "2fa.example.com")  # real name kept
        self.assertIsNone(clean_host("not a host"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
