"""
Offline tests for SpiderfootModule. sf.py is not run: the fake _exec returns
stdout in the exact form sf.py 4.x prints with `-o json` ("[" + rows joined by
",\\n" + "]"), where "type" is the human-readable event name
(sfp__stor_stdout.py replaces the code with tbl_event_types.event_descr).

    python tests/test_spiderfoot_mod.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import EntityType, Finding  # noqa: E402
from modules.spiderfoot_mod import SpiderfootModule  # noqa: E402

ROWS = [
    {"generated": 1729591200, "type": "Internet Name", "data": "docs.github.com",
     "module": "sfp_crt", "source": "github.com"},
    {"generated": 1729591201, "type": "IP Address", "data": "140.82.112.6",
     "module": "sfp_dnsresolve", "source": "docs.github.com"},
    {"generated": 1729591202, "type": "Email Address", "data": "security@github.com",
     "module": "sfp_email", "source": "github.com"},
    {"generated": 1729591203, "type": "Raw DNS Records", "data": "TXT v=spf1 ...",
     "module": "sfp_dnsresolve", "source": "github.com"},       # not mapped -> ignored
    {"generated": 1729591204, "type": "Internet Name", "data": "docs.github.com",
     "module": "sfp_dnsresolve", "source": "github.com"},       # duplicate -> once
]


def sf_stdout(rows) -> str:
    """Mimic sf.py: print('[', end=''), then rows separated by print(','), then print(']')."""
    return "[" + ",\n".join(json.dumps(r) for r in rows) + "]\n"


class SpiderfootModuleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = SpiderfootModule()
        self.seed = Finding(type=EntityType.DOMAIN, value="github.com", depth=0)
        mock.patch.object(SpiderfootModule, "_locate", return_value="/opt/spiderfoot/sf.py").start()

    def tearDown(self) -> None:
        mock.patch.stopall()

    def test_parses_real_output_shape(self):
        with mock.patch.object(SpiderfootModule, "_exec", return_value=(0, sf_stdout(ROWS), "")) as ex:
            out = self.mod.run(self.seed)
        got = sorted((f.type, f.value) for f in out)
        self.assertEqual(got, [
            (EntityType.EMAIL, "security@github.com"),
            (EntityType.IP, "140.82.112.6"),
            (EntityType.SUBDOMAIN, "docs.github.com"),
        ])
        self.assertEqual({f.meta["sf_event"] for f in out}, {"INTERNET_NAME", "IP_ADDRESS", "EMAILADDR"})
        cmd = ex.call_args.args[0]
        self.assertEqual(cmd[1], "/opt/spiderfoot/sf.py")
        self.assertEqual(cmd[cmd.index("-o") + 1], "json")

    def test_event_codes_still_accepted(self):
        rows = [{"type": "INTERNET_NAME", "data": "gist.github.com"}]
        with mock.patch.object(SpiderfootModule, "_exec", return_value=(0, sf_stdout(rows), "")):
            out = self.mod.run(self.seed)
        self.assertEqual([(f.type, f.value) for f in out], [(EntityType.SUBDOMAIN, "gist.github.com")])

    def test_empty_scan(self):
        with mock.patch.object(SpiderfootModule, "_exec", return_value=(0, "[]\n", "")):
            self.assertEqual(self.mod.run(self.seed), [])

    def test_non_json_output(self):
        with mock.patch.object(SpiderfootModule, "_exec", return_value=(0, "Traceback ...", "")), \
             self.assertLogs("osint", level="WARNING"):
            self.assertEqual(self.mod.run(self.seed), [])

    def test_timeout(self):
        with mock.patch.object(SpiderfootModule, "_exec", return_value=(-1, "", "timeout")):
            self.assertEqual(self.mod.run(self.seed), [])


class SpiderfootDegradeTest(unittest.TestCase):
    """Real _locate(), no mocks on it: missing sf.py must degrade, not crash."""

    def test_not_installed(self):
        mod = SpiderfootModule()
        with mock.patch("modules.spiderfoot_mod.shutil.which", return_value=None), \
             mock.patch.dict(os.environ, {"SPIDERFOOT_PATH": ""}), \
             mock.patch.object(SpiderfootModule, "_exec", side_effect=AssertionError("must not run")):
            self.assertFalse(mod.available())
            self.assertEqual(mod.run(Finding(type=EntityType.DOMAIN, value="github.com")), [])

    def test_messages_name_the_kali_binary(self):
        """Messages and metadata point at what Kali actually installs (`spiderfoot`)."""
        mod = SpiderfootModule()
        self.assertEqual(mod.requires_binary, "spiderfoot")
        with mock.patch("modules.spiderfoot_mod.shutil.which", return_value=None), \
             mock.patch.dict(os.environ, {"SPIDERFOOT_PATH": ""}), \
             self.assertLogs("osint", level="INFO") as logs:
            mod.run(Finding(type=EntityType.DOMAIN, value="github.com"))
        msg = logs.output[0]
        self.assertIn("spiderfoot not found", msg)
        self.assertIn("SPIDERFOOT_PATH", msg)
        self.assertNotIn("sf.py missing", msg)

    def test_found_via_spiderfoot_path(self):
        d = tempfile.mkdtemp()
        open(os.path.join(d, "sf.py"), "w").close()
        with mock.patch("modules.spiderfoot_mod.shutil.which", return_value=None), \
             mock.patch.dict(os.environ, {"SPIDERFOOT_PATH": d}):
            self.assertTrue(SpiderfootModule().available())

    def test_found_as_kali_spiderfoot_binary(self):
        """Kali ships /usr/bin/spiderfoot (a wrapper for sf.py), not sf.py on PATH."""
        mod = SpiderfootModule()
        which = lambda n: "/usr/bin/spiderfoot" if n == "spiderfoot" else None  # noqa: E731
        with mock.patch("modules.spiderfoot_mod.shutil.which", side_effect=which), \
             mock.patch.dict(os.environ, {"SPIDERFOOT_PATH": ""}), \
             mock.patch.object(SpiderfootModule, "_exec", return_value=(0, "[]\n", "")) as ex:
            self.assertTrue(mod.available())
            mod.run(Finding(type=EntityType.DOMAIN, value="github.com", depth=0))
        self.assertEqual(ex.call_args.args[0][:3], ["/usr/bin/spiderfoot", "-s", "github.com"])


class SpiderfootDataTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = SpiderfootModule()
        mock.patch.object(SpiderfootModule, "_locate", return_value="/opt/spiderfoot/sf.py").start()
        self.addCleanup(mock.patch.stopall)

    def test_sfurl_unwrapped(self):
        rows = [{"type": "Social Media Presence",
                 "data": "Twitter: <SFURL>https://twitter.com/bob</SFURL>"}]
        seed = Finding(type=EntityType.DOMAIN, value="github.com", depth=0)
        with mock.patch.object(SpiderfootModule, "_exec", return_value=(0, sf_stdout(rows), "")):
            out = self.mod.run(seed)
        self.assertEqual([(f.type, f.value) for f in out], [("profile_url", "https://twitter.com/bob")])

    def test_only_runs_on_original_inputs(self):
        self.assertFalse(self.mod.handles(Finding(type="domain", value="x.com", depth=1)))
        self.assertTrue(self.mod.handles(Finding(type="domain", value="x.com", depth=0)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
