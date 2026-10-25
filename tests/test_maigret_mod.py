"""
Offline tests for MaigretModule. _exec is mocked to write a fake maigret
report, so maigret does not need to be installed.

    python -m unittest discover -s tests
    python tests/test_maigret_mod.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

# so it also runs as a plain script from any directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import EntityType, Finding  # noqa: E402
from modules.maigret_mod import MaigretModule  # noqa: E402

REPORT = {
    "GitHub": {"url_user": "https://github.com/bob", "status": {"status": "Claimed"}},
    "Foo": {"status": {"status": "Available"}},
}


class MaigretModuleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.outdir = tempfile.mkdtemp(prefix="maigret_test_")
        self.addCleanup(shutil.rmtree, self.outdir, True)
        mock.patch.object(MaigretModule, "available", return_value=True).start()
        mock.patch("modules.maigret_mod.tempfile.mkdtemp", return_value=self.outdir).start()
        self.addCleanup(mock.patch.stopall)
        self.mod = MaigretModule()

    def _writes_report(self, user: str):
        def fake_exec(cmd, timeout=120):
            with open(os.path.join(self.outdir, f"report_{user}_simple.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(REPORT, fh)
            return 0, "", ""
        return fake_exec

    def _run(self, user: str):
        seed = Finding(type=EntityType.USERNAME, value=user, depth=0)
        with mock.patch.object(MaigretModule, "_exec", side_effect=self._writes_report(user)):
            return self.mod.run(seed)

    def test_parses_claimed_profiles(self):
        out = self._run("bob")
        self.assertEqual([(f.type, f.value) for f in out], [("profile_url", "https://github.com/bob")])
        self.assertEqual(out[0].meta["site"], "GitHub")

    def test_temp_dir_removed(self):
        self._run("bob")
        self.assertFalse(os.path.exists(self.outdir))

    def test_temp_dir_removed_on_timeout(self):
        seed = Finding(type=EntityType.USERNAME, value="bob", depth=0)
        with mock.patch.object(MaigretModule, "_exec", return_value=(-1, "", "timeout")):
            self.assertEqual(self.mod.run(seed), [])
        self.assertFalse(os.path.exists(self.outdir))

    def test_username_with_glob_chars(self):
        self.assertEqual(len(self._run("a[1]")), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
