"""
Tests for the command line and the menu wiring.

    python -m unittest discover -s tests
    python tests/test_cli.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# so it also runs as a plain script from any directory
sys.path.insert(0, ROOT)

import menu  # noqa: E402


def _main(*args: str) -> subprocess.CompletedProcess:
    """Run main.py with all outputs in a temp dir, never over the user's reports."""
    with tempfile.TemporaryDirectory() as d:
        outs = ["-o", os.path.join(d, "r.html"), "--json", os.path.join(d, "f.json"),
                "--db", os.path.join(d, "s.db")]
        return subprocess.run([sys.executable, "main.py", *args, *outs], cwd=ROOT,
                              capture_output=True, text=True, stdin=subprocess.DEVNULL,
                              timeout=60)


class CliTest(unittest.TestCase):
    def test_menu_runs_whole_suite(self):
        with mock.patch("menu.subprocess.run") as run:
            menu.run_tests()
        cmd = run.call_args.args[0]
        self.assertIn("discover", cmd)
        self.assertFalse(any("test_xposed_mod.py" in c for c in cmd))

    def test_depth_zero_rejected(self):
        self.assertEqual(_main("--username", "x", "--depth", "0", "--plain").returncode, 2)

    def test_depth_six_rejected(self):
        self.assertEqual(_main("--username", "x", "--depth", "6", "--plain").returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
