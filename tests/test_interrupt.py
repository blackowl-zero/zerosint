"""
Tests for Ctrl+C during a scan: what was found so far is kept and reported.

    python -m unittest discover -s tests
    python tests/test_interrupt.py
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# so it also runs as a plain script from any directory
sys.path.insert(0, ROOT)

import main  # noqa: E402
import menu  # noqa: E402
from core.correlator import correlate, summarize  # noqa: E402
from core.models import Finding, Target  # noqa: E402
from core.orchestrator import Orchestrator  # noqa: E402
from report import html_report  # noqa: E402


class InterruptingModule:
    """Finds one profile for the first seed, then the user hits Ctrl+C."""

    name = "fake"
    accepts = {"email", "username"}

    def __init__(self) -> None:
        self.calls = 0

    def available(self) -> bool:
        return True

    def handles(self, seed: Finding) -> bool:
        return seed.type in self.accepts

    def run(self, seed: Finding) -> list[Finding]:
        self.calls += 1
        if self.calls > 1:
            raise KeyboardInterrupt
        return [Finding(type="profile_url", value="https://example.org/bob", source=self.name,
                        parent=seed.value, confidence=0.6, depth=seed.depth + 1)]


class InterruptTest(unittest.TestCase):
    def test_orchestrator_keeps_findings_on_interrupt(self):
        t = Target(label="t")
        t.seeds = [Finding(type="username", value="bob", confidence=1.0),
                   Finding(type="email", value="a@acme.io", confidence=1.0)]
        o = Orchestrator([InterruptingModule()], max_depth=2)
        results = o.run(t)  # must not raise
        self.assertTrue(o.interrupted)
        self.assertIn("profile_url:https://example.org/bob", results)

    def test_main_writes_partial_report(self):
        with tempfile.TemporaryDirectory() as d:
            html_p, json_p = os.path.join(d, "r.html"), os.path.join(d, "f.json")
            argv = ["main.py", "--username", "bob", "--email", "a@acme.io", "--plain",
                    "-o", html_p, "--json", json_p, "--db", os.path.join(d, "s.db")]
            out = io.StringIO()
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch("main.build_modules", return_value=[InterruptingModule()]), \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                rc = main.main()
            self.assertEqual(rc, 130)
            with open(html_p, encoding="utf-8") as fh:
                self.assertIn("Scan interrupted", fh.read())
            with open(json_p, encoding="utf-8") as fh:
                self.assertIn("https://example.org/bob", [f["value"] for f in json.load(fh)])
            self.assertIn("Partial report saved", out.getvalue())

    def test_report_banner_only_when_interrupted(self):
        seed = Finding(type="username", value="bob", confidence=1.0)
        res = correlate({seed.key: seed})
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.html")
            html_report.export_html(res, [], summarize(res), "bob", p, interrupted=False)
            with open(p, encoding="utf-8") as fh:
                self.assertNotIn("Scan interrupted", fh.read())

    def test_menu_waits_for_child_on_ctrl_c(self):
        proc = mock.Mock()
        proc.wait.side_effect = [KeyboardInterrupt, 130]
        with mock.patch("menu.subprocess.Popen", return_value=proc), \
             mock.patch("menu.confirm", return_value=False), \
             contextlib.redirect_stdout(io.StringIO()):
            menu.run_scan({"email": "a@b.co"})  # must not raise
        self.assertEqual(proc.wait.call_count, 2)
        proc.kill.assert_not_called()

    def test_menu_stops_child_after_three_ctrl_c(self):
        """A hung scan must not trap the user: the third Ctrl+C stops it."""
        proc = mock.Mock()
        proc.wait.side_effect = [KeyboardInterrupt] * 3 + [-15]
        with mock.patch("menu.subprocess.Popen", return_value=proc), \
             mock.patch("menu.confirm", return_value=False), \
             contextlib.redirect_stdout(io.StringIO()):
            menu.run_scan({"email": "a@b.co"})
        proc.terminate.assert_called_once()

    def test_second_ctrl_c_ignored_while_saving(self):
        """While the partial report is written, SIGINT must not cut the files short."""
        seen = []

        def spy_export_html(*a, **kw):
            seen.append(signal.getsignal(signal.SIGINT))

        with tempfile.TemporaryDirectory() as d:
            argv = ["main.py", "--username", "bob", "--email", "a@acme.io", "--plain",
                    "-o", os.path.join(d, "r.html"), "--json", os.path.join(d, "f.json"),
                    "--db", os.path.join(d, "s.db")]
            before = signal.getsignal(signal.SIGINT)
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch("main.build_modules", return_value=[InterruptingModule()]), \
                 mock.patch("main.html_report.export_html", side_effect=spy_export_html), \
                 contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                main.main()
            self.assertEqual(seen, [signal.SIG_IGN])
            self.assertEqual(signal.getsignal(signal.SIGINT), before)  # restored

    def test_report_write_is_atomic(self):
        """A crash mid-write leaves the previous report intact, not truncated."""
        seed = Finding(type="username", value="bob", confidence=1.0)
        res = correlate({seed.key: seed})
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "f.json")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("OLD")
            with mock.patch("report.html_report.json.dump", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    html_report.export_json(res, p)
            with open(p, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "OLD")
            self.assertEqual(os.listdir(d), ["f.json"])  # no temp file left behind


if __name__ == "__main__":
    unittest.main(verbosity=2)
