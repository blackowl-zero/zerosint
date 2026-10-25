"""
Offline tests for the HTML report: self-contained graph and safe links.

    python -m unittest discover -s tests
    python tests/test_report.py
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest

# so it also runs as a plain script from any directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.correlator import correlate, summarize  # noqa: E402
from core.models import Finding  # noqa: E402
from report import html_report  # noqa: E402

try:
    import pyvis  # noqa: F401
    HAVE_PYVIS = True
except ImportError:
    HAVE_PYVIS = False


def _results(url: str = "https://github.com/bob") -> tuple[dict, list]:
    seed = Finding(type="email", value="bob@acme.io", confidence=1.0)
    child = Finding(type="profile_url", value=url, source="maigret",
                    parent=seed.value, confidence=0.55, depth=1)
    results = correlate({seed.key: seed, child.key: child})
    return results, [(seed.node_id, child.node_id)]


def _render(url: str = "https://github.com/bob") -> str:
    results, edges = _results(url)
    fd, path = tempfile.mkstemp(suffix=".html")
    os.close(fd)
    try:
        html_report.export_html(results, edges, summarize(results), "bob", path)
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    finally:
        os.remove(path)


class ReportTest(unittest.TestCase):
    @unittest.skipUnless(HAVE_PYVIS, "pyvis not installed")
    def test_graph_has_no_external_lib_refs(self):
        results, edges = _results()
        graph = html_report._build_graph_html(results, edges)
        # self-contained: no script or stylesheet loaded from anywhere
        self.assertEqual(re.findall(r"<script[^>]*\bsrc=", graph), [])
        self.assertEqual(re.findall(r"<link[^>]*\bhref=", graph), [])
        self.assertNotIn("node_modules", graph)
        self.assertIn("new vis.Network", graph)

    @unittest.skipUnless(HAVE_PYVIS, "pyvis not installed")
    def test_graph_document_has_no_white_frame(self):
        results, edges = _results()
        graph = html_report._build_graph_html(results, edges)
        self.assertRegex(graph, r"body\s*\{[^}]*margin:\s*0")
        self.assertRegex(graph, r"body\s*\{[^}]*background:\s*#0f172a")

    def test_single_html_document(self):
        self.assertEqual(_render().count("<html"), 1)

    def test_javascript_url_not_linked(self):
        doc = _render("javascript:alert(1)")
        self.assertNotIn('href="javascript', doc)
        self.assertIn("javascript:alert(1)", doc)

    def test_http_url_linked(self):
        self.assertIn('href="https://github.com/bob"', _render())


if __name__ == "__main__":
    unittest.main(verbosity=2)
