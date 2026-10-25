"""
Offline tests for the input normalizer (seed building).

    python -m unittest discover -s tests
    python tests/test_normalizer.py
"""
from __future__ import annotations

import os
import sys
import unittest

# so it also runs as a plain script from any directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.normalizer import normalize  # noqa: E402


def _pairs(seeds) -> list[tuple[str, str]]:
    return [(s.type, s.value) for s in seeds]


class NormalizerTest(unittest.TestCase):
    # (the webmail rule itself lives in the orchestrator, see tests/test_core.py)
    def test_domain_from_email_marked_as_derived(self):
        dom = [s for s in normalize({"email": "x@acme.io"}) if s.type == "domain"]
        self.assertEqual(dom[0].meta.get("derived_from"), "x@acme.io")

    def test_explicit_username_wins_over_derived(self):
        users = [s for s in normalize({"email": "bob@acme.io", "username": "bob"})
                 if s.type == "username"]
        self.assertEqual([(u.source, u.parent, u.confidence) for u in users],
                         [("input", None, 1.0)])

    def test_explicit_domain_clears_derived_mark(self):
        dom = [s for s in normalize({"email": "x@gmail.com", "domain": "gmail.com"})
               if s.type == "domain"]
        self.assertEqual(len(dom), 1)
        self.assertNotIn("derived_from", dom[0].meta)

    def test_company_domain_still_seeded(self):
        self.assertIn(("domain", "acme.io"), _pairs(normalize({"email": "a@acme.io"})))

    def test_explicit_domain_still_scanned(self):
        self.assertEqual(_pairs(normalize({"domain": "gmail.com"})), [("domain", "gmail.com")])

    def test_derived_username_stripped(self):
        seeds = normalize({"email": "  bob@acme.io "})
        users = [s.value for s in seeds if s.type == "username"]
        self.assertEqual(users, ["bob"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
