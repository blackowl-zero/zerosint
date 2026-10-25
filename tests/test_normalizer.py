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
    def test_freemail_domain_not_seeded(self):
        seeds = normalize({"email": "someone@gmail.com"})
        self.assertEqual([s.type for s in seeds], ["email", "username"])

    def test_freemail_case_insensitive(self):
        seeds = normalize({"email": "X@GMail.COM"})
        self.assertNotIn("domain", [s.type for s in seeds])

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
