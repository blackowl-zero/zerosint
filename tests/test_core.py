"""
Offline tests for the core pivot loop: dedup keys, multi-source merging and
graph edges.

    python -m unittest discover -s tests
    python tests/test_core.py
"""
from __future__ import annotations

import os
import sys
import unittest

# so it also runs as a plain script from any directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.correlator import correlate  # noqa: E402
from core.models import Finding, Target  # noqa: E402
from core.orchestrator import Orchestrator  # noqa: E402


class FakeBreachModule:
    """Reports the "Adobe" breach for every email seed it gets."""

    accepts = {"email"}

    def __init__(self, name: str = "x", repeat: int = 1) -> None:
        self.name = name
        self.repeat = repeat

    def available(self) -> bool:
        return True

    def handles(self, seed: Finding) -> bool:
        return seed.type in self.accepts

    def run(self, seed: Finding) -> list[Finding]:
        return [
            Finding(type="breach", value="Adobe", source=self.name, parent=seed.value,
                    confidence=0.85, depth=seed.depth + 1, meta={"account": seed.value})
            for _ in range(self.repeat)
        ]


def _target(*emails: str) -> Target:
    t = Target(label="t")
    t.seeds = [Finding(type="email", value=e, confidence=1.0) for e in emails]
    return t


def _breaches(results: dict) -> list[Finding]:
    return [f for f in results.values() if f.type == "breach"]


class CoreTest(unittest.TestCase):
    def test_same_breach_two_accounts_kept_separately(self):
        o = Orchestrator([FakeBreachModule()], max_depth=2)
        found = _breaches(o.run(_target("a@x.com", "b@x.com")))
        self.assertEqual(len(found), 2)
        self.assertEqual({f.meta["account"] for f in found}, {"a@x.com", "b@x.com"})

    def test_same_breach_same_account_two_sources_merged(self):
        o = Orchestrator([FakeBreachModule("x"), FakeBreachModule("y")], max_depth=2)
        results = o.run(_target("a@x.com"))
        found = _breaches(results)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].meta["all_sources"], ["x", "y"])
        correlate(results)
        self.assertEqual(found[0].meta["source_count"], 2)

    def test_edges_are_unique(self):
        o = Orchestrator([FakeBreachModule(repeat=2)], max_depth=2)
        o.run(_target("a@x.com"))
        self.assertEqual(len(o.edges), len(set(o.edges)))
        self.assertEqual(len(o.edges), 1)

    def test_breach_without_account_key_unchanged(self):
        self.assertEqual(Finding(type="breach", value="Adobe").key, "breach:adobe")


if __name__ == "__main__":
    unittest.main(verbosity=2)
