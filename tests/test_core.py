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


class DerivedUsernameTest(unittest.TestCase):
    """--email bob@acme.io also seeds the derived username 'bob'. A breach found for
    'bob' is the same person's exposure as one found for bob@acme.io: one row."""

    def _breaches(self, raw: dict):
        from core.normalizer import normalize

        class BreachBoth(FakeBreachModule):
            accepts = {"email", "username"}

        t = Target(label="t")
        t.seeds = normalize(raw)
        results = Orchestrator([BreachBoth("hibp")], max_depth=2).run(t)
        return [f for f in results.values() if f.type == "breach"]

    def test_breach_via_derived_username_merges_into_email_row(self):
        rows = self._breaches({"email": "bob@acme.io"})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].meta["account"], "bob@acme.io")
        self.assertEqual(rows[0].meta.get("also_via_username"), ["bob"])

    def test_breach_for_explicit_username_stays_separate(self):
        # the user typed both: they are separate accounts, keep both rows
        rows = self._breaches({"email": "bob@acme.io", "username": "bob"})
        self.assertEqual({r.meta["account"] for r in rows}, {"bob@acme.io", "bob"})


class EmitModule:
    """For an email seed, reports whatever domains it was given (like SpiderFoot)."""

    name = "emitter"
    accepts = {"email"}

    def __init__(self, *found: tuple[str, str]) -> None:
        self.found = found

    def available(self) -> bool:
        return True

    def handles(self, seed: Finding) -> bool:
        return seed.type in self.accepts

    def run(self, seed: Finding) -> list[Finding]:
        return [Finding(type=t, value=v, source=self.name, parent=seed.value,
                        confidence=0.6, depth=seed.depth + 1) for t, v in self.found]


class DomainRecorder:
    """Records every domain/subdomain it is asked to scan (like theHarvester)."""

    name = "recorder"
    accepts = {"domain", "subdomain"}

    def __init__(self) -> None:
        self.scanned: list[str] = []

    def available(self) -> bool:
        return True

    def handles(self, seed: Finding) -> bool:
        return seed.type in self.accepts

    def run(self, seed: Finding) -> list[Finding]:
        self.scanned.append(seed.value)
        return []


class WebmailFilterTest(unittest.TestCase):
    """Webmail domains are never scanned unless the user passed them with --domain,
    whichever module or input they come from."""

    def _run(self, raw: dict, *emitted):
        from core.normalizer import normalize
        t = Target(label="t")
        t.seeds = normalize(raw)
        rec = DomainRecorder()
        o = Orchestrator([EmitModule(*emitted), rec], max_depth=3)
        results = o.run(t)
        return rec.scanned, {(f.type, f.value) for f in results.values()}

    def test_webmail_from_a_module_not_scanned_nor_reported(self):
        scanned, found = self._run({"email": "bob@acme.io"},
                                   ("domain", "gmail.com"), ("subdomain", "mail.GMAIL.com"))
        self.assertNotIn("gmail.com", scanned)
        self.assertNotIn("mail.GMAIL.com", scanned)
        self.assertNotIn(("domain", "gmail.com"), found)
        self.assertNotIn(("subdomain", "mail.GMAIL.com"), found)

    def test_webmail_domain_of_input_email_not_scanned(self):
        scanned, found = self._run({"email": "someone@GMail.COM"})
        self.assertEqual(scanned, [])
        self.assertNotIn("domain", {t for t, _ in found})

    def test_explicit_and_email_on_same_webmail_domain_is_scanned(self):
        scanned, _ = self._run({"email": "x@gmail.com", "domain": "gmail.com"})
        self.assertEqual(scanned, ["gmail.com"])

    def test_explicit_webmail_domain_is_scanned(self):
        scanned, _ = self._run({"domain": "gmail.com"})
        self.assertEqual(scanned, ["gmail.com"])

    def test_subdomain_of_explicit_webmail_domain_is_scanned(self):
        scanned, _ = self._run({"domain": "gmail.com", "email": "bob@acme.io"},
                               ("subdomain", "mail.gmail.com"))
        self.assertIn("mail.gmail.com", scanned)

    def test_other_domains_still_scanned(self):
        scanned, _ = self._run({"email": "bob@acme.io"}, ("domain", "acme-cdn.net"))
        self.assertEqual(sorted(scanned), ["acme-cdn.net", "acme.io"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
