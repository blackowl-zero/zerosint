"""
Offline tests for PhoneInfogaModule. Mocks the phoneinfoga REST API output
and the liveness check (requests.head). No internet or binary needed.

    python -m pytest tests/
    python tests/test_phoneinfoga_mod.py
"""
from __future__ import annotations

import io
import os
import sys
import unittest
from unittest import mock

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import EntityType, Finding  # noqa: E402
from core.orchestrator import Orchestrator  # noqa: E402
from core.models import Target  # noqa: E402
from modules import phoneinfoga_mod  # noqa: E402
from modules.phoneinfoga_mod import PhoneInfogaModule, extract_site_domains  # noqa: E402
from core.correlator import correlate, summarize  # noqa: E402
from report import html_report  # noqa: E402
from ui import console as console_ui  # noqa: E402

NUMBER = "+15555550123"          # placeholder, not a real number
DIGITS = "15555550123"
NATIONAL = "5555550123"

HEAD = "modules.phoneinfoga_mod.requests.head"
GET = "modules.phoneinfoga_mod.requests.get"
POST = "modules.phoneinfoga_mod.requests.post"


def _dork(site: str | None) -> dict:
    q = f'site%3A{site}+' if site else ""
    return {
        "number": NUMBER,
        "dork": (f"site:{site} " if site else "") + f'intext:"{DIGITS}"',
        "url": f"https://www.google.com/search?q={q}intext%3A%22{DIGITS}%22"
               f"+%7C+intext%3A%22%2B{DIGITS}%22+%7C+intext%3A%22{NATIONAL}%22",
    }


# same shape as the real phoneinfoga v2.11 REST API (verified locally)
API_RESULT = {
    "local": {
        "raw_local": NATIONAL, "local": "(555) 555-0123",
        "e164": NUMBER, "international": DIGITS, "country_code": 1,
    },
    "googlesearch": {
        "social_media": [_dork("facebook.com"), _dork("vk.com")],
        "reputation": [_dork("whosenumber.info"), _dork("dead-reputation.example")],
        "individuals": [_dork("numinfo.net")],
        "disposable_providers": [_dork("dead-sms.example"), _dork("hs3x.com")],
        "general": [_dork(None)],
    },
}
DEAD = {"dead-reputation.example", "dead-sms.example"}


def _fake_head(url, **_kw):
    host = url.split("://", 1)[1]
    if host in DEAD:
        raise requests.ConnectionError("DNS failure")
    r = mock.Mock()
    r.status_code = 200
    return r


def _no_network(*a, **kw):
    raise AssertionError(f"unexpected outbound request: {a} {kw}")


class PhoneInfogaModuleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = PhoneInfogaModule()
        self.seed = Finding(type=EntityType.PHONE, value="+1 (555) 555-0123", depth=0)
        # binary "present", API mocked, no other GET/POST allowed
        self.patches = [
            mock.patch.object(PhoneInfogaModule, "available", return_value=True),
            mock.patch.object(PhoneInfogaModule, "_query_api", return_value=API_RESULT),
            mock.patch(GET, side_effect=_no_network),
            mock.patch(POST, side_effect=_no_network),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self) -> None:
        mock.patch.stopall()

    def _run(self, head_side_effect=_fake_head):
        with mock.patch(HEAD, side_effect=head_side_effect) as head:
            out = self.mod.run(self.seed)
        return out, head

    def test_metadata(self):
        m = PhoneInfogaModule()
        self.assertEqual(m.name, "phoneinfoga")
        self.assertEqual(m.accepts, {EntityType.PHONE})
        self.assertEqual(m.requires_binary, "phoneinfoga")
        self.assertTrue(m.handles(self.seed))
        self.assertFalse(m.handles(Finding(type=EntityType.EMAIL, value="a@b.c")))

    def test_extract_site_domains(self):
        self.assertEqual(extract_site_domains(_dork("vk.com")["url"]), ["vk.com"])
        self.assertEqual(extract_site_domains(_dork(None)["url"]), [])
        self.assertEqual(extract_site_domains("not a url"), [])

    def test_single_phone_finding(self):
        out, _ = self._run()
        self.assertEqual(len(out), 1)
        f = out[0]
        self.assertEqual(f.type, EntityType.PHONE)
        self.assertEqual(f.value, NUMBER)
        self.assertEqual(f.source, "phoneinfoga")
        self.assertEqual(f.parent, self.seed.value)
        self.assertEqual(f.confidence, 0.8)
        self.assertEqual(f.depth, 1)
        for k in ("e164", "international", "country_code"):
            self.assertIn(k, f.meta)
        self.assertEqual(f.meta["e164"], NUMBER)
        self.assertEqual(f.meta["international"], DIGITS)
        self.assertEqual(set(f.meta["dorks"]),
                         {"social", "reputation", "individuals", "disposable", "general"})

    def test_no_null_meta_and_unavailable_marked(self):
        out, _ = self._run()
        meta = out[0].meta
        self.assertNotIn(None, meta.values())
        for k in ("carrier", "line_type", "country"):
            self.assertNotIn(k, meta)   # not returned by the offline scanner -> omitted
        self.assertEqual(set(meta["unavailable"]), {"carrier", "line_type"})
        for why in meta["unavailable"].values():
            self.assertIn("NUMVERIFY_API_KEY", why)

    def test_carrier_kept_when_scanner_returns_it(self):
        api = {"local": dict(API_RESULT["local"], carrier="ExampleTel", line_type="mobile"),
               "googlesearch": API_RESULT["googlesearch"]}
        with mock.patch.object(PhoneInfogaModule, "_query_api", return_value=api):
            out, _ = self._run()
        self.assertEqual(out[0].meta["carrier"], "ExampleTel")
        self.assertEqual(out[0].meta["line_type"], "mobile")
        self.assertNotIn("unavailable", out[0].meta)

    def test_dead_domains_dropped_live_kept(self):
        out, _ = self._run()
        dorks = out[0].meta["dorks"]
        kept = {d for items in dorks.values() for it in items for d in it["domains"]}
        self.assertEqual(kept, {"facebook.com", "vk.com", "whosenumber.info",
                                "numinfo.net", "hs3x.com"})
        self.assertFalse(kept & DEAD)
        self.assertEqual(len(dorks["reputation"]), 1)
        self.assertEqual(len(dorks["disposable"]), 1)
        self.assertEqual(len(dorks["general"]), 1)   # no site: -> kept
        flt = out[0].meta["dork_filter"]
        self.assertEqual(flt["status"], "filtered")
        self.assertEqual(set(flt["dead_domains"]), DEAD)
        # links stay as Google URLs (clickable) and are never fetched
        for items in dorks.values():
            for it in items:
                self.assertTrue(it["url"].startswith("https://www.google.com/search?q="))

    def test_phone_never_in_outbound_request(self):
        _, head = self._run()
        self.assertTrue(head.called)
        for call in head.call_args_list:
            url = call.args[0]
            # bare domain only, never google, never the number
            self.assertRegex(url, r"^https?://[a-z0-9.-]+$")
            self.assertNotIn("google", url)
            for needle in (DIGITS, NATIONAL, NUMBER, "%2B" + DIGITS, "555-0123"):
                self.assertNotIn(needle, url)
            self.assertNotIn(DIGITS, str(call.kwargs))

    def test_offline_keeps_all_links_unfiltered(self):
        out, _ = self._run(head_side_effect=requests.ConnectionError("offline"))
        dorks = out[0].meta["dorks"]
        total = sum(len(v) for v in dorks.values())
        self.assertEqual(total, 8)
        self.assertEqual(out[0].meta["dork_filter"]["status"], "skipped")
        self.assertTrue(out[0].meta["dork_filter"]["reason"])

    def test_liveness_crash_keeps_all_links(self):
        with mock.patch.object(phoneinfoga_mod, "check_domains", side_effect=RuntimeError("boom")):
            out, _ = self._run()
        self.assertEqual(sum(len(v) for v in out[0].meta["dorks"].values()), 8)
        self.assertEqual(out[0].meta["dork_filter"]["status"], "skipped")

    def test_binary_missing_returns_empty(self):
        with mock.patch.object(PhoneInfogaModule, "available", return_value=False):
            self.assertEqual(self.mod.run(self.seed), [])

    def test_api_failure_returns_empty(self):
        with mock.patch.object(PhoneInfogaModule, "_query_api", return_value=None):
            self.assertEqual(self.mod.run(self.seed), [])

    def test_bad_json_returns_empty(self):
        """Real _query_api with a server returning non-JSON -> [] without crashing."""
        self.patches[1].stop()
        proc = mock.Mock()
        proc.poll.return_value = None
        bad = mock.Mock()
        bad.json.side_effect = ValueError("not json")
        with mock.patch("modules.phoneinfoga_mod.subprocess.Popen", return_value=proc), \
             mock.patch(GET, return_value=mock.Mock()), \
             mock.patch(POST, return_value=bad) as post, \
             mock.patch(HEAD, side_effect=_no_network):
            self.assertEqual(self.mod.run(self.seed), [])
        proc.terminate.assert_called()
        # the number goes ONLY to the local phoneinfoga
        for call in post.call_args_list:
            self.assertTrue(call.args[0].startswith("http://127.0.0.1:"))

    def test_does_not_rescan_own_output(self):
        own = Finding(type=EntityType.PHONE, value=NUMBER, source="phoneinfoga", depth=1)
        self.assertEqual(self.mod.run(own), [])

    def test_e164_seed_counted_in_summary_table_and_ui(self):
        """Seed already in E164 form: the result must count as a normal finding."""
        target = Target(label="t")
        target.add_seed(EntityType.PHONE, NUMBER)
        with mock.patch(HEAD, side_effect=_fake_head):
            orch = Orchestrator([self.mod], max_depth=2)
            results = correlate(orch.run(target))
        found = [f for f in results.values() if f.source == "phoneinfoga"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].value, NUMBER)
        self.assertIn("dorks", found[0].meta)
        # input seed stays a plain input, untouched by the module
        seed = results[f"phone:{NUMBER}"]
        self.assertEqual(seed.source, "input")
        self.assertNotIn("dorks", seed.meta)
        # CLI count, by-type and HTML findings table
        summary = summarize(results)
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["by_type"], {"phone": 1})
        self.assertIn("phoneinfoga", html_report._rows(results))
        # graph edge input -> result
        self.assertIn((seed.node_id, found[0].node_id), orch.edges)
        # Rich summary table (if rich is installed)
        if console_ui.RICH_AVAILABLE:
            from rich.console import Console
            ui = console_ui.RichUI()
            ui.console = Console(record=True, width=120, file=io.StringIO())
            ui.summary(results, summary, "t", {})
            text = ui.console.export_text()
            self.assertIn("1 findings", text)
            self.assertIn("phoneinfoga", text)
        section = html_report._phone_section(results)
        self.assertIn("Phone intelligence", section)
        self.assertIn("vk.com", section)
        self.assertNotIn("site%3Adead-sms.example", section)  # dead link removed


if __name__ == "__main__":
    unittest.main(verbosity=2)
