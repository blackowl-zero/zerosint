"""
Offline tests for BreachModule (HIBP) and check_password_pwned. They mock
requests.get and time.sleep, so no internet and no waiting:

    python -m unittest discover -s tests
    python tests/test_breach_mod.py
"""
from __future__ import annotations

import hashlib
import os
import sys
import unittest
from unittest import mock

# so it also runs as a plain script from any directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import EntityType, Finding  # noqa: E402
from modules.breach_mod import BreachModule, check_password_pwned  # noqa: E402

GET = "modules.breach_mod.requests.get"
SLEEP = "modules.breach_mod.time.sleep"


def _resp(status: int, payload=None, headers=None, text: str = ""):
    """Fake requests.Response with status, json(), text and headers."""
    r = mock.Mock()
    r.status_code = status
    r.headers = headers or {}
    r.json.return_value = payload
    r.text = text
    return r


class BreachModuleTest(unittest.TestCase):
    def setUp(self) -> None:
        with mock.patch.dict(os.environ, {"HIBP_API_KEY": "k"}):
            self.mod = BreachModule()
        self.seed = Finding(type=EntityType.EMAIL, value="test@example.com", depth=0)

    def _sleeps(self, sleep) -> list:
        return [c.args[0] for c in sleep.call_args_list]

    def test_persistent_429_gives_up_cleanly(self):
        with mock.patch(GET, return_value=_resp(429)) as get, \
             mock.patch(SLEEP) as sleep, \
             self.assertLogs("osint", level="ERROR") as logs:
            out = self.mod.run(self.seed)
        self.assertEqual(out, [])
        self.assertEqual(get.call_count, 4)
        self.assertEqual(self._sleeps(sleep), [1, 2, 4])
        self.assertEqual(len([r for r in logs.records if r.levelname == "ERROR"]), 1)

    def test_retry_after_header_honoured(self):
        seq = [_resp(429, headers={"retry-after": "3"}), _resp(404)]
        with mock.patch(GET, side_effect=seq), mock.patch(SLEEP) as sleep:
            self.assertEqual(self.mod.run(self.seed), [])
        self.assertEqual(self._sleeps(sleep), [3])

    def test_retry_after_capped(self):
        seq = [_resp(429, headers={"retry-after": "999"}), _resp(404)]
        with mock.patch(GET, side_effect=seq), mock.patch(SLEEP) as sleep:
            self.assertEqual(self.mod.run(self.seed), [])
        self.assertEqual(self._sleeps(sleep), [10])

    def test_bad_retry_after_header_falls_back_to_backoff(self):
        seq = [_resp(429, headers={"retry-after": "soon"}), _resp(404)]
        with mock.patch(GET, side_effect=seq), mock.patch(SLEEP) as sleep:
            self.assertEqual(self.mod.run(self.seed), [])
        self.assertEqual(self._sleeps(sleep), [1])

    def test_account_is_url_encoded(self):
        # "#" would otherwise cut the URL into a fragment; "@" stays readable
        seed = Finding(type=EntityType.EMAIL, value="a#b+c@x.com", depth=0)
        with mock.patch(GET, return_value=_resp(404)) as get:
            self.mod.run(seed)
        self.assertTrue(get.call_args.args[0].endswith("/breachedaccount/a%23b%2Bc@x.com"))

    def test_parses_breaches(self):
        payload = [{"Name": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
                    "DataClasses": ["Emails"]}]
        with mock.patch(GET, return_value=_resp(200, payload)):
            out = self.mod.run(self.seed)
        self.assertEqual(len(out), 1)
        f = out[0]
        self.assertEqual(f.type, "breach")
        self.assertEqual(f.value, "Adobe")
        self.assertEqual(f.meta["account"], self.seed.value)
        self.assertEqual(f.confidence, 0.9)


class PwnedPasswordTest(unittest.TestCase):
    def test_pwned_ignores_malformed_lines(self):
        pw = "password"
        suffix = hashlib.sha1(pw.encode()).hexdigest().upper()[5:]
        body = "garbage\n" + suffix + ":42"
        with mock.patch(GET, return_value=_resp(200, text=body)):
            self.assertEqual(check_password_pwned(pw), 42)


if __name__ == "__main__":
    unittest.main(verbosity=2)
