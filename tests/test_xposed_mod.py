"""
Offline tests for XposedModule. They mock requests.get, so no internet is
needed. They run with pytest or as a plain script:

    python -m pytest tests/
    python tests/test_xposed_mod.py
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

import requests

# so it also runs as a plain script from any directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import EntityType, Finding  # noqa: E402
from modules.xposed_mod import XposedModule  # noqa: E402

GET = "modules.xposed_mod.requests.get"
SLEEP = "modules.xposed_mod.time.sleep"


def _resp(status: int, payload=None, headers=None, bad_json: bool = False):
    """Fake requests.Response with status, json() and headers."""
    r = mock.Mock()
    r.status_code = status
    r.headers = headers or {}
    if bad_json:
        r.json.side_effect = ValueError("not json")
    else:
        r.json.return_value = payload
    return r


# same shape as the real API response (verified live)
FOUND = {
    "breaches": [["Adobe", "LinkedIn", "Dropbox"]],
    "email": "test@example.com",
    "status": "success",
}
NOT_FOUND = {"Error": "Not found"}


class XposedModuleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = XposedModule()
        self.seed = Finding(type=EntityType.EMAIL, value="test@example.com", depth=0)

    def test_metadata(self):
        self.assertEqual(self.mod.name, "xposedornot")
        self.assertEqual(self.mod.accepts, {EntityType.EMAIL})
        self.assertIsNone(self.mod.requires_binary)
        self.assertTrue(self.mod.available())
        self.assertTrue(self.mod.handles(self.seed))
        self.assertFalse(self.mod.handles(Finding(type=EntityType.USERNAME, value="x")))

    def test_breaches_found(self):
        with mock.patch(GET, return_value=_resp(200, FOUND)) as get:
            out = self.mod.run(self.seed)

        url = get.call_args.args[0]
        self.assertEqual(url, "https://api.xposedornot.com/v1/check-email/test@example.com")
        self.assertEqual(get.call_args.kwargs["headers"]["User-Agent"], "zerosint/0.1")
        self.assertIn("timeout", get.call_args.kwargs)

        self.assertEqual([f.value for f in out], ["Adobe", "LinkedIn", "Dropbox"])
        for f in out:
            self.assertEqual(f.type, EntityType.BREACH.value)
            self.assertEqual(f.source, "xposedornot")
            self.assertEqual(f.parent, "test@example.com")
            self.assertEqual(f.confidence, 0.85)
            self.assertEqual(f.depth, 1)
            self.assertEqual(f.meta, {"account": "test@example.com"})

    def test_depth_follows_seed(self):
        seed = Finding(type=EntityType.EMAIL, value="a@b.com", depth=1)
        with mock.patch(GET, return_value=_resp(200, FOUND)):
            out = self.mod.run(seed)
        self.assertTrue(all(f.depth == 2 for f in out))

    def test_nested_and_duplicate_names_flattened(self):
        payload = {"breaches": [["Adobe", "LinkedIn"], ["Adobe", "", "Yahoo"]]}
        with mock.patch(GET, return_value=_resp(200, payload)):
            out = self.mod.run(self.seed)
        self.assertEqual([f.value for f in out], ["Adobe", "LinkedIn", "Yahoo"])

    def test_not_found_404(self):
        with mock.patch(GET, return_value=_resp(404, NOT_FOUND)):
            self.assertEqual(self.mod.run(self.seed), [])

    def test_not_found_200(self):
        with mock.patch(GET, return_value=_resp(200, NOT_FOUND)):
            self.assertEqual(self.mod.run(self.seed), [])

    def test_429_retries_once_then_succeeds(self):
        responses = [_resp(429, {}, {"retry-after": "3"}), _resp(200, FOUND)]
        with mock.patch(GET, side_effect=responses) as get, mock.patch(SLEEP) as sleep:
            out = self.mod.run(self.seed)
        self.assertEqual(get.call_count, 2)
        sleep.assert_called_once_with(3)
        self.assertEqual(len(out), 3)

    def test_429_twice_gives_up(self):
        with mock.patch(GET, return_value=_resp(429, {}, {"retry-after": "999"})) as get, \
                mock.patch(SLEEP) as sleep:
            out = self.mod.run(self.seed)
        self.assertEqual(out, [])
        self.assertEqual(get.call_count, 2)  # ONE retry, not unlimited
        sleep.assert_called_once_with(10)    # Retry-After is capped at 10s

    def test_request_exception(self):
        with mock.patch(GET, side_effect=requests.ConnectionError("down")):
            self.assertEqual(self.mod.run(self.seed), [])

    def test_server_error(self):
        with mock.patch(GET, return_value=_resp(500, {"detail": "oops"})):
            self.assertEqual(self.mod.run(self.seed), [])

    def test_bad_json(self):
        with mock.patch(GET, return_value=_resp(200, bad_json=True)):
            self.assertEqual(self.mod.run(self.seed), [])

    def test_email_is_url_encoded(self):
        # "#" would otherwise cut the URL into a fragment; "@" stays as the API expects
        seed = Finding(type=EntityType.EMAIL, value="a#b+c@x.com", depth=0)
        with mock.patch(GET, return_value=_resp(404, NOT_FOUND)) as get:
            self.mod.run(seed)
        self.assertTrue(get.call_args.args[0].endswith("/check-email/a%23b%2Bc@x.com"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
