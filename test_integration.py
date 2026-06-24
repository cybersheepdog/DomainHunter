"""Integration-ish tests for the HTTP lookup flows, using a fake aiohttp session
(no network). Covers RDAP parsing, the RDAP 429 Retry-After path, and crt.sh.

Run with:  python -m unittest test_integration
"""
import asyncio
import os
import tempfile
import unittest

from domainhunter import AdvancedDomainHunter


class FakeResp:
    def __init__(self, status, json_data=None, headers=None):
        self.status = status
        self._json = json_data
        self.headers = headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def json(self, content_type=None):
        return self._json


class FakeSession:
    """Returns queued responses in order; records requested URLs."""
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        return self._responses.pop(0)


class IntegrationBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        for fn in ("monitored_domains.txt", "abused_tlds.dict"):
            open(os.path.join(d, fn), "w").close()
        self.hunter = AdvancedDomainHunter(
            config_path=os.path.join(d, "config.ini"),
            target_domains_path=os.path.join(d, "monitored_domains.txt"),
            tlds_dict_path=os.path.join(d, "abused_tlds.dict"),
        )
        self.sem = asyncio.Semaphore(2)

    def tearDown(self):
        self.hunter.executor.shutdown(wait=False)
        self.hunter.whois_executor.shutdown(wait=False)
        self.tmp.cleanup()


RDAP_OK = {
    "events": [{"eventAction": "registration", "eventDate": "2019-05-06T00:00:00Z"}],
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [
        ["fn", {}, "text", "Jane"], ["email", {}, "text", "j@e.com"]]]}],
}


class TestRdapFlow(IntegrationBase):
    def test_success(self):
        sess = FakeSession([FakeResp(200, RDAP_OK)])
        out = asyncio.run(self.hunter.fetch_rdap("evil.com", sess, self.sem))
        self.assertEqual(out["Created"], "2019-05-06")
        self.assertEqual(out["Registrant"], "Jane")
        self.assertEqual(len(sess.calls), 1)

    def test_429_then_success_retries(self):
        sess = FakeSession([
            FakeResp(429, headers={"Retry-After": "0"}),
            FakeResp(200, RDAP_OK),
        ])
        out = asyncio.run(self.hunter.fetch_rdap("evil.com", sess, self.sem))
        self.assertIsNotNone(out)
        self.assertEqual(out["Created"], "2019-05-06")
        self.assertEqual(len(sess.calls), 2)  # retried once

    def test_429_no_retry_after_gives_up(self):
        sess = FakeSession([FakeResp(429, headers={})])
        out = asyncio.run(self.hunter.fetch_rdap("evil.com", sess, self.sem))
        self.assertIsNone(out)
        self.assertEqual(len(sess.calls), 1)

    def test_404_returns_none(self):
        sess = FakeSession([FakeResp(404)])
        self.assertIsNone(asyncio.run(self.hunter.fetch_rdap("evil.com", sess, self.sem)))

    def test_no_session(self):
        self.assertIsNone(asyncio.run(self.hunter.fetch_rdap("evil.com", None, self.sem)))


class TestCtFlow(IntegrationBase):
    def test_hit(self):
        sess = FakeSession([FakeResp(200, [{"id": 1}, {"id": 2}])])
        out = asyncio.run(self.hunter.fetch_ct_logs("evil.com", sess, self.sem))
        self.assertEqual(out, {"certs": 2})

    def test_empty_is_none(self):
        sess = FakeSession([FakeResp(200, [])])
        self.assertIsNone(asyncio.run(self.hunter.fetch_ct_logs("evil.com", sess, self.sem)))

    def test_non_200_is_none(self):
        sess = FakeSession([FakeResp(503)])
        self.assertIsNone(asyncio.run(self.hunter.fetch_ct_logs("evil.com", sess, self.sem)))


if __name__ == "__main__":
    unittest.main()
