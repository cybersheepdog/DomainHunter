"""Unit tests for the real-time monitor's pure logic (matching + message parsing).

Run with:  python -m unittest test_realtime
"""
import json
import os
import tempfile
import unittest

from domainhunter import AdvancedDomainHunter
from realtime_monitor import RealtimeMonitor


class RealtimeTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.domains_path = os.path.join(d, "monitored_domains.txt")
        self.tlds_path = os.path.join(d, "abused_tlds.dict")
        with open(self.domains_path, "w") as f:
            f.write("google.com\nexample.co.uk\n")
        with open(self.tlds_path, "w") as f:
            f.write("xyz\n")
        self.hunter = AdvancedDomainHunter(
            config_path=os.path.join(d, "config.ini"),
            target_domains_path=self.domains_path,
            tlds_dict_path=self.tlds_path,
        )
        self.mon = RealtimeMonitor(self.hunter, certstream_url="wss://unused/")

    def tearDown(self):
        self.hunter.executor.shutdown(wait=False)
        self.hunter.whois_executor.shutdown(wait=False)
        self.tmp.cleanup()


class TestMatching(RealtimeTestBase):
    def test_exact_permutation_matches(self):
        m = self.mon.match("gogle.com")          # omission of 'o'
        self.assertIsNotNone(m)
        self.assertEqual(m[1][0], "google.com")

    def test_subdomain_of_permutation_matches(self):
        m = self.mon.match("login.gogle.com")     # subdomain on a permutation
        self.assertIsNotNone(m)
        self.assertEqual(m[0], "gogle.com")

    def test_wildcard_stripped(self):
        self.assertIsNotNone(self.mon.match("*.gogle.com"))

    def test_multi_label_tld_permutation(self):
        # example.co.uk -> name 'example', tld 'co.uk'; an omission like 'example'->'exmple'
        hit = None
        for cand in ("exmple.co.uk", "exaple.co.uk", "exampl.co.uk"):
            if self.mon.match(cand):
                hit = cand
                break
        self.assertIsNotNone(hit, "expected at least one co.uk omission permutation to match")

    def test_unrelated_domain_no_match(self):
        self.assertIsNone(self.mon.match("totally-unrelated-site.com"))
        self.assertIsNone(self.mon.match(""))

    def test_legit_domain_not_a_permutation(self):
        # The monitored domain itself is never emitted as its own permutation.
        self.assertIsNone(self.mon.match("google.com"))


class TestExtractDomains(RealtimeTestBase):
    def test_certificate_update(self):
        raw = json.dumps({
            "message_type": "certificate_update",
            "data": {"leaf_cert": {"all_domains": ["a.com", "*.b.com"]}},
        })
        self.assertEqual(self.mon.extract_domains(raw), ["a.com", "*.b.com"])

    def test_heartbeat_and_garbage(self):
        self.assertEqual(self.mon.extract_domains(json.dumps({"message_type": "heartbeat"})), [])
        self.assertEqual(self.mon.extract_domains("not json"), [])
        self.assertEqual(self.mon.extract_domains(json.dumps({"data": {}})), [])


if __name__ == "__main__":
    unittest.main()
