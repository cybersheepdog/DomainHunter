"""Unit tests for DomainHunter's pure logic (no network / I/O side effects).

Run with:  python -m unittest test_domainhunter
"""
import os
import tempfile
import unittest
from datetime import datetime, timedelta

from domainhunter import AdvancedDomainHunter, WHOIS_CACHE_TTL_DAYS


class HunterTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.config_path = os.path.join(d, "config.ini")
        self.domains_path = os.path.join(d, "monitored_domains.txt")
        self.tlds_path = os.path.join(d, "abused_tlds.dict")
        with open(self.domains_path, "w") as f:
            f.write("google.com\n")
        with open(self.tlds_path, "w") as f:
            f.write("xyz\ntop\n")
        self.hunter = AdvancedDomainHunter(
            config_path=self.config_path,
            target_domains_path=self.domains_path,
            tlds_dict_path=self.tlds_path,
        )

    def tearDown(self):
        self.hunter.executor.shutdown(wait=False)
        self.tmp.cleanup()


class TestPermutations(HunterTestBase):
    def test_basic_properties(self):
        perms = self.hunter.generate_permutations("google.com")
        self.assertGreater(len(perms), 20)
        # The original domain must never be emitted as its own permutation.
        self.assertNotIn("google.com", perms)
        # Every key is a full domain with a label and a TLD.
        for dom in perms:
            self.assertIn(".", dom)

    def test_known_mutations_present(self):
        perms = self.hunter.generate_permutations("google.com")
        self.assertIn("gogle.com", perms)        # omission
        self.assertIn("google.xyz", perms)       # abused TLD swap
        self.assertIn("googel.com", perms)        # transposition
        self.assertIn("google-login.com", perms)  # dictionary affix

    def test_short_domain_returns_empty(self):
        self.assertEqual(self.hunter.generate_permutations("localhost"), {})


class TestClassification(HunterTestBase):
    def setUp(self):
        super().setUp()
        self.baseline = datetime(2026, 6, 1)

    def _rec(self, domain, created):
        return {"Domain": domain, "Date Created": created}

    def test_buckets(self):
        active = [
            self._rec("old.com", "2024-01-01"),       # predates baseline -> silent
            self._rec("new.com", "2026-06-15"),       # after baseline    -> new
            self._rec("unknown.com", None),           # unknown date      -> new (alert)
            self._rec("already.com", "2020-01-01"),   # already tracked   -> skipped
        ]
        existing = {"already.com"}
        new, silent = self.hunter.classify_new_records(active, existing, self.baseline)
        new_domains = {r["Domain"] for r in new}
        silent_domains = {r["Domain"] for r in silent}
        self.assertEqual(new_domains, {"new.com", "unknown.com"})
        self.assertEqual(silent_domains, {"old.com"})

    def test_existing_match_is_case_insensitive(self):
        active = [self._rec("Already.COM", "2026-06-15")]
        new, silent = self.hunter.classify_new_records(active, {"already.com"}, self.baseline)
        self.assertEqual(new, [])
        self.assertEqual(silent, [])


class TestHelpers(HunterTestBase):
    def test_excel_path(self):
        self.assertEqual(self.hunter._excel_path("example.com"), "example_com.xlsx")
        self.assertEqual(self.hunter._excel_path("example.net"), "example_net.xlsx")
        self.assertEqual(self.hunter._excel_path("sub.example.co.uk"), "sub_example_co_uk.xlsx")

    def test_parse_created(self):
        self.assertEqual(AdvancedDomainHunter._parse_created("2025-03-04"), datetime(2025, 3, 4))
        self.assertIsNone(AdvancedDomainHunter._parse_created(None))
        self.assertIsNone(AdvancedDomainHunter._parse_created("not-a-date"))

    def test_cache_fresh(self):
        today = datetime.now().strftime("%Y-%m-%d")
        old = (datetime.now() - timedelta(days=WHOIS_CACHE_TTL_DAYS + 1)).strftime("%Y-%m-%d")
        self.assertTrue(AdvancedDomainHunter._cache_fresh(today))
        self.assertFalse(AdvancedDomainHunter._cache_fresh(old))
        self.assertFalse(AdvancedDomainHunter._cache_fresh(None))

    def test_phash_distance(self):
        self.assertEqual(AdvancedDomainHunter._phash_distance("f" * 16, "f" * 16), 0)
        self.assertEqual(AdvancedDomainHunter._phash_distance("0" * 16, "f" * 16), 64)
        self.assertIsNone(AdvancedDomainHunter._phash_distance(None, "f" * 16))

    def test_esc(self):
        self.assertEqual(AdvancedDomainHunter._esc("<script>"), "&lt;script&gt;")
        self.assertEqual(AdvancedDomainHunter._esc(None), "")
        self.assertEqual(AdvancedDomainHunter._esc('a"&b'), "a&quot;&amp;b")


class TestHtmlTableEscaping(HunterTestBase):
    def test_injection_is_escaped(self):
        records = [{
            "Permutation Type": "Homoglyph",
            "Domain": "evil.com",
            "Registrant Name": "<script>alert(1)</script>",
            "Visual Distance": 3,
        }]
        out = self.hunter.build_html_table(records)
        self.assertNotIn("<script>alert(1)</script>", out)
        self.assertIn("&lt;script&gt;", out)
        # A close visual distance should be highlighted as a clone.
        self.assertIn("visual clone", out)


if __name__ == "__main__":
    unittest.main()
