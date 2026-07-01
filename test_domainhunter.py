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
        self.hunter.whois_executor.shutdown(wait=False)
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

    def test_no_case_variant_of_original(self):
        # Regression: bitsquatting flips the ASCII case bit; case variants must not be
        # emitted as permutations (DNS is case-insensitive -> same host as original).
        perms = self.hunter.generate_permutations("google.com")
        self.assertTrue(all(k == k.lower() for k in perms), "all permutation keys must be lowercase")
        self.assertNotIn("google.com", {k.lower() for k in perms})


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

    def test_norm(self):
        self.assertEqual(AdvancedDomainHunter._norm(None), "")
        self.assertEqual(AdvancedDomainHunter._norm("nan"), "")
        self.assertEqual(AdvancedDomainHunter._norm("  x "), "x")

    def test_parse_retry_after(self):
        self.assertEqual(AdvancedDomainHunter._parse_retry_after("5"), 5.0)
        self.assertIsNone(AdvancedDomainHunter._parse_retry_after(None))
        self.assertIsNone(AdvancedDomainHunter._parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"))


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


class TestChangeDetection(HunterTestBase):
    def _rec(self, **over):
        base = {"Domain": "evil.com", "IP": "", "Name Server": "", "Mail Server": "",
                "Visual Distance": None, "Registrant Name": "", "Organization": ""}
        base.update(over)
        return base

    def test_mail_activation_alerts(self):
        old = self._rec(IP="1.1.1.1")
        new = self._rec(IP="1.1.1.1", **{"Mail Server": "mx.evil.com"})
        changes, updated = self.hunter.detect_changes([new], {"evil.com": old})
        self.assertTrue(any("Mail server" in c["Event"] for c in changes))
        self.assertTrue(any(c["Severity"] == "HIGH" for c in changes))
        self.assertIn("evil.com", updated)

    def test_ip_churn_ignored_by_default(self):
        old = self._rec(IP="1.1.1.1", **{"Name Server": "ns.x"})
        new = self._rec(IP="2.2.2.2", **{"Name Server": "ns.x"})   # only the IP rotated
        changes, updated = self.hunter.detect_changes([new], {"evil.com": old})
        self.assertEqual(changes, [])
        self.assertEqual(updated, {})

    def test_record_reorder_is_not_a_change(self):
        old = self._rec(IP="1.1.1.1", **{"Name Server": "a.ns, b.ns"})
        new = self._rec(IP="1.1.1.1", **{"Name Server": "b.ns, a.ns"})   # same set, reordered
        changes, _ = self.hunter.detect_changes([new], {"evil.com": old})
        self.assertEqual(changes, [])

    def test_visual_clone_appearance_is_critical(self):
        old = self._rec(IP="1.1.1.1", **{"Visual Distance": None})
        new = self._rec(IP="1.1.1.1", **{"Visual Distance": 3})
        changes, _ = self.hunter.detect_changes([new], {"evil.com": old})
        self.assertTrue(any(c["Severity"] == "CRITICAL" for c in changes))

    def test_went_live_alerts(self):
        old = self._rec(IP="")             # was parked / not resolving
        new = self._rec(IP="9.9.9.9")
        changes, _ = self.hunter.detect_changes([new], {"evil.com": old})
        self.assertTrue(any("went live" in c["Event"] for c in changes))

    def test_nameserver_redelegation_alerts(self):
        old = self._rec(IP="1.1.1.1", **{"Name Server": "ns.parking"})
        new = self._rec(IP="1.1.1.1", **{"Name Server": "ns.hosting"})
        changes, _ = self.hunter.detect_changes([new], {"evil.com": old})
        self.assertTrue(any(c["Severity"] == "MEDIUM" for c in changes))

    def test_registrant_change_ignored_by_default(self):
        old = self._rec(IP="1.1.1.1", **{"Registrant Name": "Joe"})
        new = self._rec(IP="1.1.1.1", **{"Registrant Name": "Jane"})
        changes, _ = self.hunter.detect_changes([new], {"evil.com": old})
        self.assertEqual(changes, [])

    def test_event_carries_phash_and_detected(self):
        old = self._rec(IP="1.1.1.1")
        new = self._rec(IP="1.1.1.1", **{"Mail Server": "mx.x", "PHash": "ff00",
                                         "Detected": "2026-06-24 10:00:00"})
        changes, _ = self.hunter.detect_changes([new], {"evil.com": old})
        self.assertTrue(changes)
        self.assertEqual(changes[0]["PHash"], "ff00")
        self.assertEqual(changes[0]["Detected"], "2026-06-24 10:00:00")

    def test_unknown_domain_skipped(self):
        changes, updated = self.hunter.detect_changes([self._rec(Domain="brandnew.com", IP="1.2.3.4")], {})
        self.assertEqual(changes, [])
        self.assertEqual(updated, {})


class TestAssembleRecord(HunterTestBase):
    def test_shape_and_mapping(self):
        dns_data = {"IP": "1.2.3.4", "Name Server": "ns1", "Mail Server": "mx1", "Active": True}
        reg = {"Created": "2020-01-01", "Updated": "2021-02-02", "Registrant": "Joe",
               "Org": "Acme", "Email1": "a@x.com", "Email2": None}
        rec = AdvancedDomainHunter._assemble_record("evil.com", "Omission", "CT-RT", dns_data, reg, "abc", 7)
        self.assertEqual(set(rec.keys()), set(self.hunter.EXCEL_COLUMNS))
        self.assertIn("Detected", rec)
        self.assertTrue(rec["Detected"])
        self.assertEqual(rec["PHash"], "abc")
        self.assertEqual(rec["Domain"], "evil.com")
        self.assertEqual(rec["Discovery Source"], "CT-RT")
        self.assertEqual(rec["Date Created"], "2020-01-01")
        self.assertEqual(rec["IP"], "1.2.3.4")
        self.assertEqual(rec["Visual Distance"], 7)
        self.assertEqual(rec["Registered Email 1"], "a@x.com")


class TestRdapParsing(HunterTestBase):
    def test_events_and_entities(self):
        data = {
            "events": [
                {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2023-08-20T09:00:00Z"},
            ],
            "entities": [
                {"roles": ["registrant"], "vcardArray": ["vcard", [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Jane Doe"],
                    ["org", {}, "text", "Example LLC"],
                    ["email", {}, "text", "jane@example.com"],
                ]]},
            ],
        }
        out = self.hunter._parse_rdap(data)
        self.assertEqual(out["Created"], "1997-09-15")
        self.assertEqual(out["Updated"], "2023-08-20")
        self.assertEqual(out["Registrant"], "Jane Doe")
        self.assertEqual(out["Org"], "Example LLC")
        self.assertEqual(out["Email1"], "jane@example.com")

    def test_empty(self):
        out = self.hunter._parse_rdap({})
        self.assertIsNone(out["Created"])
        self.assertIsNone(out["Registrant"])

    def test_vcard_org_as_list(self):
        vcard = ["vcard", [["org", {}, "text", ["Example LLC", "Dept"]]]]
        name, org, email = self.hunter._parse_vcard(vcard)
        self.assertEqual(org, "Example LLC")


class TestFalsePositiveReduction(HunterTestBase):
    def _rec(self, **over):
        base = {"Domain": "evil.com", "IP": "", "Name Server": "", "Mail Server": "",
                "Visual Distance": None, "Registrant Name": "", "Organization": ""}
        base.update(over)
        return base

    def test_ignore_list_exact_and_suffix(self):
        self.hunter.ignored_domains = {"evil.com", "partner.co.uk"}
        self.assertTrue(self.hunter._is_ignored("evil.com"))
        self.assertTrue(self.hunter._is_ignored("www.evil.com"))        # subdomain
        self.assertTrue(self.hunter._is_ignored("mail.partner.co.uk"))  # multi-label suffix
        self.assertFalse(self.hunter._is_ignored("notevil.com"))

    def test_own_infra_suppression(self):
        primary = {"203.0.113.5"}
        self.assertTrue(self.hunter._is_own_infra(self._rec(IP="203.0.113.5"), primary))
        self.assertFalse(self.hunter._is_own_infra(self._rec(IP="198.51.100.9"), primary))
        self.assertFalse(self.hunter._is_own_infra(self._rec(IP="203.0.113.5"), set()))

    def test_parking_suppresses_went_live(self):
        old = self._rec(IP="")
        new = self._rec(IP="1.2.3.4", **{"Name Server": "ns1.sedoparking.com"})
        changes, _ = self.hunter.detect_changes([new], {"evil.com": old})
        self.assertFalse(any("went live" in c["Event"] for c in changes))

    def test_nonparking_went_live_still_alerts(self):
        old = self._rec(IP="")
        new = self._rec(IP="1.2.3.4", **{"Name Server": "ns1.realhost.com"})
        changes, _ = self.hunter.detect_changes([new], {"evil.com": old})
        self.assertTrue(any("went live" in c["Event"] for c in changes))

    def test_ns_move_to_parking_suppressed(self):
        old = self._rec(IP="1.1.1.1", **{"Name Server": "ns.realhost.com"})
        new = self._rec(IP="1.1.1.1", **{"Name Server": "ns1.bodis.com"})
        changes, _ = self.hunter.detect_changes([new], {"evil.com": old})
        self.assertEqual(changes, [])

    def test_placeholder_mx_not_activation(self):
        old = self._rec(IP="1.1.1.1")
        new = self._rec(IP="1.1.1.1", **{"Mail Server": "localhost"})
        changes, _ = self.hunter.detect_changes([new], {"evil.com": old})
        self.assertFalse(any("Mail" in c["Event"] for c in changes))

    def test_confirmation_holds_then_alerts(self):
        change = {"Domain": "evil.com", "Event": "Mail server went live", "Old": "none",
                  "New": "mx.x", "Severity": "HIGH"}
        state = {}
        confirmed, _ = self.hunter._confirm_changes([dict(change)], state)
        self.assertEqual(confirmed, [])                 # 1st sighting held
        self.assertIn("pending_changes", state)
        confirmed2, doms2 = self.hunter._confirm_changes([dict(change)], state)
        self.assertEqual(len(confirmed2), 1)            # 2nd sighting confirms
        self.assertIn("evil.com", doms2)

    def test_confirmation_revert_drops(self):
        change = {"Domain": "evil.com", "Event": "X", "Old": "a", "New": "b", "Severity": "LOW"}
        state = {}
        self.hunter._confirm_changes([dict(change)], state)   # pending
        confirmed, _ = self.hunter._confirm_changes([], state)  # not seen next run -> drop
        self.assertEqual(confirmed, [])
        self.assertEqual(state.get("pending_changes"), {})


if __name__ == "__main__":
    unittest.main()
