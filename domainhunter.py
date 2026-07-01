# Python Standard Library Imports
import asyncio
import html
import json
import logging
import os
import socket
import sys

from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

# 3rd Party Imports
import aiohttp
import configparser
import dns.asyncresolver
import imagehash
import pandas as pd
import smtplib
import whois

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email import encoders
from PIL import Image

# Default runtime limits / tunables. Every one of these can be overridden per-install
# via a [SCAN] section in config.ini (created automatically on first run).
MAX_CONCURRENT_DNS = 40      # In-flight domains during DNS resolution
MAX_CONCURRENT_RDAP = 20     # In-flight RDAP (HTTP) registration lookups
MAX_CONCURRENT_WHOIS = 5     # Port-43 WHOIS fallback; servers rate-limit aggressively
MAX_CONCURRENT_RENDER = 4    # Headless page renders are heavy; cap parallelism
MAX_CONCURRENT_CT = 4        # crt.sh is easily overwhelmed; keep this very low
THREAD_POOL_SIZE = 5         # Worker pool for blocking phash computation

DNS_TIMEOUT = 2.0            # Seconds per DNS query
RDAP_TIMEOUT = 5.0           # Seconds per RDAP HTTP request
CT_TIMEOUT = 10.0            # Seconds per crt.sh request (it can be slow)
RDAP_MAX_RETRY_WAIT = 10.0   # Max seconds to honor an RDAP 429 Retry-After
WHOIS_QUERY_DELAY = 0.25     # Politeness delay (seconds) between WHOIS queries
WHOIS_CACHE_TTL_DAYS = 30    # Reuse a cached registration record for this many days
VISUAL_MATCH_THRESHOLD = 10  # Max perceptual-hash Hamming distance to flag a visual clone

CT_DISCOVERY = False         # Opt-in: check crt.sh for permutations that don't resolve
CHANGE_DETECTION = True      # Alert when a tracked domain's infrastructure changes

RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/{domain}"
CRTSH_URL = "https://crt.sh/?q={domain}&output=json"

# Brand logo shown at the foot of every alert email (embedded inline via Content-ID).
LOGO_CID = "domainhunter_logo"
LOGO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "brand", "domainhunter-logo-email.png")

# Configure Logging. Everything (including DEBUG) is written to the log file so failures
# stay diagnosable; the console stays at INFO unless DOMAINHUNTER_DEBUG is set.
DEBUG_ENABLED = os.environ.get("DOMAINHUNTER_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")

logger = logging.getLogger("DomainHunter")
logger.setLevel(logging.DEBUG)
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

file_handler = logging.FileHandler("domainhunter.log", mode="a", encoding="utf-8")
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.DEBUG)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(message)s'))
console_handler.setLevel(logging.DEBUG if DEBUG_ENABLED else logging.INFO)
logger.addHandler(console_handler)


class AdvancedDomainHunter:
    # Fields watched for change detection on already-tracked domains.
    WATCHED_FIELDS = ["IP", "Name Server", "Mail Server", "Registrant Name", "Organization"]

    EXCEL_COLUMNS = [
        "Permutation Type", "Domain", "Discovery Source", "Date Created", "Last Updated",
        "Registrant Name", "Organization", "PHash", "Visual Distance",
        "Name Server", "IP", "Mail Server", "Registered Email 1", "Registered Email 2"
    ]

    def __init__(self, config_path="config.ini", target_domains_path="monitored_domains.txt", tlds_dict_path="abused_tlds.dict"):
        self.config_path = config_path
        self.target_domains_path = target_domains_path
        self.tlds_dict_path = tlds_dict_path

        self.config = configparser.ConfigParser()
        self.load_config()

        self.monitored_domains = self._load_file_lines(self.target_domains_path)
        self.abused_tlds = self._load_file_lines(self.tlds_dict_path)

        # Two pools: blocking WHOIS fallback is isolated from phash computation so they
        # never starve each other.
        self.executor = ThreadPoolExecutor(max_workers=self.thread_pool_size)
        self.whois_executor = ThreadPoolExecutor(max_workers=self.max_concurrent_whois)

        # One shared async resolver, reused for every lookup.
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = self.dns_timeout
        self.resolver.lifetime = self.dns_timeout

        # QWERTY Keyboard proximity matrix for structural insertion mutations
        self.qwerty_matrix = {
            'a': ['q', 'w', 's', 'z'], 'b': ['v', 'g', 'h', 'n'], 'c': ['x', 'd', 'f', 'v'],
            'd': ['s', 'e', 'r', 'f', 'c', 'x'], 'e': ['w', 's', 'd', 'r'], 'f': ['d', 'r', 't', 'g', 'v', 'c'],
            'g': ['f', 't', 'y', 'h', 'b', 'v'], 'h': ['g', 'y', 'u', 'j', 'n', 'b'], 'i': ['u', 'j', 'k', 'o'],
            'j': ['h', 'u', 'i', 'k', 'm', 'n'], 'k': ['j', 'i', 'o', 'l', 'm'], 'l': ['k', 'o', 'p'],
            'm': ['n', 'j', 'k', 'l'], 'n': ['b', 'h', 'j', 'm'], 'o': ['i', 'k', 'l', 'p'],
            'p': ['o', 'l'], 'q': ['1', '2', 'w', 'a'], 'r': ['e', 'd', 'f', 't'], 's': ['a', 'w', 'e', 'd', 'x', 'z'],
            't': ['r', 'f', 'g', 'y'], 'u': ['y', 'h', 'j', 'i'], 'v': ['c', 'f', 'g', 'b'],
            'w': ['q', 'a', 's', 'e'], 'x': ['z', 's', 'd', 'c'], 'y': ['t', 'g', 'h', 'u'], 'z': ['a', 's', 'x'],
            '0': ['9', 'p'], '1': ['2', 'q'], '2': ['1', '3', 'q', 'w'], '3': ['2', '4', 'w', 'e'],
            '4': ['3', '5', 'e', 'r'], '5': ['4', '6', 'r', 't'], '6': ['5', '7', 't', 'y'],
            '7': ['6', '8', 'y', 'u'], '8': ['7', '9', 'u', 'i'], '9': ['8', '0', 'i', 'o']
        }

        # Unicode Homoglyph Look-alike Map (Latin to Cyrillic/Greek/Extended transitions)
        self.homoglyph_matrix = {
            'a': ['а', 'à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'α'],
            'c': ['с', 'ć', 'ĉ', 'ċ', 'č', '¢'],
            'e': ['е', 'è', 'é', 'ê', 'ë', 'ė', 'ě', 'ε', 'е'],
            'i': ['і', 'ì', 'í', 'î', 'ï', 'ı', 'ι'],
            'j': ['ј', 'ĵ', 'ǰ'],
            'o': ['о', 'ò', 'ó', 'â', 'õ', 'ö', 'ø', 'ο', 'о'],
            'p': ['р', 'ρ'],
            's': ['ѕ', 'ś', 'ŝ', 'ş', 'š'],
            'w': ['ԝ', 'ŵ'],
            'x': ['х', '×'],
            'y': ['у', 'ý', 'ÿ', 'γ']
        }

        # High-probability threat hunting dictionary modifiers
        self.hunting_keywords = [
            'login', 'secure', 'vpn', 'verify', 'account', 'mail', 'support',
            'update', 'portal', 'signin', 'auth', 'service', 'admin'
        ]

    def load_config(self):
        if os.path.exists(self.config_path):
            self.config.read(self.config_path)

        changed = False
        if 'EMAIL' not in self.config:
            self.config['EMAIL'] = {
                'password': '',
                'receiver_email': '',
                'sender_email': ''
            }
            changed = True

        scan_defaults = {
            'max_concurrent_dns': str(MAX_CONCURRENT_DNS),
            'max_concurrent_rdap': str(MAX_CONCURRENT_RDAP),
            'max_concurrent_whois': str(MAX_CONCURRENT_WHOIS),
            'max_concurrent_render': str(MAX_CONCURRENT_RENDER),
            'max_concurrent_ct': str(MAX_CONCURRENT_CT),
            'thread_pool_size': str(THREAD_POOL_SIZE),
            'dns_timeout': str(DNS_TIMEOUT),
            'rdap_timeout': str(RDAP_TIMEOUT),
            'ct_timeout': str(CT_TIMEOUT),
            'rdap_max_retry_wait': str(RDAP_MAX_RETRY_WAIT),
            'whois_query_delay': str(WHOIS_QUERY_DELAY),
            'whois_cache_ttl_days': str(WHOIS_CACHE_TTL_DAYS),
            'visual_match_threshold': str(VISUAL_MATCH_THRESHOLD),
            'ct_discovery': str(CT_DISCOVERY),
            'change_detection': str(CHANGE_DETECTION),
        }
        if 'SCAN' not in self.config:
            self.config['SCAN'] = scan_defaults
            changed = True
        else:
            # Backfill any keys added in newer versions without clobbering user values.
            for k, v in scan_defaults.items():
                if k not in self.config['SCAN']:
                    self.config['SCAN'][k] = v
                    changed = True

        if changed:
            with open(self.config_path, 'w') as f:
                self.config.write(f)

        # Resolve tunables into typed instance attributes (fall back to module defaults
        # if a value is missing or malformed).
        def _int(key, default):
            try:
                return self.config.getint('SCAN', key)
            except Exception:
                return default

        def _float(key, default):
            try:
                return self.config.getfloat('SCAN', key)
            except Exception:
                return default

        def _bool(key, default):
            try:
                return self.config.getboolean('SCAN', key)
            except Exception:
                return default

        self.max_concurrent_dns = _int('max_concurrent_dns', MAX_CONCURRENT_DNS)
        self.max_concurrent_rdap = _int('max_concurrent_rdap', MAX_CONCURRENT_RDAP)
        self.max_concurrent_whois = _int('max_concurrent_whois', MAX_CONCURRENT_WHOIS)
        self.max_concurrent_render = _int('max_concurrent_render', MAX_CONCURRENT_RENDER)
        self.max_concurrent_ct = _int('max_concurrent_ct', MAX_CONCURRENT_CT)
        self.thread_pool_size = _int('thread_pool_size', THREAD_POOL_SIZE)
        self.dns_timeout = _float('dns_timeout', DNS_TIMEOUT)
        self.rdap_timeout = _float('rdap_timeout', RDAP_TIMEOUT)
        self.ct_timeout = _float('ct_timeout', CT_TIMEOUT)
        self.rdap_max_retry_wait = _float('rdap_max_retry_wait', RDAP_MAX_RETRY_WAIT)
        self.whois_query_delay = _float('whois_query_delay', WHOIS_QUERY_DELAY)
        self.whois_cache_ttl_days = _int('whois_cache_ttl_days', WHOIS_CACHE_TTL_DAYS)
        self.visual_match_threshold = _int('visual_match_threshold', VISUAL_MATCH_THRESHOLD)
        self.ct_discovery = _bool('ct_discovery', CT_DISCOVERY)
        self.change_detection = _bool('change_detection', CHANGE_DETECTION)

    def _load_file_lines(self, path):
        if not os.path.exists(path):
            logger.info(f"[-] Warning: Reference file '{path}' not found. Creating empty file.")
            with open(path, 'w') as f: pass
            return []
        with open(path, 'r') as f:
            return [line.strip().lower().lstrip('.') for line in f if line.strip() and not line.startswith('#')]

    @staticmethod
    def _excel_path(primary_domain):
        """Per-target workbook name keyed on the FULL domain so e.g. example.com and
        example.net do not collide on the same file."""
        safe = primary_domain.strip().lower().replace('.', '_')
        return f"{safe}.xlsx"

    def _state_path(self, target_excel):
        """Sidecar file holding the baseline date and the registration cache for a target."""
        return f"{os.path.splitext(target_excel)[0]}.state.json"

    def _load_state(self, state_path):
        try:
            with open(state_path, 'r') as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"Could not read state '{state_path}': {e}")
        return {}

    def _save_state(self, state_path, state):
        """Atomic write: serialize to a temp file then replace, so an interrupted run
        can never leave a half-written (corrupt) state file."""
        tmp = f"{state_path}.tmp"
        try:
            with open(tmp, 'w') as f:
                json.dump(state, f)
            os.replace(tmp, state_path)
        except Exception as e:
            logger.info(f"[-] Could not persist state '{state_path}': {e}")
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass

    def _write_excel_atomic(self, df, target_excel):
        """Atomic workbook write via temp file + os.replace to protect the baseline.
        Columns are normalized to EXCEL_COLUMNS so the schema stays stable across runs."""
        tmp = f"{target_excel}.tmp"
        try:
            df = df.reindex(columns=self.EXCEL_COLUMNS)
            df.to_excel(tmp, index=False)
            os.replace(tmp, target_excel)
        except Exception as e:
            logger.info(f"[-] Could not write workbook '{target_excel}': {e}")
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass

    @staticmethod
    def _baseline_date_from_state(state):
        bd = state.get('baseline_date')
        if bd:
            try:
                return datetime.strptime(bd, "%Y-%m-%d")
            except Exception:
                pass
        return None

    @staticmethod
    def _parse_created(value):
        """Parse a date (WHOIS 'YYYY-MM-DD' or RDAP ISO-8601) into a datetime, or None."""
        if not value:
            return None
        try:
            return datetime.strptime(str(value)[:10], "%Y-%m-%d")
        except Exception:
            return None

    @staticmethod
    def _cache_fresh(fetched_str, ttl_days=WHOIS_CACHE_TTL_DAYS):
        """True if a cached registration record fetched on `fetched_str` is within TTL."""
        fetched = AdvancedDomainHunter._parse_created(fetched_str)
        if fetched is None:
            return False
        return (datetime.now() - fetched) <= timedelta(days=ttl_days)

    @staticmethod
    def _phash_distance(h1, h2):
        """Hamming distance between two perceptual-hash hex strings, or None."""
        if not h1 or not h2:
            return None
        try:
            return imagehash.hex_to_hash(str(h1)) - imagehash.hex_to_hash(str(h2))
        except Exception:
            return None

    @staticmethod
    def _norm(value):
        """Normalize a field for comparison: None/NaN/'' all collapse to ''."""
        if value is None:
            return ""
        s = str(value).strip()
        if s.lower() in ("nan", "none"):
            return ""
        return s

    def classify_new_records(self, active_records, existing_domains, baseline_date):
        """Split freshly-resolved records into genuine new discoveries vs. domains that
        predate the baseline (registered before the first scan but only now resolving).

        Pure function — no I/O — so it can be unit tested directly.
        """
        new_discoveries, silent_additions = [], []
        for record in active_records:
            if str(record.get('Domain', '')).lower() in existing_domains:
                continue
            created = self._parse_created(record.get('Date Created'))
            if created is not None and baseline_date is not None and created.date() < baseline_date.date():
                # Registered before the baseline was taken: it existed at first scan but
                # wasn't captured (parked / no DNS / transient lookup failure). Record it
                # to correct the baseline, but do not raise a false alert.
                silent_additions.append(record)
            else:
                new_discoveries.append(record)
        return new_discoveries, silent_additions

    def detect_changes(self, active_records, existing_by_domain):
        """Compare freshly-scanned active records against the last-stored row for the same
        domain. Returns (changes, updated) where `changes` is a list of
        {Domain, Field, Old, New} dicts and `updated` maps domain.lower() -> new record.

        A change is only reported when the NEW value is non-empty and differs from the old
        one, so transient data loss (e.g. RDAP redaction) doesn't generate noise.
        Pure function — no I/O — so it can be unit tested directly.
        """
        changes, updated = [], {}
        for rec in active_records:
            dom = str(rec.get("Domain", "")).lower()
            old = existing_by_domain.get(dom)
            if not old:
                continue
            row_changes = []
            for field in self.WATCHED_FIELDS:
                o = self._norm(old.get(field))
                n = self._norm(rec.get(field))
                if n and n != o:
                    row_changes.append({"Domain": rec.get("Domain"), "Field": field, "Old": o, "New": n})
            if row_changes:
                updated[dom] = rec
                changes.extend(row_changes)
        return changes, updated

    def generate_permutations(self, domain):
        """
        12 permutation vectors with domain name (IDN) punycode normalization.
        """
        permutations = {}
        parts = domain.split('.')
        if len(parts) < 2:
            return permutations
        name, original_tld = parts[0], '.'.join(parts[1:])

        def add_mutation(mut_name, p_type, tld=original_tld):
            if not mut_name:
                return
            try:
                puny_name = mut_name.encode('idna').decode('utf-8')
                # Lowercase + case-insensitive compare. DNS is case-insensitive, and the
                # stdlib idna codec doesn't fold case on pure-ASCII labels, so a case-bit
                # flip (e.g. bitsquatting 'g'->'G') would otherwise yield 'Google.com' --
                # the SAME host as the original. Normalize so such variants collapse onto
                # the original and are correctly excluded.
                full_dom = f"{puny_name}.{tld}".lower()
                if full_dom != domain.lower():
                    permutations[full_dom] = p_type
            except Exception as e:
                logger.debug(f"Skipped permutation '{mut_name}.{tld}': {e}")

        # 1. Abused TLD Swapping
        for t in self.abused_tlds:
            add_mutation(name, "Abused TLD Swap", tld=t)

        # 2. Character Omissions
        for i in range(len(name)):
            omit = name[:i] + name[i+1:]
            add_mutation(omit, "Omission")

        # 3. Bitsquatting
        for i in range(len(name)):
            c = name[i]
            for bit in range(8):
                mutated_char = chr(ord(c) ^ (1 << bit))
                if mutated_char.isalnum() and mutated_char != c:
                    add_mutation(name[:i] + mutated_char + name[i+1:], "Bitsquatting")

        # 4. Character Substitutions
        subs = {'o': ['0', 'p'], 'i': ['1', 'l', 'u'], 'e': ['3', 'w', 'r'], 'a': ['4', 's']}
        for i, c in enumerate(name):
            if c in subs:
                for replacement in subs[c]:
                    add_mutation(name[:i] + replacement + name[i+1:], "Substitution")

        # 5. Advanced Homoglyphs (Unicode Look-alikes / IDN Attacks)
        for i, c in enumerate(name):
            if c in self.homoglyph_matrix:
                for glyph in self.homoglyph_matrix[c]:
                    add_mutation(name[:i] + glyph + name[i+1:], "Homoglyph")

        # 6. Hyphenation Insertion
        for i in range(1, len(name)):
            add_mutation(name[:i] + '-' + name[i:], "Hyphenation")

        # 7. Keyboard Proximity / Fat-Finger Insertions
        for i in range(len(name)):
            c = name[i]
            if c in self.qwerty_matrix:
                for near_key in self.qwerty_matrix[c]:
                    add_mutation(name[:i] + near_key + name[i:], "Keyboard Insertion")
                    add_mutation(name[:i+1] + near_key + name[i+1:], "Keyboard Insertion")

        # 8. Transposition (Adjacent Character Anagramming)
        for i in range(len(name) - 1):
            transposed = name[:i] + name[i+1] + name[i] + name[i+2:]
            add_mutation(transposed, "Transposition")

        # 9. Key Repetition (Sticky Keys / Double Clicks)
        for i in range(len(name)):
            repeated = name[:i] + name[i] + name[i] + name[i+1:]
            add_mutation(repeated, "Repetition")

        # 10. Vowel Swapping Matrix
        vowels = ['a', 'e', 'i', 'o', 'u']
        for i, c in enumerate(name):
            if c in vowels:
                for v in vowels:
                    if v != c:
                        add_mutation(name[:i] + v + name[i+1:], "Vowel Swap")

        # 11. Subdomain Root-Chaining Insertion
        for i in range(1, len(name)):
            add_mutation(name[:i] + '.' + name[i:], "Subdomain Insertion")

        # 12. Corporate Dictionary Affixes (Prepending/Appending)
        for kw in self.hunting_keywords:
            add_mutation(f"{kw}-{name}", "Dictionary Affix")
            add_mutation(f"{name}-{kw}", "Dictionary Affix")
            add_mutation(f"{kw}{name}", "Dictionary Affix")
            add_mutation(f"{name}{kw}", "Dictionary Affix")

        return permutations

    async def _resolve(self, domain, rdtype, attempts=2):
        """Single DNS query against the shared resolver, retried once on timeout (a
        timeout is often transient; NXDOMAIN/NoAnswer are not retried). Returns the
        answer or None."""
        for i in range(attempts):
            try:
                return await self.resolver.resolve(domain, rdtype)
            except Exception as e:
                is_timeout = "timeout" in type(e).__name__.lower()
                if is_timeout and i + 1 < attempts:
                    logger.debug(f"{rdtype} timeout for {domain}, retrying")
                    continue
                logger.debug(f"{rdtype} lookup failed for {domain}: {e}")
                return None
        return None

    async def resolve_dns_records(self, domain, sem):
        async with sem:
            results = {"IP": None, "Mail Server": None, "Name Server": None, "Active": False}

            # A, MX and NS are independent — fire them concurrently instead of serially.
            a_ans, mx_ans, ns_ans = await asyncio.gather(
                self._resolve(domain, 'A'),
                self._resolve(domain, 'MX'),
                self._resolve(domain, 'NS'),
            )

            if a_ans is not None:
                results["IP"] = ", ".join(str(ip) for ip in a_ans)
                results["Active"] = True
            if mx_ans is not None:
                results["Mail Server"] = ", ".join(str(mx.exchange).rstrip('.') for mx in mx_ans)
                results["Active"] = True
            if ns_ans is not None:
                results["Name Server"] = ", ".join(str(ns.target).rstrip('.') for ns in ns_ans)
                results["Active"] = True

            return results

    @staticmethod
    def _empty_registration():
        return {"Created": None, "Updated": None, "Registrant": None, "Org": None, "Email1": None, "Email2": None}

    @staticmethod
    def _parse_vcard(vcard):
        """Extract (name, org, email) from an RDAP jCard / vcardArray."""
        name = org = email = None
        try:
            for prop in vcard[1]:
                key = (prop[0] or "").lower()
                val = prop[3] if len(prop) > 3 else None
                if key == "fn" and not name:
                    name = val
                elif key == "org" and not org:
                    org = val[0] if isinstance(val, list) and val else val
                elif key == "email" and not email:
                    email = val
        except Exception:
            pass
        return name, org, email

    def _parse_rdap(self, data):
        """Map an RDAP JSON response into the same shape as fetch_blocking_whois output."""
        out = self._empty_registration()
        if not isinstance(data, dict):
            return out

        for ev in data.get("events", []) or []:
            action = (ev.get("eventAction") or "").lower()
            d = self._parse_created(ev.get("eventDate"))
            if d is None:
                continue
            if action == "registration" and out["Created"] is None:
                out["Created"] = d.strftime("%Y-%m-%d")
            elif action in ("last changed", "last update", "last update of rdap database") and out["Updated"] is None:
                out["Updated"] = d.strftime("%Y-%m-%d")

        emails = []
        for ent in data.get("entities", []) or []:
            roles = [str(r).lower() for r in (ent.get("roles") or [])]
            name, org, email = self._parse_vcard(ent.get("vcardArray"))
            if email:
                emails.append(email)
            if "registrant" in roles:
                if name and not out["Registrant"]:
                    out["Registrant"] = name
                if org and not out["Org"]:
                    out["Org"] = org
        if emails:
            out["Email1"] = emails[0]
            if len(emails) > 1:
                out["Email2"] = emails[1]
        return out

    @staticmethod
    def _parse_retry_after(value):
        """Parse a Retry-After header (delta-seconds form only) into a float, or None."""
        if not value:
            return None
        try:
            return float(str(value).strip())
        except Exception:
            return None

    async def fetch_rdap(self, domain, session, sem):
        """Query RDAP (modern HTTP/JSON WHOIS replacement). Honors a 429 Retry-After once
        (capped). Returns parsed data or None."""
        if session is None:
            return None
        async with sem:
            url = RDAP_BOOTSTRAP_URL.format(domain=domain)
            timeout = aiohttp.ClientTimeout(total=self.rdap_timeout)
            for attempt in range(2):
                try:
                    async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
                        if resp.status == 429:
                            wait = self._parse_retry_after(resp.headers.get("Retry-After"))
                            if attempt == 0 and wait is not None and wait <= self.rdap_max_retry_wait:
                                logger.debug(f"RDAP 429 for {domain}; waiting {wait}s")
                                await asyncio.sleep(wait)
                                continue
                            logger.debug(f"RDAP rate-limited for {domain}")
                            return None
                        if resp.status != 200:
                            logger.debug(f"RDAP {resp.status} for {domain}")
                            return None
                        data = await resp.json(content_type=None)
                        return self._parse_rdap(data)
                except Exception as e:
                    logger.debug(f"RDAP lookup failed for {domain}: {e}")
                    return None
        return None

    async def fetch_ct_logs(self, domain, session, sem):
        """Check Certificate Transparency logs (crt.sh) for certs issued to `domain`.
        A hit means the domain exists / is being set up even if it isn't resolving yet.
        Returns a small dict on a hit, else None."""
        if session is None:
            return None
        async with sem:
            url = CRTSH_URL.format(domain=domain)
            try:
                timeout = aiohttp.ClientTimeout(total=self.ct_timeout)
                async with session.get(url, timeout=timeout) as resp:
                    if resp.status != 200:
                        logger.debug(f"crt.sh {resp.status} for {domain}")
                        return None
                    data = await resp.json(content_type=None)
            except Exception as e:
                logger.debug(f"crt.sh lookup failed for {domain}: {e}")
                return None
        if isinstance(data, list) and data:
            return {"certs": len(data)}
        return None

    def fetch_blocking_whois(self, domain):
        out = self._empty_registration()
        retries = 2
        delay = 1.0

        for attempt in range(retries + 1):
            try:
                w = whois.whois(domain)

                if isinstance(w.creation_date, list) and w.creation_date:
                    out["Created"] = w.creation_date[0].strftime("%Y-%m-%d") if w.creation_date[0] else None
                elif w.creation_date:
                    out["Created"] = w.creation_date.strftime("%Y-%m-%d")

                if isinstance(w.updated_date, list) and w.updated_date:
                    out["Updated"] = w.updated_date[0].strftime("%Y-%m-%d") if w.updated_date[0] else None
                elif w.updated_date:
                    out["Updated"] = w.updated_date.strftime("%Y-%m-%d")

                out["Registrant"] = w.name
                out["Org"] = w.org

                if w.emails:
                    if isinstance(w.emails, list):
                        out["Email1"] = w.emails[0]
                        if len(w.emails) > 1: out["Email2"] = w.emails[1]
                    else:
                        out["Email1"] = w.emails
                break

            except (ConnectionResetError, ConnectionRefusedError, socket.timeout) as e:
                logger.debug(f"WHOIS transient error for {domain} (attempt {attempt + 1}): {e}")
                if attempt == retries:
                    break
                import time
                time.sleep(delay)
                delay *= 2
            except Exception as e:
                logger.debug(f"WHOIS lookup failed for {domain}: {e}")
                break
        return out

    async def _get_registration(self, domain, session, rdap_sem, whois_sem, whois_cache):
        """Resolve registration data with a cache, preferring fast RDAP and falling back
        to port-43 WHOIS only when RDAP yields nothing useful."""
        cached = whois_cache.get(domain) if whois_cache is not None else None
        if cached and cached.get("Created") and self._cache_fresh(cached.get("fetched"), self.whois_cache_ttl_days):
            logger.debug(f"Registration cache hit for {domain}")
            return cached

        data = await self.fetch_rdap(domain, session, rdap_sem)

        if not data or not data.get("Created"):
            # RDAP unavailable for this TLD or incomplete -> fall back to WHOIS.
            loop = asyncio.get_event_loop()
            async with whois_sem:
                data = await loop.run_in_executor(self.whois_executor, self.fetch_blocking_whois, domain)
                await asyncio.sleep(self.whois_query_delay)

        if not data:
            data = self._empty_registration()
        data["fetched"] = datetime.now().strftime("%Y-%m-%d")
        if whois_cache is not None:
            whois_cache[domain] = data
        return data

    async def fetch_visual_phash(self, domain, browser, render_sem):
        """
        Render the live page with a headless browser and return a perceptual hash of the
        screenshot. This captures what a *visitor* sees, so a pixel-cloned phishing page
        can be matched against the legitimate site's baseline hash.

        Tries HTTPS first, falls back to HTTP. Returns None if rendering is unavailable
        (no browser) or the page can't be loaded — the rest of the pipeline still works.
        """
        if browser is None:
            return None

        async with render_sem:
            for scheme in ("https", "http"):
                context = None
                try:
                    context = await browser.new_context(ignore_https_errors=True)
                    page = await context.new_page()
                    await page.goto(f"{scheme}://{domain}", timeout=8000, wait_until="domcontentloaded")
                    png_bytes = await page.screenshot(full_page=False)
                    await context.close()
                    context = None

                    def compute():
                        from io import BytesIO
                        return str(imagehash.phash(Image.open(BytesIO(png_bytes))))

                    return await asyncio.get_event_loop().run_in_executor(self.executor, compute)
                except Exception as e:
                    logger.debug(f"Render failed for {scheme}://{domain}: {e}")
                    if context is not None:
                        try:
                            await context.close()
                        except Exception:
                            pass
            return None

    @staticmethod
    def _assemble_record(domain, p_type, source, dns_data, reg, phash_val, distance):
        """Build a single result row from the gathered signals. Pure — unit-testable."""
        return {
            "Permutation Type": p_type,
            "Domain": domain,
            "Discovery Source": source,
            "Date Created": reg["Created"],
            "Last Updated": reg["Updated"],
            "Registrant Name": reg["Registrant"],
            "Organization": reg["Org"],
            "PHash": phash_val,
            "Visual Distance": distance,
            "Name Server": dns_data["Name Server"],
            "IP": dns_data["IP"],
            "Mail Server": dns_data["Mail Server"],
            "Registered Email 1": reg["Email1"],
            "Registered Email 2": reg["Email2"],
        }

    async def enrich_domain(self, domain, p_type, source, *, dns_sem, rdap_sem, whois_sem,
                            render_sem, session, browser, whois_cache, baseline_phash,
                            dns_data=None):
        """Shared enrichment used by BOTH the batch scanner and the real-time monitor:
        gather DNS + registration + visual hash for one domain and assemble a record.
        Pass `dns_data` to reuse a resolution the caller already performed."""
        if dns_data is None:
            dns_data = await self.resolve_dns_records(domain, dns_sem)
        reg = await self._get_registration(domain, session, rdap_sem, whois_sem, whois_cache)
        phash_val = await self.fetch_visual_phash(domain, browser, render_sem)
        distance = self._phash_distance(phash_val, baseline_phash)
        return self._assemble_record(domain, p_type, source, dns_data, reg, phash_val, distance)

    async def process_candidate(self, domain, p_type, dns_sem, rdap_sem, whois_sem, render_sem,
                                ct_sem, session, browser, whois_cache, baseline_phash):
        logger.debug(f"[*] Processing Permutation: {domain}")

        dns_data = await self.resolve_dns_records(domain, dns_sem)
        source = "DNS" if dns_data["Active"] else None

        if not dns_data["Active"]:
            # Domain doesn't resolve. Optionally consult CT logs: a cert means the squat
            # exists / is being prepared even before it goes live.
            if self.ct_discovery:
                ct = await self.fetch_ct_logs(domain, session, ct_sem)
                if ct:
                    source = "CT"
            if source is None:
                return None

        return await self.enrich_domain(
            domain, p_type, source,
            dns_sem=dns_sem, rdap_sem=rdap_sem, whois_sem=whois_sem, render_sem=render_sem,
            session=session, browser=browser, whois_cache=whois_cache,
            baseline_phash=baseline_phash, dns_data=dns_data,
        )

    @staticmethod
    def _esc(value):
        """Escape a cell value for safe inclusion in HTML email (WHOIS/RDAP fields are
        attacker-controlled, so this prevents markup/script injection)."""
        if value is None or value == "":
            return ""
        return html.escape(str(value))

    def build_html_table(self, records):
        esc = self._esc
        table = """
        <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse; font-family: Arial, sans-serif; font-size: 12px;">
            <tr style="background-color: #f2f2f2;">
                <th>Permutation Type</th>
                <th>Domain</th>
                <th>Discovery Source</th>
                <th>Date Created</th>
                <th>Last Updated</th>
                <th>Registrant Name</th>
                <th>Organization</th>
                <th>PHash</th>
                <th>Visual Distance</th>
                <th>Name Server</th>
                <th>IP</th>
                <th>Mail Server</th>
                <th>Registered Email 1</th>
                <th>Registered Email 2</th>
            </tr>
        """
        for r in records:
            distance = r.get('Visual Distance')
            is_clone = isinstance(distance, (int, float)) and distance <= self.visual_match_threshold
            row_style = ' style="background-color: #ffe0e0;"' if is_clone else ''
            distance_cell = "" if distance is None else esc(distance)
            if is_clone:
                distance_cell = f"<b>{distance_cell} (visual clone)</b>"
            table += f"""
            <tr{row_style}>
                <td>{esc(r.get('Permutation Type'))}</td>
                <td><b>{esc(r.get('Domain'))}</b></td>
                <td>{esc(r.get('Discovery Source'))}</td>
                <td>{esc(r.get('Date Created'))}</td>
                <td>{esc(r.get('Last Updated'))}</td>
                <td>{esc(r.get('Registrant Name'))}</td>
                <td>{esc(r.get('Organization'))}</td>
                <td>{esc(r.get('PHash'))}</td>
                <td>{distance_cell}</td>
                <td>{esc(r.get('Name Server'))}</td>
                <td>{esc(r.get('IP'))}</td>
                <td>{esc(r.get('Mail Server'))}</td>
                <td>{esc(r.get('Registered Email 1'))}</td>
                <td>{esc(r.get('Registered Email 2'))}</td>
            </tr>
            """
        table += "</table>"
        return table

    def build_changes_table(self, changes):
        esc = self._esc
        table = """
        <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse; font-family: Arial, sans-serif; font-size: 12px;">
            <tr style="background-color: #f2f2f2;">
                <th>Domain</th>
                <th>Field</th>
                <th>Old Value</th>
                <th>New Value</th>
            </tr>
        """
        for c in changes:
            table += f"""
            <tr>
                <td><b>{esc(c.get('Domain'))}</b></td>
                <td>{esc(c.get('Field'))}</td>
                <td>{esc(c.get('Old'))}</td>
                <td>{esc(c.get('New'))}</td>
            </tr>
            """
        table += "</table>"
        return table

    def _send_email(self, subject, html_body, target_excel):
        """Shared SMTP send used by both new-discovery and change alerts."""
        try:
            email_config = self.config['EMAIL']
            sender = email_config.get('sender_email')
            receiver = email_config.get('receiver_email')
            # Prefer an env var (or Gmail app password) so the secret need not live in
            # config.ini; fall back to the config value for backwards compatibility.
            password = os.environ.get('DOMAINHUNTER_EMAIL_PASSWORD') or email_config.get('password')

            if not sender or not receiver or not password:
                logger.info("[-] Email configuration missing details. Email skipped.")
                return

            msg = MIMEMultipart('related')
            msg['From'] = sender
            msg['To'] = receiver
            msg['Subject'] = subject

            # Brand footer on every email. The logo is embedded inline (cid:) below; the
            # alt text is shown if the image is unavailable for any reason.
            footer = (
                '<hr style="border:none;border-top:1px solid #E1E6EC;margin:26px 0 12px"/>'
                f'<img src="cid:{LOGO_CID}" width="240" '
                'alt="DomainHunter — typosquat &amp; phishing threat hunting" '
                'style="display:block;height:auto;max-width:240px"/>'
            )
            if "</body>" in html_body:
                html_body = html_body.replace("</body>", footer + "</body>", 1)
            else:
                html_body = html_body + footer
            msg.attach(MIMEText(html_body, 'html'))

            # Inline logo (Content-ID). Attached once; referenced by the footer above.
            if os.path.exists(LOGO_PATH):
                try:
                    with open(LOGO_PATH, "rb") as lf:
                        logo = MIMEImage(lf.read())
                    logo.add_header("Content-ID", f"<{LOGO_CID}>")
                    logo.add_header("Content-Disposition", "inline", filename="domainhunter-logo.png")
                    msg.attach(logo)
                except Exception as e:
                    logger.debug(f"Could not attach logo: {e}")

            if target_excel and os.path.exists(target_excel):
                with open(target_excel, "rb") as attachment:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(target_excel)}")
                msg.attach(part)

            logger.info("[*] Sending Email...")
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender, password)
            server.send_message(msg)
            server.quit()
            logger.info("[+] Email Sent Successfully")
        except Exception as e:
            logger.info(f"[-] Error sending email: {e}")

    def dispatch_alert_email(self, records, target_excel, primary_domain, is_initial=False):
        safe_domain = self._esc(primary_domain)
        if is_initial:
            subject = f"DomainHunter Initial Baseline Scan - {primary_domain}"
            intro_text = f"Initial baseline tracking loop completed for {safe_domain}. Below is the structural footprint catalog of currently active mutations."
        else:
            subject = f"DomainHunter Alert: New Mutations Identified for {primary_domain}"
            intro_text = f"CRITICAL: New typosquatting/phishing mutations have been identified targeting <b>{safe_domain}</b>."

        html_body = f"""
        <html>
            <body>
                <p style="font-family: Arial, sans-serif; font-size: 14px;">{intro_text}</p>
                <hr/>
                <h3>Detected Infrastructure Details ({len(records)} entries):</h3>
                {self.build_html_table(records)}
                <br/>
                <p style="font-family: Arial, sans-serif; font-size: 11px; color: #555;">
                    This is an automated operational metric alert sent by DomainHunter. Full tracking state history is preserved inside {target_excel}.
                </p>
            </body>
        </html>
        """
        self._send_email(subject, html_body, target_excel)

    def dispatch_change_email(self, changes, target_excel, primary_domain):
        safe_domain = self._esc(primary_domain)
        subject = f"DomainHunter Alert: Infrastructure Changes for {primary_domain}"
        intro_text = (
            f"Changes detected on already-tracked look-alike domains for <b>{safe_domain}</b>. "
            "A parked squat going live or changing hosting/registrant can signal an imminent campaign."
        )
        html_body = f"""
        <html>
            <body>
                <p style="font-family: Arial, sans-serif; font-size: 14px;">{intro_text}</p>
                <hr/>
                <h3>Detected Changes ({len(changes)} field change(s)):</h3>
                {self.build_changes_table(changes)}
                <br/>
                <p style="font-family: Arial, sans-serif; font-size: 11px; color: #555;">
                    This is an automated operational metric alert sent by DomainHunter. Full tracking state history is preserved inside {target_excel}.
                </p>
            </body>
        </html>
        """
        self._send_email(subject, html_body, target_excel)

    def _migrate_legacy_files(self, primary_domain, target_excel):
        """Older versions named the workbook after just the domain name (e.g. example.xlsx).
        If such a file exists and the new full-domain file does not, migrate it (and its
        state sidecar) so existing baselines are preserved rather than re-created."""
        legacy_excel = f"{primary_domain.split('.')[0]}.xlsx"
        if legacy_excel == target_excel or os.path.exists(target_excel) or not os.path.exists(legacy_excel):
            return
        try:
            os.rename(legacy_excel, target_excel)
            legacy_state = self._state_path(legacy_excel)
            if os.path.exists(legacy_state):
                os.rename(legacy_state, self._state_path(target_excel))
            logger.info(f"[*] Migrated legacy baseline '{legacy_excel}' -> '{target_excel}'")
        except Exception as e:
            logger.info(f"[-] Could not migrate legacy file '{legacy_excel}': {e}")

    async def scan_single_domain(self, primary_domain, dns_sem, rdap_sem, whois_sem, render_sem,
                                 ct_sem, session, browser):
        target_excel = self._excel_path(primary_domain)
        self._migrate_legacy_files(primary_domain, target_excel)
        state_path = self._state_path(target_excel)
        state = self._load_state(state_path)
        whois_cache = state.get('whois_cache', {})

        logger.info(f"\n[*] Target Domain: {primary_domain}")
        target_map = self.generate_permutations(primary_domain)

        if not target_map:
            logger.info(f"[-] No permutations generated for: {primary_domain}")
            return

        # Baseline visual fingerprint of the legitimate site, used to flag pixel clones.
        baseline_phash = await self.fetch_visual_phash(primary_domain, browser, render_sem)
        if baseline_phash:
            logger.debug(f"Baseline visual hash for {primary_domain}: {baseline_phash}")

        logger.info(f"[*] Analyzing {len(target_map)} unique structural mutations for {primary_domain}...")

        tasks = [
            self.process_candidate(dom, p_type, dns_sem, rdap_sem, whois_sem, render_sem,
                                   ct_sem, session, browser, whois_cache, baseline_phash)
            for dom, p_type in target_map.items()
        ]

        # return_exceptions=True so one bad candidate can't cancel the whole batch.
        resolved_outputs = await asyncio.gather(*tasks, return_exceptions=True)
        active_records = []
        errors = 0
        for r in resolved_outputs:
            if isinstance(r, Exception):
                errors += 1
                logger.debug(f"Candidate task error: {r!r}")
            elif r is not None:
                active_records.append(r)

        is_initial_run = not os.path.exists(target_excel)
        new_discoveries = []
        silent_additions = []
        changes = []

        if is_initial_run:
            logger.info(f"[*] Excel document '{target_excel}' does not exist. Creating file and generating baseline entries...")
            if active_records:
                self._write_excel_atomic(pd.DataFrame(active_records), target_excel)
                logger.info(f"[+] Baseline dataset generated inside -> {target_excel}")
                self.dispatch_alert_email(active_records, target_excel, primary_domain, is_initial=True)
            else:
                self._write_excel_atomic(pd.DataFrame(columns=self.EXCEL_COLUMNS), target_excel)
                logger.info(f"[*] Baseline established for {primary_domain}, but no active permutations were discovered.")
            # Record when this baseline was captured so later runs can tell a genuinely
            # newly-registered domain apart from one that merely started resolving.
            state['baseline_date'] = datetime.now().strftime("%Y-%m-%d")
        else:
            try:
                df_existing = pd.read_excel(target_excel)
                existing_records = df_existing.to_dict('records')
            except Exception as e:
                logger.debug(f"Could not read existing workbook '{target_excel}': {e}")
                existing_records = []

            existing_by_domain = {str(r.get('Domain', '')).lower(): r for r in existing_records}
            existing_domains = set(existing_by_domain.keys())

            baseline_date = self._baseline_date_from_state(state)
            if baseline_date is None:
                # Legacy baseline created before state tracking existed: approximate the
                # cutoff from the spreadsheet's last-modified time and persist it.
                try:
                    baseline_date = datetime.fromtimestamp(os.path.getmtime(target_excel))
                except Exception:
                    baseline_date = datetime.now()
                state['baseline_date'] = baseline_date.strftime("%Y-%m-%d")

            new_discoveries, silent_additions = self.classify_new_records(
                active_records, existing_domains, baseline_date
            )

            updated = {}
            if self.change_detection:
                changes, updated = self.detect_changes(active_records, existing_by_domain)

            additions = new_discoveries + silent_additions
            if additions or updated:
                # Rebuild the sheet: keep existing rows (swapping in updated ones) + append.
                rows = [updated.get(str(r.get('Domain', '')).lower(), r) for r in existing_records]
                rows.extend(additions)
                self._write_excel_atomic(pd.DataFrame(rows), target_excel)

            if new_discoveries:
                logger.info(f"[+] New variations found! Added to {target_excel} and sending email alert...")
                self.dispatch_alert_email(new_discoveries, target_excel, primary_domain, is_initial=False)
            elif silent_additions:
                logger.info(f"[*] {len(silent_additions)} domain(s) now resolving predate the baseline; recorded without alert.")
            else:
                logger.info("[-] No new variations found.")

            if changes:
                logger.info(f"[+] {len(changes)} infrastructure change(s) detected; sending change alert...")
                self.dispatch_change_email(changes, target_excel, primary_domain)

        # Persist the (possibly updated) baseline date and registration cache for next run.
        state['whois_cache'] = whois_cache
        self._save_state(state_path, state)

        # Concise end-of-scan summary.
        clones = sum(
            1 for r in active_records
            if isinstance(r.get('Visual Distance'), (int, float)) and r['Visual Distance'] <= self.visual_match_threshold
        )
        ct_found = sum(1 for r in active_records if r.get('Discovery Source') == 'CT')
        logger.info(
            f"[=] Summary for {primary_domain}: {len(active_records)} active "
            f"({ct_found} via CT), {len(new_discoveries)} new, {len(silent_additions)} pre-baseline, "
            f"{len(changes)} change(s), {clones} visual clone(s), {errors} task error(s)."
        )

    async def _launch_browser(self, playwright):
        """Launch a single shared headless Chromium for the whole run. Returns the browser
        or None (with a helpful log line) if Chromium isn't available, so visual hashing
        degrades gracefully instead of crashing the scan.

        On very new distros Playwright may not ship a bundled Chromium build (e.g.
        'does not support chromium on ubuntu26.04-x64'). To use a system browser instead,
        set DOMAINHUNTER_BROWSER_PATH (binary path) or DOMAINHUNTER_BROWSER_CHANNEL
        (e.g. 'chromium', 'chrome'). If headless Chromium fails to open its socket
        (snap / containers / root), set DOMAINHUNTER_BROWSER_NO_SANDBOX=1.
        """
        launch_kwargs = {"headless": True}
        channel = os.environ.get("DOMAINHUNTER_BROWSER_CHANNEL", "").strip()
        exe_path = os.environ.get("DOMAINHUNTER_BROWSER_PATH", "").strip()
        if channel:
            launch_kwargs["channel"] = channel
        if exe_path:
            launch_kwargs["executable_path"] = exe_path
        if os.environ.get("DOMAINHUNTER_BROWSER_NO_SANDBOX", "").strip().lower() in ("1", "true", "yes", "on"):
            launch_kwargs["args"] = ["--no-sandbox", "--disable-dev-shm-usage"]

        try:
            return await playwright.chromium.launch(**launch_kwargs)
        except Exception as e:
            logger.info(
                "[-] Headless browser unavailable; visual-clone detection disabled. "
                "Try 'playwright install chromium', or set DOMAINHUNTER_BROWSER_PATH / "
                f"DOMAINHUNTER_BROWSER_CHANNEL (and DOMAINHUNTER_BROWSER_NO_SANDBOX=1). ({e})"
            )
            return None

    async def pipeline_execution(self):
        if not self.monitored_domains:
            logger.info("[-] Monitored domains target list is empty. Please add domains to monitored_domains.txt")
            return

        dns_sem = asyncio.Semaphore(self.max_concurrent_dns)
        rdap_sem = asyncio.Semaphore(self.max_concurrent_rdap)
        whois_sem = asyncio.Semaphore(self.max_concurrent_whois)
        render_sem = asyncio.Semaphore(self.max_concurrent_render)
        ct_sem = asyncio.Semaphore(self.max_concurrent_ct)

        # Optional dependency: visual hashing works only if Playwright is installed.
        playwright_cm = None
        browser = None
        try:
            from playwright.async_api import async_playwright
            playwright_cm = async_playwright()
            playwright = await playwright_cm.start()
            browser = await self._launch_browser(playwright)
        except Exception as e:
            logger.info(
                "[-] Playwright not installed; visual-clone detection disabled. "
                f"Install with 'pip install playwright' then 'playwright install chromium'. ({e})"
            )

        connector = aiohttp.TCPConnector(limit=self.max_concurrent_rdap, ttl_dns_cache=300)
        headers = {"Accept": "application/rdap+json, application/json"}
        try:
            async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
                for primary_domain in self.monitored_domains:
                    await self.scan_single_domain(
                        primary_domain, dns_sem, rdap_sem, whois_sem, render_sem, ct_sem, session, browser
                    )
        finally:
            if browser is not None:
                try:
                    await browser.close()
                except Exception as e:
                    logger.debug(f"Error closing browser: {e}")
            if playwright_cm is not None:
                try:
                    await playwright_cm.stop()
                except Exception as e:
                    logger.debug(f"Error stopping Playwright: {e}")

    def run(self):
        try:
            asyncio.run(self.pipeline_execution())
        finally:
            self.executor.shutdown(wait=True)
            self.whois_executor.shutdown(wait=True)

def main():
    """Console entry point for a one-shot batch scan."""
    AdvancedDomainHunter().run()


if __name__ == "__main__":
    main()
