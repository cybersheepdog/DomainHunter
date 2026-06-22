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
import configparser
import dns.asyncresolver
import imagehash
import pandas as pd
import smtplib
import whois

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from PIL import Image

# Runtime Limits to prevent socket exhaustion given the expanded permutation pool
MAX_CONCURRENT_DNS = 40     # Throttled slightly to handle the larger volume safely
MAX_CONCURRENT_WHOIS = 5    # WHOIS servers rate-limit aggressively; keep this low
MAX_CONCURRENT_RENDER = 4   # Headless page renders are heavy; cap parallelism
THREAD_POOL_SIZE = 5        # Throttled worker pool for blocking operations

WHOIS_QUERY_DELAY = 0.25    # Politeness delay (seconds) between WHOIS queries
WHOIS_CACHE_TTL_DAYS = 30   # Reuse a cached WHOIS record for this many days
VISUAL_MATCH_THRESHOLD = 10 # Max perceptual-hash Hamming distance to flag a visual clone

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
    def __init__(self, config_path="config.ini", target_domains_path="monitored_domains.txt", tlds_dict_path="abused_tlds.dict"):
        self.config_path = config_path
        self.target_domains_path = target_domains_path
        self.tlds_dict_path = tlds_dict_path
        
        self.config = configparser.ConfigParser()
        self.load_config()
        
        self.monitored_domains = self._load_file_lines(self.target_domains_path)
        self.abused_tlds = self._load_file_lines(self.tlds_dict_path)
        self.executor = ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE)

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
        
        if 'EMAIL' not in self.config:
            self.config['EMAIL'] = {
                'password': '',
                'receiver_email': '',
                'sender_email': ''
            }
            with open(self.config_path, 'w') as f:
                self.config.write(f)

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
        """Sidecar file holding the baseline date and the WHOIS cache for a target."""
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
        try:
            with open(state_path, 'w') as f:
                json.dump(state, f)
        except Exception as e:
            logger.info(f"[-] Could not persist state '{state_path}': {e}")

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
        """Parse a WHOIS creation date (stored as 'YYYY-MM-DD') into a datetime, or None."""
        if not value:
            return None
        try:
            return datetime.strptime(str(value)[:10], "%Y-%m-%d")
        except Exception:
            return None

    @staticmethod
    def _cache_fresh(fetched_str):
        """True if a cached WHOIS record fetched on `fetched_str` is still within TTL."""
        fetched = AdvancedDomainHunter._parse_created(fetched_str)
        if fetched is None:
            return False
        return (datetime.now() - fetched) <= timedelta(days=WHOIS_CACHE_TTL_DAYS)

    @staticmethod
    def _phash_distance(h1, h2):
        """Hamming distance between two perceptual-hash hex strings, or None."""
        if not h1 or not h2:
            return None
        try:
            return imagehash.hex_to_hash(str(h1)) - imagehash.hex_to_hash(str(h2))
        except Exception:
            return None

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
                full_dom = f"{puny_name}.{tld}"
                if full_dom != domain:
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

    async def resolve_dns_records(self, domain, sem):
        async with sem:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.0
            results = {"IP": None, "Mail Server": None, "Name Server": None, "Active": False}
            
            try:
                a_records = await resolver.resolve(domain, 'A')
                results["IP"] = ", ".join([str(ip) for ip in a_records])
                results["Active"] = True
            except Exception as e:
                logger.debug(f"A lookup failed for {domain}: {e}")

            try:
                mx_records = await resolver.resolve(domain, 'MX')
                results["Mail Server"] = ", ".join([str(mx.exchange).rstrip('.') for mx in mx_records])
                results["Active"] = True
            except Exception as e:
                logger.debug(f"MX lookup failed for {domain}: {e}")

            try:
                ns_records = await resolver.resolve(domain, 'NS')
                results["Name Server"] = ", ".join([str(ns.target).rstrip('.') for ns in ns_records])
                results["Active"] = True
            except Exception as e:
                logger.debug(f"NS lookup failed for {domain}: {e}")

            return results

    def fetch_blocking_whois(self, domain):
        out = {"Created": None, "Updated": None, "Registrant": None, "Org": None, "Email1": None, "Email2": None}
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

    async def _get_whois(self, domain, whois_sem, whois_cache):
        """Return WHOIS data for `domain`, using a persistent cache and throttling live
        lookups so we don't trip WHOIS rate limits."""
        cached = whois_cache.get(domain) if whois_cache is not None else None
        if cached and cached.get("Created") and self._cache_fresh(cached.get("fetched")):
            logger.debug(f"WHOIS cache hit for {domain}")
            return cached

        loop = asyncio.get_event_loop()
        async with whois_sem:
            whois_data = await loop.run_in_executor(self.executor, self.fetch_blocking_whois, domain)
            await asyncio.sleep(WHOIS_QUERY_DELAY)  # politeness delay while holding the slot

        whois_data["fetched"] = datetime.now().strftime("%Y-%m-%d")
        if whois_cache is not None:
            whois_cache[domain] = whois_data
        return whois_data

    async def process_candidate(self, domain, p_type, dns_sem, whois_sem, render_sem,
                                browser, whois_cache, baseline_phash):
        logger.info(f"[*] Processing Permutation: {domain}")

        dns_data = await self.resolve_dns_records(domain, dns_sem)
        if not dns_data["Active"]:
            return None

        whois_data = await self._get_whois(domain, whois_sem, whois_cache)
        phash_val = await self.fetch_visual_phash(domain, browser, render_sem)
        distance = self._phash_distance(phash_val, baseline_phash)

        return {
            "Permutation Type": p_type,
            "Domain": domain,
            "Date Created": whois_data["Created"],
            "Last Updated": whois_data["Updated"],
            "Registrant Name": whois_data["Registrant"],
            "Organization": whois_data["Org"],
            "PHash": phash_val,
            "Visual Distance": distance,
            "Name Server": dns_data["Name Server"],
            "IP": dns_data["IP"],
            "Mail Server": dns_data["Mail Server"],
            "Registered Email 1": whois_data["Email1"],
            "Registered Email 2": whois_data["Email2"]
        }

    @staticmethod
    def _esc(value):
        """Escape a cell value for safe inclusion in HTML email (WHOIS fields are
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
            is_clone = isinstance(distance, (int, float)) and distance <= VISUAL_MATCH_THRESHOLD
            row_style = ' style="background-color: #ffe0e0;"' if is_clone else ''
            distance_cell = "" if distance is None else esc(distance)
            if is_clone:
                distance_cell = f"<b>{distance_cell} (visual clone)</b>"
            table += f"""
            <tr{row_style}>
                <td>{esc(r.get('Permutation Type'))}</td>
                <td><b>{esc(r.get('Domain'))}</b></td>
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

    def dispatch_alert_email(self, records, target_excel, primary_domain, is_initial=False):
        try:
            email_config = self.config['EMAIL']
            sender = email_config.get('sender_email')
            receiver = email_config.get('receiver_email')
            password = email_config.get('password')

            if not sender or not receiver or not password:
                logger.info(f"[-] Email configuration missing details. Email skipped for {primary_domain}.")
                return

            msg = MIMEMultipart('alternative')
            msg['From'] = sender
            msg['To'] = receiver
            
            safe_domain = self._esc(primary_domain)
            if is_initial:
                msg['Subject'] = f"DomainHunter Initial Baseline Scan - {primary_domain}"
                intro_text = f"Initial baseline tracking loop completed for {safe_domain}. Below is the structural footprint catalog of currently active mutations."
            else:
                msg['Subject'] = f"DomainHunter Alert: New Mutations Identified for {primary_domain}"
                intro_text = f"CRITICAL: New typosquatting/phishing mutations have been identified targeting <b>{safe_domain}</b>."

            table_html = self.build_html_table(records)
            html_body = f"""
            <html>
                <body>
                    <p style="font-family: Arial, sans-serif; font-size: 14px;">{intro_text}</p>
                    <hr/>
                    <h3>Detected Infrastructure Details ({len(records)} entries):</h3>
                    {table_html}
                    <br/>
                    <p style="font-family: Arial, sans-serif; font-size: 11px; color: #555;">
                        This is an automated operational metric alert sent by DomainHunter. Full tracking state history is preserved inside {target_excel}.
                    </p>
                </body>
            </html>
            """
            msg.attach(MIMEText(html_body, 'html'))

            if os.path.exists(target_excel):
                with open(target_excel, "rb") as attachment:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename={target_excel}")
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

    EXCEL_COLUMNS = [
        "Permutation Type", "Domain", "Date Created", "Last Updated",
        "Registrant Name", "Organization", "PHash", "Visual Distance",
        "Name Server", "IP", "Mail Server", "Registered Email 1", "Registered Email 2"
    ]

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

    async def scan_single_domain(self, primary_domain, dns_sem, whois_sem, render_sem, browser):
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
            self.process_candidate(dom, p_type, dns_sem, whois_sem, render_sem,
                                   browser, whois_cache, baseline_phash)
            for dom, p_type in target_map.items()
        ]

        resolved_outputs = await asyncio.gather(*tasks)
        active_records = [r for r in resolved_outputs if r is not None]

        is_initial_run = not os.path.exists(target_excel)
        new_discoveries = []

        if is_initial_run:
            logger.info(f"[*] Excel document '{target_excel}' does not exist. Creating file and generating baseline entries...")
            if active_records:
                df_new = pd.DataFrame(active_records)
                df_new.to_excel(target_excel, index=False)
                logger.info(f"[+] Baseline dataset generated inside -> {target_excel}")
                self.dispatch_alert_email(active_records, target_excel, primary_domain, is_initial=True)
            else:
                df_empty = pd.DataFrame(columns=self.EXCEL_COLUMNS)
                df_empty.to_excel(target_excel, index=False)
                logger.info(f"[*] Baseline established for {primary_domain}, but no active permutations were discovered.")
            # Record when this baseline was captured so later runs can tell a genuinely
            # newly-registered domain apart from one that merely started resolving.
            state['baseline_date'] = datetime.now().strftime("%Y-%m-%d")
        else:
            try:
                df_existing = pd.read_excel(target_excel)
                existing_domains = set(df_existing['Domain'].astype(str).str.lower().tolist())
            except Exception as e:
                logger.debug(f"Could not read existing workbook '{target_excel}': {e}")
                existing_domains = set()
                df_existing = pd.DataFrame()

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

            additions = new_discoveries + silent_additions
            if additions:
                df_delta = pd.DataFrame(additions)
                df_final = pd.concat([df_existing, df_delta], ignore_index=True)
                df_final.to_excel(target_excel, index=False)

            if new_discoveries:
                logger.info(f"[+] New variations found! Added to {target_excel} and sending email alert...")
                self.dispatch_alert_email(new_discoveries, target_excel, primary_domain, is_initial=False)
            elif silent_additions:
                logger.info(f"[*] {len(silent_additions)} domain(s) now resolving predate the baseline; recorded without alert.")
            else:
                logger.info("[-] No new variations found.")

        # Persist the (possibly updated) baseline date and WHOIS cache for next run.
        state['whois_cache'] = whois_cache
        self._save_state(state_path, state)

    async def _launch_browser(self, playwright):
        """Launch a single shared headless Chromium for the whole run. Returns the browser
        or None (with a helpful log line) if Playwright/Chromium isn't installed, so visual
        hashing degrades gracefully instead of crashing the scan."""
        try:
            return await playwright.chromium.launch(headless=True)
        except Exception as e:
            logger.info(
                "[-] Headless browser unavailable; visual-clone detection disabled. "
                f"Run 'playwright install chromium' to enable it. ({e})"
            )
            return None

    async def pipeline_execution(self):
        if not self.monitored_domains:
            logger.info("[-] Monitored domains target list is empty. Please add domains to monitored_domains.txt")
            return

        dns_sem = asyncio.Semaphore(MAX_CONCURRENT_DNS)
        whois_sem = asyncio.Semaphore(MAX_CONCURRENT_WHOIS)
        render_sem = asyncio.Semaphore(MAX_CONCURRENT_RENDER)

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

        try:
            for primary_domain in self.monitored_domains:
                await self.scan_single_domain(primary_domain, dns_sem, whois_sem, render_sem, browser)
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

if __name__ == "__main__":
    hunter = AdvancedDomainHunter()
    hunter.run()
