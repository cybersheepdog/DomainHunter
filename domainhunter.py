# Python Standard Library Imports
import asyncio
import logging
import os
import socket
import sys

from datetime import datetime
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
from email import encoders
from PIL import Image

# Runtime Limits to prevent socket exhaustion given the expanded permutation pool
MAX_CONCURRENT_DNS = 40     # Throttled slightly to handle the larger volume safely
MAX_CONCURRENT_HTTP = 8     # Preserved socket limits for HTTP sessions
THREAD_POOL_SIZE = 5        # Throttled worker pool for blocking operations

# Configure Logging
logger = logging.getLogger("DomainHunter")
logger.setLevel(logging.INFO)
log_formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

file_handler = logging.FileHandler("domainhunter.log", mode="a", encoding="utf-8")
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(message)s'))
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
            except Exception:
                pass

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
            except Exception: pass

            try:
                mx_records = await resolver.resolve(domain, 'MX')
                results["Mail Server"] = ", ".join([str(mx.exchange).rstrip('.') for mx in mx_records])
                results["Active"] = True
            except Exception: pass

            try:
                ns_records = await resolver.resolve(domain, 'NS')
                results["Name Server"] = ", ".join([str(ns.target).rstrip('.') for ns in ns_records])
                results["Active"] = True
            except Exception: pass

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
                
            except (ConnectionResetError, ConnectionRefusedError, socket.timeout):
                if attempt == retries:
                    break
                import time
                time.sleep(delay)
                delay *= 2
            except Exception:
                break
        return out

    async def fetch_phash(self, domain, session, sem):
        """
        Defaults to HTTPS with fallback to HTTP upon handshake or cert validation failures.
        """
        async with sem:
            url = f"https://{domain}"
            retries = 2
            
            for attempt in range(retries + 1):
                try:
                    timeout = aiohttp.ClientTimeout(total=3.0, connect=2.0)
                    async with session.get(url, timeout=timeout, allow_redirects=True) as response:
                        content_type = response.headers.get('Content-Type', '')
                        if response.status == 200 and 'image' in content_type:
                            img_bytes = await response.read()
                            
                            def compute():
                                from io import BytesIO
                                img = Image.open(BytesIO(img_bytes))
                                return str(imagehash.phash(img))
                            
                            return await asyncio.get_event_loop().run_in_executor(self.executor, compute)
                    break
                    
                except (aiohttp.ClientSSLError, aiohttp.ClientConnectorCertificateError):
                    # Gracefully bypass certificate drops and retry utilizing port 80 pathing directly
                    url = f"http://{domain}"
                    await asyncio.sleep(0.1)
                except (aiohttp.ClientOSError, aiohttp.ServerDisconnectedError, 
                        asyncio.TimeoutError, aiohttp.ServerTimeoutError, 
                        ConnectionResetError, ConnectionRefusedError):
                    if attempt == retries:
                        return None
                    await asyncio.sleep(0.5 * (attempt + 1))
                except Exception:
                    return None
            return None

    async def process_candidate(self, domain, p_type, dns_sem, http_sem, http_session):
        logger.info(f"[*] Processing Permutation: {domain}")
        
        dns_data = await self.resolve_dns_records(domain, dns_sem)
        if not dns_data["Active"]:
            return None

        loop = asyncio.get_event_loop()
        whois_data = await loop.run_in_executor(self.executor, self.fetch_blocking_whois, domain)
        phash_val = await self.fetch_phash(domain, http_session, http_sem)

        return {
            "Permutation Type": p_type,
            "Domain": domain,
            "Date Created": whois_data["Created"],
            "Last Updated": whois_data["Updated"],
            "Registrant Name": whois_data["Registrant"],
            "Organization": whois_data["Org"],
            "PHash": phash_val,
            "Name Server": dns_data["Name Server"],
            "IP": dns_data["IP"],
            "Mail Server": dns_data["Mail Server"],
            "Registered Email 1": whois_data["Email1"],
            "Registered Email 2": whois_data["Email2"]
        }

    def build_html_table(self, records):
        html = """
        <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse; font-family: Arial, sans-serif; font-size: 12px;">
            <tr style="background-color: #f2f2f2;">
                <th>Permutation Type</th>
                <th>Domain</th>
                <th>Date Created</th>
                <th>Last Updated</th>
                <th>Registrant Name</th>
                <th>Organization</th>
                <th>PHash</th>
                <th>Name Server</th>
                <th>IP</th>
                <th>Mail Server</th>
                <th>Registered Email 1</th>
                <th>Registered Email 2</th>
            </tr>
        """
        for r in records:
            html += f"""
            <tr>
                <td>{r.get('Permutation Type') or ''}</td>
                <td><b>{r.get('Domain') or ''}</b></td>
                <td>{r.get('Date Created') or ''}</td>
                <td>{r.get('Last Updated') or ''}</td>
                <td>{r.get('Registrant Name') or ''}</td>
                <td>{r.get('Organization') or ''}</td>
                <td>{r.get('PHash') or ''}</td>
                <td>{r.get('Name Server') or ''}</td>
                <td>{r.get('IP') or ''}</td>
                <td>{r.get('Mail Server') or ''}</td>
                <td>{r.get('Registered Email 1') or ''}</td>
                <td>{r.get('Registered Email 2') or ''}</td>
            </tr>
            """
        html += "</table>"
        return html

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
            
            if is_initial:
                msg['Subject'] = f"DomainHunter Initial Baseline Scan - {primary_domain}"
                intro_text = f"Initial baseline tracking loop completed for {primary_domain}. Below is the structural footprint catalog of currently active mutations."
            else:
                msg['Subject'] = f"DomainHunter Alert: New Mutations Identified for {primary_domain}"
                intro_text = f"CRITICAL: New typosquatting/phishing mutations have been identified targeting <b>{primary_domain}</b>."

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

    async def scan_single_domain(self, primary_domain, dns_sem, http_sem, session):
        domain_prefix = primary_domain.split('.')[0]
        target_excel = f"{domain_prefix}.xlsx"

        logger.info(f"\n[*] Target Domain: {primary_domain}")
        target_map = self.generate_permutations(primary_domain)
        
        if not target_map:
            logger.info(f"[-] No permutations generated for: {primary_domain}")
            return

        logger.info(f"[*] Analyzing {len(target_map)} unique structural mutations for {primary_domain}...")
        
        tasks = [
            self.process_candidate(dom, p_type, dns_sem, http_sem, session)
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
                df_empty = pd.DataFrame(columns=[
                    "Permutation Type", "Domain", "Date Created", "Last Updated", 
                    "Registrant Name", "Organization", "PHash", "Name Server", 
                    "IP", "Mail Server", "Registered Email 1", "Registered Email 2"
                ])
                df_empty.to_excel(target_excel, index=False)
                logger.info(f"[*] Baseline established for {primary_domain}, but no active permutations were discovered.")
        else:
            try:
                df_existing = pd.read_excel(target_excel)
                existing_domains = set(df_existing['Domain'].astype(str).str.lower().tolist())
            except Exception:
                existing_domains = set()
                df_existing = pd.DataFrame()

            for record in active_records:
                if record['Domain'].lower() not in existing_domains:
                    new_discoveries.append(record)

            if new_discoveries:
                logger.info(f"[+] New variations found! Adding to {target_excel} and sending email alert...")
                df_delta = pd.DataFrame(new_discoveries)
                df_final = pd.concat([df_existing, df_delta], ignore_index=True)
                df_final.to_excel(target_excel, index=False)
                self.dispatch_alert_email(new_discoveries, target_excel, primary_domain, is_initial=False)
            else:
                logger.info("[-] No new variations found.")

    async def pipeline_execution(self):
        if not self.monitored_domains:
            logger.info("[-] Monitored domains target list is empty. Please add domains to monitored_domains.txt")
            return

        dns_sem = asyncio.Semaphore(MAX_CONCURRENT_DNS)
        http_sem = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
        
        connector = aiohttp.TCPConnector(limit_per_host=2, ttl_dns_cache=300)
        async with aiohttp.ClientSession(connector=connector) as session:
            for primary_domain in self.monitored_domains:
                await self.scan_single_domain(primary_domain, dns_sem, http_sem, session)

    def run(self):
        asyncio.run(self.pipeline_execution())

if __name__ == "__main__":
    hunter = AdvancedDomainHunter()
    hunter.run()
