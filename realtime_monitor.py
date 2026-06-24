"""
Real-time Certificate Transparency monitor for DomainHunter.

Instead of polling on a schedule, this connects to a CertStream firehose
(WebSocket) and watches every certificate issued across the public CT logs as it
happens. Each certificate's domains are matched against the permutation set of the
monitored domains, so a look-alike is caught within seconds of a cert being issued
— often before the squat is even resolving in DNS.

This is a companion to the batch scanner (domainhunter.py), not a replacement:
the batch run gives you a full periodic sweep; this gives you low-latency alerts.

Run it standalone:

    python realtime_monitor.py                 # uses config.ini / monitored_domains.txt
    python realtime_monitor.py --url wss://my-certstream.internal/
    python realtime_monitor.py --flush 30      # email/flush buffer every 30s

It reuses AdvancedDomainHunter for permutation generation, DNS/RDAP/visual
enrichment, the workbook schema, and email delivery, so findings land in the same
per-domain .xlsx files and alert format as the scheduled scans.

Requires aiohttp (already a DomainHunter dependency). No new packages.
"""
import argparse
import asyncio
import json
import os
import signal

import aiohttp
import pandas as pd

from domainhunter import AdvancedDomainHunter, logger

# Public CertStream firehose. The hosted server can be flaky; self-host
# (https://github.com/CaliDog/certstream-server) and override via --url / config
# for production reliability.
DEFAULT_CERTSTREAM_URL = "wss://certstream.calidog.io/"
DEFAULT_FLUSH_SECONDS = 60
MAX_RECONNECT_BACKOFF = 60
MAX_SEEN = 200_000  # cap the in-memory dedupe set so a long run can't grow unbounded


class RealtimeMonitor:
    def __init__(self, hunter, certstream_url=None, flush_seconds=None):
        self.hunter = hunter
        self.url = (
            certstream_url
            or hunter.config.get('REALTIME', 'certstream_url', fallback=DEFAULT_CERTSTREAM_URL)
        )
        try:
            cfg_flush = hunter.config.getint('REALTIME', 'flush_seconds', fallback=DEFAULT_FLUSH_SECONDS)
        except Exception:
            cfg_flush = DEFAULT_FLUSH_SECONDS
        self.flush_seconds = flush_seconds or cfg_flush

        self.index = {}          # permutation domain (lower) -> (primary_domain, p_type)
        self.seen_path = "realtime_seen.json"
        self.seen = self._load_seen()   # domains already handled (persisted across restarts)
        self.existing = {}       # primary_domain -> set(domains already in its workbook)
        self.baselines = {}      # primary_domain -> baseline visual phash (computed once)
        self.whois_cache = {}    # primary_domain -> registration cache dict
        self.buffers = {}        # primary_domain -> [pending records]
        self._stop = asyncio.Event()
        self._build_index()

    # ---- index / matching (pure, unit-testable) -----------------------------

    def _build_index(self):
        for primary in self.hunter.monitored_domains:
            for dom, p_type in self.hunter.generate_permutations(primary).items():
                self.index[dom.lower()] = (primary, p_type)
        # Belt-and-suspenders: never watch the legitimate monitored domains themselves,
        # even if one happens to collide with another's permutation set.
        for primary in self.hunter.monitored_domains:
            self.index.pop(primary.lower(), None)
        logger.info(
            f"[*] Realtime index built: {len(self.index)} permutations across "
            f"{len(self.hunter.monitored_domains)} monitored domain(s)."
        )

    def match(self, fqdn):
        """Return (matched_domain, (primary, p_type)) if the FQDN — or any of its
        parent suffixes (to handle subdomains / multi-label TLDs) — is a tracked
        permutation, else None."""
        if not fqdn:
            return None
        d = str(fqdn).strip().lower().lstrip('*').lstrip('.').rstrip('.')
        labels = d.split('.')
        for i in range(len(labels) - 1):
            cand = '.'.join(labels[i:])
            hit = self.index.get(cand)
            if hit:
                return cand, hit
        return None

    @staticmethod
    def extract_domains(raw):
        """Pull the certificate's domains out of a CertStream message. Returns []
        for heartbeats, malformed payloads, or non-certificate messages."""
        try:
            obj = json.loads(raw)
        except Exception:
            return []
        if not isinstance(obj, dict) or obj.get("message_type") != "certificate_update":
            return []
        leaf = (obj.get("data") or {}).get("leaf_cert") or {}
        domains = leaf.get("all_domains")
        return domains if isinstance(domains, list) else []

    # ---- enrichment / persistence -------------------------------------------

    def _load_seen(self):
        try:
            with open(self.seen_path) as f:
                data = json.load(f)
            if isinstance(data, list):
                return set(data[-MAX_SEEN:])
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"Could not load seen set: {e}")
        return set()

    def _save_seen(self):
        try:
            tmp = self.seen_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(sorted(self.seen)[:MAX_SEEN], f)
            os.replace(tmp, self.seen_path)
        except Exception as e:
            logger.debug(f"Could not save seen set: {e}")

    def _load_existing(self, primary):
        if primary in self.existing:
            return self.existing[primary]
        path = self.hunter._excel_path(primary)
        doms = set()
        if os.path.exists(path):
            try:
                df = pd.read_excel(path)
                doms = set(df['Domain'].astype(str).str.lower().tolist())
            except Exception as e:
                logger.debug(f"Could not read existing workbook for {primary}: {e}")
        self.existing[primary] = doms
        return doms

    async def _baseline_phash(self, primary, res):
        if primary in self.baselines:
            return self.baselines[primary]
        ph = await self.hunter.fetch_visual_phash(primary, res['browser'], res['render'])
        self.baselines[primary] = ph
        return ph

    async def _enrich_and_buffer(self, domain, primary, p_type, res):
        try:
            baseline = await self._baseline_phash(primary, res)
            # Reuse the scanner's shared enrichment so batch and real-time stay identical.
            record = await self.hunter.enrich_domain(
                domain, p_type, "CT-RT",
                dns_sem=res['dns'], rdap_sem=res['rdap'], whois_sem=res['whois'],
                render_sem=res['render'], session=res['session'], browser=res['browser'],
                whois_cache=self.whois_cache.setdefault(primary, {}),
                baseline_phash=baseline,
            )
            self.buffers.setdefault(primary, []).append(record)
            logger.info(f"[!] CT match: {domain}  (looks like {primary}, {p_type})")
        except Exception as e:
            logger.debug(f"Enrichment failed for {domain}: {e}")

    async def _flush_all(self):
        for primary, records in list(self.buffers.items()):
            if not records:
                continue
            self.buffers[primary] = []
            existing = self._load_existing(primary)
            fresh = []
            for r in records:
                dom = str(r["Domain"]).lower()
                if dom in existing:
                    continue
                existing.add(dom)
                fresh.append(r)
            if not fresh:
                continue

            target_excel = self.hunter._excel_path(primary)
            try:
                if os.path.exists(target_excel):
                    df_existing = pd.read_excel(target_excel)
                    df_final = pd.concat([df_existing, pd.DataFrame(fresh)], ignore_index=True)
                else:
                    df_final = pd.DataFrame(fresh)
                self.hunter._write_excel_atomic(df_final, target_excel)
            except Exception as e:
                logger.info(f"[-] Could not update workbook for {primary}: {e}")

            logger.info(f"[+] {len(fresh)} new CT discovery(ies) for {primary}; sending alert...")
            self.hunter.dispatch_alert_email(fresh, target_excel, primary, is_initial=False)

    async def _flush_loop(self):
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.flush_seconds)
            except asyncio.TimeoutError:
                pass
            await self._flush_all()
            self._save_seen()

    # ---- stream loop --------------------------------------------------------

    async def _consume(self, res):
        backoff = 1
        while not self._stop.is_set():
            try:
                logger.info(f"[*] Connecting to CertStream: {self.url}")
                async with res['session'].ws_connect(self.url, heartbeat=30, max_msg_size=0) as ws:
                    logger.info("[+] Connected. Watching certificate transparency stream...")
                    backoff = 1
                    async for msg in ws:
                        if msg.type != aiohttp.WSMsgType.TEXT:
                            continue
                        for fqdn in self.extract_domains(msg.data):
                            m = self.match(fqdn)
                            if not m:
                                continue
                            matched_domain, (primary, p_type) = m
                            if matched_domain in self.seen:
                                continue
                            if len(self.seen) < MAX_SEEN:
                                self.seen.add(matched_domain)
                            asyncio.create_task(
                                self._enrich_and_buffer(matched_domain, primary, p_type, res)
                            )
            except asyncio.CancelledError:
                raise
            except Exception as e:
                if self._stop.is_set():
                    break
                logger.info(f"[-] Stream error ({e}); reconnecting in {backoff}s...")
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=backoff)
                except asyncio.TimeoutError:
                    pass
                backoff = min(backoff * 2, MAX_RECONNECT_BACKOFF)

    async def run(self):
        if not self.index:
            logger.info("[-] No permutations to watch. Add domains to monitored_domains.txt.")
            return

        res = {
            'dns': asyncio.Semaphore(self.hunter.max_concurrent_dns),
            'rdap': asyncio.Semaphore(self.hunter.max_concurrent_rdap),
            'whois': asyncio.Semaphore(self.hunter.max_concurrent_whois),
            'render': asyncio.Semaphore(self.hunter.max_concurrent_render),
            'browser': None,
            'session': None,
        }

        playwright_cm = None
        try:
            from playwright.async_api import async_playwright
            playwright_cm = async_playwright()
            pw = await playwright_cm.start()
            res['browser'] = await self.hunter._launch_browser(pw)
        except Exception as e:
            logger.info(f"[-] Playwright unavailable; visual hashing disabled in monitor. ({e})")

        connector = aiohttp.TCPConnector(limit=self.hunter.max_concurrent_rdap, ttl_dns_cache=300)
        headers = {"Accept": "application/rdap+json, application/json"}
        try:
            async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
                res['session'] = session
                flusher = asyncio.create_task(self._flush_loop())
                try:
                    await self._consume(res)
                finally:
                    self._stop.set()
                    flusher.cancel()
                    try:
                        await flusher
                    except (asyncio.CancelledError, Exception):
                        pass
                    await self._flush_all()  # drain anything buffered before exit
                    self._save_seen()
        finally:
            if res['browser'] is not None:
                try:
                    await res['browser'].close()
                except Exception:
                    pass
            if playwright_cm is not None:
                try:
                    await playwright_cm.stop()
                except Exception:
                    pass

    def request_stop(self):
        self._stop.set()


def main():
    parser = argparse.ArgumentParser(description="DomainHunter real-time CT monitor")
    parser.add_argument("--url", help="CertStream WebSocket URL", default=None)
    parser.add_argument("--flush", type=int, default=None,
                        help="Seconds between alert/flush cycles")
    args = parser.parse_args()

    hunter = AdvancedDomainHunter()
    monitor = RealtimeMonitor(hunter, certstream_url=args.url, flush_seconds=args.flush)

    async def runner():
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, monitor.request_stop)
            except (NotImplementedError, RuntimeError):
                pass  # e.g. Windows
        await monitor.run()

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        pass
    finally:
        hunter.executor.shutdown(wait=False)
        hunter.whois_executor.shutdown(wait=False)


if __name__ == "__main__":
    main()
