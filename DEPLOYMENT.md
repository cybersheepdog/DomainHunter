# DomainHunter — Deployment & Operations

DomainHunter has two run modes that share the same configuration, workbooks, and alerts:

- **Batch scan** (`domainhunter.py`) — a full periodic sweep of every permutation.
- **Real-time monitor** (`realtime_monitor.py`) — watches the Certificate Transparency
  firehose and alerts within seconds of a look-alike certificate being issued.

## Configuration

Three files live in the working directory:

- `config.ini` — `[EMAIL]` credentials and a `[SCAN]` section of tunables (created with
  sensible defaults on first run).
- `monitored_domains.txt` — one domain per line.
- `abused_tlds.dict` — TLDs to swap in for the "Abused TLD" permutation vector.

### Secrets

Do **not** commit the SMTP password. Provide it via environment variable instead; it
takes precedence over `config.ini`:

```bash
export DOMAINHUNTER_EMAIL_PASSWORD='your-gmail-app-password'
```

### `[SCAN]` tunables (with defaults)

| Key | Default | Purpose |
|-----|---------|---------|
| `max_concurrent_dns` | 40 | In-flight DNS resolutions |
| `max_concurrent_rdap` | 20 | In-flight RDAP lookups |
| `max_concurrent_whois` | 5 | WHOIS fallback (rate-limited) |
| `max_concurrent_render` | 4 | Headless renders for visual hashing |
| `max_concurrent_ct` | 4 | crt.sh lookups (keep low) |
| `dns_timeout` / `rdap_timeout` / `ct_timeout` | 2 / 5 / 10 s | Per-request timeouts |
| `rdap_max_retry_wait` | 10 s | Max honored RDAP `Retry-After` |
| `whois_cache_ttl_days` | 30 | Registration cache lifetime |
| `visual_match_threshold` | 10 | Max pHash Hamming distance to flag a clone |
| `ct_discovery` | false | In batch mode, also check crt.sh for non-resolving permutations |
| `change_detection` | true | Master switch for infrastructure-change alerts on tracked domains |
| `alert_on_visual_clone` | true | Alert when a domain starts serving a look-alike page (CRITICAL) |
| `alert_on_mail` | true | Alert when a mail server appears/changes — credential/BEC prep (HIGH) |
| `alert_on_activation` | true | Alert when a parked/non-resolving look-alike starts resolving (HIGH) |
| `alert_on_nameserver` | true | Alert on nameserver re-delegation, e.g. parking → hosting (MEDIUM) |
| `alert_on_ip` | false | Alert on IP-only changes — noisy (CDN/round-robin rotation); off by default |
| `alert_on_registrant` | false | Alert on registrant/org changes — noisy (WHOIS-privacy flicker); off by default |

Change alerts are **signal-based**: they fire only on transitions that suggest a
look-alike is standing up real infrastructure, not on benign churn. Multi-value records
(A/MX/NS) are compared as unordered sets, so DNS round-robin reordering is never a
"change." When an alert fires, that row is refreshed in the workbook, so the same event
won't re-alert on the next run. If you still get noise, flip `alert_on_nameserver` off;
if you want everything, turn `alert_on_ip` / `alert_on_registrant` on.

### False-positive reduction

| Key | Default | Purpose |
|-----|---------|---------|
| `change_confirm_runs` | 2 | A change must persist across this many scans before it emails (flap suppression). Set to 1 to alert immediately. |
| `suppress_own_infra` | true | Don't alert on look-alikes that resolve to the protected domain's own IPs (defensive registrations). |
| `parking_ip_prefixes` | (empty) | Comma-separated IP prefixes to treat as parking, e.g. `91.195.240.,199.59.243.`. |

Additional stackable defenses:

- **Parking awareness** — a built-in list of parking nameservers (Sedo, Bodis, Afternic,
  HugeDomains, ParkingCrew, etc.) means a squat landing on parking isn't treated as
  "going live," and moves *to* parking aren't flagged. Override/extend it with an optional
  `parking_nameservers.txt` (one substring per line). Placeholder/null MX is ignored too.
- **Ignore list** — put domains you've cleared (partners, CDNs, your own) in an optional
  `ignored_domains.txt` (one per line; a parent domain also covers its subdomains). They
  are never alerted, in both the batch scan and the real-time monitor.
- **Two-scan confirmation** — with `change_confirm_runs = 2` (default), a transition seen
  once is held as "pending" and only alerts if the next scan still sees it; transient
  blips that revert are dropped silently.

## Browser / visual-clone detection

Visual hashing needs Chromium. On unsupported/new host OSes (e.g. Ubuntu 26.04) the
bundled download may be unavailable; use one of:

```bash
export DOMAINHUNTER_BROWSER_PATH=/snap/bin/chromium     # system Chromium binary
export DOMAINHUNTER_BROWSER_CHANNEL=chromium            # or a Playwright channel
export DOMAINHUNTER_BROWSER_NO_SANDBOX=1                # snap/containers/root socket errors
```

Without a browser the scan still runs; it just skips visual hashing.

## Real-time monitor

```bash
python realtime_monitor.py                       # public CertStream (can be flaky)
python realtime_monitor.py --url ws://host:8080/ # self-hosted CertStream (recommended)
python realtime_monitor.py --flush 30            # alert/flush cadence (seconds)
```

It dedupes via a persisted `realtime_seen.json`, so restarting won't re-alert on
already-seen domains. Findings batch into per-domain workbooks and a single alert email
per flush cycle.

## Docker

The image is built on Playwright's Python base, which bundles Chromium and its system
libraries — so visual hashing works regardless of host OS.

```bash
# put config.ini, monitored_domains.txt, abused_tlds.dict in ./data
echo "DOMAINHUNTER_EMAIL_PASSWORD=your-app-password" > .env

docker compose up -d certstream monitor    # self-hosted CertStream + live monitor
docker compose run --rm scanner            # one-off batch sweep
```

Drive the batch `scanner` from a host cron or scheduler for periodic full sweeps while
the `monitor` provides low-latency coverage in between.

## Tests

```bash
python -m unittest test_domainhunter test_realtime test_integration
```
