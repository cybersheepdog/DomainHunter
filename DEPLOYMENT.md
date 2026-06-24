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
| `change_detection` | true | Alert when a tracked domain's infrastructure changes |

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
