# DomainHunter
[![Build Status](https://img.shields.io/badge/platform-Linux-blue.svg)](https://shields.io/)
![Maintenance](https://img.shields.io/maintenance/yes/2026.svg?style=flat-square)
[![GitHub last commit](https://img.shields.io/github/last-commit/cybersheepdog/DomainHunter.svg?style=flat-square)](https://github.com/cybersheepdog/DomainHunter/commit/main)
![GitHub](https://img.shields.io/github/license/cybersheepdog/DomainHunter)

DomainHunter hunts typosquatting and phishing look-alike domains for the brands you want to
protect. For each monitored domain it generates a large set of permutations, finds which ones
actually exist (DNS + RDAP/WHOIS, and optionally Certificate Transparency), fingerprints their
live pages to catch visual clones, tracks everything in a per-domain Excel workbook, and emails
high-signal alerts with the workbook attached.

It runs two complementary ways:

- **Batch scan** (`domainhunter.py`) — a full periodic sweep of every permutation. Great on a
  cron/schedule.
- **Real-time monitor** (`realtime_monitor.py`) — watches the Certificate Transparency firehose
  and alerts within seconds of a look-alike certificate being issued, often before the domain
  even resolves.

## Features

- **12 permutation vectors** — bitsquatting, omission, substitution, homoglyph / IDN, abused-TLD
  swap, keyboard proximity, transposition, repetition, vowel swap, hyphenation, subdomain
  insertion, and corporate dictionary affixes.
- **Existence checks** — concurrent DNS (A/MX/NS), registration via **RDAP** (fast, structured)
  with a port-43 **WHOIS** fallback, and optional **CT-log discovery** (crt.sh) to catch squats
  that exist but don't resolve yet.
- **Visual-clone detection** — renders each live page with a headless browser and compares a
  perceptual hash against your real site's baseline; a low **Visual Distance** flags a pixel clone.
- **Signal-based change detection** on already-tracked domains — alerts only on transitions that
  suggest adversary infrastructure standing up (mail going live, a visual clone appearing, a
  parked domain going live, re-delegation to real hosting), with severity levels, two-scan
  confirmation, a per-event cooldown, and suppression of parking, your own defensive
  registrations, and an ignore list.
- **Per-domain Excel workbooks** with atomic writes, plus **HTML email alerts** that carry the
  DomainHunter logo and the detection time / perceptual hash.
- **Deployable** natively (systemd) or via **Docker** with a bundled self-hosted CertStream server.

## How it works

1. Each monitored domain is expanded into hundreds of permutations.
2. Every permutation is checked for existence (DNS, then RDAP/WHOIS; optionally CT logs).
3. Live pages are rendered and perceptually hashed against the protected site.
4. Results are written to `<domain>_<tld>.xlsx`. The **first** run for a domain establishes a
   baseline and emails the full catalog of currently-active look-alikes.
5. Later runs email only the delta: newly-appeared look-alikes, and high-signal **changes** on
   ones already tracked. The real-time monitor feeds newly-issued-certificate matches into the
   same workbooks and alert format.

## Workbook / email columns

Permutation Type, Domain, **Discovery Source** (`DNS` / `CT` / `CT-RT`), **Detected** (when it was
first observed), Date Created, Last Updated, Registrant Name, Organization, **PHash** (perceptual
hash of the live page), **Visual Distance** (Hamming distance to your site's baseline — low = clone),
Name Server, IP, Mail Server, Registered Email 1, Registered Email 2.

## Quick start

```bash
pip install -r requirements.txt
playwright install chromium          # optional: enables visual-clone detection
```

Create your inputs:

- `monitored_domains.txt` — one domain to protect per line.
- `abused_tlds.dict` — TLDs to swap in for the "abused TLD" vector.
- `config.ini` — `[EMAIL]` settings (or set `DOMAINHUNTER_EMAIL_PASSWORD` in the environment).
  A `[SCAN]` section of tunables is created automatically on first run.

Run a batch sweep, or start the live monitor:

```bash
python domainhunter.py                 # one-off batch scan (schedule via cron)
python realtime_monitor.py             # real-time CT monitor
```

Docker (bundles Chromium + a self-hosted CertStream server):

```bash
docker compose up -d certstream monitor    # live monitor
docker compose run --rm scanner            # one-off batch sweep
```

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for the full configuration reference (all `[SCAN]` knobs,
false-positive controls, browser/env-var options, systemd + Docker setup).

## When emails are sent

- **Initial baseline** (first run for a domain): one email listing every currently-active
  look-alike. This is the only email that contains the full set.
- **New discovery**: a look-alike not previously tracked appears — the email contains just the new
  domain(s).
- **Infrastructure change**: a high-signal transition on an already-tracked domain — the email
  contains just the change (severity, old → new). These are gated by confirmation, severity, and a
  cooldown to stay high-fidelity; see DEPLOYMENT.md.

Email is skipped entirely if `[EMAIL]` sender/receiver/password aren't configured.

## Scheduling

Run the batch scanner on whatever cadence fits (daily/weekly/monthly) via cron or a systemd timer,
and optionally run the real-time monitor continuously for low-latency coverage in between.

## Tests

```bash
python -m unittest test_domainhunter test_realtime test_integration
```
