# NorthHarv

**Advanced Cyberspace Intelligence Platform — local PoC**

NorthHarv is a self-hosted internet scanner and intelligence platform. It continuously scans IP ranges you own or are authorized to scan, fingerprints every open port it finds, correlates findings against public vulnerability databases, and stores everything in a local SQLite database. A FastAPI web UI lets you search, explore, and export all results. Two dedicated detection pipelines run on top of the raw banners to surface payment-card numbers and general PII/secret leaks directly from service responses.

> **Legal notice:** You are responsible for scanning only networks you own or have explicit written authorization to scan. Unauthorized scanning is illegal in most jurisdictions. This tool is provided for authorized security research and PoC purposes only.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Directory Layout](#directory-layout)
3. [Core Scanning Engine](#core-scanning-engine)
4. [Detection Pipelines](#detection-pipelines)
   - [Payment Card Detector](#payment-card-detector-enginecard_detectorpy)
   - [Identity & Secret Detector](#identity--secret-detector-engineid_detectorpy)
5. [Web UI & REST API](#web-ui--rest-api)
6. [Threat Intelligence Feeds](#threat-intelligence-feeds)
7. [Signature Databases](#signature-databases)
8. [Database Schema](#database-schema)
9. [Installation](#installation)
10. [Configuration](#configuration)
11. [Usage](#usage)
12. [REST API Reference](#rest-api-reference)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        run.py (entry point)                  │
│          web mode ─────────────┐  CLI mode (all else)       │
└────────────────────────────────│────────────────────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │  northharv/web.py         │
                    │  FastAPI + Jinja2 UI       │
                    │  REST API  WebSocket       │
                    └────────────┬─────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
┌─────────▼──────┐  ┌────────────▼──────┐  ┌──────────▼───────┐
│  engine/core.py │  │engine/id_detector │  │engine/card_       │
│  Scanner + DB   │  │.py  PII/secret    │  │detector.py  PAN  │
│  Fingerprinter  │  │     detection     │  │     detection    │
│  CVE correlator │  └───────────────────┘  └──────────────────┘
│  Daemon         │
└─────────┬───────┘
          │
┌─────────▼───────────────────────────────────────┐
│  SQLite — cyberscan.db                           │
│  hosts · observations · scan_rounds              │
│  pci_findings · id_findings · cve · kev · epss  │
└──────────────────────────────────────────────────┘
```

The scanner lives in `engine/core.py`. It is single-file, uses only the Python standard library for the core scan loop, and auto-detects optional accelerators (masscan, nmap, geoip2). `northharv/web.py` wraps it in a FastAPI application that serves both a browser UI and a JSON REST API.

---

## Directory Layout

```
NorthHarv/
├── run.py                      # Unified entry point (web + CLI)
├── allowlist.txt               # One CIDR per line — ONLY these ranges are scanned
├── requirements.txt
│
├── engine/
│   ├── core.py                 # Scanner, DB, fingerprinter, daemon, CVE correlator
│   ├── card_detector.py        # PAN / payment-card detection pipeline
│   ├── id_detector.py          # PII + secret detection pipeline
│   ├── signatures.py           # Wappalyzer / JARM / WAF signature loader
│   └── cache/                  # On-disk signature caches (auto-refreshed)
│
├── northharv/
│   ├── web.py                  # FastAPI application, all routes, WebSocket
│   └── wordlists.py            # Wordlist manager for directory enumeration
│
├── ui/
│   ├── templates/              # Jinja2 HTML templates (one per page)
│   └── static/
│       ├── css/style.css
│       └── js/main.js
│
├── nvd_cache/                  # NVD JSON feeds (CVE-20xx.json.xz, EPSS, KEV)
├── wordlists_cache/            # Downloaded wordlists for enumeration
└── ip2asn.csv                  # Offline IP→ASN mapping
```

---

## Core Scanning Engine

**`engine/core.py`** — ~2 000 lines, stdlib-only core.

### Scan pipeline

1. **Allowlist enforcement** — `allowlist.txt` is read on every daemon cycle. Any CIDR not in the file is never touched. DNS-resolved hostnames are checked against the allowlist before any packet is sent, so a crafted redirect can never widen the scope.

2. **Port discovery** — Two strategies, tried in order:
   - **masscan** (if installed) — SYN scan at up to 100 000 pps. Configurable via `RATE_PPS`.
   - **asyncio fallback** — Pure-Python TCP connect scan at up to 512 concurrent connections (`CONCURRENCY`). No root required.

3. **Banner grabbing** — For every open port, a 2-second raw TCP read collects the service banner. TLS ports get a full handshake; the leaf certificate is parsed (subject, issuer, SANs, expiry, key type, self-signed flag) using a hand-rolled DER parser — no `openssl` binary required.

4. **Fingerprinting** — ~40 regex rules map banner text to `(service_name, product, version, CPE)`. CPE identifiers are stored and later joined against the NVD CVE feed.

5. **HTTP probing** — HTTP/HTTPS ports get a full `GET /` with a randomized user-agent. The response captures: HTTP status, `Server:` header, page title, favicon murmur3 hash (for Shodan-style icon search), WAF detection, and Wappalyzer technology fingerprinting.

6. **JARM fingerprinting** — TLS services get a JARM hash computed from seven specially crafted Client Hello packets. The hash is compared against a database of known C2 / malicious TLS stacks.

7. **HASSH / JA3s** — SSH and TLS session fingerprints stored for correlation.

8. **Geo + ASN enrichment** — IP→country/city via MaxMind GeoIP2 (optional) or the bundled `ip2asn.csv` offline CSV.

9. **CVE correlation** — Every `(product, version, CPE)` triple is looked up in the local NVD cache. Matching CVEs, their CVSS score, CISA KEV status, and EPSS exploit-probability score are stored per host.

10. **Risk scoring** — A composite integer score (0–100) is computed from CVSS, EPSS, KEV presence, open attack surface, exposed service type, and self-signed certificate status.

11. **Change detection** — Every scan creates a new `scan_round`. The `diff` command and `/api/diff` endpoint compare any two rounds and return new/removed/changed hosts.

### Daemon mode

```
python run.py daemon --interval 24
```

Runs forever. Every `--interval` hours it re-scans all allowlisted CIDRs, opens a new scan round, and updates the database. The daemon writes a heartbeat every 60 seconds; the dashboard shows whether it is live. The allowlist is re-read at the start of each cycle, so new ranges are picked up without a restart.

### Query language

The `query` command and `/api/search` endpoint understand a simple field:value expression language:

| Expression | Meaning |
|---|---|
| `product:nginx` | Product field contains "nginx" |
| `port:443` | Specific port |
| `country:PH` | Country code |
| `org:Amazon` | ASN org |
| `cve:CVE-2021-44228` | Host has this CVE |
| `kev:true` | Host has a CISA KEV vulnerability |
| `tag:web` | Host has this tag |
| `service:ssh` | Service name |
| `title:admin` | HTTP page title |
| `jarm:xxx` | JARM hash match |
| `tls:expired` | Certificate is expired |
| `risk:>80` | Risk score above threshold |
| bare text | Full-text search across banner |

Multiple expressions are ANDed. Full-text uses SQLite FTS5.

---

## Detection Pipelines

Both pipelines run against the raw banner text (HTTP headers + response body) stored in the database. They are invoked at scan time and can be re-run via backfill endpoints.

---

### Payment Card Detector (`engine/card_detector.py`)

Scans banner text for Primary Account Numbers (PANs) and correlated card data.

#### How it works

1. **Regex matching** — Two patterns:
   - **Amex** — 4-6-5 grouping (`3[47]xxxx xxxxxx xxxxx`)
   - **Standard 16-digit** — 4-4-4-4 grouping, anchored to known BIN prefixes (Visa 4xxx, MC 51–55 / 2221–2720, Discover 6011/64/65, UnionPay 62xx, JCB 35xx)

2. **Luhn checksum** — Only mathematically valid PANs pass. Random digit strings are rejected.

3. **Noise filters** — All-identical digits (`0000000000000000`) and perfectly monotone sequences (`1234567890123456`) are dropped.

4. **BIN classification** — The first 6 digits are looked up in a built-in IIN table covering Visa, MasterCard, Amex, Discover, UnionPay, JCB, and Diners Club. Returns network, issuer name, country, and funding type (credit/debit/prepaid).

5. **Expiration date extraction** — Searches ±300 characters around the PAN for an `MM/YY` pattern (months 01–12, years 20–29).

6. **CVV extraction** — Searches the same window for a CVV/CVC keyword followed by 3–4 digits.

7. **Masking** — The full PAN is never stored. Only `BIN6 + *** + last4` is retained (e.g. `411111******1111`).

Results go into the `pci_findings` table. The `/pci` page and `/api/pci/findings` endpoint surface them.

---

### Identity & Secret Detector (`engine/id_detector.py`)

A multi-category detection engine for PII and leaked secrets in service banners.

#### Detection categories

| Category | Types detected |
|---|---|
| **Government IDs** | Philippine National ID, SSS, TIN, PhilHealth, UMID, Passport, Driver's License |
| **Personal Information** | Email address, phone number, date of birth, residential address, full name |
| **Financial** | Payment card number (PAN), CVV presence, bank account number, financial statements |
| **Secrets** | AWS access key, GitHub token, Google API key, Slack token, JWT, Bearer token, private key, database connection string, exposed password, high-entropy string |

#### Pipeline stages

1. **Document classification** — The banner is classified as plain text, JSON, HTML, or binary. JSON documents get structured key-name hinting on top of regex scanning.

2. **Detector functions** — Four specialized detectors run in parallel:
   - `government_id_detector` — Regex rules with mandatory context keywords (e.g., "SSS number" must appear near the matched digits).
   - `personal_information_detector` — Email, phone, DOB, address, name rules. Phone numbers use ITU-T E.164 and regional formats. Names use a capitalized two-word heuristic with a stop-word list that rejects HTTP error phrases and UI labels.
   - `financial_data_detector` — PAN regex with Luhn + BIN + hex-context + network-length validation (see below). CVV presence flagging.
   - `secret_detector` — Exact-match rules for AWS/GitHub/Google/Slack key formats, JWT structure, and Shannon-entropy scan for high-entropy strings (≥4.0 bits/char over 16–256 chars).

3. **Context scoring** — Every candidate is scored ±0.15 based on whether domain-specific keywords appear within 80 characters. Date-of-birth candidates require a word-boundary match of `dob`, `date of birth`, `birthday`, `birthdate`, or `born` — URL path components (e.g. `zakaznik.dobrynet.sk`) do not qualify.

4. **Validation layer** — Candidates with validators run additional checks:
   - **Luhn** (PANs): digit-only extraction → BIN prefix check (must start with 3, 4, 5, or 6) → grouping check (must match 4-4-4-4, 4-6-5, or similar standard layouts) → **network-length check** (digit count must match the BIN network: Amex=15, Diners=14, Visa=13–16, etc.) → **hex-context check** (rejects numbers immediately adjacent to hex letters, catching CDN cookies and UUID embeddings) → Luhn checksum.
   - **Entropy** (high-entropy strings): Shannon entropy ≥ 4.0.

5. **False-positive suppression** — Multiple layers beyond validation:
   - Email addresses that look like SSH algorithm identifiers (`curve25519-sha256@libssh.org`), FTP developer contacts, UUID local-parts, or Unix-timestamp local-parts are silently dropped.
   - Full-name candidates that contain stop words (HTTP verbs, error phrases, UI labels, protocol terms) are dropped.
   - DOB candidates that match the HTTP `Date:` header format without a real DOB keyword in context are dropped.
   - Entropy scan rejects pure-hex and pure-lowercase strings.

6. **Confidence scoring** — Final confidence = `base_confidence + context_delta + validation_bonus − validation_penalty`. Only findings above `min_confidence_to_report` (default 0.55) are kept.

7. **Risk & compliance tagging** — Each finding is tagged with:
   - **Risk severity** (critical / high / medium / low / info) derived from a per-data-type base severity weighted by confidence.
   - **Compliance frameworks** — PCI DSS for financial types, PH DPA for Philippine government IDs, ISO 27001 / GDPR for personal information, SOC 2 / ISO 27001 for secrets.

8. **Deduplication** — Findings are deduplicated across all banners in a scan session using a hash of the evidence span. The same leaked secret at two different hosts produces two findings; the same secret repeated in one banner produces one.

9. **Evidence retention** — Raw evidence values are stored unredacted so findings are actionable. CVV values are an exception: the presence is flagged but the digits themselves are never stored (`[CVV PRESENT — NOT RETAINED]`).

10. **Expiration date & CVV extraction** — For validated PAYMENT_CARD_NUMBER findings, `_card_context()` searches ±300 characters for `MM/YY` and a CVV keyword + 3–4 digits and stores them in `exp_date` / `cvv_hint` columns.

Results go into the `id_findings` table. The `/id` page and `/api/id/findings` endpoint surface them. TXT and JSON exports are available at `/api/id/export`.

#### Accuracy on the included dataset

After full false-positive elimination passes, a scan of 23 254 real internet banners produces **25 genuine findings** with zero false positives:

| Type | Count | Notes |
|---|---|---|
| JWT | 5 | Real session cookies and API JWTs in HTTP responses |
| GOOGLE_API_KEY | 1 | Confirmed live key in TLS certificate |
| EMAIL_ADDRESS | 4 | Real operator contacts in FTP / SMTP banners |
| PHONE_NUMBER | 14 | Real numbers in HTTP pages and banners |
| FULL_NAME | 1 | Organization name in TLS certificate |
| PAYMENT_CARD | 0 | No real PANs in this dataset |

---

## Web UI & REST API

Start the web server:

```bash
python run.py web --port 8080
```

Open `http://localhost:8080` in your browser.

### Pages

| URL | Description |
|---|---|
| `/` | Dashboard — scan stats, daemon status, risk distribution, CVE counts |
| `/search` | Full-text + field search across all hosts |
| `/host/<ip>` | Per-host detail — services, CVEs, TLS, geo, tech stack, history |
| `/scan` | Launch a one-shot scan from the UI; live WebSocket progress feed |
| `/discover` | Crawl a running scan in real-time, see hosts as they appear |
| `/changes` | Change detection — new / removed / changed hosts since last round |
| `/timeline` | Scan history timeline |
| `/map` | World map of discovered hosts |
| `/pci` | Payment card findings (masked) |
| `/id` | Identity / PII / secret findings |
| `/export` | Bulk CSV / JSON export with filters |
| `/feeds` | NVD + KEV + EPSS feed sync status and manual refresh |
| `/wordlists` | Manage enumeration wordlists |
| `/explore` | Tag cloud, ASN explorer, tech distribution |
| `/watchlist` | Saved host watchlist |
| `/cve/<id>` | CVE detail page |

### Key REST endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/stats` | Global counts, CVE stats, risk distribution |
| GET | `/api/search?q=...` | Search hosts |
| GET | `/api/host/:ip` | Host summary |
| GET | `/api/host/:ip/:port/history` | Per-port observation history |
| POST | `/api/scan` | Start a scan (body: `{cidr, ports}`) |
| GET | `/api/scan/:id` | Scan status |
| WS | `/ws/scan/:id` | Live scan event stream |
| GET | `/api/diff?a=N&b=M` | Diff two scan rounds |
| GET | `/api/changes` | Recent changes |
| GET | `/api/pci/findings` | Payment card findings |
| GET | `/api/id/findings` | PII/secret findings |
| GET | `/api/id/export` | Download findings as TXT or JSON |
| POST | `/api/id/backfill` | Re-run ID detector on all stored banners |
| POST | `/api/pci/backfill` | Re-run card detector on all stored banners |
| POST | `/api/feeds/sync` | Sync NVD + KEV + EPSS |
| GET | `/api/feeds/status` | Feed freshness |
| GET | `/api/jarm?ip=...&port=...` | Live JARM fingerprint |
| GET | `/api/risk?ip=...&port=...` | Risk score details |
| POST | `/api/enumerate` | Start directory enumeration |
| GET | `/api/explore` | Tag / ASN / tech distribution |
| GET | `/api/graph` | Host relationship graph |
| GET | `/api/export` | Bulk export (CSV / JSON / JSONL) |

---

## Threat Intelligence Feeds

Synced from public sources via `python run.py sync-feeds` or the `/api/feeds/sync` endpoint:

| Feed | Source | Purpose |
|---|---|---|
| **NVD CVE** | github.com/fkie-cad/nvd-json-data-feeds | Full CVE database, per-year `.json.xz` |
| **CISA KEV** | cisa.gov | Known Exploited Vulnerabilities catalog |
| **EPSS** | empiricalsecurity.com | Exploit Prediction Scoring System |

Feeds are stored as compressed files in `nvd_cache/`. CVEs are correlated at scan time via CPE matching and also retroactively via `/api/pci/backfill`.

---

## Signature Databases

Three live-updated signature databases in `engine/signatures.py`:

| Database | Source | Purpose |
|---|---|---|
| **Wappalyzer** | wappalyzer/wappalyzer (or enthec/webappanalyzer fallback) | Technology fingerprinting from HTTP headers and body |
| **JARM C2** | cedowens/C2-JARM | Known C2 / malware TLS fingerprints |
| **WAF signatures** | stamparm/identYwaf | Web Application Firewall detection |

Each database has a primary URL, a fallback URL, a 7-day on-disk cache, and a small built-in table that works offline. Refreshes happen on a background thread at startup.

---

## Database Schema

**`cyberscan.db`** (SQLite)

| Table | Key columns | Description |
|---|---|---|
| `hosts` | `ip, port` (PK) | One row per open port with all fingerprint data |
| `observations` | `ip, port, scan_round` | Historical snapshot per scan round |
| `scan_rounds` | `id, started_at, finished_at` | Scan round metadata |
| `pci_findings` | `masked_pan, bin_prefix, card_network` | Payment card hits (masked only) |
| `id_findings` | `finding_id, detected_data_type, redacted_evidence, exp_date, cvv_hint` | PII/secret hits |
| `cve` | `cve_id, cvss, description` | CVE records from NVD |
| `kev` | `cve_id` | CISA KEV entries |
| `epss` | `cve_id, score` | EPSS scores |
| `annotations` | `ip, port, notes, tags, starred` | User annotations |
| `watchlist` | `ip` | Watched hosts |
| `hostnames` | `ip, hostname` | Reverse DNS and cert SAN entries |
| `daemon_state` | single row | Daemon heartbeat and scheduling state |

---

## Installation

```bash
git clone https://github.com/kaneki654/NorthHarv
cd NorthHarv
pip install -r requirements.txt

# Optional: faster scanning
# Install masscan: https://github.com/robertdavidgraham/masscan
# Install nmap:    sudo apt install nmap
# Download GeoIP2: set GEOIP_DB=/path/to/GeoLite2-City.mmdb
```

---

## Configuration

All settings are environment variables with safe defaults:

| Variable | Default | Description |
|---|---|---|
| `CYBERSCAN_DB` | `cyberscan.db` | SQLite database path |
| `CYBERSCAN_ALLOWLIST` | `allowlist.txt` | Allowlist file path |
| `MASSCAN_BIN` | `masscan` | Path to masscan binary |
| `NMAP_BIN` | `nmap` | Path to nmap binary |
| `GEOIP_DB` | _(empty)_ | Path to MaxMind GeoLite2-City.mmdb |
| `ASN_CSV` | _(empty)_ | Path to IP→ASN CSV (uses bundled `ip2asn.csv` if unset) |
| `CONCURRENCY` | `512` | Max concurrent TCP connections |
| `TIMEOUT` | `2.0` | Per-connection timeout in seconds |
| `RATE_PPS` | `100000` | masscan packets per second |
| `NORTHHARV_NO_SIG_REFRESH` | _(unset)_ | Set to `1` to skip signature auto-refresh |

**`allowlist.txt`** — one CIDR per line, blank lines and `#` comments ignored:

```
# My lab network
192.168.1.0/24
10.0.0.0/8

# Authorized external range
203.0.113.0/24
```

---

## Usage

```bash
# Initialize the database and create an allowlist template
python run.py init

# Sync threat intelligence feeds (NVD + CISA KEV + EPSS)
python run.py sync-feeds

# One-shot scan of a CIDR range
python run.py scan --cidr 192.168.1.0/24

# Scan specific ports only
python run.py scan --cidr 10.0.0.0/8 --ports 22,80,443,8080

# Start the continuous daemon (re-scans every 24 hours)
python run.py daemon --interval 24

# Start the web UI
python run.py web --port 8080

# Search the database from CLI
python run.py query "product:nginx country:PH"

# Show database statistics
python run.py stats

# Compare two scan rounds
python run.py diff --round-a 1 --round-b 2
```
