# Changelog

All notable changes to Spider Crawl are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.1] — 2026-11-15

### 🎉 Initial public release

### Added
- 10 passive recon sources queried in parallel:
  Wayback Machine, Common Crawl (×5 indexes), AlienVault OTX, URLScan.io,
  VirusTotal, crt.sh, RapidDNS, HackerTarget, GitHub code dorks, Shodan
- Fully async core (`aiohttp`) with per-source semaphores and exponential-backoff retries
- URL normalization: dedup, canonical scheme/port, sorted query strings
- Auto-classification into `urls / parameters / js / sensitive / pdf / images / media`
- Unique query-parameter-key extraction per domain
- Subdomain harvesting across all sources
- Machine-readable JSON report per domain (per-source counts, timing, errors)
- Dependency-free `.env` loader — API keys via environment or gitignored `.env`
- `--proxy` support for full Burp Suite visibility
- Single-domain (`-d`) and bulk list (`-l`) modes
- Rich terminal UI: live progress, per-source result lines, summary tables

### Security
- No hardcoded API keys — all credentials are read from env vars / `.env`

[1.0.1]: https://github.com/nkbeast/Spider-Crawl/releases/tag/v1.0.1
