# Changelog

All notable changes to indic.

## [Unreleased]

### Added
- **Enricher trait + Registry**: adding a new enricher is now a single line in `registry.rs` — no dispatch changes needed.
- **Bulk export**: `POST /lookup/bulk` accepts `"format": "stix"|"csv"` to export all results as a single STIX 2.1 bundle or CSV.
- **Tracing spans**: `#[tracing::instrument]` on `run()` and `dispatch()` for per-lookup timing in traces.
- **Dockerfile with cargo-chef**: layer-cached dependency builds for faster rebuilds.

### Changed
- `enrich.rs` dispatch rewritten from ~730 lines of per-type match arms to ~50-line `run_enrichers()` using the registry.
- All enrich submodules made `pub(crate)` for registry access.

## [0.2.0] — 2026-07-12

### Added
- **STIX 2.1 + CSV export**: `GET /lookup/export?q=...&format=stix|csv`.
- **Bulk lookup**: `POST /lookup/bulk` — up to 20 observables in parallel.
- **Rate limiting**: 30 req/min per IP, HTTP 429 on excess.
- **Prometheus metrics**: `GET /metrics?token=...&format=prometheus`.
- **Bogon detection**: RFC 1918/5735/6598/6890 + IPv6 bogon ranges.
- **MITRE ATT&CK mapping**: CWE → Technique for CVE reports.
- **Threat actor aggregation**: malware family names from MalwareBazaar, Triage, etc.
- **IOC decay scoring**: freshness score 0.0–1.0 over a 90-day sliding window.
- **URL content analysis**: keyless enricher — HTTP HEAD, title extraction, security headers.
- **EmailRep.io**: email reputation enricher (free tier).
- **Config hot-reload**: `kill -SIGHUP` reloads API keys without restart.
- **SQLite history**: `INDIC_HISTORY=1` — lookup history with 90-day purge.
- **Cross-correlation**: `GET /correlate?q=...` — /24 IP neighbors, similar domains, same-year CVEs.
- **Dashboard**: `GET /dashboard[?token=]` — public stats + gated recent lookups detail.
- **IOC extraction**: `POST /extract` — extracts IPs, domains, hashes, CVEs, URLs, emails from text.
- **History filters**: `GET /history?kind=&verdict=` — filter by observable type and verdict.
- **Veille Module A — watchlist**: `INDIC_WATCH_DOMAINS` — monitors CT certs + GitHub mentions per domain.
- **Veille Module C — dark web**: Ahmia.fi framework (`INDIC_DARKWEB_ENABLED=1`, disabled by default).
- **Custom alert rules**: `INDIC_ALERT_RULES` + `INDIC_ALERT_OBSERVABLES` for threshold-based alerts.

### Frontend
- Signal filter bar: All / Critical / Suspect / Other with live counters.
- STIX + CSV export buttons in the report header.
- Dashboard landing: total lookups, verdicts, top types as colored chips.
- PWA: network-first service worker + manifest + offline support.
- Graph node colors by verdict (red / orange / green).
- Keyboard shortcuts: `1`=All, `2`=Critical, `3`=Suspect, `4`=Other.
- IOC extractor widget: textarea → Extract button → clickable chips.

### Fixed
- Full `SIG_HUE` coverage: c2, botnet, malware, phishing, threat, suspicious, sanctions, exploit, info, osint.
- `/metrics` accepts `?token=` in addition to `x-indic-token` header.
- Service worker switched to network-first (no more stale cache).
- `Cache-Control: no-cache, no-store, must-revalidate` on landing.
- Export buttons inline (no longer stacked).
- Dashboard "Top types" as colored chips instead of plain text.
- "Clean" label renamed from "Propres" → "Légitimes".

## [0.1.0] — initial

### Added
- 43+ enrichers: abuseipdb, blocklists, censys, circl_hashlookup, criminalip, crtsh, cve, cvedb, dns, dshield, fullhunt, github, gravatar, greynoise, hudsonrock, ikwyd, intelx, internetdb, ipdata, ipgeo, ipinfo, ipqs, leakix, local, malwarebazaar, metadefender, osv, otx, proxycheck, rdap, rdap_domain, rdns, ripestat, safebrowsing, scamalytics, shodan, stopforumspam, threatfox, urlhaus, urlscan, virustotal, vpnapi, wayback + hybridanalysis, triage, phone, onion.
- 13 observable types: ip, cidr, domain, url, email, hash, cve, asn, crypto, username, phone, onion, package.
- Weighted verdict: corroboration-based scoring + popularity prior (Majestic top-100k).
- Recursive pivot graph: force-directed canvas, expand-on-click.
- Offline datasets: IP-to-ASN, PeeringDB, cloud ranges, VPN ranges, blocklists, GeoLite2.
- Push to MISP + OpenCTI.
- Scheduled veille: CISA KEV + IntelX pastes + Apple security advisories → Pushover.
- Web UI: single-file embedded frontend (dark/light, pivot graph, landing examples).
- 125 tests, clippy strict.
