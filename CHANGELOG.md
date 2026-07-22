# Changelog

All notable changes to indic.

## [Unreleased]

### Fixed
- **Resolvers DNS publics classés « suspect »** : `1.1.1.1` ressortait suspect
  parce qu'ipdata l'annonce `malicious`, alors qu'un resolver figure dans les
  journaux de tout le monde — victimes comprises. Le prior « légitime »
  n'existait que pour les domaines ; il couvre désormais une liste curée de
  resolvers publics. Périmètre étroit : les adresses de résolution seulement,
  pas les IP de CDN, qui hébergent réellement du contenu malveillant.
  Contrairement au prior domaine, celui-ci est évalué **après** le test de
  corroboration : trois sources sérieuses l'emportent toujours.


## [0.3.0] — 2026-07-22

Release centrée sur l'exploitation : ce que l'outil montre, comment on lui fait
confiance, et comment on voit qu'il va mal.

### Added

**Interface**
- **Comparateur** ancré à la fiche : l'observable affiché face à 1 ou 2 autres,
  attributs alignés dans une grille unique, seules les lignes divergentes
  marquées. Graphe de la relation, pivots communs cliquables, diff des signaux.
  `POST /compare` accepte `{items:[…]}` (2 à 3) ; `{a,b}` reste supporté.
- **Extracteur d'IOC** en overlay dédié (touche `e`), résultats groupés par type,
  et **« Tout analyser »** qui enchaîne sur `/lookup/bulk` par lots de 20 avec
  affichage progressif.
- **Panneau « santé des sources »** dans les réglages : état (active / coupée /
  sans clé), quota consommé, ok/err/latence et **dernière erreur** par source,
  problèmes remontés en tête.
- **Section Endpoints** dans les réglages : chaque route avec sa méthode, son
  badge `token`, un lien d'ouverture et un `curl` prêt à coller.
- **Corrélations** avec l'historique affichées dans la fiche, observables liés
  cliquables.
- Nouvelle marque (réticule), lisible dès 16 px, et image de preview sociale.

**Sources**
- **Traceix** : verdicts antivirus multi-moteurs, capacités CAPA avec techniques
  MITRE ATT&CK, règle YARA générée — trois recherches par SHA-256 en parallèle.
- **AURA** : classification IA par SHA-256, corpus distinct de Traceix.
- **Décrypteurs de ransomware** : une adresse BTC rattachée à une famille mène
  désormais à l'outil de déchiffrement public quand il existe.

**Exploitation**
- **Cache d'enrichissement persistant** : les résultats survivent aux
  redéploiements. Les échecs, eux, ne sont pas persistés — une source qui a
  échoué mérite une nouvelle tentative.
- **Quotas locaux** par source, persistés (`validin` 9/jour, `fullhunt` 9/mois) :
  l'appel n'est pas émis une fois le plafond atteint, donc aucun dépassement
  côté fournisseur.
- **`INDIC_DISABLED_SOURCES`** : couper une source sans toucher à sa clé.
- **`INDIC_SKIP_BOOTSTRAP`** : démarrer sans télécharger les datasets (CI/e2e).

**Qualité**
- **Type-check du front** : JSDoc vérifié par `tsc --checkJs --noEmit`, sans
  bundler ni étape de build. `$()` n'accepte que les identifiants réellement
  présents dans `index.html`.
- **CI front** : `node --check`, type-check et suite Playwright — le front
  n'avait aucune barrière automatique.
- **CodeQL** (rust + javascript-typescript) sur push, PR et hebdomadairement.
- **Fixtures** : réponses réelles enregistrées et rejouées dans les tests.

### Fixed

- **Corrélations fausses** : le prédicat de recherche dans l'historique était
  ignoré. Un lookup de `8.8.8.8` annonçait `1.1.1.1` comme étant dans son /24,
  « domaines similaires » comparait 20 caractères de chaîne, et une IP revue
  trois fois comptait pour trois. Prédicats réels + déduplication.
- **Token en query string** : `/settings` et `/correlate` passaient le token
  dans l'URL, donc dans l'historique du navigateur et les logs du proxy. Il
  transite désormais en en-tête `x-indic-token`.
- **`?q=` cassé** : `render()` déréférençait un élément que la landing crée
  paresseusement. Tout lien partagé ou favori tombait sur « erreur réseau ».
- **Service worker** : désinscrit à chaque chargement, il ne prenait jamais le
  contrôle ; et il mettait en cache les réponses `/lookup`, laissant sur le
  disque la trace de chaque observable analysé. Ne traite plus que la coquille.
  URL versionnée `/sw.js?v=N`, Cloudflare écrasant le `Cache-Control` d'origine.
- **Filtres de signaux** : « Autres » ne couvrait que la teinte `slate`, donc
  certains signaux n'apparaissaient dans aucun filtre. Les trois filtres
  partitionnent désormais l'ensemble, et un filtre vide est masqué.
- **`build.rs`** échouait silencieusement si une balise d'`index.html` était
  reformatée : page livrée sans style, build vert.
- **IntelX** : `"records": null` faisait échouer la désérialisation
  (`#[serde(default)]` ne couvre pas un champ nul).
- Faux positif CodeQL critique levé en renommant `nonce` (compteur de
  transactions Ethereum) en `tx_count`.

### Changed

- `GET /settings` expose `sources[]` et `disabled_sources`.
- Pied de page réécrit ; la limite des listes gratuites est une mise en garde
  visible, plus une subordonnée en fin de phrase.
- README : captures regénérées, comparateur et extracteur documentés, table des
  endpoints complétée, décompte des sources corrigé (~75).

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
