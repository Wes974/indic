# indic — changelog & roadmap

> Session du 12 juillet 2026 — ~20 features, 125 tests, clippy strict.

---

## 🆕 Nouvelles fonctionnalités

### Backend (API & enrichers)

| Feature | Endpoint / Config | Description |
|---|---|---|
| **STIX 2.1 + CSV export** | `GET /lookup/export?q=...&format=stix\|csv` | Export bundle STIX 2.1 ou CSV aplati |
| **Bulk lookup** | `POST /lookup/bulk` | Jusqu'à 20 observables en parallèle |
| **Rate limiting** | — | 30 req/min par IP, HTTP 429 si dépassé |
| **Prometheus metrics** | `GET /metrics?token=...&format=prometheus` | Format exposition Prometheus scrapeable |
| **Bogon detection** | — | Détection RFC 1918/5735/6598/6890 + IPv6 |
| **MITRE ATT&CK** | — | Mapping CWE→Technique pour les rapports CVE |
| **Threat actors** | — | Agrégation des familles malware (MalwareBazaar, Triage…) |
| **IOC decay scoring** | — | Score fraîcheur 0.0–1.0 sur 90 jours glissants |
| **URL content analysis** | — | Enricher keyless : HEAD HTTP, titre, headers sécu |
| **EmailRep.io** | — | Enricher réputation email (gratuit, gated) |
| **Config hot-reload** | SIGHUP | `kill -SIGHUP` recharge les clés API sans redémarrer |
| **SQLite history** | `INDIC_HISTORY=1` | Historique des lookups, purgé à 90j |
| **Cross-correlation** | `GET /correlate?q=...` | /24 IP, domaines similaires, CVEs même année |
| **Dashboard** | `GET /dashboard[?token=]` | Stats publiques + détail gated (20 derniers) |
| **IOC extraction** | `POST /extract` | Extrait IP/domaines/hashes/CVE/URLs/emails d'un texte |
| **History filters** | `GET /history?kind=&verdict=` | Filtre par type d'observable et verdict |
| **Module A — watchlist** | `INDIC_WATCH_DOMAINS` | Surveille les certs CT + mentions GitHub par domaine |
| **Module C — dark web** | `INDIC_DARKWEB_ENABLED=1` | Framework Ahmia.fi (désactivé par défaut) |
| **Custom alert rules** | `INDIC_ALERT_RULES` + `INDIC_ALERT_OBSERVABLES` | Règles type `c2_alert:c2:1` |

### Frontend

| Feature | Description |
|---|---|
| **Signal filters** | Barre Tous / Critiques / Suspects / Autres avec compteurs (N) |
| **Export buttons** | STIX + CSV dans le header rapport (ligne STIX · CSV · json) |
| **Dashboard landing** | Stats publiques : lookups totaux, verdicts, top types en chips colorés |
| **PWA** | Service worker network-first + manifest + offline |
| **Graph colors** | Nœud central coloré par verdict (rouge/orange/vert) |
| **Keyboard shortcuts** | `1`=Tous, `2`=Critiques, `3`=Suspects, `4`=Autres |
| **IOC extractor widget** | Textarea → bouton Extraire → chips cliquables |

### Correctifs

- `SIG_HUE` complet : c2, botnet, malware, phishing, threat, suspicious, sanctions, exploit, info, osint
- `/metrics` accepte `?token=` en plus du header `x-indic-token`
- Service worker en **network-first** (plus de cache stale)
- `Cache-Control: no-cache, no-store, must-revalidate` sur la landing
- Export buttons en ligne (plus empilés)
- Dashboard "Top types" en chips colorés au lieu de texte brut
- "Propres" → "Légitimes"

---

## 🔮 Next steps (pistes)

### Quick wins
- **Comparateur** : coller 2 observables → rapport côte à côte. Utile pour comparer deux IPs suspectes
- **Nœuds du graphe récursif colorés** : quand on expand un nœud, récupérer le verdict du lookup et colorer le nœud (aujourd'hui seul le central est coloré)
- **Module C dark web activable** : `INDIC_DARKWEB_ENABLED=1` + `INDIC_DARKWEB_KEYWORDS=ransomware,leak` → le framework est déjà codé
- **Tests de bout en bout** : quelques tests HTTP sur l'API (reqwest + tokio-test)

### Medium
- **CF Access MISP** : l'UI MISP est publique, protégée seulement par son login. Cloudflare Access (Zero Trust) mettrait un 2FA devant. Besoin d'un token API Cloudflare avec `Access: Apps and Policies: Edit`
- **Tableau de bord filtré** : `/dashboard?kind=ip&verdict=malicious` pour explorer l'historique depuis la landing
- **Export bulk** : exporter tous les résultats d'un `/lookup/bulk` en CSV/STIX d'un coup
- **Rétention configurable** : `INDIC_HISTORY_RETENTION_DAYS=90` au lieu de 90j fixe

### Plus lourd
- **Déploiement honeypot** : le kit est prêt (`honeypot/` : Cowrie + OpenCanary + collector). Besoin d'un VPS Hetzner ~5 €/mois (jamais sur le VPS Oracle)
- **Dark web crawler** : passer de read-only (Ahmia) à un vrai connecteur Tor (arti-client en Rust) — garde-fou à lever
- **Multi-tenancy** : tokens API multiples, quotas par token, historiques séparés
- **Threat intel feed sortant** : qu'indic produise son propre feed (MISP/STIX/TXT) que d'autres outils peuvent consommer
- **Intégration TheHive/Cortex** : les plateformes de réponse à incident

### Dette technique
- **Test de l'API** : quelques tests d'intégration (appeler `/lookup?q=8.8.8.8` et vérifier la forme de la réponse)
- **Compression brotli/gzip** : activer sur les réponses JSON volumineuses
- **Docker multi-stage optimisé** : l'image fait ~85 Mo, on pourrait viser ~40 Mo avec UPX ou un linker LTO
- **Observabilité** : exporter les métriques en OpenTelemetry en plus de Prometheus

---

## 📊 Chiffres

| Métrique | Valeur |
|---|---|
| Tests | **125** (tous verts) |
| Clippy | **0 warning** (`-D warnings`) |
| Enrichers | ~70 |
| Types d'observables | 13 |
| Endpoints API | 14 |
| Fichiers modifiés | 59 |
| Lignes ajoutées | +2333 |
| Modules Rust ajoutés | 8 (`stix`, `rate`, `history`, `correlate`, `attack`, `darkweb`, `emailrep`, `url_analysis`) |
