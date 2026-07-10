# Honeypot indic — kit de déploiement

Honeypot défensif dont les IOC alimentent indic → MISP → OpenCTI.

```
Attaquant → Cowrie (SSH/Telnet) ┐
            OpenCanary (FTP/HTTP/MySQL) ┤→ logs JSON → collector.py → indic POST /push → MISP + OpenCTI
```

Choix retenus : **Cowrie** (interaction, éprouvé, MISP natif) + **OpenCanary** (tripwire léger). Pas de T-Pot (trop lourd) ni Beelzebub (écarté au profit de Cowrie).

## ⚠️ Règles non négociables
- **Hôte DÉDIÉ et SÉPARÉ** — jamais sur le même hôte qu'indic / ta prod. Surface d'attaque partagée + risque de pivot. Reco : un petit VPS jetable (ex. Hetzner CX22 ~4,60 €/mo), sur un **compte distinct**.
- **SSH admin sur un port non standard AVANT tout** : Cowrie occupe le 22 (c'est l'appât). Si tu ne bouges pas ton SSH, tu te coupes l'accès en lançant le honeypot.

## Étapes

1. **Créer la box** : Hetzner CX22 (2 vCPU / 4 Go / 40 Go), Ubuntu 24.04, sur un compte séparé.
2. **Déplacer ton SSH admin** : dans `/etc/ssh/sshd_config` → `Port 62222`, puis `systemctl restart ssh`. **Reconnecte-toi sur `:62222` et vérifie que ça marche** avant de continuer.
3. **Docker** : `curl -fsSL https://get.docker.com | sh` (script inspecté au préalable) + `apt install docker-compose-plugin`.
4. **Copier ce dossier** `honeypot/` sur la box (ex. `~/honeypot`).
5. **`.env`** à côté du compose :
   ```
   INDIC_TOKEN=<le même INDIC_TOKEN que le .env de ton instance indic>
   # optionnel : INDIC_URL=https://indic.example.com
   ```
6. **Durcir** : `sudo ./harden.sh 62222` (egress default-deny, inbound = appâts + ton SSH admin).
7. **Lancer** : `docker compose up -d`.

## Vérifier
- Depuis une autre machine : `ssh root@<ip_honeypot>` avec un faux mot de passe → Cowrie loggue la tentative.
- `docker compose logs -f collector` → doit afficher `push <ton_ip> -> HTTP 200`.
- L'IP doit apparaître dans indic (`/lookup?q=<ip>`) puis dans MISP/OpenCTI (le `/push` est gaté + déjà branché).

## Notes
- **Ports appâts** : Cowrie 22 (SSH) + 23 (Telnet) ; OpenCanary 21 (FTP), 80 (HTTP), 3306 (MySQL). Ajustables dans `docker-compose.yml` / `opencanary.conf` + `harden.sh`.
- **Dédup** : le collecteur ne repousse pas une même IP avant `COLLECTOR_DEDUP_TTL` (1 h) → protège les quotas indic.
- **RGPD** : une IP = donnée personnelle ; base légale « intérêt légitime » (sécurité), rétention conseillée 6-12 mois.
- **Egress** : `harden.sh` laisse le 443 sortant ouvert (updates + push indic). Compromis accepté (hôte jetable). Durcir davantage = restreindre par IP, mais indic est derrière Cloudflare (IPs multiples).
- **Maintenance** : `docker compose pull && up -d` de temps en temps. Sauvegarde `data/` si tu veux garder les captures.
