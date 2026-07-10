#!/usr/bin/env bash
# Durcissement de l'hôte honeypot (Ubuntu/Debian + ufw).
#
# Objectif : limiter le pivot si le honeypot est compromis → egress default-deny,
# inbound ouvert uniquement sur les ports appâts + ton SSH admin.
#
# ⚠️ AVANT de lancer : déplace ton SSH admin sur un port NON standard (Cowrie
#    prend le 22). Édite /etc/ssh/sshd_config → `Port 62222`, `systemctl restart ssh`,
#    reconnecte-toi sur ce port, PUIS lance ce script (sinon tu te coupes l'accès).
#
# Usage : sudo ./harden.sh [PORT_SSH_ADMIN]   (défaut 62222)
set -euo pipefail

ADMIN_SSH_PORT="${1:-62222}"

command -v ufw >/dev/null || { echo "ufw absent : apt install ufw"; exit 1; }

ufw --force reset
ufw default deny incoming
ufw default deny outgoing

# --- Ton accès admin ---
ufw allow "${ADMIN_SSH_PORT}"/tcp comment "admin SSH"

# --- Ports appâts (attaquants) ---
ufw allow 22/tcp   comment "Cowrie SSH"
ufw allow 23/tcp   comment "Cowrie Telnet"
ufw allow 21/tcp   comment "OpenCanary FTP"
ufw allow 80/tcp   comment "OpenCanary HTTP"
ufw allow 3306/tcp comment "OpenCanary MySQL"

# --- Egress minimal (mises à jour + DNS/NTP + push vers indic en HTTPS) ---
ufw allow out 53            comment "DNS"
ufw allow out 123/udp       comment "NTP"
ufw allow out 80/tcp        comment "apt"
ufw allow out 443/tcp       comment "HTTPS (updates + push indic)"

ufw --force enable
ufw status verbose

echo
echo "⚠️ Rappel : l'egress 443 reste ouvert (nécessaire pour indic + updates)."
echo "   Un honeypot compromis pourrait exfiltrer via 443. C'est le compromis"
echo "   accepté ; l'hôte est jetable et sur un compte séparé."
