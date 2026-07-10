#!/usr/bin/env python3
"""Collecteur honeypot → indic.

Tail les logs JSON de Cowrie + OpenCanary, extrait les IP attaquantes publiques
et les pousse dans indic (`POST /push`), qui enrichit puis relaie vers MISP +
OpenCTI (plumbing déjà en place). Dédup avec TTL pour ne pas marteler indic.

Stdlib uniquement (pas de dépendance à installer). Config par variables d'env :
  INDIC_URL           base indic (défaut https://indic.example.com)
  INDIC_TOKEN         token indic (requis) — gate le /push
  COLLECTOR_LOGS      chemins des logs, séparés par des virgules
  COLLECTOR_DEDUP_TTL secondes avant de re-pousser une même IP (défaut 3600)
"""

import ipaddress
import json
import os
import threading
import time
import urllib.parse
import urllib.request

INDIC_URL = os.environ.get("INDIC_URL", "https://indic.example.com").rstrip("/")
INDIC_TOKEN = os.environ.get("INDIC_TOKEN", "")
DEDUP_TTL = int(os.environ.get("COLLECTOR_DEDUP_TTL", "3600"))
LOGS = [
    p.strip()
    for p in os.environ.get(
        "COLLECTOR_LOGS",
        "/logs/cowrie/cowrie.json,/logs/opencanary/opencanary.log",
    ).split(",")
    if p.strip()
]
# Champs IP source rencontrés dans Cowrie / OpenCanary.
IP_FIELDS = ("src_ip", "src_host")

_seen: dict[str, float] = {}
_lock = threading.Lock()


def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        a.is_private
        or a.is_loopback
        or a.is_link_local
        or a.is_multicast
        or a.is_reserved
        or a.is_unspecified
    )


def extract_ip(line: str) -> str | None:
    try:
        ev = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(ev, dict):
        return None
    for f in IP_FIELDS:
        v = ev.get(f)
        if isinstance(v, str) and is_public_ip(v):
            return v
    return None


def push(ip: str) -> None:
    now = time.time()
    with _lock:
        if now - _seen.get(ip, 0.0) < DEDUP_TTL:
            return
        _seen[ip] = now
    query = urllib.parse.urlencode({"q": ip, "token": INDIC_TOKEN})
    req = urllib.request.Request(f"{INDIC_URL}/push?{query}", method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"[collector] push {ip} -> HTTP {r.status}", flush=True)
    except Exception as e:  # noqa: BLE001 — on ne veut jamais crasher le tail
        print(f"[collector] push {ip} échec : {e}", flush=True)


def tail(path: str):
    """Suit un fichier ligne à ligne, en gérant l'attente et la rotation."""
    while not os.path.exists(path):
        time.sleep(2)
    f = open(path, "r", errors="replace")
    f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    while True:
        line = f.readline()
        if line:
            yield line
            continue
        time.sleep(1)
        try:
            if os.stat(path).st_ino != inode:  # rotation → réouvre
                f.close()
                f = open(path, "r", errors="replace")
                inode = os.fstat(f.fileno()).st_ino
        except FileNotFoundError:
            pass


def watch(path: str) -> None:
    print(f"[collector] surveille {path}", flush=True)
    for line in tail(path):
        ip = extract_ip(line)
        if ip:
            push(ip)


def main() -> None:
    if not INDIC_TOKEN:
        raise SystemExit("[collector] INDIC_TOKEN manquant — arrêt")
    print(f"[collector] démarrage → {INDIC_URL}, logs={LOGS}", flush=True)
    threads = [threading.Thread(target=watch, args=(p,), daemon=True) for p in LOGS]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
