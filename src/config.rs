//! Configuration via variables d'environnement (`.env` chargé au démarrage).

use std::path::PathBuf;

pub struct Config {
    /// Répertoire des datasets bruts téléchargés.
    pub data_dir: PathBuf,
    /// Adresse d'écoute de l'API.
    pub bind: String,
    /// Intervalle de rafraîchissement des feeds (heures) ; 0 = pas de refresh auto.
    pub refresh_hours: u64,
}

impl Config {
    pub fn from_env() -> Self {
        let data_dir = std::env::var("INDIC_DATA_DIR")
            .unwrap_or_else(|_| "./data".to_string())
            .into();
        let bind = std::env::var("INDIC_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        let refresh_hours = std::env::var("INDIC_REFRESH_HOURS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(12);
        Self {
            data_dir,
            bind,
            refresh_hours,
        }
    }
}

/// URLs des feeds (surchargées par env si besoin). Certaines sources sont
/// hébergées sur des hôtes hors sandbox : le refresh réel se fait sur le VPS.
pub struct FeedUrls {
    pub iptoasn: String,
    pub iptoasn6: String,
    pub peeringdb: String,
    pub tor: String,
    pub vpn: String,
    pub datacenter: String,
    pub proxies: String,
    /// iCloud Private Relay : plages de sortie officielles Apple (CSV).
    pub private_relay: String,
    // Feeds de menace IP (attribution : réseau criminel / C2 / abus).
    pub spamhaus_v4: String,
    pub spamhaus_v6: String,
    pub feodo: String,
    pub ipsum: String,
    // APIs VPN par provider (attribution nominale du service, façon spur.us).
    pub nordvpn: String,
    pub mullvad: String,
    /// Majestic Million : top domaines mondiaux (CSV) — prior de popularité.
    pub majestic: String,
    /// tg12/PoC_CVEs : index CVE → dépôts PoC GitHub (offline, sans clé).
    pub poc_cves: String,
}

impl Default for FeedUrls {
    fn default() -> Self {
        Self {
            iptoasn: env_or(
                "INDIC_FEED_IPTOASN",
                "https://iptoasn.com/data/ip2asn-v4.tsv.gz",
            ),
            iptoasn6: env_or(
                "INDIC_FEED_IPTOASN6",
                "https://iptoasn.com/data/ip2asn-v6.tsv.gz",
            ),
            // PeeringDB : dump bulk des réseaux, on ne garde que asn + info_type.
            peeringdb: env_or(
                "INDIC_FEED_PEERINGDB",
                "https://www.peeringdb.com/api/net?fields=asn,info_type,info_types",
            ),
            tor: env_or(
                "INDIC_FEED_TOR",
                "https://check.torproject.org/torbulkexitlist",
            ),
            vpn: env_or(
                "INDIC_FEED_VPN",
                "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
            ),
            datacenter: env_or(
                "INDIC_FEED_DATACENTER",
                "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
            ),
            proxies: env_or(
                "INDIC_FEED_PROXIES",
                "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_proxies.netset",
            ),
            // iCloud Private Relay : CSV `cidr,country,region,city` (1ʳᵉ colonne = CIDR).
            private_relay: env_or(
                "INDIC_FEED_PRIVATE_RELAY",
                "https://mask-api.icloud.com/egress-ip-ranges.csv",
            ),
            // Spamhaus DROP : netblocks hijackés/loués par des criminels (JSON lines).
            spamhaus_v4: env_or(
                "INDIC_FEED_SPAMHAUS_V4",
                "https://www.spamhaus.org/drop/drop_v4.json",
            ),
            spamhaus_v6: env_or(
                "INDIC_FEED_SPAMHAUS_V6",
                "https://www.spamhaus.org/drop/drop_v6.json",
            ),
            // Feodo Tracker : IP de C2 de botnets (Emotet, QakBot, Pikabot…).
            feodo: env_or(
                "INDIC_FEED_FEODO",
                "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
            ),
            // IPsum niveau 3 : IP présentes dans ≥ 3 blacklists (corroboration).
            ipsum: env_or(
                "INDIC_FEED_IPSUM",
                "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
            ),
            // NordVPN : liste complète des serveurs (champ `station` = IP d'entrée).
            nordvpn: env_or(
                "INDIC_FEED_NORDVPN",
                "https://api.nordvpn.com/v1/servers?limit=8000",
            ),
            // Mullvad : tous les relais (`ipv4_addr_in` / `ipv6_addr_in`).
            mullvad: env_or(
                "INDIC_FEED_MULLVAD",
                "https://api.mullvad.net/www/relays/all/",
            ),
            // Majestic Million : CSV trié par rang (colonne `Domain` = apex).
            // Prior de légitimité — un domaine très populaire n'est quasiment
            // jamais un IOC (les signaux portent sur du contenu hébergé).
            majestic: env_or(
                "INDIC_FEED_MAJESTIC",
                "https://downloads.majestic.com/majestic_million.csv",
            ),
            // tg12/PoC_CVEs : table markdown `| CVE | / | url github |`.
            poc_cves: env_or(
                "INDIC_FEED_POC_CVES",
                "https://raw.githubusercontent.com/tg12/PoC_CVEs/main/cve_links.txt",
            ),
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
