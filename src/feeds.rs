//! Updater des datasets : télécharge chaque feed dans le `data_dir`.
//!
//! Les échecs individuels sont loggés mais non fatals (refresh partiel OK).
//! Note sandbox : `iptoasn.com`, `www.peeringdb.com` et `check.torproject.org`
//! ne sont pas whitelistés en sandbox locale ; le refresh complet tourne sur le VPS.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use reqwest::Client;

use crate::config::FeedUrls;

/// Version des feeds : à bumper dès qu'on ajoute/modifie une source, pour forcer
/// un refetch au démarrage (cf. `needs_bootstrap`). Écrite dans `.feedversion`.
pub const FEED_VERSION: &str = "14";

/// Nombre de domaines Majestic conservés pour le prior de popularité. Borne la
/// mémoire (~6 Mo) et cadre le prior sur les domaines *réellement* majeurs :
/// un domaine profond dans le classement ne mérite pas d'annuler des signaux.
const POPULAR_TOP_N: usize = 100_000;

/// Blocklists domaine (nom → URL), format domaines plats. Un 404 est ignoré.
/// hagezi : `tif` (threat intel), `ultimate` (Multi Ultimate — ads/tracking/télémétrie,
/// ex. `dit.whatsapp.net`), `doh`, `dyndns`, `fake` (thématiques sous `wildcard/*-onlydomains`).
/// + Phishing Army (phishing) et red.flag.domains (domaines .fr suspects récemment déposés).
const DOMAIN_LISTS: &[(&str, &str)] = &[
    (
        "tif",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt",
    ),
    (
        "ultimate",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt",
    ),
    (
        "doh",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/doh.txt",
    ),
    (
        "dyndns",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns-onlydomains.txt",
    ),
    (
        "fake",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt",
    ),
    (
        "phishing_army",
        "https://phishing.army/download/phishing_army_blocklist.txt",
    ),
    (
        "redflag",
        "https://dl.red.flag.domains/red.flag.domains.txt",
    ),
];

/// Plages IP publiées par les grands clouds (keyless). Nom = provider affiché.
/// JSON : on ramasse récursivement toute chaîne CIDR (robuste aux formats variés :
/// AWS `ip_prefix`, GCP `ipv4Prefix`, Oracle `regions[].cidrs[].cidr`, GitHub `/meta`,
/// Fastly `addresses`).
const CLOUD_JSON: &[(&str, &str)] = &[
    ("AWS", "https://ip-ranges.amazonaws.com/ip-ranges.json"),
    ("GCP", "https://www.gstatic.com/ipranges/cloud.json"),
    (
        "Oracle",
        "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
    ),
    ("GitHub", "https://api.github.com/meta"),
    ("Fastly", "https://api.fastly.com/public-ip-list"),
    // Azure : la page de download MS est derrière Akamai (fingerprinting anti-bot
    // qui bloque reqwest — curl passe, pas rustls). On passe par un mirror GitHub
    // du JSON ServiceTags officiel, régénéré automatiquement chaque semaine.
    // `collect_cidrs` extrait les `addressPrefixes` (~107k CIDR).
    (
        "Azure",
        "https://raw.githubusercontent.com/enzo-g/azureIPranges/main/docs/json-history/ServiceTags_Public.json",
    ),
];

/// Clouds publiant des listes texte (une CIDR par ligne), éventuellement multi-URL.
const CLOUD_TEXT: &[(&str, &[&str])] = &[(
    "Cloudflare",
    &[
        "https://www.cloudflare.com/ips-v4/",
        "https://www.cloudflare.com/ips-v6/",
    ],
)];

/// Vrai si les datasets sont absents ou si la version des feeds a changé
/// (→ force un refetch complet au démarrage quand on ajoute/modifie des sources).
pub fn needs_bootstrap(data_dir: &Path) -> bool {
    if !data_dir.join("ip2asn-v4.tsv").exists() || !data_dir.join("ip2asn-v6.tsv").exists() {
        return true;
    }
    std::fs::read_to_string(data_dir.join(".feedversion"))
        .map(|s| s.trim() != FEED_VERSION)
        .unwrap_or(true)
}

pub async fn update_all(data_dir: &Path, urls: &FeedUrls) -> Result<()> {
    tokio::fs::create_dir_all(data_dir)
        .await
        .with_context(|| format!("création du data_dir {}", data_dir.display()))?;

    let client = Client::builder()
        .user_agent("indic/0.1 (personal CTI tool)")
        .timeout(Duration::from_secs(180))
        .build()?;

    // Texte brut (listes de CIDR/IP + CSV ASdb).
    fetch_text(&client, &urls.tor, &data_dir.join("tor-exits.txt")).await;
    fetch_text(&client, &urls.vpn, &data_dir.join("vpn.txt")).await;
    fetch_text(&client, &urls.datacenter, &data_dir.join("datacenter.txt")).await;
    fetch_text(&client, &urls.proxies, &data_dir.join("proxies.txt")).await;
    fetch_text(&client, &urls.peeringdb, &data_dir.join("peeringdb.json")).await;
    // iCloud Private Relay : CSV → on ne garde que la 1ʳᵉ colonne (CIDR).
    fetch_csv_cidrs(
        &client,
        &urls.private_relay,
        &data_dir.join("private_relay.txt"),
    )
    .await;

    // Gzip → décompression (dumps iptoasn v4 + v6).
    fetch_gzip(&client, &urls.iptoasn, &data_dir.join("ip2asn-v4.tsv")).await;
    fetch_gzip(&client, &urls.iptoasn6, &data_dir.join("ip2asn-v6.tsv")).await;

    // Blocklists domaine (dans data/blocklists/).
    let blocklists_dir = data_dir.join("blocklists");
    let _ = tokio::fs::create_dir_all(&blocklists_dir).await;
    for (name, url) in DOMAIN_LISTS {
        fetch_text(&client, url, &blocklists_dir.join(format!("{name}.txt"))).await;
    }

    // Feeds de menace IP (data/ipthreat/) → chargés en RangeSet, rapportés en signaux.
    let ipthreat_dir = data_dir.join("ipthreat");
    let _ = tokio::fs::create_dir_all(&ipthreat_dir).await;
    // Spamhaus DROP : JSON lines {"cidr":…} → CIDR bruts (v4 + v6 fusionnés).
    fetch_spamhaus(
        &client,
        &[&urls.spamhaus_v4, &urls.spamhaus_v6],
        &ipthreat_dir.join("spamhaus_drop.txt"),
    )
    .await;
    // Feodo (IP plates + en-tête #) et IPsum (IP plates) → tels quels, `push_line` filtre.
    fetch_text(&client, &urls.feodo, &ipthreat_dir.join("feodo.txt")).await;
    fetch_text(&client, &urls.ipsum, &ipthreat_dir.join("ipsum.txt")).await;
    // NB : abuse.ch SSLBL "IPs only" déprécié le 2025-01-03 → non intégré. Les IP
    // de C2 SSL sont couvertes par Feodo Tracker + ThreatFox (déjà présents).
    // Spamhaus ASN-DROP : ASN entièrement malveillants (JSON-lines) → réputation ASN.
    fetch_asndrop(
        &client,
        "https://www.spamhaus.org/drop/asndrop.json",
        &data_dir.join("asndrop.txt"),
    )
    .await;

    // OFAC : adresses crypto sanctionnées (ETH + BTC), une par ligne (repo 0xB10C).
    fetch_text_multi(
        &client,
        &[
            "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.txt",
            "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_BTC.txt",
        ],
        &data_dir.join("ofac_crypto.txt"),
    )
    .await;

    // VPN par provider (data/vpnprov/) : le nom de fichier = clé provider affichée.
    let vpnprov_dir = data_dir.join("vpnprov");
    let _ = tokio::fs::create_dir_all(&vpnprov_dir).await;
    fetch_json_ips(
        &client,
        &urls.nordvpn,
        &vpnprov_dir.join("NordVPN.txt"),
        &["station", "ipv6_station"],
    )
    .await;
    fetch_json_ips(
        &client,
        &urls.mullvad,
        &vpnprov_dir.join("Mullvad.txt"),
        &["ipv4_addr_in", "ipv6_addr_in"],
    )
    .await;

    // Plages cloud (data/cloud/) : tag `datacenter:<provider>` sur l'IP.
    let cloud_dir = data_dir.join("cloud");
    let _ = tokio::fs::create_dir_all(&cloud_dir).await;
    for (name, url) in CLOUD_JSON {
        fetch_cloud_json(&client, url, &cloud_dir.join(format!("{name}.txt"))).await;
    }
    for (name, urls) in CLOUD_TEXT {
        fetch_text_multi(&client, urls, &cloud_dir.join(format!("{name}.txt"))).await;
    }
    // DigitalOcean : CSV dont la 1ʳᵉ colonne est un CIDR.
    fetch_csv_cidrs(
        &client,
        "https://www.digitalocean.com/geo/google.csv",
        &cloud_dir.join("DigitalOcean.txt"),
    )
    .await;

    // MaxMind GeoLite2 (géo offline précise) — clé MAXMIND_LICENSE_KEY dans l'env.
    fetch_maxmind(
        &client,
        "GeoLite2-City",
        &data_dir.join("GeoLite2-City.mmdb"),
    )
    .await;

    // Popularité (data/popular.txt) : top domaines Majestic → prior de légitimité.
    fetch_majestic(
        &client,
        &urls.majestic,
        &data_dir.join("popular.txt"),
        POPULAR_TOP_N,
    )
    .await;

    // PoC publics par CVE (data/poc_cves.txt) : tg12/PoC_CVEs, offline.
    fetch_poc_cves(&client, &urls.poc_cves, &data_dir.join("poc_cves.txt")).await;

    // Marque la version des feeds (évite un refetch au prochain boot si inchangée).
    let _ = tokio::fs::write(data_dir.join(".feedversion"), FEED_VERSION).await;
    Ok(())
}

/// Télécharge un JSON cloud et en extrait récursivement toutes les CIDR.
async fn fetch_cloud_json(client: &Client, url: &str, dest: &Path) {
    match download_text(client, url).await {
        Ok(body) => {
            let mut out = Vec::new();
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                collect_cidrs(&v, &mut out);
            }
            if out.is_empty() {
                tracing::warn!("aucune CIDR extraite de {url}");
            } else {
                write_out(dest, out.join("\n").as_bytes(), url).await;
            }
        }
        Err(e) => tracing::error!("téléchargement {url} : {e:#}"),
    }
}

/// Concatène plusieurs listes texte de CIDR (ex. Cloudflare v4 + v6).
async fn fetch_text_multi(client: &Client, urls: &[&str], dest: &Path) {
    let mut out = String::new();
    for url in urls {
        match download_text(client, url).await {
            Ok(body) => {
                for line in body.lines() {
                    let l = line.trim();
                    if !l.is_empty() {
                        out.push_str(l);
                        out.push('\n');
                    }
                }
            }
            Err(e) => tracing::error!("téléchargement {url} : {e:#}"),
        }
    }
    if !out.is_empty() {
        write_out(dest, out.as_bytes(), "cloud-text").await;
    }
}

/// Ramasse récursivement toute chaîne ressemblant à un CIDR dans un JSON.
fn collect_cidrs(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) if is_cidr(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|x| collect_cidrs(x, out)),
        serde_json::Value::Object(o) => o.values().for_each(|x| collect_cidrs(x, out)),
        _ => {}
    }
}

/// `a.b.c.d/n` ou `ipv6/n` valide.
fn is_cidr(s: &str) -> bool {
    let Some((ip, mask)) = s.split_once('/') else {
        return false;
    };
    mask.parse::<u8>().is_ok()
        && (ip.parse::<std::net::Ipv4Addr>().is_ok() || ip.parse::<std::net::Ipv6Addr>().is_ok())
}

/// Tableau JSON de serveurs → fichier plat d'IP, en extrayant `fields` (champs
/// string) de chaque élément (ex. NordVPN `station`, Mullvad `ipv4_addr_in`).
async fn fetch_json_ips(client: &Client, url: &str, dest: &Path, fields: &[&str]) {
    match download_text(client, url).await {
        Ok(body) => {
            let mut out = String::new();
            if let Ok(serde_json::Value::Array(items)) =
                serde_json::from_str::<serde_json::Value>(&body)
            {
                for it in &items {
                    for f in fields {
                        if let Some(ip) = it.get(*f).and_then(|x| x.as_str()) {
                            let ip = ip.trim();
                            if !ip.is_empty() {
                                out.push_str(ip);
                                out.push('\n');
                            }
                        }
                    }
                }
            }
            if !out.is_empty() {
                write_out(dest, out.as_bytes(), url).await;
            }
        }
        Err(e) => tracing::error!("téléchargement {url} : {e:#}"),
    }
}

/// CSV dont la 1ʳᵉ colonne est un CIDR/IP (ex. iCloud Private Relay) → fichier
/// plat de CIDR (le reste des colonnes géo est ignoré).
/// tg12/PoC_CVEs : table markdown (`| CVE-… |` puis `| https://github.com/… |`).
/// On aplatit en `CVE\turl\turl…` par ligne (une CVE + ses dépôts PoC).
async fn fetch_poc_cves(client: &Client, url: &str, dest: &Path) {
    fn flush(out: &mut String, cve: &Option<String>, urls: &[&str]) {
        if let Some(c) = cve
            && !urls.is_empty()
        {
            out.push_str(c);
            for u in urls {
                out.push('\t');
                out.push_str(u);
            }
            out.push('\n');
        }
    }
    match download_text(client, url).await {
        Ok(body) => {
            let mut out = String::new();
            let mut current: Option<String> = None;
            let mut urls: Vec<&str> = Vec::new();
            for line in body.lines() {
                let cell = line
                    .trim()
                    .trim_start_matches('|')
                    .trim_end_matches('|')
                    .trim();
                if cell.starts_with("CVE-") && cell.len() >= 8 {
                    flush(&mut out, &current, &urls);
                    current = Some(cell.to_string());
                    urls.clear();
                } else if cell.starts_with("http") {
                    urls.push(cell);
                }
            }
            flush(&mut out, &current, &urls);
            if !out.is_empty() {
                write_out(dest, out.as_bytes(), url).await;
            }
        }
        Err(e) => tracing::error!("téléchargement {url} : {e:#}"),
    }
}

/// Majestic Million : CSV trié par rang. On garde l'apex (colonne `Domain`,
/// index 2) des `top_n` premières lignes → prior de popularité/légitimité.
/// Un domaine très populaire signalé par des feeds = quasi toujours du contenu
/// hébergé, pas le domaine lui-même (le verdict le neutralise).
async fn fetch_majestic(client: &Client, url: &str, dest: &Path, top_n: usize) {
    match download_text(client, url).await {
        Ok(body) => {
            let mut out = String::new();
            // 1ʳᵉ ligne = en-tête ; fichier déjà trié par `GlobalRank` croissant.
            for line in body.lines().skip(1).take(top_n) {
                if let Some(domain) = line.split(',').nth(2) {
                    let d = domain.trim().to_ascii_lowercase();
                    if !d.is_empty() {
                        out.push_str(&d);
                        out.push('\n');
                    }
                }
            }
            if !out.is_empty() {
                write_out(dest, out.as_bytes(), url).await;
            }
        }
        Err(e) => tracing::error!("téléchargement {url} : {e:#}"),
    }
}

async fn fetch_csv_cidrs(client: &Client, url: &str, dest: &Path) {
    match download_text(client, url).await {
        Ok(body) => {
            let mut out = String::new();
            for line in body.lines() {
                if let Some(cidr) = line.split(',').next() {
                    let cidr = cidr.trim();
                    if !cidr.is_empty() {
                        out.push_str(cidr);
                        out.push('\n');
                    }
                }
            }
            write_out(dest, out.as_bytes(), url).await;
        }
        Err(e) => tracing::error!("téléchargement {url} : {e:#}"),
    }
}

/// Spamhaus DROP : chaque ligne est un objet JSON `{"cidr":…,"sblid":…}` (les
/// lignes de métadonnées n'ont pas de champ `cidr` et sont ignorées). On
/// concatène les CIDR des URLs fournies dans un fichier plat.
async fn fetch_spamhaus(client: &Client, urls: &[&str], dest: &Path) {
    let mut cidrs = String::new();
    for url in urls {
        match download_text(client, url).await {
            Ok(body) => {
                for line in body.lines() {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line)
                        && let Some(cidr) = v.get("cidr").and_then(|c| c.as_str())
                    {
                        cidrs.push_str(cidr);
                        cidrs.push('\n');
                    }
                }
            }
            Err(e) => tracing::error!("téléchargement {url} : {e:#}"),
        }
    }
    if !cidrs.is_empty() {
        write_out(dest, cidrs.as_bytes(), "spamhaus-drop").await;
    }
}

/// Spamhaus ASN-DROP : JSON-lines `{"asn":N,...}` (lignes de métadonnées sans
/// `asn` ignorées) → un numéro d'ASN par ligne.
async fn fetch_asndrop(client: &Client, url: &str, dest: &Path) {
    match download_text(client, url).await {
        Ok(body) => {
            let mut out = String::new();
            for line in body.lines() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line)
                    && let Some(asn) = v.get("asn").and_then(|a| a.as_u64())
                {
                    out.push_str(&asn.to_string());
                    out.push('\n');
                }
            }
            if !out.is_empty() {
                write_out(dest, out.as_bytes(), url).await;
            }
        }
        Err(e) => tracing::error!("téléchargement {url} : {e:#}"),
    }
}

/// Télécharge une base GeoLite2 (tar.gz signé par la licence) et en extrait le
/// `.mmdb`. Clé lue dans l'env `MAXMIND_LICENSE_KEY` (skip si absente/vide).
async fn fetch_maxmind(client: &Client, edition: &str, dest: &Path) {
    let key = match std::env::var("MAXMIND_LICENSE_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => return,
    };
    let url = format!(
        "https://download.maxmind.com/app/geoip_download?edition_id={edition}&license_key={key}&suffix=tar.gz"
    );
    let bytes = match client
        .get(&url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
    {
        Ok(r) => match r.bytes().await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("maxmind {edition} : {e}");
                return;
            }
        },
        Err(e) => {
            tracing::error!("maxmind {edition} : {e}");
            return;
        }
    };
    // Extraction tar SYNCHRONE (l'itérateur tar n'est pas Send → jamais tenu à
    // travers un await) : on récupère les octets du `.mmdb` dans un bloc borné.
    let mmdb: Option<Vec<u8>> = {
        let mut archive = tar::Archive::new(GzDecoder::new(&bytes[..]));
        match archive.entries() {
            Ok(entries) => {
                let mut found = None;
                for mut entry in entries.flatten() {
                    let is_mmdb = entry
                        .path()
                        .map(|p| p.extension().and_then(|e| e.to_str()) == Some("mmdb"))
                        .unwrap_or(false);
                    if is_mmdb {
                        let mut buf = Vec::new();
                        if entry.read_to_end(&mut buf).is_ok() {
                            found = Some(buf);
                        }
                        break;
                    }
                }
                found
            }
            Err(e) => {
                tracing::error!("maxmind {edition} : archive illisible ({e})");
                None
            }
        }
    };
    // Écriture APRÈS avoir relâché l'itérateur tar (await OK ici).
    match mmdb {
        // Label sans l'URL (elle contient la clé de licence).
        Some(buf) => write_out(dest, &buf, &format!("maxmind:{edition}")).await,
        None => tracing::warn!("maxmind {edition} : aucun .mmdb dans l'archive"),
    }
}

async fn fetch_text(client: &Client, url: &str, dest: &Path) {
    match download_text(client, url).await {
        Ok(body) => write_out(dest, body.as_bytes(), url).await,
        Err(e) => tracing::error!("téléchargement {url} : {e:#}"),
    }
}

async fn fetch_gzip(client: &Client, url: &str, dest: &Path) {
    match download_gzip(client, url).await {
        Ok(text) => write_out(dest, text.as_bytes(), url).await,
        Err(e) => tracing::error!("téléchargement {url} : {e:#}"),
    }
}

async fn write_out(dest: &Path, bytes: &[u8], url: &str) {
    match tokio::fs::write(dest, bytes).await {
        Ok(()) => tracing::info!(
            "maj {} ({} octets) depuis {url}",
            dest.display(),
            bytes.len()
        ),
        Err(e) => tracing::error!("écriture {} : {e}", dest.display()),
    }
}

async fn download_text(client: &Client, url: &str) -> Result<String> {
    let resp = client.get(url).send().await?.error_for_status()?;
    Ok(resp.text().await?)
}

async fn download_gzip(client: &Client, url: &str) -> Result<String> {
    let resp = client.get(url).send().await?.error_for_status()?;
    let bytes = resp.bytes().await?;
    let mut decoder = GzDecoder::new(&bytes[..]);
    let mut out = String::new();
    decoder
        .read_to_string(&mut out)
        .context("décompression gzip")?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_cidr_detects() {
        assert!(is_cidr("52.95.110.0/24"));
        assert!(is_cidr("2600:1f00::/24"));
        assert!(!is_cidr("example.com"));
        assert!(!is_cidr("52.95.110.0"));
        assert!(!is_cidr("not/a/cidr"));
    }

    #[test]
    fn collect_cidrs_walks_nested_json() {
        let v = serde_json::json!({
            "syncToken": "123",
            "prefixes": [{"ip_prefix": "52.95.110.0/24", "region": "us-east-1"}],
            "ipv6_prefixes": [{"ipv6_prefix": "2600:1f00::/24"}],
            "regions": [{"cidrs": [{"cidr": "1.2.3.0/24"}]}]
        });
        let mut out = Vec::new();
        collect_cidrs(&v, &mut out);
        assert!(out.contains(&"52.95.110.0/24".to_string()));
        assert!(out.contains(&"2600:1f00::/24".to_string()));
        assert!(out.contains(&"1.2.3.0/24".to_string()));
        assert_eq!(out.len(), 3); // "123", "us-east-1" ignorés
    }
}
