//! Le `Store` : datasets chargés en mémoire + logique de classification.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use anyhow::Result;

use crate::asn::{AsnDb, AsnType};
use crate::model::{AnonType, InfraType, IpReport, Signal};
use crate::ranges::{RangeSet, ip_to_u128};

// Noms de fichiers attendus dans le data_dir (produits par l'updater).
const F_IPTOASN: &str = "ip2asn-v4.tsv";
const F_IPTOASN6: &str = "ip2asn-v6.tsv";
const F_PEERINGDB: &str = "peeringdb.json";
const F_TOR: &str = "tor-exits.txt";
const F_VPN: &str = "vpn.txt";
const F_DATACENTER: &str = "datacenter.txt";
const F_PROXIES: &str = "proxies.txt";
const F_RELAY: &str = "private_relay.txt";

#[derive(Default)]
pub struct Store {
    asn: AsnDb,
    net_type: AsnType,
    tor: RangeSet,
    vpn: RangeSet,
    datacenter: RangeSet,
    proxies: RangeSet,
    /// iCloud Private Relay : plages de sortie officielles Apple.
    relay: RangeSet,
    /// Blocklists domaine (hagezi, Phishing Army, red.flag.domains) : nom → domaines.
    blocklists: HashMap<String, HashSet<String>>,
    /// Feeds de menace IP (Spamhaus DROP, Feodo, IPsum) : nom → ranges.
    /// Rapportés en signaux d'attribution ; n'affectent pas le verdict d'anonymat.
    ip_threat: HashMap<String, RangeSet>,
    /// VPN par provider (NordVPN, Mullvad) : nom → ranges. Attribution nominale.
    vpn_providers: HashMap<String, RangeSet>,
    /// Plages cloud par provider (AWS, GCP, Cloudflare…) : nom → ranges. Tag datacenter.
    cloud_providers: HashMap<String, RangeSet>,
    /// ASN entièrement malveillants (Spamhaus ASN-DROP) : réputation ASN.
    asn_drop: HashSet<u32>,
    /// Adresses crypto sanctionnées (OFAC SDN) : ETH minuscule, BTC tel quel.
    ofac_crypto: HashSet<String>,
    /// Apex des domaines les plus populaires (Majestic top-N) : prior de
    /// légitimité pour le verdict (neutralise les signaux dus au contenu hébergé).
    popular_domains: HashSet<String>,
    /// CVE → dépôts PoC GitHub (tg12/PoC_CVEs) : signal d'exploitabilité offline.
    poc_cves: HashMap<String, Vec<String>>,
    /// Base GeoLite2-City (MaxMind) pour la géo offline précise, si disponible.
    geoip: Option<maxminddb::Reader<Vec<u8>>>,
}

/// Géolocalisation précise issue de GeoLite2-City.
pub struct GeoCity {
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
}

impl Store {
    /// Charge tous les datasets présents dans `data_dir`. Un fichier absent
    /// laisse simplement la source vide (dégradation gracieuse).
    pub fn load_from_dir(data_dir: &Path) -> Store {
        let p4 = data_dir.join(F_IPTOASN);
        let p6 = data_dir.join(F_IPTOASN6);
        let asn = load_or_default("iptoasn", || {
            AsnDb::load_tsvs(&[p4.as_path(), p6.as_path()])
        });
        let net_type = load_or_default("peeringdb", || {
            AsnType::load_peeringdb(&data_dir.join(F_PEERINGDB))
        });
        let tor = load_ranges(&data_dir.join(F_TOR));
        let vpn = load_ranges(&data_dir.join(F_VPN));
        let datacenter = load_ranges(&data_dir.join(F_DATACENTER));
        let proxies = load_ranges(&data_dir.join(F_PROXIES));
        let relay = load_ranges(&data_dir.join(F_RELAY));
        let blocklists = load_blocklists(&data_dir.join("blocklists"));
        let ip_threat = load_range_dir(&data_dir.join("ipthreat"));
        let vpn_providers = load_range_dir(&data_dir.join("vpnprov"));
        let cloud_providers = load_range_dir(&data_dir.join("cloud"));
        let asn_drop = load_asn_set(&data_dir.join("asndrop.txt"));
        let ofac_crypto = load_crypto_set(&data_dir.join("ofac_crypto.txt"));
        let popular_domains = load_domain_set(&data_dir.join("popular.txt"));
        let poc_cves = load_poc_cves(&data_dir.join("poc_cves.txt"));
        let geoip = maxminddb::Reader::open_readfile(data_dir.join("GeoLite2-City.mmdb")).ok();

        tracing::info!(
            asn = asn.len(),
            peeringdb = net_type.len(),
            tor = tor.len(),
            vpn = vpn.len(),
            datacenter = datacenter.len(),
            proxies = proxies.len(),
            relay = relay.len(),
            blocklists = blocklists.len(),
            ip_threat = ip_threat.len(),
            vpn_providers = vpn_providers.len(),
            cloud_providers = cloud_providers.len(),
            asn_drop = asn_drop.len(),
            ofac_crypto = ofac_crypto.len(),
            popular_domains = popular_domains.len(),
            poc_cves = poc_cves.len(),
            geoip = geoip.is_some(),
            "datasets chargés"
        );

        Store {
            asn,
            net_type,
            tor,
            vpn,
            datacenter,
            proxies,
            relay,
            blocklists,
            ip_threat,
            vpn_providers,
            cloud_providers,
            asn_drop,
            ofac_crypto,
            popular_domains,
            poc_cves,
            geoip,
        }
    }

    /// Blocklists contenant `domain` (ou un de ses parents enregistrables).
    pub fn blocklist_hits(&self, domain: &str) -> Vec<String> {
        if self.blocklists.is_empty() {
            return Vec::new();
        }
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        // Le domaine + ses suffixes parents (≥ 2 labels).
        let mut candidates = vec![d.clone()];
        let mut rest = d.as_str();
        while let Some(pos) = rest.find('.') {
            let parent = &rest[pos + 1..];
            if parent.contains('.') {
                candidates.push(parent.to_string());
            }
            rest = parent;
        }
        let mut hits: Vec<String> = self
            .blocklists
            .iter()
            .filter(|(_, set)| candidates.iter().any(|c| set.contains(c)))
            .map(|(name, _)| name.clone())
            .collect();
        hits.sort();
        hits
    }

    /// Vrai si l'adresse crypto est sanctionnée (OFAC SDN). L'adresse ETH doit
    /// être en minuscules (comme fournie par `Observable::detect`).
    pub fn is_sanctioned_crypto(&self, addr: &str) -> bool {
        self.ofac_crypto.contains(addr)
    }

    /// L'apex fait-il partie des domaines majeurs (Majestic top-N) ? Prior de
    /// légitimité — élargit la liste curée de `verdict.rs` au top mondial réel.
    pub fn is_popular_domain(&self, apex: &str) -> bool {
        self.popular_domains.contains(apex)
    }

    /// Dépôts PoC GitHub connus pour une CVE (tg12/PoC_CVEs). Vide si aucun.
    pub fn poc_repos(&self, cve: &str) -> Vec<String> {
        self.poc_cves.get(cve).cloned().unwrap_or_default()
    }

    /// Géolocalisation précise (ville/région/coord.) via GeoLite2, si disponible.
    pub fn geoip_city(&self, ip: IpAddr) -> Option<GeoCity> {
        let result = self.geoip.as_ref()?.lookup(ip).ok()?;
        let c: maxminddb::geoip2::City = result.decode().ok()??;
        Some(GeoCity {
            city: c.city.names.english.map(|s| s.to_string()),
            region: c
                .subdivisions
                .first()
                .and_then(|d| d.names.english.map(|s| s.to_string())),
            country: c.country.iso_code.map(str::to_string),
            lat: c.location.latitude,
            lon: c.location.longitude,
        })
    }

    /// Enrichit une IPv4. Erreur si l'entrée n'est pas une IPv4 valide.
    pub fn lookup(&self, ip_str: &str) -> Result<IpReport> {
        let ip = IpAddr::from_str(ip_str.trim())
            .map_err(|_| anyhow::anyhow!("IP invalide : {ip_str}"))?;
        let v = ip_to_u128(ip);

        // --- ASN / géo ---
        let (asn, as_name, country) = match self.asn.lookup(v) {
            Some(e) => (
                Some(e.asn),
                (!e.name.is_empty()).then(|| e.name.clone()),
                (!e.country.is_empty()).then(|| e.country.clone()),
            ),
            None => (None, None, None),
        };
        let pdb_infra = asn.and_then(|a| self.net_type.lookup(a));

        // --- Signaux d'anonymisation ---
        let mut signals: Vec<Signal> = Vec::new();
        let is_tor = self.tor.contains(v);
        let is_relay = self.relay.contains(v);
        let is_vpn_list = self.vpn.contains(v);
        // Attribution VPN nominale (NordVPN, Mullvad…) : premier provider contenant l'IP.
        let vpn_provider = self
            .vpn_providers
            .iter()
            .find(|(_, rs)| rs.contains(v))
            .map(|(name, _)| name.clone());
        let is_vpn = is_vpn_list || vpn_provider.is_some();
        let is_proxy = self.proxies.contains(v);
        let is_dc_list = self.datacenter.contains(v);
        // Attribution cloud nominale (AWS, GCP, Cloudflare…) : premier provider contenant l'IP.
        let cloud_provider = self
            .cloud_providers
            .iter()
            .find(|(_, rs)| rs.contains(v))
            .map(|(name, _)| name.clone());
        let is_dc = is_dc_list || cloud_provider.is_some();

        if is_tor {
            signals.push(Signal::new("tor_exit_list", "tor"));
        }
        if is_relay {
            signals.push(Signal::with_detail(
                "icloud_private_relay",
                "relay",
                "iCloud Private Relay (sortie Apple)",
            ));
        }
        if is_vpn_list {
            signals.push(Signal::new("x4bnet_vpn", "vpn"));
        }
        if let Some(p) = &vpn_provider {
            signals.push(Signal::with_detail(&p.to_lowercase(), "vpn", p.clone()));
        }
        if is_proxy {
            signals.push(Signal::new("firehol_proxies", "proxy"));
        }
        if is_dc_list {
            signals.push(Signal::new("x4bnet_datacenter", "datacenter"));
        }
        if let Some(c) = &cloud_provider {
            signals.push(Signal::with_detail(
                &format!("cloud:{}", c.to_lowercase()),
                "datacenter",
                format!("{c} (plage cloud)"),
            ));
        }

        // Type d'infra : la liste datacenter (explicite) fait autorité, sinon
        // PeeringDB, sinon un ASN routé absent des datacenters = eyeball.
        let infra_type = if is_dc {
            InfraType::Datacenter
        } else if let Some(t) = pdb_infra {
            t
        } else if asn.is_some() {
            InfraType::Isp
        } else {
            InfraType::Unknown
        };
        // Transparence de la source du type d'infra.
        if !is_dc {
            match pdb_infra {
                Some(t) => signals.push(Signal::with_detail(
                    "peeringdb",
                    "infra",
                    infra_type_label(t),
                )),
                None if asn.is_some() => signals.push(Signal::with_detail(
                    "heuristic",
                    "infra",
                    "eyeball (hors liste datacenter)",
                )),
                None => {}
            }
        }

        // --- Feeds de menace IP (attribution ; n'affecte pas le verdict d'anonymat) ---
        let mut threat_hits: Vec<&String> = self
            .ip_threat
            .iter()
            .filter(|(_, rs)| rs.contains(v))
            .map(|(name, _)| name)
            .collect();
        threat_hits.sort();
        for name in threat_hits {
            signals.push(ip_threat_signal(name));
        }
        // Réputation ASN : ASN entièrement malveillant (Spamhaus ASN-DROP).
        if let Some(a) = asn
            && self.asn_drop.contains(&a)
        {
            signals.push(Signal::with_detail(
                "spamhaus_asndrop",
                "malicious",
                "ASN entièrement malveillant — Spamhaus ASN-DROP",
            ));
        }

        // --- Bogon (adresses réservées / non routables) ---
        if is_bogon(ip) {
            signals.push(Signal::with_detail(
                "bogon",
                "info",
                "adresse réservée / non routable (RFC 1918/5735/6598/6890)",
            ));
        }

        // --- Verdict ---
        let anonymous = is_tor || is_relay || is_vpn || is_proxy;
        let anon_type = if is_tor {
            AnonType::Tor
        } else if is_relay {
            AnonType::Relay
        } else if is_vpn {
            AnonType::Vpn
        } else if is_proxy {
            AnonType::Proxy
        } else if infra_type == InfraType::Datacenter {
            AnonType::Datacenter
        } else if infra_type == InfraType::Isp || infra_type == InfraType::Mobile {
            AnonType::Residential
        } else {
            AnonType::Unknown
        };

        let confidence = confidence_for(is_tor, is_relay, is_vpn, is_proxy, infra_type);
        // Attribution du provider (Apple Relay prioritaire, sinon VPN nominal).
        let provider = if is_relay {
            Some("iCloud Private Relay".to_string())
        } else {
            vpn_provider.clone().or_else(|| cloud_provider.clone())
        };

        Ok(IpReport {
            ip: ip.to_string(),
            asn,
            as_name,
            country,
            infra_type,
            anonymous,
            anon_type,
            provider,
            confidence,
            signals,
        })
    }
}

fn confidence_for(
    is_tor: bool,
    is_relay: bool,
    is_vpn: bool,
    is_proxy: bool,
    infra: InfraType,
) -> f32 {
    if is_tor {
        0.99 // liste Tor faisant autorité
    } else if is_relay {
        0.95 // liste de sortie Apple faisant autorité
    } else if is_vpn || is_proxy {
        0.9
    } else if infra == InfraType::Datacenter {
        0.6 // hébergeur : anonymisable mais pas de match direct
    } else if infra == InfraType::Isp || infra == InfraType::Mobile {
        0.8 // résidentiel : confiance dans « non anonyme »
    } else {
        0.3
    }
}

fn infra_type_label(t: InfraType) -> &'static str {
    match t {
        InfraType::Datacenter => "datacenter",
        InfraType::Isp => "isp",
        InfraType::Mobile => "mobile",
        InfraType::Education => "education",
        InfraType::Government => "government",
        InfraType::Unknown => "unknown",
    }
}

fn load_or_default<T: Default>(name: &str, f: impl FnOnce() -> Result<T>) -> T {
    match f() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("{name} indisponible ({e:#}) — source vide");
            T::default()
        }
    }
}

fn load_ranges(path: &Path) -> RangeSet {
    let mut rs = RangeSet::new();
    match std::fs::read_to_string(path) {
        Ok(text) => {
            for line in text.lines() {
                rs.push_line(line);
            }
        }
        Err(e) => tracing::warn!("{} indisponible ({e}) — source vide", path.display()),
    }
    rs.build();
    rs
}

/// Charge un fichier d'ASN (un entier par ligne) en `HashSet<u32>`.
fn load_asn_set(path: &Path) -> HashSet<u32> {
    match std::fs::read_to_string(path) {
        Ok(text) => text.lines().filter_map(|l| l.trim().parse().ok()).collect(),
        Err(_) => HashSet::new(),
    }
}

/// Charge les adresses crypto sanctionnées. Les ETH (`0x…`) sont normalisées en
/// minuscules (hex insensible à la casse) ; les BTC restent telles quelles.
fn load_crypto_set(path: &Path) -> HashSet<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| {
                if l.starts_with("0x") || l.starts_with("0X") {
                    l.to_ascii_lowercase()
                } else {
                    l.to_string()
                }
            })
            .collect(),
        Err(_) => HashSet::new(),
    }
}

/// Charge l'index PoC (`CVE\turl\turl…` par ligne) en `CVE → dépôts`.
fn load_poc_cves(path: &Path) -> HashMap<String, Vec<String>> {
    let mut out = HashMap::new();
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines() {
            let mut it = line.split('\t');
            if let Some(cve) = it.next() {
                let urls: Vec<String> = it.map(str::to_string).collect();
                if !cve.is_empty() && !urls.is_empty() {
                    out.insert(cve.to_string(), urls);
                }
            }
        }
    }
    out
}

/// Charge un fichier de domaines (un apex par ligne) en `HashSet`, minuscule,
/// sans lignes vides ni commentaires. Sert au prior de popularité (Majestic).
fn load_domain_set(path: &Path) -> HashSet<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_ascii_lowercase())
            .collect(),
        Err(_) => HashSet::new(),
    }
}

/// Signal d'attribution pour un feed de menace IP (le « pourquoi »).
fn ip_threat_signal(name: &str) -> Signal {
    let (category, detail) = match name {
        "spamhaus_drop" => ("malicious", "netblock criminel — Spamhaus DROP"),
        "feodo" => ("c2", "C2 de botnet — Feodo Tracker"),
        "ipsum" => ("abuse", "IP abusive — présente dans ≥ 3 blacklists (IPsum)"),
        _ => ("threat", "listée dans un feed de menace"),
    };
    Signal::with_detail(name, category, detail)
}

/// Charge chaque `<nom>.txt` d'un dossier en `RangeSet` nommé (feeds de menace IP).
fn load_range_dir(dir: &Path) -> HashMap<String, RangeSet> {
    let mut out = HashMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("txt") {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let rs = load_ranges(&path);
        if !rs.is_empty() {
            out.insert(name.to_string(), rs);
        }
    }
    out
}

/// Charge chaque `<liste>.txt` du dossier blocklists en ensemble de domaines.
fn load_blocklists(dir: &Path) -> HashMap<String, HashSet<String>> {
    let mut out = HashMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("txt") {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Ok(text) = std::fs::read_to_string(&path) {
            let set: HashSet<String> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| l.to_ascii_lowercase())
                .collect();
            if !set.is_empty() {
                out.insert(name.to_string(), set);
            }
        }
    }
    out
}

/// Vérifie si une IP est un bogon (adresse réservée / non routable sur
/// l'Internet public). Basé sur les RFC 1918, 5735, 6598, 6890 et IPv6.
pub fn is_bogon(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let rfc1918: [ipnet::Ipv4Net; 3] = [
                "10.0.0.0/8".parse().unwrap(),
                "172.16.0.0/12".parse().unwrap(),
                "192.168.0.0/16".parse().unwrap(),
            ];
            let special: [ipnet::Ipv4Net; 6] = [
                "0.0.0.0/8".parse().unwrap(),
                "100.64.0.0/10".parse().unwrap(),
                "127.0.0.0/8".parse().unwrap(),
                "169.254.0.0/16".parse().unwrap(),
                "192.0.0.0/24".parse().unwrap(),
                "198.18.0.0/15".parse().unwrap(),
            ];
            let multicast: ipnet::Ipv4Net = "224.0.0.0/4".parse().unwrap();
            let reserved: ipnet::Ipv4Net = "240.0.0.0/4".parse().unwrap();
            rfc1918.iter().any(|n| n.contains(&v4))
                || special.iter().any(|n| n.contains(&v4))
                || multicast.contains(&v4)
                || reserved.contains(&v4)
        }
        IpAddr::V6(v6) => {
            let bogon6: [ipnet::Ipv6Net; 5] = [
                "::1/128".parse().unwrap(),
                "fe80::/10".parse().unwrap(),
                "fc00::/7".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
                "ff00::/8".parse().unwrap(),
            ];
            bogon6.iter().any(|n| n.contains(&v6))
        }
    }
}
