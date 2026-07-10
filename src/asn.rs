//! Résolution ASN offline (dumps iptoasn v4+v6) et classification de type d'ASN
//! (PeeringDB `info_type` → `InfraType`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::model::InfraType;
use crate::ranges::ip_to_u128;

/// Une entrée du dump iptoasn : intervalle IP (u128) → ASN + pays + nom.
pub struct AsnEntry {
    pub start: u128,
    pub end: u128,
    pub asn: u32,
    pub country: String,
    pub name: String,
}

/// Base ASN triée par `start`, lookup par binary search. Contient v4 (mappé
/// `::ffff:x`) et v6 dans le même espace `u128`.
#[derive(Default)]
pub struct AsnDb {
    entries: Vec<AsnEntry>,
}

impl AsnDb {
    /// Charge un ou plusieurs TSV iptoasn (`start\tend\tASN\tcountry\tdescription`),
    /// v4 comme v6. Les fichiers absents sont ignorés.
    pub fn load_tsvs(paths: &[&Path]) -> Result<Self> {
        let mut entries = Vec::new();
        for path in paths {
            let text = match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(_) => continue, // fichier absent → on saute
            };
            for line in text.lines() {
                let mut cols = line.split('\t');
                let (Some(start), Some(end), Some(asn)) = (cols.next(), cols.next(), cols.next())
                else {
                    continue;
                };
                let country = cols.next().unwrap_or("").to_string();
                let name = cols.next().unwrap_or("").to_string();
                let (Ok(start), Ok(end), Ok(asn)) = (
                    IpAddr::from_str(start),
                    IpAddr::from_str(end),
                    asn.parse::<u32>(),
                ) else {
                    continue;
                };
                if asn == 0 {
                    continue; // non routé chez iptoasn
                }
                entries.push(AsnEntry {
                    start: ip_to_u128(start),
                    end: ip_to_u128(end),
                    asn,
                    country,
                    name,
                });
            }
        }
        if entries.is_empty() {
            anyhow::bail!("aucun dump iptoasn trouvé");
        }
        entries.sort_unstable_by_key(|e| e.start);
        Ok(Self { entries })
    }

    pub fn lookup(&self, ip: u128) -> Option<&AsnEntry> {
        match self.entries.binary_search_by(|e| e.start.cmp(&ip)) {
            Ok(idx) => Some(&self.entries[idx]),
            Err(0) => None,
            Err(idx) => {
                let e = &self.entries[idx - 1];
                (ip <= e.end).then_some(e)
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

// --- Classification de type d'ASN via PeeringDB ---

#[derive(Deserialize)]
struct PdbNet {
    asn: u32,
    #[serde(default)]
    info_type: String,
    #[serde(default)]
    info_types: Vec<String>,
}

#[derive(Deserialize)]
struct PdbResponse {
    data: Vec<PdbNet>,
}

/// Mappe ASN → `InfraType` à partir du dump PeeringDB `/api/net`.
#[derive(Default)]
pub struct AsnType {
    by_asn: HashMap<u32, InfraType>,
}

impl AsnType {
    /// Charge le JSON PeeringDB (`{"data":[{"asn":N,"info_type":"…"}]}`).
    pub fn load_peeringdb(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("lecture PeeringDB {}", path.display()))?;
        let resp: PdbResponse = serde_json::from_str(&text).context("parsing JSON PeeringDB")?;
        let mut by_asn = HashMap::with_capacity(resp.data.len());
        for net in resp.data {
            let raw = if net.info_type.is_empty() {
                net.info_types.first().map(String::as_str).unwrap_or("")
            } else {
                net.info_type.as_str()
            };
            let infra = classify_pdb(raw);
            if infra != InfraType::Unknown {
                by_asn.insert(net.asn, infra);
            }
        }
        Ok(Self { by_asn })
    }

    pub fn lookup(&self, asn: u32) -> Option<InfraType> {
        self.by_asn.get(&asn).copied()
    }

    pub fn len(&self) -> usize {
        self.by_asn.len()
    }
}

/// Traduit un `info_type` PeeringDB en `InfraType`.
///
/// PeeringDB n'a pas de catégorie hosting dédiée : le hosting/CDN/cloud tombe
/// dans `Content`/`Enterprise` (Google, OVH, DigitalOcean, Amazon…), qu'on
/// traite comme datacenter. `Cable/DSL/ISP` et `NSP` = réseaux « eyeball ».
fn classify_pdb(info_type: &str) -> InfraType {
    match info_type {
        "Cable/DSL/ISP" | "NSP" => InfraType::Isp,
        "Content" | "Enterprise" | "Network Services" => InfraType::Datacenter,
        "Educational/Research" => InfraType::Education,
        _ => InfraType::Unknown,
    }
}
