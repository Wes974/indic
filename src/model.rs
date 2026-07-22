//! Types du rapport d'enrichissement — le contrat de sortie de l'API.

use serde::{Deserialize, Serialize};

/// Type d'infrastructure derrière l'IP (dérivé du type d'ASN via ASdb).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InfraType {
    /// Hébergeur / cloud → typique des VPN et proxies commerciaux.
    Datacenter,
    /// Réseau « eyeball » résidentiel ou business (FAI).
    Isp,
    /// Opérateur mobile.
    Mobile,
    Education,
    #[allow(dead_code)]
    Government,
    /// Non classé.
    Unknown,
}

/// Nature de l'anonymisation détectée.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnonType {
    Tor,
    Vpn,
    Proxy,
    /// Apple Private Relay / Cloudflare WARP (branché prochainement).
    #[allow(dead_code)]
    Relay,
    /// Hébergeur sans match d'anonymiseur explicite.
    Datacenter,
    /// IP résidentielle sans signal d'anonymisation.
    Residential,
    Unknown,
}

/// Un signal = une source qui a matché. Transparence totale, pas de boîte noire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    /// Identifiant de la source (`tor_exit_list`, `x4bnet_vpn`, ...).
    pub source: String,
    /// Catégorie du signal (`tor`, `vpn`, `datacenter`, `proxy`, ...).
    pub category: String,
    /// Détail optionnel (nom du provider, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Signal {
    pub fn new(source: &str, category: &str) -> Self {
        Self {
            source: source.into(),
            category: category.into(),
            detail: None,
        }
    }
    pub fn with_detail(source: &str, category: &str, detail: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            category: category.into(),
            detail: Some(detail.into()),
        }
    }
}

/// Rapport complet pour une IP — l'équivalent de la fiche spur.us.
#[derive(Debug, Clone, Serialize)]
pub struct IpReport {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    pub infra_type: InfraType,
    /// Vrai si Tor / VPN / proxy détecté.
    pub anonymous: bool,
    pub anon_type: AnonType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Confiance 0.0–1.0 dérivée du nombre et de la qualité des signaux.
    pub confidence: f32,
    pub signals: Vec<Signal>,
}
