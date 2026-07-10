//! Service caché Tor (`.onion`) : version + contexte. Pas de résolution clearnet
//! (nécessite Tor) → purement descriptif/offline.

use crate::enrich::{Ctx, Enrichment, Fact};

pub async fn enrich_onion(addr: &str, _ctx: &Ctx) -> Enrichment {
    let label_len = addr.strip_suffix(".onion").map_or(0, str::len);
    let version = if label_len == 56 {
        "v3 (ed25519)"
    } else {
        "v2 (retiré de Tor en 2021)"
    };
    let facts = vec![
        Fact::new("réseau", "Tor — service caché (hidden service)"),
        Fact::new("version", version),
        Fact::new("accès", "non résolvable en clearnet (nécessite Tor)"),
    ];
    Enrichment {
        source: "onion".into(),
        facts,
        signals: vec![],
        pivots: vec![],
        error: None,
    }
}
