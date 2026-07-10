//! Enricher blocklists domaine — dans quelles listes le domaine figure et ce que
//! chaque liste signifie (le « pourquoi »). Local (lit le Store), sans clé.
//! Agrège hagezi (tif/ultimate/doh/dyndns/fake), Phishing Army et red.flag.domains.

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    let hits = ctx.store.load().blocklist_hits(domain);
    if hits.is_empty() {
        return Enrichment::ok(
            "blocklists",
            vec![Fact::new("blocklists", "absent des blocklists")],
        );
    }

    let facts: Vec<Fact> = hits
        .iter()
        .map(|name| Fact::new(name, describe(name)))
        .collect();
    let has = |n: &str| hits.iter().any(|h| h == n);
    let mut signals = Vec::new();
    if has("tif") || has("fake") || has("phishing_army") {
        signals.push(Signal::with_detail(
            "blocklists",
            "malicious",
            "phishing / malware / scam",
        ));
    }
    if has("dyndns") || has("redflag") {
        signals.push(Signal::with_detail(
            "blocklists",
            "suspicious",
            "DNS dynamique / domaine FR récemment déposé",
        ));
    }
    if has("ultimate") {
        signals.push(Signal::with_detail(
            "blocklists",
            "tracking",
            "ads / tracking / télémétrie",
        ));
    }
    Enrichment {
        source: "blocklists".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

/// Sens de chaque liste (le « pourquoi c'est présent »).
fn describe(list: &str) -> &'static str {
    match list {
        "tif" => "hagezi TIF — malware / phishing / scam / C2",
        "ultimate" => "hagezi Multi Ultimate — ads / tracking / télémétrie (agrégat maximal)",
        "fake" => "hagezi — faux shops / arnaques",
        "gambling" => "hagezi — jeux d'argent",
        "dyndns" => "hagezi — DNS dynamique (souvent abusé par malware/C2)",
        "doh" => "hagezi — serveur DNS-over-HTTPS (contournement de filtrage)",
        "hoster" => "hagezi — hébergeur",
        "phishing_army" => "Phishing Army — domaine de phishing",
        "redflag" => "red.flag.domains — domaine .fr suspect récemment déposé",
        _ => "blocklist",
    }
}
