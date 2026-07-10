//! PoC publics par CVE (index tg12/PoC_CVEs, **offline** via le store) : dépôts
//! GitHub d'exploit. Un PoC public = signal d'exploitabilité fort. Sans clé.

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub fn enrich_cve(cve: &str, ctx: &Ctx) -> Enrichment {
    let repos = ctx.store.load().poc_repos(cve);
    if repos.is_empty() {
        return Enrichment::ok(
            "poc_cves",
            vec![Fact::new("poc_public", "aucun PoC public indexé")],
        );
    }
    let n = repos.len();
    let facts = vec![
        Fact::new("poc_public", format!("{n} dépôt(s) PoC sur GitHub")),
        Fact::new(
            "poc_repos",
            repos.iter().take(5).cloned().collect::<Vec<_>>().join(", "),
        ),
    ];
    Enrichment {
        source: "poc_cves".into(),
        facts,
        signals: vec![Signal::with_detail(
            "poc_cves",
            "exploit",
            format!("{n} PoC public(s) sur GitHub — exploitabilité élevée"),
        )],
        pivots: vec![],
        error: None,
    }
}
