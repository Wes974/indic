//! Décrypteurs de ransomware (PCEF) — `POST ai.perkinsfund.org/api/tool/
//! ransomnotes/links`, **sans clé**.
//!
//! Prolonge une chaîne qu'indic possédait déjà sans l'exploiter : l'enricher
//! `ransomwhere` sait rattacher une adresse BTC à une famille de ransomware,
//! puis s'arrêtait là. On va au bout — famille connue → outil de déchiffrement
//! public s'il en existe. Passer du constat à l'action.
//!
//! Volontairement **séparé de `ransomwhere`**, qui reste hors-ligne et sans
//! clé : une panne de cette API ne doit pas faire passer l'identification de
//! famille (offline, fiable) pour cassée, et le panneau de santé distingue les
//! deux sources.
//!
//! ⚠️ La couverture est **partielle** (akira et lockbit répondent, 8base et
//! conti non) : l'absence de lien ne signifie pas qu'aucun décrypteur n'existe.
//! C'est dit dans la fiche plutôt que laissé à l'interprétation.

use anyhow::Result;
use serde::Deserialize;
use serde_json::json;

use crate::enrich::{Ctx, Enrichment, Fact};

const ENDPOINT: &str = "https://ai.perkinsfund.org/api/tool/ransomnotes/links";

#[derive(Deserialize, Default)]
struct Envelope {
    /// Liens vers des décrypteurs/portails. Absent ou vide = rien de connu.
    #[serde(default)]
    results: Option<Vec<String>>,
}

pub async fn enrich_crypto(addr: &str, ctx: &Ctx) -> Enrichment {
    // Identification hors-ligne d'abord : sans famille connue, aucun appel
    // réseau n'est émis — inutile d'interroger l'API pour 99,99 % des adresses.
    // Le guard est lié séparément : `store.load()` rend un temporaire qui
    // mourrait avant l'await si on chaînait directement.
    let store = ctx.store.load();
    let Some(family) = store.ransomware_family(addr).map(str::to_string) else {
        return Enrichment::ok("decryptor", vec![Fact::new("decryptor", "sans objet")]);
    };
    drop(store);

    // Les familles de Ransomwhere portent une version ou un alias (« LockBit
    // 2.0 », « Netwalker (Mailto) ») que la base de décrypteurs ne connaît pas :
    // elle indexe le nom nu. Constaté en test — « lockbit » rend le portail
    // IC3, « lockbit 2.0 » ne rend rien. On tente l'exact, puis le nom nu.
    let base = base_name(&family);
    let mut links = fetch(ctx, &family).await;
    if base != family.to_ascii_lowercase() && links.as_ref().is_ok_and(Vec::is_empty) {
        links = fetch(ctx, &base).await;
    }

    match links {
        Ok(links) if !links.is_empty() => {
            let mut facts = vec![
                Fact::new("famille", family.clone()),
                Fact::new("décrypteur", links.join(" · ")),
            ];
            // Un portail de victimes n'est pas un outil de déchiffrement : le
            // dire évite un faux espoir.
            if links.iter().any(|l| l.contains("ic3.gov")) {
                facts.push(Fact::new("note", "portail victimes officiel (FBI IC3)"));
            }
            Enrichment::ok("decryptor", facts)
        }
        Ok(_) => Enrichment::ok(
            "decryptor",
            vec![
                Fact::new("famille", family.clone()),
                Fact::new("décrypteur", "aucun connu de cette base"),
            ],
        ),
        Err(e) => Enrichment::failed("decryptor", format!("{e:#}")),
    }
}

/// Nom de famille « nu » : sans alias entre parenthèses ni suffixe de version.
/// « LockBit 2.0 » → `lockbit`, « Netwalker (Mailto) » → `netwalker`.
fn base_name(family: &str) -> String {
    family
        .split('(')
        .next()
        .unwrap_or(family)
        .split_whitespace()
        // Coupe au premier segment qui ressemble à une version (2, 2.0, v3).
        .take_while(|t| {
            let t = t.trim_start_matches(['v', 'V']);
            !t.chars().next().is_some_and(|c| c.is_ascii_digit())
        })
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

async fn fetch(ctx: &Ctx, family: &str) -> Result<Vec<String>> {
    let resp = ctx
        .http
        .post(ENDPOINT)
        .json(&json!({ "search_term": family.to_ascii_lowercase() }))
        .send()
        .await?;
    if resp.status().is_server_error() {
        anyhow::bail!("décrypteurs HTTP {}", resp.status());
    }
    let env: Envelope = resp.json().await.unwrap_or_default();
    // Ne garder que des URL : la base renvoie parfois des chaînes libres.
    Ok(env
        .results
        .unwrap_or_default()
        .into_iter()
        .filter(|l| l.starts_with("http"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn links(v: Value) -> Vec<String> {
        let env: Envelope = serde_json::from_value(v).unwrap_or_default();
        env.results
            .unwrap_or_default()
            .into_iter()
            .filter(|l| l.starts_with("http"))
            .collect()
    }

    /// Réponse réelle relevée en production pour « akira ».
    #[test]
    fn extracts_decryptor_links() {
        let l = links(json!({
            "results": ["https://files.avast.com/files/decryptor/avast_decryptor_akira64.exe"]
        }));
        assert_eq!(l.len(), 1);
        assert!(l[0].contains("avast_decryptor_akira"));
    }

    /// Réponse réelle pour « 8base » : la base ne connaît rien. `results` peut
    /// être absent, nul ou vide — les trois doivent donner « aucun lien ».
    #[test]
    fn absence_is_tolerated_in_every_shape() {
        assert!(links(json!({})).is_empty());
        assert!(links(json!({ "results": null })).is_empty());
        assert!(links(json!({ "results": [] })).is_empty());
    }

    /// Constaté en production : la base de décrypteurs indexe le nom nu, pas
    /// celui de Ransomwhere. Sans ce repli, LockBit et Netwalker ne trouvaient
    /// rien alors qu'un lien existe.
    #[test]
    fn strips_version_and_alias_from_family() {
        assert_eq!(base_name("LockBit 2.0"), "lockbit");
        assert_eq!(base_name("Netwalker (Mailto)"), "netwalker");
        assert_eq!(base_name("Akira"), "akira");
        assert_eq!(base_name("Conti"), "conti");
        assert_eq!(base_name("REvil v2"), "revil");
    }

    /// Les entrées non-URL sont écartées : la fiche ne doit pas proposer de
    /// cliquer sur du texte libre.
    #[test]
    fn non_url_entries_are_dropped() {
        let l = links(json!({ "results": ["voir le site du CERT", "https://ok.example/d.exe"] }));
        assert_eq!(l, vec!["https://ok.example/d.exe"]);
    }
}
