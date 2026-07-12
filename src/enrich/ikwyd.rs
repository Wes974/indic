//! iknowwhatyoudownload (Peer API, api.antitor.com) — historique des torrents
//! téléchargés/partagés par une IP (données DHT ; ~3 h de latence, pas une preuve).
//! Param `key`. Gated. Clé démo gratuite (limitée) sur demande par email.

use std::net::IpAddr;

use anyhow::Result;
use serde::Deserialize;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

/// Hôte fourni avec la clé (démo = api.antitor.com). À changer si le compte diffère.
const HOST: &str = "api.antitor.com";

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("IKNOWWHATYOUDOWNLOAD_API_KEY") else {
        return Enrichment::failed("iknowwhatyoudownload", "clé absente".into());
    };
    match fetch(ctx, ip, key).await {
        Ok(r) => build(r),
        Err(e) => Enrichment::failed("iknowwhatyoudownload", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(ctx: &Ctx, ip: IpAddr, key: &str) -> Result<Resp> {
    let ip_s = ip.to_string();
    Ok(ctx
        .http
        .get(format!("https://{HOST}/history/peer"))
        .query(&[
            ("ip", ip_s.as_str()),
            ("days", "30"),
            ("contents", "50"),
            ("lang", "en"),
            ("key", key),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn build(r: Resp) -> Enrichment {
    let contents = r.contents.unwrap_or_default();
    if contents.is_empty() {
        return Enrichment::ok(
            "iknowwhatyoudownload",
            vec![Fact::new(
                "iknowwhatyoudownload",
                "aucun torrent observé (30 j)",
            )],
        );
    }

    let mut facts = vec![Fact::new("torrents", contents.len().to_string())];
    if let Some(isp) = r.isp.filter(|s| !s.is_empty()) {
        facts.push(Fact::new("isp", isp));
    }
    let cats = uniq(contents.iter().filter_map(|c| c.category.clone()), 8);
    if !cats.is_empty() {
        facts.push(Fact::new("categories", cats.join(", ")));
    }
    let sample: Vec<String> = contents
        .iter()
        .filter_map(|c| c.name.clone())
        .filter(|s| !s.is_empty())
        .take(5)
        .collect();
    if !sample.is_empty() {
        facts.push(Fact::new("sample", sample.join(" | ")));
    }

    // Activité P2P observée = signal informatif ; ChildPorno = flag fort.
    let mut signals = vec![Signal::with_detail(
        "iknowwhatyoudownload",
        "p2p",
        format!("{} torrent(s) observé(s) sur 30 j", contents.len()),
    )];
    if r.has_child_porno == Some(true) {
        signals.push(Signal::with_detail(
            "iknowwhatyoudownload",
            "abuse",
            "contenu catégorisé ChildPorno",
        ));
    }

    Enrichment {
        source: "iknowwhatyoudownload".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

/// Déduplique en conservant l'ordre, borne à `max`.
fn uniq(it: impl Iterator<Item = String>, max: usize) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for s in it {
        if !s.is_empty() && !seen.contains(&s) {
            seen.push(s);
            if seen.len() == max {
                break;
            }
        }
    }
    seen
}

#[derive(Deserialize)]
struct Resp {
    isp: Option<String>,
    #[serde(rename = "hasChildPorno")]
    has_child_porno: Option<bool>,
    contents: Option<Vec<Content>>,
}

#[derive(Deserialize)]
struct Content {
    category: Option<String>,
    name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(cat: &str, name: &str) -> Content {
        Content {
            category: Some(cat.into()),
            name: Some(name.into()),
        }
    }

    #[test]
    fn build_with_torrents() {
        let r = Resp {
            isp: Some("Free SAS".into()),
            has_child_porno: Some(false),
            contents: Some(vec![
                c("Movies", "Film A (2020)"),
                c("Music", "Album B"),
                c("Movies", "Film C"),
            ]),
        };
        let e = build(r);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "torrents" && f.value == "3")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "categories" && f.value == "Movies, Music")
        );
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "p2p");
    }

    #[test]
    fn build_child_porno_flag() {
        let r = Resp {
            isp: None,
            has_child_porno: Some(true),
            contents: Some(vec![c("XXX", "x")]),
        };
        let e = build(r);
        assert!(e.signals.iter().any(|s| s.category == "abuse"));
    }

    #[test]
    fn build_empty() {
        let e = build(Resp {
            isp: None,
            has_child_porno: Some(false),
            contents: None,
        });
        assert!(e.error.is_none());
        assert!(e.signals.is_empty());
        assert!(e.facts.iter().any(|f| f.value.contains("aucun torrent")));
    }
}
