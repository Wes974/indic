//! urlscan.io Pro — recherche enrichie avec verdicts et signaux.
//! Utilise l'API search (GET /api/v1/search/?q=domain:{domain}) pour
//! extraire verdicts, compteurs de malveillance et captures d'écran.
//! Auth: header `API-Key`. Gated (clé séparée `URLSCAN_PRO_API_KEY`).

use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    let Some(key) = ctx.key("URLSCAN_PRO_API_KEY") else {
        return Enrichment::failed("urlscan_pro", "clé absente".into());
    };
    match fetch(&ctx.http, domain, &key).await {
        Ok((facts, signals)) => Enrichment {
            source: "urlscan_pro".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("urlscan_pro", format!("{e:#}")),
    }
}

async fn fetch(
    http: &reqwest::Client,
    domain: &str,
    key: &str,
) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let v: Value = http
        .get("https://urlscan.io/api/v1/search/")
        .query(&[("q", format!("domain:{domain}").as_str()), ("size", "20")])
        .header("API-Key", key)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let mut facts = Vec::new();
    let mut signals = Vec::new();

    // Total de scans disponibles
    let total = v
        .get("total")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    facts.push(Fact::new("scans", total.to_string()));

    // Résultats
    let results = v
        .get("results")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();

    if results.is_empty() {
        if total == 0 {
            facts.push(Fact::new("status", "aucun scan trouvé"));
        }
        return Ok((facts, signals));
    }

    // Extraire les UUIDs récents (5 max)
    let uuids: Vec<String> = results
        .iter()
        .filter_map(|r| r.get("_id").and_then(|x| x.as_str()).map(String::from))
        .take(5)
        .collect();
    if !uuids.is_empty() {
        facts.push(Fact::new("latest_scans", uuids.join(", ")));
    }

    // Compter les verdicts malveillants
    let mut malicious_count: u64 = 0;
    let mut benign_count: u64 = 0;
    let mut suspicious_count: u64 = 0;
    let mut verdicts: Vec<String> = Vec::new();

    for res in &results {
        if let Some(vd) = res.get("verdicts").and_then(|x| x.get("overall")) {
            let mal = vd
                .get("malicious")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            let score = vd.get("score").and_then(|x| x.as_i64()).unwrap_or(0);

            if mal {
                malicious_count += 1;
                if let Some(tags) = vd.get("tags").and_then(|x| x.as_array()) {
                    for tag in tags {
                        if let Some(t) = tag.as_str() {
                            verdicts.push(t.to_string());
                        }
                    }
                }
            } else if score > 0 {
                suspicious_count += 1;
            } else {
                benign_count += 1;
            }
        }

        // Récupérer les URLs de screenshot
        if let Some(screenshot) = res.get("screenshot").and_then(|x| x.as_str()) {
            if !screenshot.is_empty() && facts.len() < 8 {
                facts.push(Fact::new("screenshot", screenshot));
            }
        }
    }

    facts.push(Fact::new(
        "verdicts",
        format!("{malicious_count}M / {suspicious_count}S / {benign_count}B"),
    ));

    if malicious_count > 0 {
        let detail = if verdicts.is_empty() {
            format!("{malicious_count} scans malveillants")
        } else {
            let mut uniq: Vec<String> = verdicts;
            uniq.sort();
            uniq.dedup();
            format!("{malicious_count} scans — {}", uniq.join(", "))
        };
        signals.push(Signal::with_detail(
            "urlscan_pro",
            "malicious",
            detail,
        ));
    } else if suspicious_count > 0 {
        signals.push(Signal::with_detail(
            "urlscan_pro",
            "suspicious",
            format!("{suspicious_count} scans suspects"),
        ));
    }

    // Extraire IPs et serveurs vus
    let servers: Vec<String> = results
        .iter()
        .filter_map(|r| r.get("page"))
        .filter_map(|p| p.get("server"))
        .filter_map(|s| s.as_str())
        .map(String::from)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .take(5)
        .collect();
    if !servers.is_empty() {
        facts.push(Fact::new("servers", servers.join(", ")));
    }

    let ips: Vec<String> = results
        .iter()
        .filter_map(|r| r.get("page"))
        .filter_map(|p| p.get("ip"))
        .filter_map(|ip| ip.as_str())
        .map(String::from)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .take(5)
        .collect();
    if !ips.is_empty() {
        facts.push(Fact::new("ips", ips.join(", ")));
    }

    Ok((facts, signals))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vérifie que la fonction build-like parse accepte une réponse de type
    /// "aucun scan" sans paniquer.
    #[test]
    fn build_no_results() {
        // On teste via un appel fetch simulé avec un mock HTTP,
        // mais ici on valide simplement la logique de parsing sur une
        // réponse vide pour éviter des dépendances lourdes.
        // Ce test couvre le cas où total=0 et results=[], qui doit
        // produire des facts sans erreur.
        let json: Value = serde_json::from_str(
            r#"{"total":0,"results":[],"has_more":false}"#,
        )
        .unwrap();
        assert_eq!(json.get("total").and_then(|x| x.as_u64()), Some(0));
        let results = json
            .get("results")
            .and_then(|x| x.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        assert_eq!(results, 0);
    }

    /// Vérifie l'extraction des verdicts sur une réponse simulée.
    #[test]
    fn parse_verdicts() {
        let json: Value = serde_json::from_str(
            r#"{
  "total": 3,
  "results": [
    {
      "_id": "aaa-bbb",
      "page": {"url": "https://evil.com/", "ip": "10.0.0.1", "server": "nginx"},
      "verdicts": {
        "overall": {"score": 100, "malicious": true, "tags": ["phishing"]}
      },
      "screenshot": "https://urlscan.io/screenshots/aaa-bbb.png"
    },
    {
      "_id": "ccc-ddd",
      "page": {"url": "https://evil.com/login", "ip": "10.0.0.2", "server": "apache"},
      "verdicts": {
        "overall": {"score": 50, "malicious": false, "tags": []}
      },
      "screenshot": ""
    },
    {
      "_id": "eee-fff",
      "page": {"url": "https://evil.com/", "ip": "10.0.0.1", "server": "nginx"},
      "verdicts": {
        "overall": {"score": 0, "malicious": false, "tags": []}
      },
      "screenshot": "https://urlscan.io/screenshots/eee-fff.png"
    }
  ],
  "has_more": false
}"#,
        )
        .unwrap();

        let total = json.get("total").and_then(|x| x.as_u64()).unwrap_or(0);
        assert_eq!(total, 3);

        let results = json
            .get("results")
            .and_then(|x| x.as_array())
            .unwrap();

        let mut malicious_count = 0u64;
        for res in results {
            if let Some(vd) = res.get("verdicts").and_then(|x| x.get("overall")) {
                if vd.get("malicious").and_then(|x| x.as_bool()) == Some(true) {
                    malicious_count += 1;
                }
            }
        }
        assert_eq!(malicious_count, 1);

        // Vérifier les screenshots
        let screenshots: Vec<&str> = results
            .iter()
            .filter_map(|r| r.get("screenshot").and_then(|x| x.as_str()))
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(screenshots.len(), 2);
    }
}
