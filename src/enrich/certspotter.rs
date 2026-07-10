//! CertSpotter (SSLMate) — Certificate Transparency : sous-domaines et émetteurs
//! observés dans les certificats d'un domaine. `GET api.certspotter.com/v1/issuances`,
//! `Authorization: Bearer <key>`. Gated. Pivote vers les sous-domaines découverts.

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact, Pivot};

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    let Some(key) = ctx.key("CERTSPOTTER_API_KEY") else {
        return Enrichment::failed("certspotter", "clé absente".into());
    };
    match fetch(&ctx.http, domain, key).await {
        Ok(v) => build(domain, &v),
        Err(e) => Enrichment::failed("certspotter", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(http: &reqwest::Client, domain: &str, key: &str) -> Result<Value> {
    Ok(http
        .get("https://api.certspotter.com/v1/issuances")
        .query(&[
            ("domain", domain),
            ("include_subdomains", "true"),
            ("expand", "dns_names"),
            ("expand", "issuer"),
        ])
        .bearer_auth(key)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn build(domain: &str, v: &Value) -> Enrichment {
    let issuances = v.as_array().cloned().unwrap_or_default();
    if issuances.is_empty() {
        return Enrichment::ok(
            "certspotter",
            vec![Fact::new("certspotter", "aucun certificat CT connu")],
        );
    }

    let self_lc = domain.to_ascii_lowercase();
    let mut subdomains: Vec<String> = Vec::new();
    let mut issuers: Vec<String> = Vec::new();
    let mut active = 0usize;
    for iss in &issuances {
        if iss.get("revoked").and_then(|x| x.as_bool()) != Some(true) {
            active += 1;
        }
        if let Some(names) = iss.get("dns_names").and_then(|x| x.as_array()) {
            for n in names.iter().filter_map(|x| x.as_str()) {
                let n = n.trim_start_matches("*.").to_ascii_lowercase();
                if !n.is_empty() && !subdomains.contains(&n) {
                    subdomains.push(n);
                }
            }
        }
        if let Some(name) = iss
            .get("issuer")
            .and_then(|i| i.get("friendly_name"))
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
        {
            let name = name.to_string();
            if !issuers.contains(&name) {
                issuers.push(name);
            }
        }
    }

    let mut facts = vec![
        Fact::new("certificats", issuances.len().to_string()),
        Fact::new("sous-domaines", subdomains.len().to_string()),
    ];
    if active != issuances.len() {
        facts.push(Fact::new("actifs", active.to_string()));
    }
    if !issuers.is_empty() {
        facts.push(Fact::new("émetteurs", super::dedup_join(issuers, 5)));
    }
    let sample: Vec<String> = subdomains
        .iter()
        .filter(|s| **s != self_lc)
        .take(8)
        .cloned()
        .collect();
    if !sample.is_empty() {
        facts.push(Fact::new("exemples", sample.join(", ")));
    }

    // Pivots vers les sous-domaines (bornés, hors le domaine lui-même).
    let pivots: Vec<Pivot> = subdomains
        .into_iter()
        .filter(|s| *s != self_lc)
        .take(15)
        .map(|s| Pivot {
            relation: "subdomain".into(),
            kind: "domain".into(),
            value: s,
        })
        .collect();

    Enrichment {
        source: "certspotter".into(),
        facts,
        signals: vec![],
        pivots,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_extracts_subdomains_and_pivots() {
        let v = serde_json::json!([
            {"revoked": false, "dns_names": ["example.com", "www.example.com"],
             "issuer": {"friendly_name": "Let's Encrypt"}},
            {"revoked": false, "dns_names": ["*.api.example.com"],
             "issuer": {"friendly_name": "Let's Encrypt"}}
        ]);
        let e = build("example.com", &v);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "certificats" && f.value == "2")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "émetteurs" && f.value.contains("Let's Encrypt"))
        );
        assert!(e.pivots.iter().any(|p| p.value == "www.example.com"));
        // wildcard `*.` retiré
        assert!(e.pivots.iter().any(|p| p.value == "api.example.com"));
    }

    #[test]
    fn build_empty() {
        let e = build("example.com", &serde_json::json!([]));
        assert!(e.error.is_none());
        assert!(e.facts.iter().any(|f| f.value.contains("aucun certificat")));
    }
}
