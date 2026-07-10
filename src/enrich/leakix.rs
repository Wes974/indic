//! LeakIX — services exposés + fuites (leaks) d'un host. Header `api-key`.
//! Réponse potentiellement volumineuse (ou `{}`/null) → parse défensif en
//! `serde_json::Value`, on n'en garde qu'un échantillon. Gated (token).

use std::net::IpAddr;

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(key) = ctx.key("LEAKIX_API_KEY") else {
        return Enrichment::failed("leakix", "clé absente".into());
    };
    match fetch(ctx, ip, key).await {
        Ok(e) => e,
        Err(e) => Enrichment::failed("leakix", format!("{e:#}")),
    }
}

async fn fetch(ctx: &Ctx, ip: IpAddr, key: &str) -> Result<Enrichment> {
    let url = format!("https://leakix.net/host/{ip}");
    let v: Value = ctx
        .http
        .get(url.as_str())
        .header("api-key", key)
        .header("Accept", "application/json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(build(&v))
}

fn build(v: &Value) -> Enrichment {
    let services = v
        .get("Services")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let leaks = v
        .get("Leaks")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();

    let mut facts = Vec::new();
    if !services.is_empty() {
        facts.push(Fact::new("services", services.len().to_string()));
        // Échantillon port (software) — 10 max, dédupliqué.
        let mut sample: Vec<String> = Vec::new();
        for s in &services {
            let port = s.get("port").and_then(as_text);
            let soft = s
                .get("software")
                .and_then(|sw| sw.get("name"))
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty());
            let entry = match (port, soft) {
                (Some(p), Some(sw)) => format!("{p} ({sw})"),
                (Some(p), None) => p,
                (None, Some(sw)) => sw.to_string(),
                (None, None) => continue,
            };
            if !sample.contains(&entry) {
                sample.push(entry);
            }
            if sample.len() == 10 {
                break;
            }
        }
        if !sample.is_empty() {
            facts.push(Fact::new("exposed", sample.join(", ")));
        }
    }
    if !leaks.is_empty() {
        facts.push(Fact::new("leaks", leaks.len().to_string()));
    }

    // Fuite exposée > simple service exposé.
    let mut signals = Vec::new();
    if !leaks.is_empty() {
        signals.push(Signal::with_detail(
            "leakix",
            "malicious",
            format!("{} fuite(s) exposée(s)", leaks.len()),
        ));
    } else if !services.is_empty() {
        signals.push(Signal::with_detail(
            "leakix",
            "info",
            format!("{} services exposés", services.len()),
        ));
    }

    if facts.is_empty() {
        facts.push(Fact::new("leakix", "aucune donnée"));
    }
    Enrichment {
        source: "leakix".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

/// LeakIX renvoie parfois `port` en string ("443") ou en nombre : on tolère les deux.
fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => (!s.is_empty()).then(|| s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_leaks_malicious() {
        let v = serde_json::json!({
            "Services": [
                { "port": "443", "protocol": "https", "software": { "name": "nginx" } },
                { "port": "22", "protocol": "ssh" }
            ],
            "Leaks": [ { "severity": "high" } ]
        });
        let e = build(&v);
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "malicious");
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "services" && f.value == "2")
        );
        assert!(e.facts.iter().any(|f| f.key == "leaks" && f.value == "1"));
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "exposed" && f.value == "443 (nginx), 22")
        );
    }

    #[test]
    fn build_services_only_info() {
        let v = serde_json::json!({
            "Services": [ { "port": 8080 } ],
            "Leaks": []
        });
        let e = build(&v);
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "info");
    }

    #[test]
    fn build_empty() {
        let v = serde_json::json!({});
        let e = build(&v);
        assert!(e.signals.is_empty());
        assert_eq!(e.facts[0].value, "aucune donnée");
    }
}
