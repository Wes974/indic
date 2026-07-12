//! proxycheck.io — détection VPN/proxy + score de risque (0-100).
//! L'IP interrogée est une clé dynamique de la réponse → parse défensif en
//! `serde_json::Value`. Clé en query `key`. Gated (token).

use std::net::IpAddr;

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("PROXYCHECK_API_KEY") else {
        return Enrichment::failed("proxycheck", "clé absente".into());
    };
    match fetch(ctx, ip, key).await {
        Ok(e) => e,
        Err(e) => Enrichment::failed("proxycheck", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(ctx: &Ctx, ip: IpAddr, key: &str) -> Result<Enrichment> {
    let ip_s = ip.to_string();
    let url = format!("https://proxycheck.io/v2/{ip_s}");
    let v: Value = ctx
        .http
        .get(url.as_str())
        .query(&[("vpn", "1"), ("risk", "1"), ("key", key)])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(build(&v, &ip_s))
}

fn build(v: &Value, ip: &str) -> Enrichment {
    // Statut applicatif ("error"/"denied") remonté comme erreur.
    if let Some(st) = v.get("status").and_then(|x| x.as_str())
        && st != "ok"
    {
        let msg = v.get("message").and_then(|x| x.as_str()).unwrap_or(st);
        return Enrichment::failed("proxycheck", format!("statut API : {msg}"));
    }

    // Le résultat est sous une clé dynamique = l'IP interrogée.
    let Some(node) = v.get(ip) else {
        return Enrichment::ok("proxycheck", vec![Fact::new("proxycheck", "aucune donnée")]);
    };

    let proxy = node.get("proxy").and_then(|x| x.as_str()).unwrap_or("no");
    let kind = node
        .get("type")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty());
    let risk = node.get("risk").and_then(|x| x.as_i64());

    let mut facts = vec![Fact::new("proxy", proxy)];
    if let Some(t) = kind {
        facts.push(Fact::new("type", t));
    }
    if let Some(r) = risk {
        facts.push(Fact::new("risk", format!("{r}/100")));
    }

    let mut signals = Vec::new();
    if proxy == "yes" {
        let detail = kind.unwrap_or("proxy").to_string();
        // Risque élevé → on renforce en malicious plutôt que suspicious.
        let category = if risk.unwrap_or(0) >= 66 {
            "malicious"
        } else {
            "suspicious"
        };
        signals.push(Signal::with_detail("proxycheck", category, detail));
    }

    Enrichment {
        source: "proxycheck".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_high_risk_proxy_malicious() {
        let v = serde_json::json!({
            "status": "ok",
            "1.2.3.4": { "proxy": "yes", "type": "VPN", "risk": 80 }
        });
        let e = build(&v, "1.2.3.4");
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "malicious");
        assert_eq!(e.signals[0].detail.as_deref(), Some("VPN"));
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "risk" && f.value == "80/100")
        );
    }

    #[test]
    fn build_clean_no_signal() {
        let v = serde_json::json!({
            "status": "ok",
            "8.8.8.8": { "proxy": "no", "type": "Business", "risk": 0 }
        });
        let e = build(&v, "8.8.8.8");
        assert!(e.signals.is_empty());
        assert!(e.facts.iter().any(|f| f.key == "proxy" && f.value == "no"));
    }

    #[test]
    fn build_api_error() {
        let v = serde_json::json!({ "status": "error", "message": "clé invalide" });
        let e = build(&v, "8.8.8.8");
        assert!(e.error.is_some());
    }
}
