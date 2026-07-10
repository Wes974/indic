//! ipdata.co — géoloc + ASN + flags de menace (tor/proxy/datacenter/attacker…).
//! Clé en query `api-key`. Gated (token).

use std::net::IpAddr;

use anyhow::Result;
use serde::Deserialize;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(key) = ctx.key("IPDATA_API_KEY") else {
        return Enrichment::failed("ipdata", "clé absente".into());
    };
    match fetch(ctx, ip, key).await {
        Ok(e) => e,
        Err(e) => Enrichment::failed("ipdata", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(ctx: &Ctx, ip: IpAddr, key: &str) -> Result<Enrichment> {
    let url = format!("https://api.ipdata.co/{ip}");
    let resp: Resp = ctx
        .http
        .get(url.as_str())
        .query(&[("api-key", key)])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(build(resp))
}

fn build(r: Resp) -> Enrichment {
    let mut facts = Vec::new();
    if let Some(c) = r.country_name.filter(|s| !s.is_empty()) {
        facts.push(Fact::new("country", c));
    }
    if let Some(asn) = &r.asn
        && let Some(name) = asn.name.as_deref().filter(|s| !s.is_empty())
    {
        // On préfixe le numéro d'AS quand il est fourni.
        let label = match asn.asn.as_deref().filter(|s| !s.is_empty()) {
            Some(num) => format!("{name} ({num})"),
            None => name.to_string(),
        };
        facts.push(Fact::new("asn", label));
    }

    let t = r.threat.unwrap_or_default();
    // Flags d'anonymisation actifs, joints.
    let mut flags = Vec::new();
    if t.is_tor {
        flags.push("tor");
    }
    if t.is_proxy {
        flags.push("proxy");
    }
    if t.is_datacenter {
        flags.push("datacenter");
    }
    if t.is_icloud_relay {
        flags.push("icloud_relay");
    }
    if t.is_anonymous {
        flags.push("anonymous");
    }
    if !flags.is_empty() {
        facts.push(Fact::new("flags", flags.join(", ")));
    }
    if !t.blocklists.is_empty() {
        facts.push(Fact::new("blocklists", t.blocklists.len().to_string()));
    }

    // Menace confirmée > anonymisation seule.
    let mut signals = Vec::new();
    if t.is_known_attacker || t.is_known_abuser || t.is_threat {
        signals.push(Signal::with_detail(
            "ipdata",
            "malicious",
            "menace connue (attacker/abuser/threat)",
        ));
    } else if t.is_anonymous || t.is_proxy || t.is_tor {
        signals.push(Signal::with_detail(
            "ipdata",
            "suspicious",
            flags.join(", "),
        ));
    }

    if facts.is_empty() {
        facts.push(Fact::new("ipdata", "aucune donnée"));
    }
    Enrichment {
        source: "ipdata".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

#[derive(Deserialize)]
struct Resp {
    country_name: Option<String>,
    asn: Option<Asn>,
    threat: Option<Threat>,
}

#[derive(Deserialize)]
struct Asn {
    asn: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize, Default)]
struct Threat {
    #[serde(default)]
    is_tor: bool,
    #[serde(default)]
    is_proxy: bool,
    #[serde(default)]
    is_datacenter: bool,
    #[serde(default)]
    is_icloud_relay: bool,
    #[serde(default)]
    is_anonymous: bool,
    #[serde(default)]
    is_known_attacker: bool,
    #[serde(default)]
    is_known_abuser: bool,
    #[serde(default)]
    is_threat: bool,
    #[serde(default)]
    blocklists: Vec<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_known_attacker_malicious() {
        let r = Resp {
            country_name: Some("United States".into()),
            asn: Some(Asn {
                asn: Some("AS15169".into()),
                name: Some("Google LLC".into()),
            }),
            threat: Some(Threat {
                is_datacenter: true,
                is_threat: true,
                is_known_attacker: true,
                blocklists: vec![serde_json::json!({"name": "myip.ms", "type": "bots"})],
                ..Default::default()
            }),
        };
        let e = build(r);
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "malicious");
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "asn" && f.value == "Google LLC (AS15169)")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "blocklists" && f.value == "1")
        );
    }

    #[test]
    fn build_datacenter_only_no_signal() {
        let r = Resp {
            country_name: Some("United States".into()),
            asn: None,
            threat: Some(Threat {
                is_datacenter: true,
                ..Default::default()
            }),
        };
        let e = build(r);
        assert!(e.signals.is_empty()); // datacenter seul n'est pas suspect
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "flags" && f.value == "datacenter")
        );
    }

    #[test]
    fn build_anonymous_suspicious() {
        let r = Resp {
            country_name: None,
            asn: None,
            threat: Some(Threat {
                is_proxy: true,
                is_anonymous: true,
                ..Default::default()
            }),
        };
        let e = build(r);
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "suspicious");
    }
}
