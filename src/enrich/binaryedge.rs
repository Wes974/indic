//! BinaryEdge — événements de scan internet + score de risque.
//! Clé header `X-Key`, gated.

use std::net::IpAddr;

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(key) = ctx.key("BINARYEDGE_API_KEY") else {
        return Enrichment::failed("binaryedge", "clé absente".into());
    };
    match fetch(&ctx.http, ip, &key).await {
        Ok((facts, signals)) => Enrichment {
            source: "binaryedge".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("binaryedge", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, ip: IpAddr, key: &str) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let url = format!("https://api.binaryedge.io/v2/query/ip/{ip}");
    let v: Value = http
        .get(&url)
        .header("X-Key", key)
        .header("Accept", "application/json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(build(&v))
}

fn build(v: &Value) -> (Vec<Fact>, Vec<Signal>) {
    let mut facts = Vec::new();
    let mut signals = Vec::new();

    // ── total events ────────────────────────────────────────────────────
    if let Some(total) = v.get("total").and_then(|x| x.as_u64()) {
        facts.push(Fact::new("events", total.to_string()));
    }

    // ── events: aggregate tags + countries ──────────────────────────────
    let mut tags: Vec<String> = Vec::new();
    let mut countries: Vec<String> = Vec::new();
    if let Some(events) = v.get("events").and_then(|x| x.as_array()) {
        for ev in events {
            // tags
            if let Some(ev_tags) = ev.get("tags").and_then(|x| x.as_array()) {
                for t in ev_tags {
                    if let Some(s) = t.as_str() {
                        let s = s.to_string();
                        if !tags.contains(&s) {
                            tags.push(s);
                        }
                    }
                }
            }
            // origin.country
            if let Some(c) = ev
                .get("origin")
                .and_then(|x| x.get("country"))
                .and_then(|x| x.as_str())
            {
                let c = c.to_string();
                if !countries.contains(&c) {
                    countries.push(c);
                }
            }
        }
    }
    tags.sort();
    if !tags.is_empty() {
        facts.push(Fact::new("tags", tags.join(", ")));
    }
    countries.sort();
    if !countries.is_empty() {
        facts.push(Fact::new("country", countries.join(", ")));
    }

    // ── score ───────────────────────────────────────────────────────────
    if let Some(score) = v.get("score").and_then(|x| x.as_f64()) {
        facts.push(Fact::new("score", format!("{score:.1}")));
        if score >= 5.0 {
            signals.push(Signal::with_detail(
                "binaryedge",
                "exposed",
                format!("score {score}"),
            ));
        }
    }

    // ── signals from suspicious tags ────────────────────────────────────
    let suspicious: &[&str] = &[
        "MALICIOUS",
        "C2",
        "BOT",
        "MALWARE",
        "RANSOMWARE",
        "PHISHING",
        "EXPLOIT",
        "COMPROMISED",
    ];
    for tag in &tags {
        let upper = tag.to_uppercase();
        if suspicious.iter().any(|s| upper.contains(s)) {
            signals.push(Signal::with_detail("binaryedge", "malicious", tag.as_str()));
            break;
        }
    }

    (facts, signals)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ip_with_events_and_score() {
        let v = serde_json::json!({
            "query": "1.2.3.4",
            "total": 42,
            "events": [
                {
                    "target": {"ip": "1.2.3.4", "port": 80, "protocol": "tcp"},
                    "origin": {"type": "http", "country": "US", "ts": 1_234_567_890},
                    "tags": ["HTTP_SCANNER", "FULL_SCAN"]
                },
                {
                    "target": {"ip": "1.2.3.4", "port": 443, "protocol": "tcp"},
                    "origin": {"type": "ssl", "country": "FR", "ts": 1_234_567_900},
                    "tags": ["SSL_SCANNER"]
                }
            ],
            "score": 7.5
        });
        let (facts, signals) = build(&v);
        assert!(
            facts.iter().any(|f| f.key == "events" && f.value == "42"),
            "should report event count"
        );
        assert!(
            facts
                .iter()
                .any(|f| f.key == "tags" && f.value.contains("HTTP_SCANNER")),
            "should aggregate tags"
        );
        assert!(
            facts
                .iter()
                .any(|f| f.key == "country" && f.value == "FR, US"),
            "should sort and deduplicate countries"
        );
        assert!(
            facts.iter().any(|f| f.key == "score" && f.value == "7.5"),
            "should report score"
        );
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, "exposed");
    }

    #[test]
    fn parse_malicious_tags_signal() {
        let v = serde_json::json!({
            "total": 5,
            "events": [
                {
                    "origin": {"country": "RU"},
                    "tags": ["MALWARE", "C2_SERVER"]
                }
            ]
        });
        let (_facts, signals) = build(&v);
        assert!(!_facts.is_empty());
        assert_eq!(signals[0].category, "malicious");
    }

    #[test]
    fn parse_empty_response() {
        let v = serde_json::json!({});
        let (facts, signals) = build(&v);
        assert!(facts.is_empty());
        assert!(signals.is_empty());
    }
}
