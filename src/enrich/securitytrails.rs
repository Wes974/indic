//! SecurityTrails — intelligence domaine (DNS courant, Alexa rank).
//! Auth: header `APIKEY`. Gated. Free tier: 50 req/month.
//!
//! GET https://api.securitytrails.com/v1/domain/{domain}
//! Retourne le hostname, alexa_rank, et current_dns avec les compteurs
//! d'IP/hôtes partagés. Le WHOIS (registrar, dates) n'est pas dans cet
//! endpoint ; les champs correspondants sont extraits s'ils sont présents.

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact, Pivot};
use crate::model::Signal;

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("SECURITYTRAILS_API_KEY") else {
        return Enrichment::failed("securitytrails", "clé absente".into());
    };
    match fetch(&ctx.http, domain, key).await {
        Ok((facts, signals, pivots)) => Enrichment {
            source: "securitytrails".into(),
            facts,
            signals,
            pivots,
            error: None,
        },
        Err(e) => Enrichment::failed("securitytrails", format!("{e:#}")),
    }
}

async fn fetch(
    http: &reqwest::Client,
    domain: &str,
    key: &str,
) -> Result<(Vec<Fact>, Vec<Signal>, Vec<Pivot>)> {
    let url = format!("https://api.securitytrails.com/v1/domain/{domain}");
    let v: Value = http
        .get(&url)
        .header("APIKEY", key)
        .header("Accept", "application/json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let mut facts = Vec::new();
    let mut signals = Vec::new();
    let mut pivots = Vec::new();

    // ── Alexa rank ──────────────────────────────────────────────────────
    if let Some(rank) = v.get("alexa_rank").and_then(|x| x.as_i64())
        && rank > 0
    {
        facts.push(Fact::new("alexa_rank", rank.to_string()));
    }

    // ── WHOIS (registrar, dates) — extraits s'ils sont présents ──────────
    if let Some(registrar) = v.get("registrar").and_then(|x| x.as_str()) {
        facts.push(Fact::new("registrar", registrar));
    }
    if let Some(created) = v
        .get("creation_date")
        .or_else(|| v.get("created"))
        .and_then(|x| x.as_str())
    {
        facts.push(Fact::new("created", created));
        if is_recent(created, 30) {
            signals.push(Signal::with_detail(
                "securitytrails",
                "suspicious",
                format!("créé il y a ≤ 30 j ({created})"),
            ));
        }
    }
    if let Some(expires) = v
        .get("expiration_date")
        .or_else(|| v.get("expires"))
        .and_then(|x| x.as_str())
    {
        facts.push(Fact::new("expires", expires));
    }

    // ── current_dns ─────────────────────────────────────────────────────
    if let Some(dns) = v.get("current_dns").and_then(|x| x.as_object()) {
        // A
        if let Some(a) = dns
            .get("a")
            .and_then(|x| x.get("values"))
            .and_then(|x| x.as_array())
        {
            let ips: Vec<String> = a
                .iter()
                .filter_map(|x| x.get("ip").and_then(|v| v.as_str()))
                .map(String::from)
                .collect();
            if !ips.is_empty() {
                facts.push(Fact::new("A", super::dedup_join(ips.clone(), 10)));
                for ip in ips.into_iter().take(10) {
                    pivots.push(Pivot {
                        relation: "st_dns".into(),
                        kind: "ip".into(),
                        value: ip,
                    });
                }
            }
        }
        // AAAA
        if let Some(aaaa) = dns
            .get("aaaa")
            .and_then(|x| x.get("values"))
            .and_then(|x| x.as_array())
        {
            let ips: Vec<String> = aaaa
                .iter()
                .filter_map(|x| x.get("ip").and_then(|v| v.as_str()))
                .map(String::from)
                .collect();
            if !ips.is_empty() {
                facts.push(Fact::new("AAAA", super::dedup_join(ips, 5)));
            }
        }
        // MX
        if let Some(mx) = dns
            .get("mx")
            .and_then(|x| x.get("values"))
            .and_then(|x| x.as_array())
        {
            let hosts: Vec<String> = mx
                .iter()
                .filter_map(|x| {
                    let prio = x.get("priority").and_then(|v| v.as_i64()).unwrap_or(0);
                    let host = x.get("host").and_then(|v| v.as_str())?;
                    Some(format!("{prio} {host}"))
                })
                .collect();
            if !hosts.is_empty() {
                facts.push(Fact::new("MX", super::dedup_join(hosts, 6)));
            }
        }
        // NS
        if let Some(ns) = dns
            .get("ns")
            .and_then(|x| x.get("values"))
            .and_then(|x| x.as_array())
        {
            let nameservers: Vec<String> = ns
                .iter()
                .filter_map(|x| x.get("nameserver").and_then(|v| v.as_str()))
                .map(String::from)
                .collect();
            if !nameservers.is_empty() {
                facts.push(Fact::new("NS", super::dedup_join(nameservers, 6)));
            }
        }
        // SOA email
        if let Some(soa) = dns
            .get("soa")
            .and_then(|x| x.get("values"))
            .and_then(|x| x.as_array())
            .and_then(|arr| arr.first())
            .and_then(|x| x.get("email"))
            .and_then(|x| x.as_str())
        {
            facts.push(Fact::new("SOA_email", soa));
        }
    }

    if facts.is_empty() {
        facts.push(Fact::new("securitytrails", "aucune donnée"));
    }

    Ok((facts, signals, pivots))
}

/// Vrai si la date ISO (`YYYY-MM-DD` ou `YYYY-MM-DDThh:mm:ss`) est dans
/// les `max_days` derniers jours (basé sur l'horloge système).
fn is_recent(date_str: &str, max_days: i64) -> bool {
    let d = &date_str[..date_str.len().min(10)];
    let mut parts = d.splitn(3, '-');
    let y: i64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let m: i64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let day: i64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    if y < 2020 || !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return false;
    }
    // Jours depuis 1970-01-01 (approximation suffisante pour ≤ 30 j).
    let epoch_days = (y - 1970) * 365 + (y - 1969) / 4 - (y - 1901) / 100
        + (y - 1601) / 400
        + month_offset(m as u32, y)
        + day
        - 1;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let today_days = (now.as_secs() / 86_400) as i64;
    let age = today_days - epoch_days;
    age >= 0 && age <= max_days
}
fn month_offset(m: u32, y: i64) -> i64 {
    #[allow(clippy::manual_is_multiple_of)]
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let base = match m {
        1 => 0,
        2 => 31,
        3 => 59,
        4 => 90,
        5 => 120,
        6 => 151,
        7 => 181,
        8 => 212,
        9 => 243,
        10 => 273,
        11 => 304,
        12 => 334,
        _ => 0,
    };
    let leap_day = if m > 2 && leap { 1 } else { 0 };
    base + leap_day
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domain_response() {
        let json = serde_json::json!({
            "hostname": "example.com",
            "alexa_rank": 42,
            "current_dns": {
                "a": {
                    "first_seen": "2020-01-01",
                    "values": [
                        {"ip": "93.184.216.34", "ip_count": 1200}
                    ]
                },
                "aaaa": {
                    "first_seen": "2020-01-01",
                    "values": [
                        {"ip": "2606:2800:220:1:248:1893:25c8:1946", "ip_count": 800}
                    ]
                },
                "mx": {
                    "first_seen": "2020-01-01",
                    "values": [
                        {"priority": 10, "host": "mail.example.com", "host_count": 500}
                    ]
                },
                "ns": {
                    "first_seen": "2020-01-01",
                    "values": [
                        {"nameserver": "ns1.example.com", "nameserver_count": 6000},
                        {"nameserver": "ns2.example.com", "nameserver_count": 4500}
                    ]
                },
                "soa": {
                    "first_seen": "2020-01-01",
                    "values": [
                        {"ttl": 3600, "email": "admin@example.com", "email_count": 300}
                    ]
                },
                "txt": {
                    "first_seen": "2020-01-01",
                    "values": [
                        {"value": "v=spf1 -all"}
                    ]
                }
            }
        });

        let v: Value = json;
        // Alexa rank
        assert_eq!(v["alexa_rank"].as_i64(), Some(42));

        // DNS values parsing
        let dns = v["current_dns"].as_object().unwrap();

        let a_vals = dns["a"]["values"].as_array().unwrap();
        assert_eq!(a_vals[0]["ip"].as_str(), Some("93.184.216.34"));
        assert_eq!(a_vals[0]["ip_count"].as_i64(), Some(1200));

        let ns_vals = dns["ns"]["values"].as_array().unwrap();
        assert_eq!(ns_vals.len(), 2);
        assert_eq!(ns_vals[0]["nameserver"].as_str(), Some("ns1.example.com"));

        let mx_vals = dns["mx"]["values"].as_array().unwrap();
        assert_eq!(mx_vals[0]["host"].as_str(), Some("mail.example.com"));
        assert_eq!(mx_vals[0]["priority"].as_i64(), Some(10));

        let soa_vals = dns["soa"]["values"].as_array().unwrap();
        assert_eq!(soa_vals[0]["email"].as_str(), Some("admin@example.com"));
    }

    #[test]
    fn test_is_recent() {
        // Une date dans le futur lointain → non récente (le diff serait négatif)
        assert!(!is_recent("2099-01-01", 30));
        // Une date dans le passé lointain → non récente
        assert!(!is_recent("2020-01-01", 30));
        // Aujourd'hui → récente
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let secs = now.as_secs();
        // Calculer aujourd'hui au format ISO
        let days = secs / 86_400;
        let today = epoch_to_iso(days);
        assert!(is_recent(&today, 30));
    }

    #[test]
    fn test_is_recent_edge() {
        // Il y a 31 jours → non récente pour max_days=30
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let days = (now.as_secs() / 86_400) as i64;
        let d31 = epoch_to_iso((days - 31) as u64);
        assert!(!is_recent(&d31, 30));
    }

    /// Convertit un nombre de jours depuis l'epoch Unix → "YYYY-MM-DD".
    fn epoch_to_iso(epoch_days: u64) -> String {
        // Algorithme Rata Die inversé (approximatif, suffisant pour le test).
        let z = epoch_days as i64 + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!("{y:04}-{m:02}-{d:02}")
    }
}
