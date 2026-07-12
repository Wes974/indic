//! Export STIX 2.1 et CSV des rapports d'enrichissement.
//!
//! STIX 2.1 : émet un bundle `observed-data` avec l'observable principal + les
//! pivots en `sighting`/`relationship`. CSV : une ligne par source/fait (flatten).

use crate::enrich::Report;
use serde_json::{Map, Value, json};

/// Génère un bundle STIX 2.1 à partir d'un rapport.
pub fn to_stix21(report: &Report) -> Value {
    let now = chrono_now();
    let sco_id = format!("observed-data--{}", make_uuid(&report.query));
    let mut objects: Vec<Value> = Vec::new();

    // Identity: indic
    objects.push(json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--00000000-0000-0000-0000-000000000001",
        "name": "indic CTI",
        "identity_class": "system"
    }));

    // SCO principal
    let sco = build_sco(
        &sco_id,
        &report.kind,
        &report.query,
        &report.enrichments,
        &report.ip,
        &report.verdict,
        &now,
    );
    objects.push(sco);

    // Labels (signaux)
    let mut labels: Vec<String> = report
        .enrichments
        .iter()
        .flat_map(|e| e.signals.iter())
        .map(|s| format!("indic:{}", s.category))
        .collect();
    labels.sort();
    labels.dedup();

    // Object marking pour le TLP (TLP:WHITE par défaut)
    objects.push(json!({
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": now,
        "definition_type": "statement",
        "definition": { "statement": "TLP:WHITE" },
        "object_marking_refs": ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"]
    }));

    // Relationships pour les pivots
    for (i, pivot) in report.pivots.iter().enumerate() {
        let target_id = format!("sco--pivot-{}", i);
        objects.push(json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": target_id,
            "created": now,
            "modified": now,
            "name": format!("Pivot: {}", pivot.value),
            "pattern": format!("[{}:value = '{}']", stix_type_for_kind(&pivot.kind), pivot.value),
            "pattern_type": "stix",
            "valid_from": now,
            "labels": [format!("pivot:{}", pivot.relation)]
        }));
        objects.push(json!({
            "type": "relationship",
            "spec_version": "2.1",
            "id": format!("relationship--pivot-{}", i),
            "created": now,
            "modified": now,
            "relationship_type": "related-to",
            "source_ref": sco_id,
            "target_ref": target_id
        }));
    }

    json!({
        "type": "bundle",
        "spec_version": "2.1",
        "id": format!("bundle--{}", make_uuid(&report.query)),
        "objects": objects
    })
}

fn build_sco(
    id: &str,
    kind: &str,
    value: &str,
    enrichments: &[crate::enrich::Enrichment],
    ip: &Option<crate::model::IpReport>,
    verdict: &Option<crate::verdict::Verdict>,
    now: &str,
) -> Value {
    let stix_type = stix_type_for_kind(kind);

    let mut extensions: Map<String, Value> = Map::new();
    let mut labels: Vec<Value> = Vec::new();

    // Injecter les signaux en tant que labels
    for enr in enrichments {
        for sig in &enr.signals {
            labels.push(json!(format!("indic:{}:{}", sig.category, sig.source)));
        }
        for fact in &enr.facts {
            extensions.insert(fact.key.clone(), json!(fact.value));
        }
    }

    if let Some(v) = verdict {
        labels.push(json!(format!("indic:verdict:{}", v.label)));
        extensions.insert(
            "indic_verdict".into(),
            json!({"label": v.label, "score": v.score, "rationale": v.rationale}),
        );
    }

    if let Some(ipr) = ip {
        if let Some(co) = &ipr.country {
            extensions.insert("country".into(), json!(co));
        }
        if let Some(asn) = ipr.asn {
            extensions.insert("asn".into(), json!(asn));
        }
    }

    json!({
        "type": stix_type,
        "spec_version": "2.1",
        "id": id,
        "created": now,
        "modified": now,
        "value": value,
        "labels": labels,
        "extensions": { "indic-enrichment": extensions }
    })
}

fn stix_type_for_kind(kind: &str) -> &str {
    match kind {
        "ip" => "ipv4-addr",
        "domain" => "domain-name",
        "url" => "url",
        "email" => "email-addr",
        "hash" => "file",
        "cve" => "x-cti-cve",
        "asn" => "x-cti-asn",
        "cidr" => "ipv4-addr",
        "crypto" => "x-cti-crypto-address",
        "username" => "x-cti-username",
        "phone" => "x-cti-phone",
        "onion" => "domain-name",
        "package" => "x-cti-package",
        _ => "x-cti-observable",
    }
}

/// Génère un CSV aplati (une ligne par source/fait).
pub fn to_csv(report: &Report) -> String {
    let mut out = String::from("type,value,source,category,key,value,signal\n");
    for enr in &report.enrichments {
        if let Some(err) = &enr.error {
            out.push_str(&format!(
                "{},{},{},error,error,{},\n",
                report.kind, report.query, enr.source, err
            ));
            continue;
        }
        for fact in &enr.facts {
            out.push_str(&format!(
                "{},{},{},fact,{},{},\n",
                report.kind,
                report.query,
                enr.source,
                fact.key,
                csv_escape(&fact.value)
            ));
        }
        for sig in &enr.signals {
            out.push_str(&format!(
                "{},{},{},signal,{},{},{}\n",
                report.kind,
                report.query,
                enr.source,
                sig.category,
                sig.source,
                sig.detail.as_deref().unwrap_or("")
            ));
        }
    }
    if let Some(v) = &report.verdict {
        out.push_str(&format!(
            "{},{},indic,verdict,{},{},{}\n",
            report.kind,
            report.query,
            v.label,
            v.score,
            csv_escape(&v.rationale)
        ));
    }
    out
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn chrono_now() -> String {
    // STIX timestamp format: 2024-01-15T10:30:00.000Z
    // Évite une dépendance chrono — on génère un timestamp ISO8601 basique.
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Formatage manuel basique: YYYY-MM-DDTHH:MM:SS.sssZ
    let days = secs / 86400;
    let (y, m, d) = days_to_ymd(days as i64);
    let time = secs % 86400;
    let h = time / 3600;
    let mi = (time % 3600) / 60;
    let s = time % 60;
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.000Z")
}

/// Conversion jours depuis epoch Unix → (année, mois, jour) — algorithme civil.
fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Algorithme de Howard Hinnant
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn make_uuid(_seed: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    _seed.hash(&mut h);
    let n = h.finish();
    format!("{n:016x}-0000-0000-0000-000000000000")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_escape_handles_commas_and_quotes() {
        assert_eq!(csv_escape("simple"), "simple");
        assert_eq!(csv_escape("hello, world"), "\"hello, world\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn stix_type_mapping() {
        assert_eq!(stix_type_for_kind("ip"), "ipv4-addr");
        assert_eq!(stix_type_for_kind("domain"), "domain-name");
        assert_eq!(stix_type_for_kind("cve"), "x-cti-cve");
    }

    #[test]
    fn csv_empty_report() {
        let report = crate::enrich::Report {
            query: "1.2.3.4".into(),
            kind: "ip".into(),
            ip: None,
            enrichments: vec![],
            pivots: vec![],
            verdict: None,
            threat_actors: vec![],
            freshness: None,
        };
        let csv = to_csv(&report);
        assert!(csv.starts_with("type,value,source,"));
    }
}
