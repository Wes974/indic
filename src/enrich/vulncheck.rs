//! VulnCheck KEV — un CVE est-il dans la liste des vulnérabilités activement
//! exploitées (Known Exploited Vulnerabilities) ? `GET api.vulncheck.com/v3/index/
//! vulncheck-kev?cve=`, `Authorization: Bearer`. Gated. Présence = exploité → signal.

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_cve(cve: &str, ctx: &Ctx) -> Enrichment {
    let Some(key) = ctx.key("VULNCHECK_API_KEY") else {
        return Enrichment::failed("vulncheck", "clé absente".into());
    };
    match fetch(&ctx.http, cve, key).await {
        Ok(v) => build(&v),
        Err(e) => Enrichment::failed("vulncheck", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(http: &reqwest::Client, cve: &str, key: &str) -> Result<Value> {
    Ok(http
        .get("https://api.vulncheck.com/v3/index/vulncheck-kev")
        .query(&[("cve", cve)])
        .bearer_auth(key)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn build(v: &Value) -> Enrichment {
    let data = v
        .get("data")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    if data.is_empty() {
        return Enrichment::ok(
            "vulncheck",
            vec![Fact::new("kev", "non (absent de VulnCheck KEV)")],
        );
    }
    let rec = &data[0];

    let mut facts = vec![Fact::new("kev", "OUI — exploité connu (VulnCheck KEV)")];
    if let Some(d) = rec
        .get("date_added")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
    {
        facts.push(Fact::new("date_ajout", d));
    }
    let rw = rec.get("knownRansomwareCampaignUse");
    let is_ransomware = rw
        .and_then(|x| x.as_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("known"))
        || rw.and_then(|x| x.as_bool()).unwrap_or(false);
    if is_ransomware {
        facts.push(Fact::new(
            "ransomware",
            "utilisé dans des campagnes ransomware",
        ));
    }
    let xdb = arr_len(rec, "vulncheck_xdb");
    let reported = arr_len(rec, "vulncheck_reported_exploitation");
    if xdb + reported > 0 {
        facts.push(Fact::new(
            "exploits_référencés",
            (xdb + reported).to_string(),
        ));
    }
    if let Some(vp) = rec
        .get("vendorProject")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
    {
        let prod = rec.get("product").and_then(|x| x.as_str()).unwrap_or("");
        facts.push(Fact::new(
            "produit",
            format!("{vp} {prod}").trim().to_string(),
        ));
    }

    let signals = vec![Signal::with_detail(
        "vulncheck",
        "malicious",
        "CVE activement exploité (KEV)",
    )];
    Enrichment {
        source: "vulncheck".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

fn arr_len(v: &Value, key: &str) -> usize {
    v.get(key).and_then(|x| x.as_array()).map_or(0, |a| a.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_kev_present() {
        let v = serde_json::json!({"data": [{
            "date_added": "2021-12-10", "knownRansomwareCampaignUse": "Known",
            "vulncheck_xdb": [{}, {}], "vendorProject": "Apache", "product": "Log4j2"
        }]});
        let e = build(&v);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "kev" && f.value.contains("OUI"))
        );
        assert!(e.facts.iter().any(|f| f.key == "ransomware"));
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "exploits_référencés" && f.value == "2")
        );
        assert_eq!(e.signals[0].category, "malicious");
    }

    #[test]
    fn build_not_kev() {
        let e = build(&serde_json::json!({"data": []}));
        assert!(e.signals.is_empty());
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "kev" && f.value.contains("non"))
        );
    }
}
