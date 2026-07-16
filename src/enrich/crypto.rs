//! Enricher crypto (BTC/ETH) : sanctions OFAC (dataset offline) + (ETH) solde et
//! nombre de transactions via Etherscan V2 (`api.etherscan.io/v2/api`, chainid=1).

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact, Pivot};
use crate::model::Signal;

/// Chaîne dérivée de l'adresse (`eth` si `0x…`, sinon `btc`).
pub fn chain(addr: &str) -> &'static str {
    if addr.starts_with("0x") { "eth" } else { "btc" }
}

/// Vrai si `addr` est un **hash de transaction** ETH (`0x` + 64 hex) plutôt
/// qu'une adresse (`0x` + 40 hex).
fn is_eth_tx(addr: &str) -> bool {
    addr.strip_prefix("0x")
        .or_else(|| addr.strip_prefix("0X"))
        .is_some_and(|h| h.len() == 64)
}

/// Sanctions OFAC + type de chaîne (offline, pas de réseau).
pub async fn ofac(addr: &str, ctx: &Ctx) -> Enrichment {
    // Un txid n'est pas une adresse → pas de check sanctions, juste le contexte.
    if is_eth_tx(addr) {
        return Enrichment {
            source: "ofac".into(),
            facts: vec![
                Fact::new("chain", "Ethereum"),
                Fact::new("type", "hash de transaction"),
            ],
            signals: vec![],
            pivots: vec![],
            error: None,
        };
    }
    let ch = chain(addr);
    let mut facts = vec![Fact::new(
        "chain",
        if ch == "eth" { "Ethereum" } else { "Bitcoin" },
    )];
    let mut signals = Vec::new();
    if ctx.store.load().is_sanctioned_crypto(addr) {
        facts.push(Fact::new("ofac", "OUI — adresse sanctionnée"));
        signals.push(Signal::with_detail(
            "ofac_sdn",
            "malicious",
            "adresse crypto sanctionnée (OFAC SDN)",
        ));
    } else {
        facts.push(Fact::new("ofac", "non listée"));
    }
    Enrichment {
        source: "ofac".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

/// Etherscan V2 (ETH uniquement) : solde + nombre de tx envoyées (nonce). Gated.
pub async fn etherscan(addr: &str, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("ETHERSCAN_API_KEY") else {
        return Enrichment::failed("etherscan", "clé absente".into());
    };
    // Hash de transaction → détails de la tx ; sinon adresse → solde + nonce.
    if is_eth_tx(addr) {
        return match fetch_tx(&ctx.http, addr, key).await {
            Ok(e) => e,
            Err(e) => Enrichment::failed("etherscan", super::scrub(format!("{e:#}"), key)),
        };
    }
    match fetch(&ctx.http, addr, key).await {
        Ok((wei, nonce)) => build(wei, nonce),
        Err(e) => Enrichment::failed("etherscan", super::scrub(format!("{e:#}"), key)),
    }
}

/// Détails d'une transaction ETH via `eth_getTransactionByHash` (from/to/valeur/
/// bloc) + pivots vers les adresses impliquées (elles-mêmes ré-analysables).
async fn fetch_tx(http: &reqwest::Client, txid: &str, key: &str) -> Result<Enrichment> {
    const BASE: &str = "https://api.etherscan.io/v2/api";
    let v: Value = http
        .get(BASE)
        .query(&[
            ("chainid", "1"),
            ("module", "proxy"),
            ("action", "eth_getTransactionByHash"),
            ("txhash", txid),
            ("apikey", key),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let Some(r) = v.get("result").filter(|x| !x.is_null()) else {
        return Ok(Enrichment::ok(
            "etherscan",
            vec![Fact::new("etherscan", "transaction introuvable")],
        ));
    };
    let hexnum = |k: &str| {
        r.get(k)
            .and_then(Value::as_str)
            .and_then(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16).ok())
    };
    let from = r.get("from").and_then(Value::as_str).unwrap_or("?");
    let to = r.get("to").and_then(Value::as_str).unwrap_or("?");
    let eth = hexnum("value").unwrap_or(0) as f64 / 1e18;

    let mut facts = vec![
        Fact::new("from", from),
        Fact::new("to", to),
        Fact::new("valeur", format!("{eth:.6} ETH")),
    ];
    if let Some(b) = hexnum("blockNumber") {
        facts.push(Fact::new("bloc", b.to_string()));
    }
    let mut pivots = Vec::new();
    for (rel, a) in [("from", from), ("to", to)] {
        if a.len() == 42 && a.starts_with("0x") {
            pivots.push(Pivot {
                relation: rel.into(),
                kind: "crypto".into(),
                value: a.to_string(),
            });
        }
    }
    Ok(Enrichment {
        source: "etherscan".into(),
        facts,
        signals: vec![],
        pivots,
        error: None,
    })
}

async fn fetch(http: &reqwest::Client, addr: &str, key: &str) -> Result<(u128, u64)> {
    const BASE: &str = "https://api.etherscan.io/v2/api";
    // Solde (wei, décimal string) — u128 suffit (offre totale ETH ≪ u128::MAX).
    let b: Value = http
        .get(BASE)
        .query(&[
            ("chainid", "1"),
            ("module", "account"),
            ("action", "balance"),
            ("address", addr),
            ("tag", "latest"),
            ("apikey", key),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let wei: u128 = b
        .get("result")
        .and_then(|x| x.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // Nombre de tx envoyées (nonce, hex) via le proxy JSON-RPC.
    let n: Value = http
        .get(BASE)
        .query(&[
            ("chainid", "1"),
            ("module", "proxy"),
            ("action", "eth_getTransactionCount"),
            ("address", addr),
            ("tag", "latest"),
            ("apikey", key),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let nonce = n
        .get("result")
        .and_then(|x| x.as_str())
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    Ok((wei, nonce))
}

fn build(wei: u128, nonce: u64) -> Enrichment {
    let eth = wei as f64 / 1e18;
    Enrichment {
        source: "etherscan".into(),
        facts: vec![
            Fact::new("balance", format!("{eth:.4} ETH")),
            Fact::new("tx_envoyées", nonce.to_string()),
        ],
        signals: vec![],
        pivots: vec![],
        error: None,
    }
}

/// mempool.space (BTC) : solde + total reçu + nombre de tx. Keyless, live.
/// Complète Etherscan (ETH) côté Bitcoin.
pub async fn mempool(addr: &str, ctx: &Ctx) -> Enrichment {
    if chain(addr) != "btc" {
        return Enrichment::failed("mempool", "adresse BTC uniquement".into());
    }
    let url = format!("https://mempool.space/api/address/{addr}");
    match fetch_json(&ctx.http, &url).await {
        Ok(v) => parse_mempool(&v),
        Err(e) => Enrichment::failed("mempool", format!("{e:#}")),
    }
}

async fn fetch_json(http: &reqwest::Client, url: &str) -> Result<Value> {
    Ok(http.get(url).send().await?.error_for_status()?.json().await?)
}

/// Solde = reçu − dépensé (satoshis → BTC). `chain_stats` = confirmé on-chain ;
/// le mempool non confirmé est ignoré pour le solde.
fn parse_mempool(v: &Value) -> Enrichment {
    let stat = |k: &str| {
        v.get("chain_stats")
            .and_then(|s| s.get(k))
            .and_then(Value::as_i64)
            .unwrap_or(0)
    };
    let funded = stat("funded_txo_sum");
    let spent = stat("spent_txo_sum");
    let balance = (funded - spent) as f64 / 1e8;
    let received = funded as f64 / 1e8;
    Enrichment::ok(
        "mempool",
        vec![
            Fact::new("chain", "Bitcoin"),
            Fact::new("balance", format!("{balance:.8} BTC")),
            Fact::new("reçu_total", format!("{received:.8} BTC")),
            Fact::new("tx", stat("tx_count").to_string()),
        ],
    )
}

/// Ransomwhere (offline) : adresse BTC ayant reçu des paiements de ransomware,
/// avec la famille (Locky, Conti, Netwalker…). Keyless.
pub async fn ransomwhere(addr: &str, ctx: &Ctx) -> Enrichment {
    if chain(addr) != "btc" {
        return Enrichment::failed("ransomwhere", "adresse BTC uniquement".into());
    }
    let store = ctx.store.load();
    let mut facts = Vec::new();
    let mut signals = Vec::new();
    match store.ransomware_family(addr) {
        Some(family) => {
            facts.push(Fact::new("ransomware", format!("OUI — {family}")));
            signals.push(Signal::with_detail(
                "ransomwhere",
                "malicious",
                format!("adresse de ransomware ({family})"),
            ));
        }
        None => facts.push(Fact::new("ransomware", "non listée")),
    }
    Enrichment {
        source: "ransomwhere".into(),
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
    fn chain_detection() {
        assert_eq!(chain("0xabc"), "eth");
        assert_eq!(chain("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), "btc");
    }

    #[test]
    fn etherscan_build() {
        let e = build(1_500_000_000_000_000_000, 42);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "balance" && f.value.contains("1.5"))
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "tx_envoyées" && f.value == "42")
        );
    }

    #[test]
    fn eth_tx_vs_address() {
        assert!(is_eth_tx(&format!("0x{}", "a".repeat(64))));
        assert!(!is_eth_tx(&format!("0x{}", "a".repeat(40))));
        assert!(!is_eth_tx("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
    }

    #[test]
    fn mempool_parses_balance() {
        let v = serde_json::json!({
            "chain_stats": {
                "funded_txo_sum": 5_722_561_471_i64,
                "spent_txo_sum": 0,
                "tx_count": 63639
            }
        });
        let e = parse_mempool(&v);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "balance" && f.value.starts_with("57.2"))
        );
        assert!(e.facts.iter().any(|f| f.key == "tx" && f.value == "63639"));
    }
}
