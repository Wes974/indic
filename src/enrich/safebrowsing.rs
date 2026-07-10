//! Google Safe Browsing v5 (`hashes:search`) — URL/domaine signalé malware /
//! phishing / unwanted software. Param `key`. Gated.
//!
//! v5 : on canonicalise l'URL, génère les expressions host×path (spec Google),
//! SHA-256 chacune, envoie les préfixes 4 octets, puis on matche les full hashes
//! retournés localement. La réponse est en **protobuf** (l'API v5 ignore
//! `Accept: application/json`) → décodage wire-format minimal ci-dessous.
//! Canonicalisation pragmatique (cas d'évasion exotiques → faux négatifs).
//! Les erreurs ne contiennent JAMAIS l'URL (qui porte `?key=`) → pas de fuite.

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, domain).await
}
pub async fn enrich_url(url: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, url).await
}

async fn run(ctx: &Ctx, input: &str) -> Enrichment {
    let Some(key) = ctx.key("GOOGLE_SAFEBROWSING_API_KEY") else {
        return Enrichment::failed("safebrowsing", "clé absente".into());
    };
    let exprs = expressions(input);
    if exprs.is_empty() {
        return Enrichment::failed("safebrowsing", "non canonicalisable".into());
    }
    let full: Vec<[u8; 32]> = exprs.iter().map(|e| sha256(e)).collect();
    let mut prefixes: Vec<String> = full.iter().map(|h| STANDARD.encode(&h[..4])).collect();
    prefixes.sort();
    prefixes.dedup();

    match search(ctx, key, &prefixes).await {
        Ok(body) => build(&body, &full),
        Err(e) => Enrichment::failed("safebrowsing", format!("{e}")),
    }
}

/// Renvoie le corps protobuf brut. Erreurs sanitizées : jamais l'URL (elle
/// contient `?key=…`), seulement le code HTTP ou un libellé générique.
async fn search(ctx: &Ctx, key: &str, prefixes: &[String]) -> Result<Vec<u8>> {
    let mut params: Vec<(&str, &str)> = vec![("key", key)];
    for p in prefixes {
        params.push(("hashPrefixes", p.as_str()));
    }
    let resp = ctx
        .http
        .get("https://safebrowsing.googleapis.com/v5/hashes:search")
        .query(&params)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("requête Safe Browsing échouée"))?;
    let status = resp.status();
    let body = resp
        .bytes()
        .await
        .map_err(|_| anyhow::anyhow!("lecture réponse échouée"))?;
    if !status.is_success() {
        anyhow::bail!("Safe Browsing HTTP {}", status.as_u16());
    }
    Ok(body.to_vec())
}

fn build(body: &[u8], ours: &[[u8; 32]]) -> Enrichment {
    let mut threats: Vec<String> = Vec::new();
    for (full_hash, types) in parse_response(body) {
        if !ours.iter().any(|h| h.as_slice() == full_hash.as_slice()) {
            continue;
        }
        if types.is_empty() {
            let m = "menace (type non précisé)".to_string();
            if !threats.contains(&m) {
                threats.push(m);
            }
        }
        for t in types {
            let label = threat_label(t);
            if !threats.contains(&label) {
                threats.push(label);
            }
        }
    }
    if threats.is_empty() {
        return Enrichment::ok(
            "safebrowsing",
            vec![Fact::new("safebrowsing", "aucune menace connue")],
        );
    }
    let joined = threats.join(", ");
    Enrichment {
        source: "safebrowsing".into(),
        facts: vec![Fact::new("threats", joined.clone())],
        signals: vec![Signal::with_detail("safebrowsing", "malicious", joined)],
        pivots: vec![],
        error: None,
    }
}

fn threat_label(t: u64) -> String {
    match t {
        1 => "malware",
        2 => "phishing / ingénierie sociale",
        3 => "logiciel indésirable",
        4 => "application potentiellement nuisible",
        _ => "menace (type inconnu)",
    }
    .to_string()
}

fn sha256(s: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().into()
}

// ── Décodage protobuf minimal de SearchHashesResponse ──────────────────────
// full_hashes=1 (repeated FullHash) ; FullHash{ full_hash=1 bytes,
// full_hash_details=2 repeated FullHashDetail } ; FullHashDetail{ threat_type=1 varint }.

/// (full_hash, [threat_type…]) pour chaque FullHash renvoyé.
fn parse_response(buf: &[u8]) -> Vec<(Vec<u8>, Vec<u64>)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let Some((field, wire)) = read_tag(buf, &mut pos) else {
            break;
        };
        if field == 1 && wire == 2 {
            match read_len_delim(buf, &mut pos) {
                Some(sub) => out.push(parse_full_hash(sub)),
                None => break,
            }
        } else if !skip_field(buf, &mut pos, wire) {
            break;
        }
    }
    out
}

fn parse_full_hash(buf: &[u8]) -> (Vec<u8>, Vec<u64>) {
    let (mut hash, mut types) = (Vec::new(), Vec::new());
    let mut pos = 0;
    while pos < buf.len() {
        let Some((field, wire)) = read_tag(buf, &mut pos) else {
            break;
        };
        match (field, wire) {
            (1, 2) => match read_len_delim(buf, &mut pos) {
                Some(b) => hash = b.to_vec(),
                None => break,
            },
            (2, 2) => match read_len_delim(buf, &mut pos) {
                Some(sub) => {
                    if let Some(t) = parse_detail(sub) {
                        types.push(t);
                    }
                }
                None => break,
            },
            _ => {
                if !skip_field(buf, &mut pos, wire) {
                    break;
                }
            }
        }
    }
    (hash, types)
}

fn parse_detail(buf: &[u8]) -> Option<u64> {
    let mut pos = 0;
    let mut tt = None;
    while pos < buf.len() {
        let (field, wire) = read_tag(buf, &mut pos)?;
        if field == 1 && wire == 0 {
            tt = read_varint(buf, &mut pos);
        } else if !skip_field(buf, &mut pos, wire) {
            break;
        }
    }
    tt
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0;
    loop {
        if *pos >= buf.len() || shift >= 64 {
            return None;
        }
        let b = buf[*pos];
        *pos += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
}

fn read_tag(buf: &[u8], pos: &mut usize) -> Option<(u64, u64)> {
    let tag = read_varint(buf, pos)?;
    Some((tag >> 3, tag & 0x7))
}

fn read_len_delim<'a>(buf: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let len = read_varint(buf, pos)? as usize;
    if *pos + len > buf.len() {
        return None;
    }
    let s = &buf[*pos..*pos + len];
    *pos += len;
    Some(s)
}

fn skip_field(buf: &[u8], pos: &mut usize, wire: u64) -> bool {
    match wire {
        0 => read_varint(buf, pos).is_some(),
        1 => {
            *pos += 8;
            *pos <= buf.len()
        }
        2 => read_len_delim(buf, pos).is_some(),
        5 => {
            *pos += 4;
            *pos <= buf.len()
        }
        _ => false,
    }
}

// ── Canonicalisation + expressions (spec Safe Browsing) ────────────────────

/// Expressions host×path (max 30). Chaîne hashée = `host+path`.
fn expressions(input: &str) -> Vec<String> {
    let (host, path) = canonicalize(input);
    if host.is_empty() {
        return vec![];
    }
    let mut out = Vec::new();
    for h in host_suffixes(&host) {
        for p in path_prefixes(&path) {
            let e = format!("{h}{p}");
            if !out.contains(&e) {
                out.push(e);
            }
        }
    }
    out.truncate(30);
    out
}

fn canonicalize(input: &str) -> (String, String) {
    let mut s: String = input
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    s = s.trim().to_string();
    if let Some(i) = s.find('#') {
        s.truncate(i);
    }
    if let Some(i) = s.find("://") {
        s = s[i + 3..].to_string();
    }
    let (host_raw, path_raw) = match s.find('/') {
        Some(i) => (s[..i].to_string(), s[i..].to_string()),
        None => (s.clone(), "/".to_string()),
    };
    let host = host_raw.rsplit('@').next().unwrap_or(&host_raw);
    let host = host
        .split(':')
        .next()
        .unwrap_or(host)
        .trim_matches('.')
        .to_ascii_lowercase();
    let mut host_clean = String::new();
    let mut prev_dot = false;
    for c in host.chars() {
        if c == '.' {
            if prev_dot {
                continue;
            }
            prev_dot = true;
        } else {
            prev_dot = false;
        }
        host_clean.push(c);
    }
    let path = canonicalize_path(if path_raw.is_empty() { "/" } else { &path_raw });
    (host_clean, path)
}

fn canonicalize_path(p: &str) -> String {
    let q_idx = p.find('?');
    let path = match q_idx {
        Some(i) => &p[..i],
        None => p,
    };
    let mut segs: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    let mut out = String::from("/");
    out.push_str(&segs.join("/"));
    if path.ends_with('/') && !out.ends_with('/') {
        out.push('/');
    }
    if let Some(i) = q_idx {
        out.push_str(&p[i..]);
    }
    out
}

fn host_suffixes(host: &str) -> Vec<String> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return vec![host.to_string()];
    }
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    let n = labels.len();
    if n < 2 {
        return vec![host.to_string()];
    }
    let mut out = vec![host.to_string()];
    let max_take = n.min(5);
    for take in (2..=max_take).rev() {
        if take == n {
            continue;
        }
        let s = labels[n - take..].join(".");
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out.truncate(5);
    out
}

fn path_prefixes(path: &str) -> Vec<String> {
    let no_query = path.split('?').next().unwrap_or(path);
    let mut out = Vec::new();
    if path.contains('?') {
        out.push(path.to_string());
    }
    out.push(no_query.to_string());
    let trimmed = no_query.trim_matches('/');
    let comps: Vec<&str> = if trimmed.is_empty() {
        vec![]
    } else {
        trimmed.split('/').collect()
    };
    let dir_comps = if no_query.ends_with('/') {
        comps.len()
    } else {
        comps.len().saturating_sub(1)
    };
    let mut acc = String::from("/");
    if !out.contains(&acc) {
        out.push(acc.clone());
    }
    for c in comps.iter().take(dir_comps) {
        acc.push_str(c);
        acc.push('/');
        if !out.contains(&acc) {
            out.push(acc.clone());
        }
    }
    out.truncate(6);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expressions_example_from_spec() {
        let e = expressions("http://a.b.c/1/2.html?param=1");
        for want in [
            "a.b.c/1/2.html?param=1",
            "a.b.c/1/2.html",
            "a.b.c/",
            "a.b.c/1/",
            "b.c/1/2.html?param=1",
            "b.c/1/2.html",
            "b.c/",
            "b.c/1/",
        ] {
            assert!(
                e.contains(&want.to_string()),
                "manquant: {want} (obtenu {e:?})"
            );
        }
        assert_eq!(e.len(), 8);
    }

    #[test]
    fn expressions_bare_domain() {
        assert_eq!(
            expressions("evil-example.com"),
            vec!["evil-example.com/".to_string()]
        );
    }

    /// Encode un SearchHashesResponse protobuf minimal (1 FullHash + 1 threat_type).
    fn encode_response(hash: &[u8; 32], threat_type: u8) -> Vec<u8> {
        let detail = vec![0x08, threat_type]; // FullHashDetail.threat_type (field 1, varint)
        let mut fh = vec![0x0A, 32]; // FullHash.full_hash (field 1, len 32)
        fh.extend_from_slice(hash);
        fh.push(0x12); // FullHash.full_hash_details (field 2, len-delim)
        fh.push(detail.len() as u8);
        fh.extend_from_slice(&detail);
        let mut resp = vec![0x0A, fh.len() as u8]; // full_hashes (field 1, len-delim)
        resp.extend_from_slice(&fh);
        resp
    }

    #[test]
    fn protobuf_match_malware() {
        let h = sha256("malware.test/");
        let body = encode_response(&h, 1); // 1 = MALWARE
        let e = build(&body, &[h]);
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "malicious");
        assert!(e.facts.iter().any(|f| f.value.contains("malware")));
    }

    #[test]
    fn protobuf_no_match_clean() {
        let h = sha256("something-else/");
        let body = encode_response(&h, 1);
        // notre hash à nous est différent → pas de match
        let e = build(&body, &[sha256("x/")]);
        assert!(e.error.is_none());
        assert!(e.signals.is_empty());
    }

    #[test]
    fn protobuf_empty_is_clean() {
        let e = build(&[], &[sha256("x/")]);
        assert!(e.error.is_none());
        assert!(e.signals.is_empty());
    }
}
