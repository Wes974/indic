//! Détection du type d'observable à partir d'une entrée « n'importe quoi ».

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

#[derive(Debug, Clone)]
pub enum Observable {
    Ip(IpAddr),
    Cidr(String),
    Domain(String),
    Url(String),
    Email(String),
    Hash(String),
    Cve(String),
    Asn(u32),
    /// Adresse crypto (ETH `0x…` ou BTC base58/bech32). Chaîne dérivée du format.
    Crypto(String),
    /// Pseudo / nom d'utilisateur (OSINT). Détecté en dernier, conservateur.
    Username(String),
    /// Numéro de téléphone au format international (`+…`).
    Phone(String),
    /// Adresse de service caché Tor (`….onion`, v2/v3).
    Onion(String),
    /// Package logiciel (`pkg:<éco>/<nom>`) → vulnérabilités OSV. Stocké « ÉcoOSV/nom ».
    Package(String),
}

impl Observable {
    /// Devine le type de `raw`. `None` si non reconnu.
    pub fn detect(raw: &str) -> Option<Observable> {
        let s = raw.trim();
        if s.is_empty() {
            return None;
        }
        if let Ok(ip) = IpAddr::from_str(s) {
            return Some(Observable::Ip(ip));
        }
        if s.contains('/') && IpNet::from_str(s).is_ok() {
            return Some(Observable::Cidr(s.to_string()));
        }
        let low = s.to_ascii_lowercase();
        if low.starts_with("http://") || low.starts_with("https://") {
            return Some(Observable::Url(s.to_string()));
        }
        // purl `pkg:<éco>/<nom>` — préfixe explicite, détecté tôt.
        if let Some(pkg) = parse_package(s) {
            return Some(Observable::Package(pkg));
        }
        if is_cve(&low) {
            return Some(Observable::Cve(low.to_uppercase()));
        }
        if is_hash(&low) {
            return Some(Observable::Hash(low));
        }
        if let Some(chain) = crypto_chain(s) {
            // ETH = hex insensible à la casse → lowercased ; BTC = base58/bech32 sensible → tel quel.
            let addr = if chain == "eth" {
                low.clone()
            } else {
                s.to_string()
            };
            return Some(Observable::Crypto(addr));
        }
        if let Some((local, domain)) = s.split_once('@')
            && !local.is_empty()
            && is_domain(domain)
        {
            return Some(Observable::Email(low));
        }
        if let Some(num) = low.strip_prefix("as")
            && let Ok(n) = num.parse::<u32>()
        {
            return Some(Observable::Asn(n));
        }
        if is_onion(&low) {
            return Some(Observable::Onion(low));
        }
        if let Some(phone) = detect_phone(s) {
            return Some(Observable::Phone(phone));
        }
        if is_domain(s) {
            return Some(Observable::Domain(low));
        }
        if is_username(s) {
            return Some(Observable::Username(low));
        }
        None
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Observable::Ip(_) => "ip",
            Observable::Cidr(_) => "cidr",
            Observable::Domain(_) => "domain",
            Observable::Url(_) => "url",
            Observable::Email(_) => "email",
            Observable::Hash(_) => "hash",
            Observable::Cve(_) => "cve",
            Observable::Asn(_) => "asn",
            Observable::Crypto(_) => "crypto",
            Observable::Username(_) => "username",
            Observable::Phone(_) => "phone",
            Observable::Onion(_) => "onion",
            Observable::Package(_) => "package",
        }
    }

    /// Valeur canonique (pour affichage / enrichers).
    pub fn value(&self) -> String {
        match self {
            Observable::Ip(ip) => ip.to_string(),
            Observable::Asn(n) => format!("AS{n}"),
            Observable::Cidr(s)
            | Observable::Domain(s)
            | Observable::Url(s)
            | Observable::Email(s)
            | Observable::Hash(s)
            | Observable::Cve(s)
            | Observable::Crypto(s)
            | Observable::Username(s)
            | Observable::Phone(s)
            | Observable::Onion(s)
            | Observable::Package(s) => s.clone(),
        }
    }
}

/// Domaine enregistrable (eTLD+1) via la Public Suffix List.
/// `api.mixpanel.com` → `mixpanel.com` ; `google.co.uk` → `google.co.uk`.
pub fn registrable_domain(domain: &str) -> Option<String> {
    psl::domain_str(domain).map(str::to_string)
}

/// purl `pkg:<éco>/<nom>` → « <ÉcosystèmeOSV>/<nom> » (nom OSV canonique).
/// Écosystèmes usuels mappés ; inconnu → `None` (détection conservatrice).
/// `split_once('/')` sur le 1er `/` : les noms scoped npm (`@angular/core`) restent entiers.
fn parse_package(s: &str) -> Option<String> {
    let (eco, name) = s.strip_prefix("pkg:")?.split_once('/')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let osv_eco = match eco.to_ascii_lowercase().as_str() {
        "pypi" => "PyPI",
        "npm" => "npm",
        "cargo" | "crates" | "crates.io" => "crates.io",
        "go" | "golang" => "Go",
        "gem" | "rubygems" => "RubyGems",
        "maven" => "Maven",
        "nuget" => "NuGet",
        "composer" | "packagist" => "Packagist",
        "hex" => "Hex",
        "pub" => "Pub",
        "swift" | "swifturl" => "SwiftURL",
        "hackage" => "Hackage",
        "cran" => "CRAN",
        _ => return None,
    };
    Some(format!("{osv_eco}/{name}"))
}

/// Service caché Tor : base32 (16 = v2 / 56 = v3) + `.onion`.
fn is_onion(s: &str) -> bool {
    s.strip_suffix(".onion").is_some_and(|label| {
        matches!(label.len(), 16 | 56)
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    })
}

/// Numéro international : `+` puis 8-15 chiffres (séparateurs ` -.()` tolérés).
/// Normalisé en `+<chiffres>`.
fn detect_phone(s: &str) -> Option<String> {
    let rest = s.strip_prefix('+')?;
    if !rest
        .chars()
        .all(|c| c.is_ascii_digit() || " -.()".contains(c))
    {
        return None;
    }
    let digits: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
    (8..=15)
        .contains(&digits.len())
        .then(|| format!("+{digits}"))
}

/// `CVE-YYYY-NNNN…`
fn is_cve(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("cve-") else {
        return false;
    };
    let mut parts = rest.split('-');
    let (Some(year), Some(num), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    year.len() == 4
        && year.chars().all(|c| c.is_ascii_digit())
        && num.len() >= 4
        && num.chars().all(|c| c.is_ascii_digit())
}

/// md5 (32) / sha1 (40) / sha256 (64) — hex pur.
fn is_hash(s: &str) -> bool {
    matches!(s.len(), 32 | 40 | 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Détecte une adresse crypto et renvoie sa chaîne (`eth`/`btc`), sinon `None`.
/// ETH = `0x` + 40 hex ; BTC = base58 (`1`/`3`, 26-35) ou bech32 (`bc1…`).
fn crypto_chain(s: &str) -> Option<&'static str> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
        && matches!(hex.len(), 40 | 64)
        && hex.chars().all(|c| c.is_ascii_hexdigit())
    {
        // 0x+40hex = adresse ETH ; 0x+64hex = hash de transaction ETH.
        return Some("eth");
    }
    let low = s.to_ascii_lowercase();
    if let Some(rest) = low.strip_prefix("bc1")
        && (11..=71).contains(&rest.len())
        && rest.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return Some("btc");
    }
    if (s.starts_with('1') || s.starts_with('3'))
        && (26..=35).contains(&s.len())
        && s.chars().all(is_base58)
    {
        return Some("btc");
    }
    None
}

/// Alphabet base58 (Bitcoin) : alphanumérique sans `0`, `O`, `I`, `l`.
fn is_base58(c: char) -> bool {
    c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l')
}

/// Heuristique domaine : labels alphanumériques/tirets, TLD non purement numérique.
fn is_domain(s: &str) -> bool {
    if s.len() > 253 || !s.contains('.') {
        return false;
    }
    if s.contains(|c: char| c.is_whitespace() || c == '/' || c == '@' || c == ':') {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    let labels_ok = labels.iter().all(|l| {
        !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    let tld_ok = labels
        .last()
        .is_some_and(|tld| tld.chars().any(|c| c.is_ascii_alphabetic()));
    labels_ok && tld_ok
}

/// Pseudo conservateur : 3-30 chars, commence par un alphanum, `[a-z0-9_-]`, ≥ 1 lettre.
fn is_username(s: &str) -> bool {
    let len = s.chars().count();
    (3..=30).contains(&len)
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && s.chars().any(|c| c.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_eth_lowercased() {
        let e = Observable::detect("0x8589427373D6D84E98730D7795D8f6f8731FDA16");
        assert!(matches!(e, Some(Observable::Crypto(a))
            if a == "0x8589427373d6d84e98730d7795d8f6f8731fda16"));
    }

    #[test]
    fn detects_btc_forms() {
        for a in [
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        ] {
            assert!(
                matches!(Observable::detect(a), Some(Observable::Crypto(_))),
                "{a}"
            );
        }
    }

    #[test]
    fn no_false_positive() {
        assert!(matches!(
            Observable::detect("example.com"),
            Some(Observable::Domain(_))
        ));
        assert!(matches!(
            Observable::detect("d41d8cd98f00b204e9800998ecf8427e"),
            Some(Observable::Hash(_))
        ));
        assert!(matches!(
            Observable::detect("8.8.8.8"),
            Some(Observable::Ip(_))
        ));
    }

    #[test]
    fn username_conservative() {
        assert!(matches!(
            Observable::detect("elonmusk"),
            Some(Observable::Username(_))
        ));
        assert!(matches!(
            Observable::detect("john_doe-42"),
            Some(Observable::Username(_))
        ));
        assert!(Observable::detect("ab").is_none()); // trop court
        assert!(Observable::detect("12345").is_none()); // aucune lettre
    }

    #[test]
    fn detects_package_purl() {
        assert!(matches!(
            Observable::detect("pkg:pypi/requests"),
            Some(Observable::Package(p)) if p == "PyPI/requests"
        ));
        // Nom scoped npm conservé entier (split sur le 1er '/').
        assert!(matches!(
            Observable::detect("pkg:npm/@angular/core"),
            Some(Observable::Package(p)) if p == "npm/@angular/core"
        ));
        // Écosystème inconnu → non reconnu comme package.
        assert!(!matches!(
            Observable::detect("pkg:doesnotexist/foo"),
            Some(Observable::Package(_))
        ));
    }
}
