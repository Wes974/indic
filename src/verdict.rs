//! Verdict pondéré — agrège les signaux avec un poids par **catégorie** et un
//! **prior de popularité** (domaines majeurs légitimes), pour éviter les faux
//! positifs sur les plateformes qui *hébergent* du malware sans être malveillantes
//! (ex. github.com flaggé « malveillant » parce que des IOC y sont hébergés).

use std::collections::BTreeMap;

use serde::Serialize;

use crate::model::Signal;

/// Verdict calibré présenté à l'utilisateur.
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    /// `clean` | `suspect` | `malicious`.
    pub label: &'static str,
    /// Score de malice pondéré (peut être négatif si prior de popularité fort).
    pub score: i32,
    /// Poids brut des signaux, avant prior (pour transparence).
    pub raw: i32,
    /// Explication en clair.
    pub rationale: String,
}

/// Poids de menace d'un signal selon sa catégorie. L'anonymisation (tor/vpn/
/// proxy), l'infra et l'« exposure » (code/pastes) ne pèsent pas ; les logs
/// d'infostealer pèsent peu (comptes volés ≠ domaine malveillant).
fn category_weight(category: &str) -> i32 {
    match category {
        "c2" | "botnet" => 5,
        "malicious" | "malware" | "phishing" | "compromised" | "sanctions" => 3,
        "abuse" | "threat" => 2,
        "suspicious" => 1,
        "infostealer" => 1,
        _ => 0,
    }
}

/// Pourquoi un observable bénéficie d'un prior « légitime ». Le motif compte :
/// un domaine majeur est innocenté parce que les IOC portent sur du contenu
/// qu'il héberge ; un resolver DNS public l'est parce qu'il apparaît dans les
/// journaux de trafic de tout le monde, victimes comprises. Deux raisons
/// différentes, deux explications différentes à l'écran.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Trust {
    /// Aucun prior.
    None,
    /// Domaine majeur, réservé, ou top-liste de popularité.
    Domain,
    /// Resolver DNS public identifié (Cloudflare, Quad9, NextDNS…).
    Resolver,
}

impl Trust {
    fn is_trusted(self) -> bool {
        self != Trust::None
    }
}

/// Calcule le verdict à partir des signaux et de la confiance dans l'observable.
/// La **corroboration** prime : une seule source ne suffit pas à condamner (les
/// feeds ont des FP — placeholders, sinkholes, hébergement), il faut plusieurs
/// sources indépendantes. Le C2 (feed haute confiance) est la seule exception.
/// `trusted` = domaine majeur ou réservé → prior « légitime ».
pub fn compute(signals: &[Signal], trust: Trust) -> Verdict {
    let trusted = trust.is_trusted();
    // Poids **max par source distincte** : une source bavarde (plusieurs
    // signaux) ne pèse pas plus lourd qu'une source sobre.
    let mut by_source: BTreeMap<&str, i32> = BTreeMap::new();
    for s in signals {
        let w = category_weight(&s.category);
        let slot = by_source.entry(s.source.as_str()).or_insert(0);
        *slot = (*slot).max(w);
    }
    let raw: i32 = by_source.values().sum();
    // Sources « sérieuses » = menace moyenne ou forte (poids ≥ 3).
    let serious = by_source.values().filter(|&&w| w >= 3).count();
    // Au moins une source C2/botnet (poids ≥ 5) : plus grave, seuil abaissé.
    let has_c2 = by_source.values().any(|&w| w >= 5);
    let pop_bonus = if trusted { 8 } else { 0 };
    let score = raw - pop_bonus;

    // Un prior de confiance n'est pas un blanc-seing : il cède devant un
    // faisceau large. Seuils relevés d'un cran pour un observable de confiance
    // — un domaine majeur héberge du contenu tiers, ce qui explique légitimement
    // quelques signaux, mais pas quatre sources indépendantes qui le désignent
    // *lui*. C'est le cas du site populaire compromis : le raisonnement « les
    // IOC portent sur ce qu'il héberge » devient faux dès qu'il est la cible.
    let condemn = if trusted { 4 } else { 3 };
    let condemn_c2 = if trusted { 3 } else { 2 };

    let (label, rationale): (&'static str, String) = if serious >= condemn
        || (has_c2 && serious >= condemn_c2)
    {
        (
            "malicious",
            if trusted {
                format!(
                    "Menace corroborée par {serious} sources indépendantes (poids {raw}) — \
                     faisceau trop large pour être imputé au seul contenu hébergé, le prior \
                     de confiance ne tient pas."
                )
            } else {
                format!("Menace corroborée par {serious} sources indépendantes (poids {raw}).")
            },
        )
    } else if trust == Trust::Domain && raw > 0 {
        (
            "clean",
            format!(
                "Signaux présents (poids {raw}) mais domaine de confiance (majeur ou \
                 réservé) — les IOC portent sur du contenu hébergé ou des comptes \
                 référencés, pas sur le domaine lui-même."
            ),
        )
    } else if trust == Trust::Resolver && raw > 0 {
        (
            "clean",
            format!(
                "Signaux présents (poids {raw}) mais resolver DNS public identifié — ces \
                 adresses figurent dans les journaux de tout le monde, victimes comprises, \
                 ce qui les fait remonter dans les feeds d'abus."
            ),
        )
    } else if serious >= 2 || has_c2 {
        (
            "suspect",
            format!("Signaux de menace concordants (poids {raw}) — à confirmer."),
        )
    } else if serious == 1 {
        (
            "suspect",
            format!("Une seule source signale une menace (poids {raw}) — non corroboré, prudence."),
        )
    } else {
        ("clean", "Aucun signal de menace corroboré.".to_string())
    };

    Verdict {
        label,
        score,
        raw,
        rationale,
    }
}

/// L'apex mérite-t-il un prior de confiance ? Domaine majeur légitime **ou**
/// domaine réservé (RFC 2606 / 6761, jamais malveillant).
pub fn is_trusted_domain(apex: &str) -> bool {
    is_reserved_domain(apex) || POPULAR.binary_search(&apex).is_ok()
}

/// Domaine réservé / à usage spécial (RFC 2606 & 6761) — `example.*`, `.test`,
/// `.invalid`, `.localhost`. Ne peut pas être un vrai IOC.
fn is_reserved_domain(apex: &str) -> bool {
    matches!(
        apex,
        "example.com" | "example.net" | "example.org" | "example.edu" | "localhost"
    ) || apex.ends_with(".test")
        || apex.ends_with(".invalid")
        || apex.ends_with(".localhost")
        || apex.ends_with(".example")
}

/// Domaines majeurs / infra légitimes (apex), **triés** pour `binary_search`.
/// Resolvers DNS publics majeurs. **Périmètre volontairement étroit** : on
/// n'innocente pas « tout Cloudflare » — les IP de CDN hébergent réellement du
/// contenu malveillant et leurs signaux sont alors légitimes. Seules les
/// adresses de résolution, qui apparaissent dans les journaux de trafic de
/// n'importe qui, bénéficient du prior.
///
/// Comparées en `IpAddr` et non en texte : `2606:4700:4700::1111` s'écrit de
/// plusieurs façons, une comparaison de chaînes en raterait la moitié.
const PUBLIC_RESOLVERS: &[&str] = &[
    // Cloudflare (1.1.1.2/.3 = filtrage malware/adulte)
    "1.1.1.1",
    "1.0.0.1",
    "1.1.1.2",
    "1.0.0.2",
    "1.1.1.3",
    "1.0.0.3",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2606:4700:4700::1112",
    "2606:4700:4700::1002",
    // Google
    "8.8.8.8",
    "8.8.4.4",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    // Quad9
    "9.9.9.9",
    "149.112.112.112",
    "9.9.9.10",
    "149.112.112.10",
    "9.9.9.11",
    "149.112.112.11",
    "2620:fe::fe",
    "2620:fe::9",
    "2620:fe::10",
    // OpenDNS / Cisco
    "208.67.222.222",
    "208.67.220.220",
    "208.67.222.123",
    "208.67.220.123",
    "2620:119:35::35",
    "2620:119:53::53",
    // AdGuard
    "94.140.14.14",
    "94.140.15.15",
    "94.140.14.15",
    "94.140.15.16",
    "2a10:50c0::ad1:ff",
    "2a10:50c0::ad2:ff",
    // CleanBrowsing
    "185.228.168.9",
    "185.228.169.9",
    "185.228.168.10",
    "185.228.169.11",
    // NextDNS
    "45.90.28.0",
    "45.90.30.0",
    // ControlD
    "76.76.2.0",
    "76.76.10.0",
    // dns0.eu
    "193.110.81.0",
    "185.253.5.0",
    // Mullvad
    "194.242.2.2",
    // Comodo Secure DNS
    "8.26.56.26",
    "8.20.247.20",
];

/// Ensemble normalisé, construit une fois : parser 50 chaînes à chaque lookup
/// serait du gaspillage pur.
static RESOLVER_SET: std::sync::LazyLock<std::collections::HashSet<std::net::IpAddr>> =
    std::sync::LazyLock::new(|| {
        PUBLIC_RESOLVERS
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect()
    });

/// Vrai si `ip` est un resolver DNS public connu.
pub fn is_public_resolver(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>()
        .is_ok_and(|a| RESOLVER_SET.contains(&a))
}

/// Prior de popularité — première passe curée ; un feed top-1M (Majestic/Tranco)
/// pourra l'élargir plus tard.
const POPULAR: &[&str] = &[
    "adobe.com",
    "akamai.com",
    "akamaihd.net",
    "amazon.com",
    "amazonaws.com",
    "apache.org",
    "apple.com",
    "atlassian.com",
    "azure.com",
    "azurewebsites.net",
    "baidu.com",
    "bing.com",
    "bitbucket.org",
    "blogspot.com",
    "cisco.com",
    "citrix.com",
    "cloudflare.com",
    "cloudflare.net",
    "cloudfront.net",
    "cnn.com",
    "debian.org",
    "digicert.com",
    "digitalocean.com",
    "discord.com",
    "docker.com",
    "dropbox.com",
    "ebay.com",
    "facebook.com",
    "fastly.net",
    "fbcdn.net",
    "gandi.net",
    "github.com",
    "github.io",
    "githubusercontent.com",
    "gitlab.com",
    "gmail.com",
    "godaddy.com",
    "google.com",
    "googleapis.com",
    "googleusercontent.com",
    "gstatic.com",
    "heroku.com",
    "hetzner.com",
    "hubspot.com",
    "ibm.com",
    "icloud.com",
    "instagram.com",
    "intel.com",
    "jsdelivr.net",
    "linkedin.com",
    "live.com",
    "mailchimp.com",
    "medium.com",
    "microsoft.com",
    "microsoftonline.com",
    "mozilla.org",
    "msn.com",
    "netflix.com",
    "nginx.com",
    "nodejs.org",
    "npmjs.com",
    "nvidia.com",
    "office.com",
    "office365.com",
    "okta.com",
    "openai.com",
    "oracle.com",
    "outlook.com",
    "ovh.com",
    "paypal.com",
    "pinterest.com",
    "pypi.org",
    "python.org",
    "quora.com",
    "reddit.com",
    "salesforce.com",
    "sentry.io",
    "shopify.com",
    "slack.com",
    "sourceforge.net",
    "spotify.com",
    "stackoverflow.com",
    "steamcommunity.com",
    "steampowered.com",
    "telegram.org",
    "tiktok.com",
    "twitch.tv",
    "twitter.com",
    "ubuntu.com",
    "vercel.app",
    "vimeo.com",
    "vk.com",
    "whatsapp.com",
    "wikipedia.org",
    "windows.net",
    "wordpress.com",
    "x.com",
    "yahoo.com",
    "yandex.com",
    "youtube.com",
    "zoom.us",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Signal;

    fn sig(source: &str, cat: &str) -> Signal {
        Signal::new(source, cat)
    }

    #[test]
    fn popular_list_is_sorted() {
        // Requis pour binary_search.
        assert!(
            POPULAR.windows(2).all(|w| w[0] < w[1]),
            "POPULAR doit être trié et sans doublon"
        );
    }

    #[test]
    fn domaine_majeur_reste_clean() {
        // github.com : signaux dus au contenu hébergé, mais domaine majeur.
        let sigs = [
            sig("threatfox", "malicious"),
            sig("hudsonrock", "infostealer"),
        ];
        assert_eq!(compute(&sigs, Trust::Domain).label, "clean");
        assert!(is_trusted_domain("github.com") && is_trusted_domain("google.com"));
    }

    #[test]
    fn domaine_reserve_clean() {
        // example.com flaggé par des sources (placeholder de malware) → réservé → clean.
        let sigs = [sig("urlhaus", "malicious"), sig("blocklist", "suspicious")];
        assert_eq!(compute(&sigs, Trust::Domain).label, "clean");
        assert!(is_trusted_domain("example.com"));
        assert!(!is_trusted_domain("evil-c2-domain.tk"));
    }

    #[test]
    fn corroboration_requise() {
        // 1 source « malicious » → suspect (non corroboré), pas malicious.
        assert_eq!(
            compute(&[sig("urlhaus", "malicious")], Trust::None).label,
            "suspect"
        );
        // 2 sources → suspect.
        assert_eq!(
            compute(
                &[sig("urlhaus", "malicious"), sig("threatfox", "malicious")],
                Trust::None,
            )
            .label,
            "suspect"
        );
        // 3 sources indépendantes → malicious.
        assert_eq!(
            compute(
                &[
                    sig("urlhaus", "malicious"),
                    sig("threatfox", "malicious"),
                    sig("otx", "malware"),
                ],
                Trust::None,
            )
            .label,
            "malicious"
        );
    }

    #[test]
    fn c2_isole_suspect_corrobore_malicious() {
        // Un C2 seul (feed haute confiance) → suspect.
        assert_eq!(compute(&[sig("feodo", "c2")], Trust::None).label, "suspect");
        // C2 + une autre source sérieuse → malicious.
        assert_eq!(
            compute(
                &[sig("feodo", "c2"), sig("urlhaus", "malicious")],
                Trust::None
            )
            .label,
            "malicious"
        );
    }

    #[test]
    fn source_bavarde_ne_sur_compte_pas() {
        // Même source émettant 3 signaux ne vaut pas 3 sources distinctes.
        let sigs = [
            sig("threatfox", "malicious"),
            sig("threatfox", "malicious"),
            sig("threatfox", "malicious"),
        ];
        assert_eq!(compute(&sigs, Trust::None).label, "suspect");
    }

    #[test]
    fn propre_sans_signal() {
        assert_eq!(compute(&[], Trust::None).label, "clean");
        // Anonymisation/infra ne pèsent pas.
        assert_eq!(
            compute(
                &[sig("tor_list", "tor"), sig("asdb", "datacenter")],
                Trust::None
            )
            .label,
            "clean"
        );
    }

    /// Cas réel qui a motivé ce prior : `1.1.1.1` sortait « suspect » parce
    /// qu'ipdata l'annonce `malicious` pendant que dshield et MISP le voient en
    /// `threat`. Un resolver DNS public apparaît dans les journaux de tout le
    /// monde, victimes comprises — ce n'est pas un attaquant.
    #[test]
    fn public_resolver_survives_a_single_malicious_source() {
        let sigs = [
            sig("ipdata", "malicious"),
            sig("dshield", "threat"),
            sig("misp", "threat"),
        ];
        assert_eq!(compute(&sigs, Trust::None).label, "suspect");
        let v = compute(&sigs, Trust::Resolver);
        assert_eq!(v.label, "clean");
        assert!(
            v.rationale.contains("resolver DNS public"),
            "l'explication doit dire pourquoi, pas juste innocenter"
        );
    }

    /// Un prior n'est pas un blanc-seing : au-delà de quatre sources sérieuses
    /// indépendantes, il cède — que ce soit un domaine majeur ou un resolver.
    #[test]
    fn the_prior_yields_to_a_broad_consensus() {
        let four: Vec<Signal> = ["a", "b", "c", "d"]
            .iter()
            .map(|s| sig(s, "malicious"))
            .collect();
        assert_eq!(compute(&four, Trust::Resolver).label, "malicious");
        assert_eq!(compute(&four, Trust::Domain).label, "malicious");
        assert!(
            compute(&four, Trust::Domain)
                .rationale
                .contains("ne tient pas"),
            "le texte doit dire que le prior a cédé, pas condamner sans expliquer"
        );

        // Trois sources : le prior tient encore, des deux côtés.
        let three: Vec<Signal> = ["a", "b", "c"]
            .iter()
            .map(|s| sig(s, "malicious"))
            .collect();
        assert_eq!(compute(&three, Trust::Resolver).label, "clean");
        assert_eq!(compute(&three, Trust::Domain).label, "clean");
        // Sans prior, trois sources suffisent : c'est bien le prior qui agit.
        assert_eq!(compute(&three, Trust::None).label, "malicious");
    }

    /// **Régression.** Avant correction, `trust == Domain` court-circuitait vers
    /// `clean` avant le test de corroboration : aucun nombre de sources ne
    /// pouvait condamner un domaine du top-100k. C'est précisément la population
    /// qui se fait compromettre — un site populaire servant une charge après
    /// compromission ressortait « Propre ».
    #[test]
    fn a_compromised_popular_domain_is_no_longer_whitewashed() {
        let sigs: Vec<Signal> = ["urlhaus", "threatfox", "safebrowsing", "virustotal", "otx"]
            .iter()
            .map(|s| sig(s, "malicious"))
            .collect();
        assert_eq!(compute(&sigs, Trust::Domain).label, "malicious");
    }

    /// Le cas de référence du README doit rester intact : `github.com` porte des
    /// signaux qui visent du contenu hébergé (2 sources sérieuses), pas le
    /// domaine. Il reste « propre ».
    #[test]
    fn github_style_hosted_content_stays_clean() {
        let sigs = [
            sig("hudsonrock", "infostealer"),
            sig("threatfox", "malicious"),
            sig("urlhaus", "malicious"),
            sig("github", "exposure"),
        ];
        assert_eq!(compute(&sigs, Trust::Domain).label, "clean");
    }

    /// Périmètre volontairement étroit    /// Périmètre volontairement étroit : les adresses de résolution seulement.
    /// Une IP de CDN Cloudflare héberge réellement du contenu malveillant, ses
    /// signaux sont légitimes et ne doivent pas être atténués.
    #[test]
    fn only_resolver_addresses_are_trusted() {
        assert!(is_public_resolver("1.1.1.1"));
        assert!(is_public_resolver("9.9.9.9"));
        assert!(is_public_resolver("45.90.28.0")); // NextDNS
        assert!(!is_public_resolver("104.16.0.1")); // CDN Cloudflare
        assert!(!is_public_resolver("1.1.1.4")); // voisin, pas un resolver
        assert!(!is_public_resolver("pas-une-ip"));
    }

    /// Les IPv6 s'écrivent de plusieurs façons : la comparaison se fait sur
    /// l'adresse analysée, jamais sur le texte.
    #[test]
    fn ipv6_matches_whatever_the_notation() {
        assert!(is_public_resolver("2606:4700:4700::1111"));
        assert!(is_public_resolver("2606:4700:4700:0:0:0:0:1111"));
        assert!(is_public_resolver(
            "2606:4700:4700:0000:0000:0000:0000:1111"
        ));
    }
}
