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

/// Calcule le verdict à partir des signaux et de la confiance dans l'observable.
/// La **corroboration** prime : une seule source ne suffit pas à condamner (les
/// feeds ont des FP — placeholders, sinkholes, hébergement), il faut plusieurs
/// sources indépendantes. Le C2 (feed haute confiance) est la seule exception.
/// `trusted` = domaine majeur ou réservé → prior « légitime ».
pub fn compute(signals: &[Signal], trusted: bool) -> Verdict {
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

    let (label, rationale): (&'static str, String) = if trusted && raw > 0 {
        (
            "clean",
            format!(
                "Signaux présents (poids {raw}) mais domaine de confiance (majeur ou réservé) — \
                 les IOC portent sur du contenu hébergé ou des comptes référencés, pas sur le \
                 domaine lui-même."
            ),
        )
    } else if serious >= 3 || (has_c2 && serious >= 2) {
        (
            "malicious",
            format!("Menace corroborée par {serious} sources indépendantes (poids {raw})."),
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
        assert_eq!(compute(&sigs, true).label, "clean");
        assert!(is_trusted_domain("github.com") && is_trusted_domain("google.com"));
    }

    #[test]
    fn domaine_reserve_clean() {
        // example.com flaggé par des sources (placeholder de malware) → réservé → clean.
        let sigs = [sig("urlhaus", "malicious"), sig("blocklist", "suspicious")];
        assert_eq!(compute(&sigs, true).label, "clean");
        assert!(is_trusted_domain("example.com"));
        assert!(!is_trusted_domain("evil-c2-domain.tk"));
    }

    #[test]
    fn corroboration_requise() {
        // 1 source « malicious » → suspect (non corroboré), pas malicious.
        assert_eq!(
            compute(&[sig("urlhaus", "malicious")], false).label,
            "suspect"
        );
        // 2 sources → suspect.
        assert_eq!(
            compute(
                &[sig("urlhaus", "malicious"), sig("threatfox", "malicious")],
                false
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
                false
            )
            .label,
            "malicious"
        );
    }

    #[test]
    fn c2_isole_suspect_corrobore_malicious() {
        // Un C2 seul (feed haute confiance) → suspect.
        assert_eq!(compute(&[sig("feodo", "c2")], false).label, "suspect");
        // C2 + une autre source sérieuse → malicious.
        assert_eq!(
            compute(&[sig("feodo", "c2"), sig("urlhaus", "malicious")], false).label,
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
        assert_eq!(compute(&sigs, false).label, "suspect");
    }

    #[test]
    fn propre_sans_signal() {
        assert_eq!(compute(&[], false).label, "clean");
        // Anonymisation/infra ne pèsent pas.
        assert_eq!(
            compute(&[sig("tor_list", "tor"), sig("asdb", "datacenter")], false).label,
            "clean"
        );
    }
}
