//! Numéro de téléphone (OSINT, offline) : pays déduit de l'indicatif
//! international (longest-prefix). Pas d'API (le numéro reste sur la machine).

use crate::enrich::{Ctx, Enrichment, Fact};

pub async fn enrich_phone(number: &str, _ctx: &Ctx) -> Enrichment {
    let digits = number.trim_start_matches('+');
    let mut facts = vec![Fact::new("format", "international (E.164)")];
    match calling_code(digits) {
        Some((code, country)) => {
            facts.push(Fact::new("indicatif", format!("+{code}")));
            facts.push(Fact::new("pays", country));
            let national = &digits[code.len()..];
            if !national.is_empty() {
                facts.push(Fact::new("national", national.to_string()));
            }
        }
        None => facts.push(Fact::new("pays", "indicatif non reconnu")),
    }
    Enrichment {
        source: "phone".into(),
        facts,
        signals: vec![],
        pivots: vec![],
        error: None,
    }
}

/// Indicatif international → pays (longest-prefix parmi les codes usuels).
fn calling_code(digits: &str) -> Option<(&'static str, &'static str)> {
    const CODES: &[(&str, &str)] = &[
        ("212", "Maroc"),
        ("213", "Algérie"),
        ("216", "Tunisie"),
        ("221", "Sénégal"),
        ("225", "Côte d'Ivoire"),
        ("234", "Nigeria"),
        ("237", "Cameroun"),
        ("243", "RD Congo"),
        ("351", "Portugal"),
        ("352", "Luxembourg"),
        ("353", "Irlande"),
        ("358", "Finlande"),
        ("359", "Bulgarie"),
        ("370", "Lituanie"),
        ("371", "Lettonie"),
        ("372", "Estonie"),
        ("380", "Ukraine"),
        ("420", "Tchéquie"),
        ("421", "Slovaquie"),
        ("852", "Hong Kong"),
        ("855", "Cambodge"),
        ("880", "Bangladesh"),
        ("886", "Taïwan"),
        ("961", "Liban"),
        ("962", "Jordanie"),
        ("966", "Arabie saoudite"),
        ("971", "Émirats arabes unis"),
        ("972", "Israël"),
        ("974", "Qatar"),
        ("20", "Égypte"),
        ("27", "Afrique du Sud"),
        ("30", "Grèce"),
        ("31", "Pays-Bas"),
        ("32", "Belgique"),
        ("33", "France"),
        ("34", "Espagne"),
        ("36", "Hongrie"),
        ("39", "Italie"),
        ("40", "Roumanie"),
        ("41", "Suisse"),
        ("43", "Autriche"),
        ("44", "Royaume-Uni"),
        ("45", "Danemark"),
        ("46", "Suède"),
        ("47", "Norvège"),
        ("48", "Pologne"),
        ("49", "Allemagne"),
        ("51", "Pérou"),
        ("52", "Mexique"),
        ("54", "Argentine"),
        ("55", "Brésil"),
        ("56", "Chili"),
        ("57", "Colombie"),
        ("58", "Venezuela"),
        ("60", "Malaisie"),
        ("61", "Australie"),
        ("62", "Indonésie"),
        ("63", "Philippines"),
        ("64", "Nouvelle-Zélande"),
        ("65", "Singapour"),
        ("66", "Thaïlande"),
        ("81", "Japon"),
        ("82", "Corée du Sud"),
        ("84", "Vietnam"),
        ("86", "Chine"),
        ("90", "Turquie"),
        ("91", "Inde"),
        ("92", "Pakistan"),
        ("98", "Iran"),
        ("1", "Amérique du Nord (US/CA)"),
        ("7", "Russie / Kazakhstan"),
    ];
    let mut best: Option<(&'static str, &'static str)> = None;
    for &(code, country) in CODES {
        if digits.starts_with(code) && best.is_none_or(|(b, _)| code.len() > b.len()) {
            best = Some((code, country));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_longest_prefix() {
        // 33 = France, mais 351 = Portugal (préfixe plus long prioritaire).
        assert_eq!(calling_code("33612345678").map(|(_, c)| c), Some("France"));
        assert_eq!(
            calling_code("351912345678").map(|(_, c)| c),
            Some("Portugal")
        );
        assert_eq!(
            calling_code("15551234567").map(|(_, c)| c),
            Some("Amérique du Nord (US/CA)")
        );
        assert!(calling_code("99900011122").is_none());
    }
}
