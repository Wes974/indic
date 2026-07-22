//! indic — détection VPN/proxy/Tor & enrichissement IP (outil CTI perso).
//! Un seul binaire : `serve` (API + front), `update` (refresh datasets), `lookup <ip>`.

mod api;
mod asn;
mod attack;
mod config;
mod correlate;
mod darkweb;
mod enrich;
mod feeds;
mod history;
mod model;
mod observable;
mod push;
mod ranges;
mod rate;
mod registry;
mod stix;
mod store;
mod veille;
mod verdict;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};

use config::{Config, FeedUrls};
use model::IpReport;
use store::Store;

/// Allowlist des noms d'env de clés API reconnues (évite d'aspirer des secrets
/// non liés : DATABASE_URL, AWS_SECRET_ACCESS_KEY, etc.).
pub const KNOWN_KEYS: &[&str] = &[
    "SHODAN_API_KEY",
    "CENSYS_API_KEY",
    "CENSYS_ORG_ID",
    "GREYNOISE_API_KEY",
    "ABUSEIPDB_API_KEY",
    "IPQUALITYSCORE_API_KEY",
    "IPINFO_TOKEN",
    "CRIMINALIP_API_KEY",
    "ONYPHE_API_KEY",
    "NETLAS_API_KEY",
    "PROXYCHECK_API_KEY",
    "VPNAPI_KEY",
    "SCAMALYTICS_API_USER",
    "SCAMALYTICS_API_KEY",
    "IPDATA_API_KEY",
    "FULLHUNT_API_KEY",
    "LEAKIX_API_KEY",
    "SPUR_API_KEY",
    "MAXMIND_ACCOUNT_ID",
    "MAXMIND_LICENSE_KEY",
    "FOFA_EMAIL",
    "FOFA_KEY",
    "ZOOMEYE_API_KEY",
    "QUAKE_API_KEY",
    "SECURITYTRAILS_API_KEY",
    "WHOISXML_API_KEY",
    "URLSCAN_API_KEY",
    "URLSCAN_PRO_API_KEY",
    "BUILTWITH_API_KEY",
    "CERTSPOTTER_API_KEY",
    "HACKERTARGET_API_KEY",
    "VALIDIN_API_KEY",
    "DNSLYTICS_API_KEY",
    "DOMAINTOOLS_API_USERNAME",
    "DOMAINTOOLS_API_KEY",
    "ABUSE_CH_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "HYBRIDANALYSIS_API_KEY",
    "TRIAGE_API_KEY",
    "MALSHARE_API_KEY",
    "TRACEIX_API_KEY",
    "INTEZER_API_KEY",
    "KASPERSKY_OPENTIP_KEY",
    "METADEFENDER_API_KEY",
    "FILESCAN_API_KEY",
    "ANYRUN_API_KEY",
    "OTX_API_KEY",
    "PULSEDIVE_API_KEY",
    "INTELX_API_KEY",
    "MALTIVERSE_API_KEY",
    "GOOGLE_SAFEBROWSING_API_KEY",
    "PHISHTANK_API_KEY",
    "MISP_URL",
    "MISP_API_KEY",
    "OPENCTI_URL",
    "OPENCTI_TOKEN",
    "HIBP_API_KEY",
    "DEHASHED_API_KEY",
    "DEHASHED_EMAIL",
    "HUNTER_IO_API_KEY",
    "EMAILREP_API_KEY",
    "LEAKCHECK_API_KEY",
    "NVD_API_KEY",
    "VULNCHECK_API_KEY",
    "VULNERS_API_KEY",
    "ETHERSCAN_API_KEY",
    "GITHUB_TOKEN",
    "IKNOWWHATYOUDOWNLOAD_API_KEY",
    // Veille : sink d'alertes Pushover.
    "PUSHOVER_TOKEN",
    "PUSHOVER_USER",
    "BINARYEDGE_API_KEY",
];

#[derive(Parser)]
#[command(
    name = "indic",
    version,
    about = "Détection VPN/proxy/Tor & enrichissement IP (CTI perso)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Lance l'API HTTP + le front (défaut).
    Serve,
    /// Télécharge / rafraîchit les datasets puis quitte.
    Update,
    /// Enrichit une IP en ligne de commande.
    Lookup { ip: String },
    /// Lance un cycle de veille une fois (watchers → alertes) puis quitte.
    Veille {
        /// Envoie une alerte de test Pushover au lieu d'un vrai cycle.
        #[arg(long)]
        test: bool,
    },
    /// Génère un script de complétion shell (bash, zsh, fish).
    Completions { shell: clap_complete::Shell },
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    init_tracing();

    let cli = Cli::parse();
    let cfg = Config::from_env();

    match cli.cmd.unwrap_or(Cmd::Serve) {
        Cmd::Update => {
            feeds::update_all(&cfg.data_dir, &FeedUrls::default()).await?;
        }
        Cmd::Lookup { ip } => {
            let store = Store::load_from_dir(&cfg.data_dir);
            print_report(&store.lookup(&ip)?);
        }
        Cmd::Veille { test } => {
            let ctx = build_ctx(&cfg)?;
            if test {
                veille::send_test(&ctx).await;
            } else {
                veille::run_once(&ctx, &cfg.data_dir).await;
            }
        }
        Cmd::Completions { shell } => {
            use clap_complete::generate;
            let mut cmd = <Cli as clap::CommandFactory>::command();
            let name = cmd.get_name().to_string();
            generate(shell, &mut cmd, &name, &mut std::io::stdout());
        }
        Cmd::Serve => serve(cfg).await?,
    }
    Ok(())
}

/// Construit le contexte partagé : datasets (hot-swappables), client HTTP,
/// clés API reconnues (allowlist `KNOWN_KEYS`), token. Partagé par `serve` et
/// la commande `veille`.
fn build_ctx(cfg: &Config) -> Result<Arc<enrich::Ctx>> {
    let store = Arc::new(ArcSwap::from_pointee(Store::load_from_dir(&cfg.data_dir)));
    let http = reqwest::Client::builder()
        .user_agent("indic/0.1")
        .timeout(Duration::from_secs(15))
        .build()?;
    let keys: std::collections::HashMap<String, String> = std::env::vars()
        .filter(|(k, v)| !v.is_empty() && KNOWN_KEYS.contains(&k.as_str()))
        .collect();
    let keys = parking_lot::RwLock::new(keys);
    let history = if std::env::var("INDIC_HISTORY").is_ok_and(|v| v == "1" || v == "true") {
        history::History::open(&cfg.data_dir.join("history.db"))
    } else {
        None
    };
    let attack_map = attack::load_attack_map(&cfg.data_dir.join("cwe2attack.csv"));
    let registry = Arc::new(registry::build());
    // `INDIC_DISABLED_SOURCES=fofa,zoomeye` — coupe des sources sans toucher à
    // leurs clés (quota épuisé, source cassée, résultats non souhaités).
    let disabled: std::collections::HashSet<String> = std::env::var("INDIC_DISABLED_SOURCES")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if !disabled.is_empty() {
        let mut names: Vec<&str> = disabled.iter().map(String::as_str).collect();
        names.sort_unstable();
        tracing::info!(sources = names.join(","), "sources désactivées");
    }
    Ok(Arc::new(enrich::Ctx {
        store,
        http,
        keys,
        token: std::env::var("INDIC_TOKEN").ok().filter(|s| !s.is_empty()),
        // `with_data_dir` : les compteurs de quota sont persistés (un quota
        // mensuel doit survivre aux redéploiements).
        cache: enrich::Cache::with_data_dir(&cfg.data_dir),
        history,
        rate_limiter: rate::RateLimiter::new(),
        registry,
        attack_map,
        disabled,
    }))
}

async fn serve(cfg: Config) -> Result<()> {
    // `INDIC_SKIP_BOOTSTRAP=1` : démarre sans datasets (tests e2e / CI). Les
    // lookups restent servis par les sources live (RDAP, rDNS…), seules les
    // listes offline sont vides — évite ~40 Mo de téléchargements par run.
    let skip_bootstrap =
        std::env::var("INDIC_SKIP_BOOTSTRAP").is_ok_and(|v| v == "1" || v == "true");
    // Bootstrap : si les datasets sont absents (premier run, ou v6 pas encore
    // téléchargé sur un volume préexistant), on télécharge avant de servir.
    if skip_bootstrap {
        tracing::warn!("INDIC_SKIP_BOOTSTRAP=1 — démarrage sans datasets offline");
    } else if feeds::needs_bootstrap(&cfg.data_dir) {
        tracing::info!("datasets absents ou version de feeds obsolète — bootstrap…");
        if let Err(e) = feeds::update_all(&cfg.data_dir, &FeedUrls::default()).await {
            tracing::error!("bootstrap échoué : {e:#}");
        }
    }

    let ctx = build_ctx(&cfg)?;

    // Refresh périodique en tâche de fond (hot-swap du store).
    if cfg.refresh_hours > 0 {
        let store = ctx.store.clone();
        let data_dir = cfg.data_dir.clone();
        let hours = cfg.refresh_hours;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(hours * 3600));
            ticker.tick().await; // consomme le tick initial immédiat
            loop {
                ticker.tick().await;
                tracing::info!("refresh périodique des datasets…");
                if let Err(e) = feeds::update_all(&data_dir, &FeedUrls::default()).await {
                    tracing::error!("refresh échoué : {e:#}");
                }
                store.store(Arc::new(Store::load_from_dir(&data_dir)));
            }
        });
    }

    // Veille proactive (optionnelle) : watchers planifiés → alertes Pushover.
    if std::env::var("INDIC_VEILLE_ENABLED").is_ok_and(|v| v == "1" || v == "true") {
        tokio::spawn(veille::run_loop(ctx.clone(), cfg.data_dir.clone()));
    }

    // SIGHUP → recharge les clés API à chaud (sans redémarrage du binaire).
    {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let Ok(mut sighup) = signal(SignalKind::hangup()) else {
                return;
            };
            while sighup.recv().await.is_some() {
                tracing::info!("SIGHUP reçu — rechargement des clés API…");
                let new_keys: std::collections::HashMap<String, String> = std::env::vars()
                    .filter(|(k, v)| !v.is_empty() && KNOWN_KEYS.contains(&k.as_str()))
                    .collect();
                let mut keys = ctx.keys.write();
                let old_count = keys.len();
                *keys = new_keys;
                let new_count = keys.len();
                drop(keys);
                tracing::info!(old = old_count, new = new_count, "clés rechargées à chaud");
            }
        });
    }

    let app = api::router(ctx);

    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    tracing::info!("indic écoute sur http://{}", cfg.bind);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal;
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => tracing::info!("SIGINT reçu, arrêt gracieux…"),
        _ = terminate => tracing::info!("SIGTERM reçu, arrêt gracieux…"),
    }
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if std::env::var("INDIC_LOG_JSON").is_ok_and(|v| v == "1") {
        fmt().json().with_env_filter(filter).init();
    } else {
        fmt().with_env_filter(filter).init();
    }
}

/// Sortie terminal lisible pour `indic lookup`.
fn print_report(r: &IpReport) {
    let anon = if r.anonymous {
        "ANONYMOUS"
    } else {
        "Not Anonymous"
    };
    println!();
    println!("  {}", r.ip);
    println!("  ────────────────────────────────");
    println!("  ASN         {}", opt_asn(r.asn));
    println!("  ORG         {}", r.as_name.as_deref().unwrap_or("—"));
    println!("  COUNTRY     {}", r.country.as_deref().unwrap_or("—"));
    println!("  INFRA       {:?}", r.infra_type);
    println!(
        "  BEHAVIOR    {anon}  ({:?}, conf {:.2})",
        r.anon_type, r.confidence
    );
    if let Some(p) = &r.provider {
        println!("  PROVIDER    {p}");
    }
    if r.signals.is_empty() {
        println!("  SIGNALS     —");
    } else {
        println!("  SIGNALS");
        for s in &r.signals {
            match &s.detail {
                Some(d) => println!("    · [{}] {} ({d})", s.category, s.source),
                None => println!("    · [{}] {}", s.category, s.source),
            }
        }
    }
    println!();
}

fn opt_asn(asn: Option<u32>) -> String {
    asn.map(|a| format!("AS{a}"))
        .unwrap_or_else(|| "—".to_string())
}

#[cfg(test)]
mod key_invariants {
    //! Garde-fou : toute clé lue via ctx.key(NOM) dans un enricher doit être
    //! dans KNOWN_KEYS (sinon filtrée à l'ingest → l'enricher ne la voit jamais)
    //! ET documentée dans .env.example (sinon l'utilisateur ne sait pas la remplir).
    //! Attrape l'oubli classique : nouvel enricher ajouté sans câbler la clé.
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// Concatène le source de tous les `.rs` sous `dir` (récursif).
    fn collect_rs(dir: &Path, out: &mut String) {
        for entry in fs::read_dir(dir).expect("lecture du dossier src/") {
            let path = entry.expect("entrée de dossier").path();
            if path.is_dir() {
                collect_rs(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push_str(&fs::read_to_string(&path).expect("lecture d'un .rs"));
                out.push('\n');
            }
        }
    }

    /// Tous les noms passés au lecteur de clé du contexte dans le source.
    /// (Le pattern recherché contient un guillemet, que ce fichier n'écrit
    /// jamais littéralement après les parenthèses → pas d'auto-match.)
    fn used_keys() -> BTreeSet<String> {
        let mut src = String::new();
        collect_rs(&root().join("src"), &mut src);
        let needle = "ctx.key(\"";
        let mut keys = BTreeSet::new();
        let mut rest = src.as_str();
        while let Some(i) = rest.find(needle) {
            rest = &rest[i + needle.len()..];
            if let Some(end) = rest.find('"') {
                keys.insert(rest[..end].to_string());
                rest = &rest[end + 1..];
            }
        }
        keys
    }

    /// Noms déclarés dans `.env.example` (lignes `NOM=`, commentées ou non).
    fn documented_keys() -> BTreeSet<String> {
        let content =
            fs::read_to_string(root().join(".env.example")).expect("lecture de .env.example");
        content
            .lines()
            .filter_map(|line| {
                let line = line.trim().trim_start_matches('#').trim();
                let name = line.split('=').next()?.trim();
                let valid = !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
                valid.then(|| name.to_string())
            })
            .collect()
    }

    #[test]
    fn used_keys_are_allowlisted() {
        let known: BTreeSet<&str> = super::KNOWN_KEYS.iter().copied().collect();
        let orphans: Vec<_> = used_keys()
            .into_iter()
            .filter(|k| !known.contains(k.as_str()))
            .collect();
        assert!(
            orphans.is_empty(),
            "clés lues par un enricher mais absentes de KNOWN_KEYS (seraient filtrées à l'ingest) : {orphans:?}"
        );
    }

    #[test]
    fn used_keys_are_documented() {
        let doc = documented_keys();
        let missing: Vec<_> = used_keys()
            .into_iter()
            .filter(|k| !doc.contains(k))
            .collect();
        assert!(
            missing.is_empty(),
            "clés lues par un enricher mais non documentées dans .env.example : {missing:?}"
        );
    }

    #[test]
    fn known_keys_are_documented() {
        let doc = documented_keys();
        let missing: Vec<_> = super::KNOWN_KEYS
            .iter()
            .filter(|k| !doc.contains(**k))
            .copied()
            .collect();
        assert!(
            missing.is_empty(),
            "clés de KNOWN_KEYS non documentées dans .env.example : {missing:?}"
        );
    }
}

#[cfg(test)]
mod tests_integration;
