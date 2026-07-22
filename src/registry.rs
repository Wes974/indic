//! Registre des enrichers — construit les adaptateurs qui enveloppent les
//! fonctions d'enrichissement existantes et les enregistre dans le `Registry`.
//!
//! Ajouter un enricher = une ligne dans ce fichier. Pas de changement dans le
//! dispatch ni dans le module de l'enricher.

use crate::enrich::{Registry, enricher};
use crate::observable::Observable;
use std::time::Duration;

use crate::enrich::{
    abuseipdb, binaryedge, blocklists, censys, certspotter, circl_hashlookup, criminalip, crtsh,
    crypto, cve, cvedb, dns, dshield, emailrep, filescan, fofa, fullhunt, github, gravatar,
    greynoise, hudsonrock, hunter, hybridanalysis, ikwyd, intelx, internetdb, ipdata, ipgeo,
    ipinfo, ipqs, leakix, malshare, maltiverse, malwarebazaar, maxmind, metadefender, misp, netlas,
    onion, onyphe, opentip, osv, otx, phone, poc, proxycheck, pulsedive, quake, rdap, rdap_domain,
    rdns, ripestat, safebrowsing, scamalytics, securitytrails, shodan, stopforumspam, threatfox,
    traceix, triage, url_analysis, urlhaus, urlscan, urlscan_pro, username, validin, virustotal,
    vpnapi, vulncheck, vulners, wayback, zoomeye,
};

// ── TTL constants (mirrored from enrich.rs) ──────────────────────────────

const TTL_RDNS: Duration = Duration::from_secs(3_600);
const TTL_RDAP: Duration = Duration::from_secs(86_400);
const TTL_SHODAN: Duration = Duration::from_secs(21_600);
const TTL_GREYNOISE: Duration = Duration::from_secs(3_600);
const TTL_DNS: Duration = Duration::from_secs(3_600);
const TTL_GEO: Duration = Duration::from_secs(86_400);
const TTL_CVE: Duration = Duration::from_secs(86_400);
const TTL_THREAT: Duration = Duration::from_secs(3_600);
const TTL_HASH: Duration = Duration::from_secs(86_400);
const TTL_PAID: Duration = Duration::from_secs(21_600);
const TTL_CENSYS: Duration = Duration::from_secs(604_800);

/// Construit le registre complet — tous les enrichers, keyless puis keyed.
pub fn build() -> Registry {
    let mut reg = Registry::new();

    // ═══════════════════════════════════════════════════════════════════════
    // IP — keyless (toujours exécutés)
    // ═══════════════════════════════════════════════════════════════════════

    // local::enrich_ip renvoie IpReport, pas Enrichment → géré dans dispatch.

    enricher!(
        reg,
        Rdns,
        "rdns",
        None,
        Observable::Ip(_),
        TTL_RDNS,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => rdns::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Rdap,
        "rdap",
        None,
        Observable::Ip(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => rdap::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        IpGeo,
        "ipgeo",
        None,
        Observable::Ip(_),
        TTL_GEO,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => ipgeo::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Dshield,
        "dshield",
        None,
        Observable::Ip(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => dshield::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        StopForumSpamIp,
        "stopforumspam",
        None,
        Observable::Ip(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => stopforumspam::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        InternetDb,
        "internetdb",
        None,
        Observable::Ip(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => internetdb::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        MaxMind,
        "maxmind",
        None,
        Observable::Ip(_),
        TTL_GEO,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => maxmind::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // ═══════════════════════════════════════════════════════════════════════
    // IP — keyed (nécessitent auth + clé présente)
    // ═══════════════════════════════════════════════════════════════════════

    enricher!(
        reg,
        Shodan,
        "shodan",
        Some("SHODAN_API_KEY"),
        Observable::Ip(_),
        TTL_SHODAN,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => shodan::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        GreyNoise,
        "greynoise",
        Some("GREYNOISE_API_KEY"),
        Observable::Ip(_),
        TTL_GREYNOISE,
        true,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => greynoise::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        VirusTotalIp,
        "virustotal",
        Some("VIRUSTOTAL_API_KEY"),
        Observable::Ip(_),
        TTL_PAID,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => virustotal::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        AbuseIpDb,
        "abuseipdb",
        Some("ABUSEIPDB_API_KEY"),
        Observable::Ip(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => abuseipdb::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    enricher!(
        reg,
        BinaryEdge,
        "binaryedge",
        Some("BINARYEDGE_API_KEY"),
        Observable::Ip(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => binaryedge::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        IpInfo,
        "ipinfo",
        Some("IPINFO_TOKEN"),
        Observable::Ip(_),
        TTL_GEO,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => ipinfo::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        IpQs,
        "ipqs",
        Some("IPQUALITYSCORE_API_KEY"),
        Observable::Ip(_),
        TTL_PAID,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => ipqs::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        CriminalIp,
        "criminalip",
        Some("CRIMINALIP_API_KEY"),
        Observable::Ip(_),
        TTL_PAID,
        true,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => criminalip::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        ThreatFoxIp,
        "threatfox",
        Some("ABUSE_CH_API_KEY"),
        Observable::Ip(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => threatfox::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        UrlHausHost,
        "urlhaus",
        Some("ABUSE_CH_API_KEY"),
        Observable::Ip(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => urlhaus::enrich_host(&ip.to_string(), ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Scamalytics,
        "scamalytics",
        Some("SCAMALYTICS_API_KEY"),
        Observable::Ip(_),
        TTL_PAID,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => scamalytics::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        IpData,
        "ipdata",
        Some("IPDATA_API_KEY"),
        Observable::Ip(_),
        TTL_GEO,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => ipdata::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        ProxyCheck,
        "proxycheck",
        Some("PROXYCHECK_API_KEY"),
        Observable::Ip(_),
        TTL_GEO,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => proxycheck::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        VpnApi,
        "vpnapi",
        Some("VPNAPI_KEY"),
        Observable::Ip(_),
        TTL_GEO,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => vpnapi::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        OtxIp,
        "otx",
        Some("OTX_API_KEY"),
        Observable::Ip(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => otx::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Censys,
        "censys",
        Some("CENSYS_API_KEY"),
        Observable::Ip(_),
        TTL_CENSYS,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => censys::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        LeakIx,
        "leakix",
        Some("LEAKIX_API_KEY"),
        Observable::Ip(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => leakix::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        UrlScanIp,
        "urlscan",
        Some("URLSCAN_API_KEY"),
        Observable::Ip(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => urlscan::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        MetaDefenderIp,
        "metadefender",
        Some("METADEFENDER_API_KEY"),
        Observable::Ip(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => metadefender::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Ikwyd,
        "iknowwhatyoudownload",
        Some("IKNOWWHATYOUDOWNLOAD_API_KEY"),
        Observable::Ip(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => ikwyd::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Netlas,
        "netlas",
        Some("NETLAS_API_KEY"),
        Observable::Ip(_),
        TTL_PAID,
        true,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => netlas::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    enricher!(
        reg,
        OnypheIp,
        "onyphe",
        Some("ONYPHE_API_KEY"),
        Observable::Ip(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => onyphe::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Fofa,
        "fofa",
        Some("FOFA_KEY"),
        Observable::Ip(_),
        TTL_PAID,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => fofa::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        ZoomEye,
        "zoomeye",
        Some("ZOOMEYE_API_KEY"),
        Observable::Ip(_),
        TTL_PAID,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => zoomeye::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Quake,
        "quake",
        Some("QUAKE_API_KEY"),
        Observable::Ip(_),
        TTL_PAID,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => quake::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        OpenTip,
        "opentip",
        Some("KASPERSKY_OPENTIP_KEY"),
        Observable::Ip(_),
        TTL_THREAT,
        true,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => opentip::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        MaltiverseIp,
        "maltiverse",
        Some("MALTIVERSE_API_KEY"),
        Observable::Ip(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => maltiverse::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        PulsediveIp,
        "pulsedive",
        Some("PULSEDIVE_API_KEY"),
        Observable::Ip(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Ip(ip) => pulsedive::enrich_ip(ip, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // ═══════════════════════════════════════════════════════════════════════
    // Domain — keyless
    // ═══════════════════════════════════════════════════════════════════════

    enricher!(
        reg,
        Dns,
        "dns",
        None,
        Observable::Domain(_),
        TTL_DNS,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => dns::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        RdapDomain,
        "rdap_domain",
        None,
        Observable::Domain(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => rdap_domain::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Crtsh,
        "crtsh",
        None,
        Observable::Domain(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => crtsh::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        WaybackDomain,
        "wayback",
        None,
        Observable::Domain(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => wayback::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        HudsonRockDomain,
        "hudsonrock",
        None,
        Observable::Domain(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => hudsonrock::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Blocklists,
        "blocklists",
        None,
        Observable::Domain(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => blocklists::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // ═══════════════════════════════════════════════════════════════════════
    // Domain — keyed
    // ═══════════════════════════════════════════════════════════════════════

    enricher!(
        reg,
        VirusTotalDomain,
        "virustotal",
        Some("VIRUSTOTAL_API_KEY"),
        Observable::Domain(_),
        TTL_PAID,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => virustotal::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        ThreatFoxDomain,
        "threatfox",
        Some("ABUSE_CH_API_KEY"),
        Observable::Domain(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => threatfox::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        UrlHausDomain,
        "urlhaus",
        Some("ABUSE_CH_API_KEY"),
        Observable::Domain(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => urlhaus::enrich_host(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        OtxDomain,
        "otx",
        Some("OTX_API_KEY"),
        Observable::Domain(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => otx::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        FullHunt,
        "fullhunt",
        Some("FULLHUNT_API_KEY"),
        Observable::Domain(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => fullhunt::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        GitHub,
        "github",
        Some("GITHUB_TOKEN"),
        Observable::Domain(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => github::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        UrlScanDomain,
        "urlscan",
        Some("URLSCAN_API_KEY"),
        Observable::Domain(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => urlscan::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    enricher!(
        reg,
        UrlScanProDomain,
        "urlscan_pro",
        Some("URLSCAN_PRO_API_KEY"),
        Observable::Domain(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => urlscan_pro::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        IntelXDomain,
        "intelx",
        Some("INTELX_API_KEY"),
        Observable::Domain(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => intelx::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        MetaDefenderDomain,
        "metadefender",
        Some("METADEFENDER_API_KEY"),
        Observable::Domain(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => metadefender::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    enricher!(
        reg,
        OnypheDomain,
        "onyphe",
        Some("ONYPHE_API_KEY"),
        Observable::Domain(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => onyphe::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        SafeBrowsingDomain,
        "safebrowsing",
        Some("GOOGLE_SAFEBROWSING_API_KEY"),
        Observable::Domain(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => safebrowsing::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        CertSpotter,
        "certspotter",
        Some("CERTSPOTTER_API_KEY"),
        Observable::Domain(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => certspotter::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Validin,
        "validin",
        Some("VALIDIN_API_KEY"),
        Observable::Domain(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => validin::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        MaltiverseDomain,
        "maltiverse",
        Some("MALTIVERSE_API_KEY"),
        Observable::Domain(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => maltiverse::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        PulsediveDomain,
        "pulsedive",
        Some("PULSEDIVE_API_KEY"),
        Observable::Domain(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => pulsedive::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    enricher!(
        reg,
        SecurityTrails,
        "securitytrails",
        Some("SECURITYTRAILS_API_KEY"),
        Observable::Domain(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Domain(d) => securitytrails::enrich_domain(&d, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // ═══════════════════════════════════════════════════════════════════════
    // Hash — keyless
    // ═══════════════════════════════════════════════════════════════════════

    enricher!(
        reg,
        HashLookup,
        "hashlookup",
        None,
        Observable::Hash(_),
        TTL_HASH,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Hash(h) => circl_hashlookup::enrich_hash(&h, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // ═══════════════════════════════════════════════════════════════════════
    // Hash — keyed
    // ═══════════════════════════════════════════════════════════════════════

    enricher!(
        reg,
        VirusTotalHash,
        "virustotal",
        Some("VIRUSTOTAL_API_KEY"),
        Observable::Hash(_),
        TTL_PAID,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Hash(h) => virustotal::enrich_hash(&h, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        ThreatFoxHash,
        "threatfox",
        Some("ABUSE_CH_API_KEY"),
        Observable::Hash(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Hash(h) => threatfox::enrich_hash(&h, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        UrlHausHash,
        "urlhaus",
        Some("ABUSE_CH_API_KEY"),
        Observable::Hash(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Hash(h) => urlhaus::enrich_hash(&h, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        MalwareBazaar,
        "malwarebazaar",
        Some("ABUSE_CH_API_KEY"),
        Observable::Hash(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Hash(h) => malwarebazaar::enrich_hash(&h, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        OtxHash,
        "otx",
        Some("OTX_API_KEY"),
        Observable::Hash(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Hash(h) => otx::enrich_hash(&h, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        MetaDefenderHash,
        "metadefender",
        Some("METADEFENDER_API_KEY"),
        Observable::Hash(_),
        TTL_HASH,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Hash(h) => metadefender::enrich_hash(&h, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        MalShare,
        "malshare",
        Some("MALSHARE_API_KEY"),
        Observable::Hash(_),
        TTL_HASH,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Hash(h) => malshare::enrich_hash(&h, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Traceix,
        "traceix",
        Some("TRACEIX_API_KEY"),
        Observable::Hash(_),
        TTL_HASH,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Hash(h) => traceix::enrich_hash(&h, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        FileScan,
        "filescan",
        Some("FILESCAN_API_KEY"),
        Observable::Hash(_),
        TTL_HASH,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Hash(h) => filescan::enrich_hash(&h, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        MaltiverseHash,
        "maltiverse",
        Some("MALTIVERSE_API_KEY"),
        Observable::Hash(_),
        TTL_HASH,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Hash(h) => maltiverse::enrich_hash(&h, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Triage,
        "triage",
        Some("TRIAGE_API_KEY"),
        Observable::Hash(_),
        TTL_HASH,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Hash(h) => triage::enrich_hash(&h, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        HybridAnalysis,
        "hybridanalysis",
        Some("HYBRIDANALYSIS_API_KEY"),
        Observable::Hash(_),
        TTL_HASH,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Hash(h) => hybridanalysis::enrich_hash(&h, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // ═══════════════════════════════════════════════════════════════════════
    // URL — keyless
    // ═══════════════════════════════════════════════════════════════════════

    enricher!(
        reg,
        UrlAnalysis,
        "url_analysis",
        None,
        Observable::Url(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Url(u) => url_analysis::enrich_url(&u, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        WaybackUrl,
        "wayback",
        None,
        Observable::Url(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Url(u) => wayback::enrich_domain(&u, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // ═══════════════════════════════════════════════════════════════════════
    // URL — keyed
    // ═══════════════════════════════════════════════════════════════════════

    enricher!(
        reg,
        VirusTotalUrl,
        "virustotal",
        Some("VIRUSTOTAL_API_KEY"),
        Observable::Url(_),
        TTL_PAID,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Url(u) => virustotal::enrich_url(&u, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        ThreatFoxUrl,
        "threatfox",
        Some("ABUSE_CH_API_KEY"),
        Observable::Url(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Url(u) => threatfox::enrich_url(&u, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        UrlHausUrl,
        "urlhaus",
        Some("ABUSE_CH_API_KEY"),
        Observable::Url(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Url(u) => urlhaus::enrich_url(&u, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        OtxUrl,
        "otx",
        Some("OTX_API_KEY"),
        Observable::Url(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Url(u) => otx::enrich_url(&u, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        UrlScanUrl,
        "urlscan",
        Some("URLSCAN_API_KEY"),
        Observable::Url(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Url(u) => urlscan::enrich_url(&u, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        MetaDefenderUrl,
        "metadefender",
        Some("METADEFENDER_API_KEY"),
        Observable::Url(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Url(u) => metadefender::enrich_url(&u, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        SafeBrowsingUrl,
        "safebrowsing",
        Some("GOOGLE_SAFEBROWSING_API_KEY"),
        Observable::Url(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Url(u) => safebrowsing::enrich_url(&u, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // ═══════════════════════════════════════════════════════════════════════
    // Email — keyless
    // ═══════════════════════════════════════════════════════════════════════

    enricher!(
        reg,
        HudsonRockEmail,
        "hudsonrock",
        None,
        Observable::Email(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Email(e) => hudsonrock::enrich_email(&e, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        StopForumSpamEmail,
        "stopforumspam",
        None,
        Observable::Email(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Email(e) => stopforumspam::enrich_email(&e, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Gravatar,
        "gravatar",
        None,
        Observable::Email(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Email(e) => gravatar::enrich_email(&e, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // ═══════════════════════════════════════════════════════════════════════
    // Email — keyed
    // ═══════════════════════════════════════════════════════════════════════

    enricher!(
        reg,
        IntelXEmail,
        "intelx",
        Some("INTELX_API_KEY"),
        Observable::Email(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Email(e) => intelx::enrich_email(&e, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Hunter,
        "hunter",
        Some("HUNTER_IO_API_KEY"),
        Observable::Email(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Email(e) => hunter::enrich_email(&e, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        EmailRep,
        "emailrep",
        Some("EMAILREP_API_KEY"),
        Observable::Email(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Email(e) => emailrep::enrich_email(&e, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // ═══════════════════════════════════════════════════════════════════════
    // CVE — keyless
    // ═══════════════════════════════════════════════════════════════════════

    enricher!(
        reg,
        Cve,
        "cve",
        None,
        Observable::Cve(_),
        TTL_CVE,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Cve(c) => cve::enrich_cve(&c, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        OsvCve,
        "osv",
        None,
        Observable::Cve(_),
        TTL_CVE,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Cve(c) => osv::enrich_cve(&c, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        CveDb,
        "cvedb",
        None,
        Observable::Cve(_),
        TTL_CVE,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Cve(c) => cvedb::enrich_cve(&c, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    // PoC (offline, pas de réseau) — pas de cache.
    enricher!(
        reg,
        PoC,
        "poc",
        None,
        Observable::Cve(_),
        TTL_CVE,
        false,
        |obs, ctx| match obs {
            Observable::Cve(c) => async move { poc::enrich_cve(&c, ctx) },
            _ => unreachable!(),
        }
    );

    // ═══════════════════════════════════════════════════════════════════════
    // CVE — keyed
    // ═══════════════════════════════════════════════════════════════════════

    enricher!(
        reg,
        VulnCheck,
        "vulncheck",
        Some("VULNCHECK_API_KEY"),
        Observable::Cve(_),
        TTL_CVE,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Cve(c) => vulncheck::enrich_cve(&c, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Vulners,
        "vulners",
        Some("VULNERS_API_KEY"),
        Observable::Cve(_),
        TTL_CVE,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Cve(c) => vulners::enrich_cve(&c, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // ═══════════════════════════════════════════════════════════════════════
    // Autres types
    // ═══════════════════════════════════════════════════════════════════════

    // ASN
    enricher!(
        reg,
        RipeStat,
        "ripestat",
        None,
        Observable::Asn(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Asn(n) => ripestat::enrich_asn(n, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // Crypto (BTC/ETH)
    enricher!(
        reg,
        Ofac,
        "ofac",
        None,
        Observable::Crypto(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Crypto(a) => crypto::ofac(&a, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Ransomwhere,
        "ransomwhere",
        None,
        Observable::Crypto(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Crypto(a) => crypto::ransomwhere(&a, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Etherscan,
        "etherscan",
        Some("ETHERSCAN_API_KEY"),
        Observable::Crypto(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Crypto(a) => crypto::etherscan(&a, ctx).await,
                _ => unreachable!(),
            }
        }
    );
    enricher!(
        reg,
        Mempool,
        "mempool",
        None,
        Observable::Crypto(_),
        TTL_THREAT,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Crypto(a) => crypto::mempool(&a, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // Corrélation MISP (multi-type, lecture) : interroge le MISP du user pour
    // dire si l'observable y est déjà documenté. Gated → seulement si autorisé.
    enricher!(
        reg,
        Misp,
        "misp",
        Some("MISP_API_KEY"),
        Observable::Ip(_)
            | Observable::Domain(_)
            | Observable::Url(_)
            | Observable::Email(_)
            | Observable::Hash(_),
        TTL_THREAT,
        false,
        |obs: Observable, ctx| async move { misp::enrich(&obs.value(), ctx).await }
    );

    // Username — keyless mais gated (empêche l'énumération ouverte).
    enricher!(
        reg,
        Username,
        "username",
        Some("__gated__"),
        Observable::Username(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Username(u) => username::enrich_username(&u, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // Phone (offline)
    enricher!(
        reg,
        Phone,
        "phone",
        None,
        Observable::Phone(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Phone(p) => phone::enrich_phone(&p, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // Onion (offline)
    enricher!(
        reg,
        Onion,
        "onion",
        None,
        Observable::Onion(_),
        TTL_RDAP,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Onion(o) => onion::enrich_onion(&o, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    // Package (pkg:éco/nom → OSV)
    enricher!(
        reg,
        OsvPackage,
        "osv",
        None,
        Observable::Package(_),
        TTL_CVE,
        false,
        |obs, ctx| async move {
            match obs {
                Observable::Package(p) => osv::enrich_package(&p, ctx).await,
                _ => unreachable!(),
            }
        }
    );

    reg
}
