//! Ensemble d'intervalles IP (`u128`) avec appartenance en O(log n).
//!
//! IPv4 et IPv6 sont unifiés : une IPv4 est mappée en `::ffff:a.b.c.d` (espace
//! IPv4-mapped, jamais routable en vrai v6 → pas de collision). On convertit
//! chaque CIDR / IP en `[start, end]` de `u128`, trié + fusionné au build ;
//! recherche par binary search sur `start`.

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

/// Convertit une IP (v4 ou v6) en `u128` (v4 mappée en `::ffff:x`).
pub fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

#[derive(Default)]
pub struct RangeSet {
    /// Trié par `start`, non chevauchant après `build()`.
    ranges: Vec<(u128, u128)>,
}

impl RangeSet {
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Ajoute une ligne de feed : IP seule ou CIDR, v4 ou v6.
    /// Ignore lignes vides et commentaires (`#`).
    pub fn push_line(&mut self, s: &str) {
        let s = s.trim();
        if s.is_empty() || s.starts_with('#') {
            return;
        }
        if let Some(range) = parse_line(s) {
            self.ranges.push(range);
        }
    }

    #[allow(dead_code)]
    pub fn push_range(&mut self, start: u128, end: u128) {
        self.ranges.push((start, end));
    }

    /// Trie et fusionne les intervalles adjacents/chevauchants.
    pub fn build(&mut self) {
        self.ranges.sort_unstable_by_key(|r| r.0);
        let mut merged: Vec<(u128, u128)> = Vec::with_capacity(self.ranges.len());
        for &(s, e) in &self.ranges {
            if let Some(last) = merged.last_mut()
                && s <= last.1.saturating_add(1)
            {
                if e > last.1 {
                    last.1 = e;
                }
                continue;
            }
            merged.push((s, e));
        }
        self.ranges = merged;
    }

    /// Vrai si `ip` (déjà en `u128`) appartient à un intervalle.
    pub fn contains(&self, ip: u128) -> bool {
        match self.ranges.binary_search_by(|&(start, _)| start.cmp(&ip)) {
            Ok(_) => true,
            Err(0) => false,
            Err(idx) => {
                let (_, end) = self.ranges[idx - 1];
                ip <= end
            }
        }
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// Parse une IP ou un CIDR (v4/v6) en intervalle `[start, end]` de `u128`.
pub fn parse_line(s: &str) -> Option<(u128, u128)> {
    if s.contains('/') {
        let net = IpNet::from_str(s).ok()?;
        Some((ip_to_u128(net.network()), ip_to_u128(net.broadcast())))
    } else {
        let ip = IpAddr::from_str(s).ok()?;
        let v = ip_to_u128(ip);
        Some((v, v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> u128 {
        ip_to_u128(IpAddr::from_str(s).unwrap())
    }

    #[test]
    fn contains_cidr_v4() {
        let mut rs = RangeSet::new();
        rs.push_line("10.0.0.0/24");
        rs.push_line("192.168.1.5");
        rs.build();
        assert!(rs.contains(u("10.0.0.0")));
        assert!(rs.contains(u("10.0.0.255")));
        assert!(!rs.contains(u("10.0.1.0")));
        assert!(rs.contains(u("192.168.1.5")));
        assert!(!rs.contains(u("192.168.1.6")));
    }

    #[test]
    fn contains_cidr_v6() {
        let mut rs = RangeSet::new();
        rs.push_line("2a01:e0a:880::/48");
        rs.build();
        assert!(rs.contains(u("2a01:e0a:880:4150:95bc:d6ff:fe00:1")));
        assert!(!rs.contains(u("2a01:e0a:881::1")));
    }

    #[test]
    fn merges_adjacent() {
        let mut rs = RangeSet::new();
        rs.push_line("1.0.0.0/25");
        rs.push_line("1.0.0.128/25");
        rs.build();
        assert_eq!(rs.len(), 1);
        assert!(rs.contains(u("1.0.0.200")));
    }

    #[test]
    fn v4_and_v6_no_collision() {
        let mut rs = RangeSet::new();
        rs.push_line("1.1.1.1");
        rs.build();
        assert!(rs.contains(u("1.1.1.1")));
        // Un v6 dont les bits bas valent 1.1.1.1 ne doit pas matcher.
        assert!(!rs.contains(u("::1.1.1.1")));
    }
}
