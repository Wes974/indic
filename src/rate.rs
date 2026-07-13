//! Rate limiter simple par IP (token bucket in-memory). Borne le nombre de
//! requêtes par minute pour protéger les quotas des sources gratuites.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::Instant;

/// Nombre de requêtes autorisées par fenêtre (par défaut 30/min pour les non-autorisés).
const DEFAULT_WINDOW_REQUESTS: u32 = 30;
/// Durée de la fenêtre glissante.
const WINDOW_SECS: u64 = 60;

pub struct RateLimiter {
    inner: Mutex<HashMap<String, Window>>,
}

struct Window {
    /// Index de début (logique) de la fenêtre.
    start: Instant,
    /// Compteur dans la fenêtre.
    count: u32,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Vérifie si `ip` peut émettre une requête. Retourne `true` si autorisé,
    /// `false` si la limite est atteinte.
    pub fn allow(&self, ip: &str) -> bool {
        let mut map = self.inner.lock();
        let now = Instant::now();
        let entry = map.entry(ip.to_string()).or_insert(Window {
            start: now,
            count: 0,
        });
        // Fenêtre expirée → reset.
        if now.duration_since(entry.start).as_secs() >= WINDOW_SECS {
            entry.start = now;
            entry.count = 0;
        }
        if entry.count >= DEFAULT_WINDOW_REQUESTS {
            return false;
        }
        entry.count += 1;
        true
    }

    /// Nombre de requêtes restantes pour `ip`.
    #[allow(dead_code)]
    pub fn remaining(&self, ip: &str) -> u32 {
        let map = self.inner.lock();
        let now = Instant::now();
        if let Some(entry) = map.get(ip)
            && now.duration_since(entry.start).as_secs() < WINDOW_SECS
        {
            DEFAULT_WINDOW_REQUESTS.saturating_sub(entry.count)
        } else {
            DEFAULT_WINDOW_REQUESTS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_allows_requests() {
        let rl = RateLimiter::new();
        for _ in 0..DEFAULT_WINDOW_REQUESTS {
            assert!(rl.allow("1.2.3.4"));
        }
        assert!(!rl.allow("1.2.3.4"), "doit bloquer après la limite");
        assert!(rl.allow("5.6.7.8"), "autre IP non bloquée");
        assert_eq!(rl.remaining("1.2.3.4"), 0);
        assert!(rl.remaining("5.6.7.8") > 0);
    }
}
