//! Historique optionnel des requêtes en SQLite (opt-in, `INDIC_HISTORY=1`).
//! Enregistre une entrée par lookup, avec l'observable, le verdict, la date.
//! Alimente le dashboard privé et la corrélation inter-observables.

use parking_lot::Mutex;
use rusqlite::{Connection, params};
use serde::Serialize;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct History {
    conn: Mutex<Connection>,
    retention_days: u32,
    purge_counter: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    pub id: i64,
    pub query: String,
    pub kind: String,
    pub verdict_label: Option<String>,
    pub verdict_score: Option<i32>,
    pub source_count: u32,
    pub signal_count: u32,
    pub ts: i64,
}

impl History {
    /// Ouvre (ou crée) la base SQLite avec rétention configurable.
    /// `INDIC_HISTORY_RETENTION_DAYS` (défaut 90j).
    pub fn open(path: &Path) -> Option<Self> {
        let conn = Connection::open(path).ok()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS lookups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query TEXT NOT NULL,
                kind TEXT NOT NULL,
                verdict_label TEXT,
                verdict_score INTEGER,
                source_count INTEGER DEFAULT 0,
                signal_count INTEGER DEFAULT 0,
                ts INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_lookups_ts ON lookups(ts);
            CREATE INDEX IF NOT EXISTS idx_lookups_query ON lookups(query);
            CREATE INDEX IF NOT EXISTS idx_lookups_kind ON lookups(kind);",
        )
        .ok()?;
        let retention = std::env::var("INDIC_HISTORY_RETENTION_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(90);
        Some(Self {
            conn: Mutex::new(conn),
            retention_days: retention,
            purge_counter: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Enregistre un lookup.
    pub fn record(
        &self,
        query: &str,
        kind: &str,
        verdict_label: Option<&str>,
        verdict_score: Option<i32>,
        source_count: u32,
        signal_count: u32,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let conn = self.conn.lock();
        let _ = conn.execute(
            "INSERT INTO lookups (query, kind, verdict_label, verdict_score, source_count, signal_count, ts) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![query, kind, verdict_label, verdict_score, source_count, signal_count, now],
        );
        drop(conn);
        // Purge périodique : tous les 100 inserts, nettoie les entrées expirées.
        let n = self
            .purge_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if n.is_multiple_of(100) {
            self.purge_older_than(self.retention_days);
        }
    }
    /// Récupère les N derniers lookups.
    pub fn recent(&self, limit: u32) -> Vec<HistoryEntry> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, query, kind, verdict_label, verdict_score, source_count, signal_count, ts
                 FROM lookups ORDER BY ts DESC LIMIT ?1",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(HistoryEntry {
                    id: row.get(0)?,
                    query: row.get(1)?,
                    kind: row.get(2)?,
                    verdict_label: row.get(3)?,
                    verdict_score: row.get(4)?,
                    source_count: row.get(5)?,
                    signal_count: row.get(6)?,
                    ts: row.get(7)?,
                })
            })
            .unwrap();
        rows.filter_map(|r| r.ok()).collect()
    }

    /// Recherche des observables corrélés (même préfixe, type similaire…).
    #[allow(dead_code)]
    pub fn correlated(&self, query: &str, kind: &str, limit: u32) -> Vec<HistoryEntry> {
        let conn = self.conn.lock();
        let pattern = format!("%{}%", query.chars().take(20).collect::<String>());
        let mut stmt = conn
            .prepare(
                "SELECT id, query, kind, verdict_label, verdict_score, source_count, signal_count, ts
                 FROM lookups WHERE kind = ?1 AND query LIKE ?2 AND query != ?3
                 ORDER BY ts DESC LIMIT ?4",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![kind, pattern, query, limit], |row| {
                Ok(HistoryEntry {
                    id: row.get(0)?,
                    query: row.get(1)?,
                    kind: row.get(2)?,
                    verdict_label: row.get(3)?,
                    verdict_score: row.get(4)?,
                    source_count: row.get(5)?,
                    signal_count: row.get(6)?,
                    ts: row.get(7)?,
                })
            })
            .unwrap();
        rows.filter_map(|r| r.ok()).collect()
    }

    /// Purge les entrées plus anciennes que `max_age_days`.
    #[allow(dead_code)]
    pub fn purge_older_than(&self, max_age_days: u32) -> i64 {
        let conn = self.conn.lock();
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(max_age_days as u64 * 86400) as i64;
        conn.execute("DELETE FROM lookups WHERE ts < ?1", params![cutoff])
            .unwrap_or(0) as i64
    }
}
