//! Redis-backed nonce persistence.
//!
//! Connection loss → fall back to in-memory only and log WARN. Nonces not
//! flushed before a restart are lost; operators monitor Redis health.

use tokio::sync::mpsc;

#[derive(Clone)]
pub struct RedisWriter {
    tx: mpsc::Sender<PersistEntry>,
}

struct PersistEntry {
    nonce: String,
    ts: i64,
    expires_at: i64,
}

impl RedisWriter {
    pub fn spawn(client: redis::Client, key_prefix: String) -> Self {
        let (tx, rx) = mpsc::channel(10_000);
        tokio::spawn(redis_writer(client, key_prefix, rx));
        Self { tx }
    }

    pub fn push(&self, nonce: String, ts: i64, expires_at: i64) {
        if let Err(err) = self.tx.try_send(PersistEntry {
            nonce,
            ts,
            expires_at,
        }) {
            match err {
                mpsc::error::TrySendError::Full(_) => tracing::warn!(
                    event = "nonce_persist_channel_full",
                    "redis persistence channel full; nonce will not survive restart"
                ),
                mpsc::error::TrySendError::Closed(_) => tracing::error!(
                    event = "nonce_persist_channel_closed"
                ),
            }
        }
    }
}

async fn redis_writer(
    client: redis::Client,
    key_prefix: String,
    mut rx: mpsc::Receiver<PersistEntry>,
) {
    let mut conn: Option<redis::aio::MultiplexedConnection> = None;

    while let Some(entry) = rx.recv().await {
        if conn.is_none() {
            match client.get_multiplexed_async_connection().await {
                Ok(c) => conn = Some(c),
                Err(err) => {
                    tracing::warn!(
                        event = "nonce_persist_failed",
                        error_code = "redis_connect_failed",
                        error_kind = ?err.kind(),
                    );
                    continue;
                }
            }
        }

        let ttl = entry.expires_at.saturating_sub(entry.ts);
        if ttl <= 0 {
            continue;
        }
        let key = format!("{key_prefix}{}", entry.nonce);
        let result = redis::cmd("SET")
            .arg(&key)
            .arg(entry.ts)
            .arg("EX")
            .arg(ttl)
            .query_async::<()>(conn.as_mut().expect("connection set"))
            .await;
        if let Err(err) = result {
            tracing::warn!(
                event = "nonce_persist_failed",
                error_code = "redis_write_failed",
                error_kind = ?err.kind(),
            );
            conn = None;
        }
    }
}

pub async fn seed_from_redis(client: &redis::Client, key_prefix: &str) -> Vec<(String, i64)> {
    let mut conn = match client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(error) => {
            tracing::warn!(
                event = "nonce_cache_seed_failed",
                error = %error,
            );
            return vec![];
        }
    };

    let match_pattern = format!("{key_prefix}*");
    let mut cursor: u64 = 0;
    let mut seed = Vec::new();
    loop {
        let scan = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&match_pattern)
            .arg("COUNT")
            .arg(1_000)
            .query_async::<(u64, Vec<String>)>(&mut conn)
            .await;
        let (next, keys) = match scan {
            Ok(x) => x,
            Err(error) => {
                tracing::warn!(event = "nonce_cache_seed_failed", error = %error);
                return vec![];
            }
        };
        for key in keys {
            let v = redis::cmd("GET")
                .arg(&key)
                .query_async::<Option<String>>(&mut conn)
                .await;
            let Some(ts) = v.ok().flatten().and_then(|r| r.parse::<i64>().ok()) else {
                continue;
            };
            if let Some(nonce) = key.strip_prefix(key_prefix) {
                seed.push((nonce.to_owned(), ts));
            }
        }
        if next == 0 {
            break;
        }
        cursor = next;
    }
    seed
}
