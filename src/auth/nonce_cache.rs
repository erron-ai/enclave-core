//! Nonce replay cache with optional Redis persistence.

use std::sync::Mutex;

use dashmap::DashMap;
use thiserror::Error;

use crate::auth::redis_nonce::RedisWriter;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NonceError {
    #[error("nonce already seen")]
    Replay,
    #[error("nonce cache at capacity")]
    AtCapacity,
}

#[derive(Debug, Error)]
pub enum RedisInitError {
    #[error("key_prefix must start with product prefix, got {0:?}")]
    PrefixMissingProduct(String),
    #[error("redis: {0}")]
    Redis(String),
}

pub struct NonceReplayCache {
    ttl_secs: i64,
    max_entries: usize,
    key_prefix: String,
    inner: DashMap<String, i64>,
    #[allow(dead_code)]
    writer: Mutex<Option<RedisWriter>>,
}

impl NonceReplayCache {
    pub fn new(ttl_secs: i64, max_entries: usize, key_prefix: String) -> Self {
        Self {
            ttl_secs,
            max_entries,
            key_prefix,
            inner: DashMap::new(),
            writer: Mutex::new(None),
        }
    }

    pub fn with_redis(
        ttl_secs: i64,
        max_entries: usize,
        key_prefix: String,
        client: redis::Client,
    ) -> Result<Self, RedisInitError> {
        let writer = RedisWriter::spawn(client, key_prefix.clone());
        Ok(Self {
            ttl_secs,
            max_entries,
            key_prefix,
            inner: DashMap::new(),
            writer: Mutex::new(Some(writer)),
        })
    }

    pub fn key_prefix(&self) -> &str {
        &self.key_prefix
    }

    pub fn ttl_secs(&self) -> i64 {
        self.ttl_secs
    }

    /// Evict expired, reject on duplicate or at-capacity, else insert.
    pub fn check_and_insert(&self, nonce: &str, now_secs: i64) -> Result<(), NonceError> {
        // Evict expired entries.
        self.inner
            .retain(|_, ts| now_secs.saturating_sub(*ts) <= self.ttl_secs);

        if self.inner.contains_key(nonce) {
            return Err(NonceError::Replay);
        }
        if self.inner.len() >= self.max_entries {
            return Err(NonceError::AtCapacity);
        }
        self.inner.insert(nonce.to_owned(), now_secs);

        if let Ok(guard) = self.writer.lock() {
            if let Some(w) = guard.as_ref() {
                w.push(nonce.to_owned(), now_secs, now_secs + self.ttl_secs);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_rejected() {
        let c = NonceReplayCache::new(600, 10, "dorsalmail.".into());
        c.check_and_insert("aaaaaaaaaaaaaaaa", 100).unwrap();
        assert_eq!(
            c.check_and_insert("aaaaaaaaaaaaaaaa", 101).unwrap_err(),
            NonceError::Replay
        );
    }

    #[test]
    fn capacity_rejects_new() {
        let c = NonceReplayCache::new(600, 2, "dorsalmail.".into());
        c.check_and_insert("aaaaaaaaaaaaaaaa", 100).unwrap();
        c.check_and_insert("bbbbbbbbbbbbbbbb", 100).unwrap();
        assert_eq!(
            c.check_and_insert("cccccccccccccccc", 100).unwrap_err(),
            NonceError::AtCapacity
        );
    }
}
