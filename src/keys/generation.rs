//! Storage shape for multi-generation keys. Rotation tooling is deferred.

#![cfg(feature = "key-generation")]

use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeySetError {
    #[error("requested generation {0} below minimum {1}")]
    BelowMinimum(u32, u32),
    #[error("requested generation {0} not found")]
    NotFound(u32),
}

pub struct KeyGeneration {
    pub version: u32,
    pub created_at_unix: i64,
    pub bytes: Zeroizing<Vec<u8>>,
}

pub struct KeySet {
    pub current: KeyGeneration,
    pub prior: Vec<KeyGeneration>,
    pub min_decrypt_generation: u32,
}

impl KeySet {
    pub fn for_decrypt(&self, requested_version: u32) -> Result<&KeyGeneration, KeySetError> {
        if requested_version < self.min_decrypt_generation {
            return Err(KeySetError::BelowMinimum(
                requested_version,
                self.min_decrypt_generation,
            ));
        }
        if self.current.version == requested_version {
            return Ok(&self.current);
        }
        self.prior
            .iter()
            .find(|g| g.version == requested_version)
            .ok_or(KeySetError::NotFound(requested_version))
    }

    pub fn for_encrypt(&self) -> &KeyGeneration {
        &self.current
    }

    pub fn rotate(&mut self, new_current: KeyGeneration) {
        let old = std::mem::replace(&mut self.current, new_current);
        self.prior.push(old);
    }
}
