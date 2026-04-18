//! A single named key slot. Move-only (no `Clone`/`Copy`/`Default`) so
//! intermediate copies can't leak unzeroized memory.

use thiserror::Error;
use zeroize::Zeroizing;

const MIN_ID_LEN: usize = 3;
const MAX_ID_LEN: usize = 80;
const MAX_DATA_LEN: usize = 4096;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SlotError {
    #[error("slot id too short: {0}")]
    IdTooShort(usize),
    #[error("slot id too long: {0}")]
    IdTooLong(usize),
    #[error("slot id contains invalid bytes")]
    IdBadChars,
    #[error("slot data too long: {0}")]
    DataTooLong(usize),
}

pub struct KeySlot {
    pub id: String,
    pub bytes: Zeroizing<Vec<u8>>,
}

impl KeySlot {
    pub fn new(id: impl Into<String>, bytes: Vec<u8>) -> Result<Self, SlotError> {
        let id: String = id.into();
        let id_bytes = id.as_bytes();
        if id_bytes.len() < MIN_ID_LEN {
            return Err(SlotError::IdTooShort(id_bytes.len()));
        }
        if id_bytes.len() > MAX_ID_LEN {
            return Err(SlotError::IdTooLong(id_bytes.len()));
        }
        if !id_bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'.' || *b == b'_')
        {
            return Err(SlotError::IdBadChars);
        }
        if bytes.len() > MAX_DATA_LEN {
            return Err(SlotError::DataTooLong(bytes.len()));
        }
        Ok(Self {
            id,
            bytes: Zeroizing::new(bytes),
        })
    }
}
