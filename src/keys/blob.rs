//! Sealed-blob plaintext format (single version).
//!
//! ```text
//! 0x01                               version byte
//! u32_be slot_count
//! for each slot:
//!     u16_be id_len
//!     id_bytes (UTF-8)
//!     u32_be data_len
//!     data_bytes
//! ```
//!
//! The AEAD AAD is the caller's `aad_prefix || header_bytes`, where
//! `header_bytes` is the version byte + slot count + every (id_len + id_bytes)
//! in order. This binds version, count, ordering of slot ids, and the product
//! prefix into the tag.

use std::collections::HashSet;

use thiserror::Error;

use crate::keys::slot::{KeySlot, SlotError};

pub const BLOB_VERSION: u8 = 0x01;

#[derive(Debug, Error)]
pub enum BlobError {
    #[error("blob too short")]
    TooShort,
    #[error("blob version mismatch: got {0:#x}")]
    BadVersion(u8),
    #[error("duplicate slot id {0:?}")]
    DuplicateId(String),
    #[error("slot id not utf-8")]
    BadIdUtf8,
    #[error("slot: {0}")]
    Slot(#[from] SlotError),
}

pub fn serialize(slots: &[KeySlot]) -> (Vec<u8> /* plaintext */, Vec<u8> /* aad-suffix */) {
    let mut plaintext = Vec::new();
    let mut aad_suffix = Vec::new();

    plaintext.push(BLOB_VERSION);
    aad_suffix.push(BLOB_VERSION);

    let count = slots.len() as u32;
    plaintext.extend_from_slice(&count.to_be_bytes());
    aad_suffix.extend_from_slice(&count.to_be_bytes());

    for slot in slots {
        let id_len = slot.id.as_bytes().len() as u16;
        let data_len = slot.bytes.len() as u32;

        plaintext.extend_from_slice(&id_len.to_be_bytes());
        plaintext.extend_from_slice(slot.id.as_bytes());
        plaintext.extend_from_slice(&data_len.to_be_bytes());
        plaintext.extend_from_slice(slot.bytes.as_slice());

        aad_suffix.extend_from_slice(&id_len.to_be_bytes());
        aad_suffix.extend_from_slice(slot.id.as_bytes());
    }

    (plaintext, aad_suffix)
}

pub fn deserialize(blob: &[u8]) -> Result<(Vec<KeySlot>, Vec<u8> /* aad-suffix */), BlobError> {
    if blob.len() < 5 {
        return Err(BlobError::TooShort);
    }
    if blob[0] != BLOB_VERSION {
        return Err(BlobError::BadVersion(blob[0]));
    }

    let mut aad_suffix = Vec::new();
    aad_suffix.push(BLOB_VERSION);

    let count = u32::from_be_bytes(blob[1..5].try_into().unwrap());
    aad_suffix.extend_from_slice(&count.to_be_bytes());

    let mut cursor = 5usize;
    let mut slots = Vec::with_capacity(count as usize);
    let mut seen: HashSet<String> = HashSet::new();
    for _ in 0..count {
        if cursor + 2 > blob.len() {
            return Err(BlobError::TooShort);
        }
        let id_len = u16::from_be_bytes(blob[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2;
        if cursor + id_len > blob.len() {
            return Err(BlobError::TooShort);
        }
        let id_bytes = &blob[cursor..cursor + id_len];
        let id = std::str::from_utf8(id_bytes)
            .map_err(|_| BlobError::BadIdUtf8)?
            .to_owned();
        cursor += id_len;

        aad_suffix.extend_from_slice(&(id_len as u16).to_be_bytes());
        aad_suffix.extend_from_slice(id_bytes);

        if cursor + 4 > blob.len() {
            return Err(BlobError::TooShort);
        }
        let data_len =
            u32::from_be_bytes(blob[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        if cursor + data_len > blob.len() {
            return Err(BlobError::TooShort);
        }
        let data = blob[cursor..cursor + data_len].to_vec();
        cursor += data_len;

        if !seen.insert(id.clone()) {
            return Err(BlobError::DuplicateId(id));
        }

        slots.push(KeySlot::new(id, data)?);
    }

    Ok((slots, aad_suffix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn roundtrip() {
        let slots = vec![
            KeySlot::new("dorsalmail.x25519", vec![0x11; 32]).unwrap(),
            KeySlot::new("dorsalmail.request_auth", vec![0x22; 32]).unwrap(),
        ];
        let (pt, aad_a) = serialize(&slots);
        let (rt, aad_b) = deserialize(&pt).unwrap();
        assert_eq!(rt.len(), 2);
        assert_eq!(rt[0].id, "dorsalmail.x25519");
        assert_eq!(rt[1].id, "dorsalmail.request_auth");
        assert_eq!(rt[0].bytes.as_slice(), &[0x11; 32]);
        assert_eq!(rt[1].bytes.as_slice(), &[0x22; 32]);
        assert_eq!(aad_a, aad_b);
    }

    #[test]
    fn rejects_wrong_version() {
        let mut blob = vec![0x02u8];
        blob.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(deserialize(&blob), Err(BlobError::BadVersion(_))));
    }

    #[test]
    fn rejects_duplicate_ids() {
        let slots = vec![
            KeySlot::new("dorsalmail.x25519", vec![0x11; 32]).unwrap(),
            KeySlot::new("dorsalmail.x25519", vec![0x22; 32]).unwrap(),
        ];
        let (pt, _) = serialize(&slots);
        assert!(matches!(deserialize(&pt), Err(BlobError::DuplicateId(_))));
    }

    #[test]
    fn key_blob_parse_rejects_truncated_at_each_stage() {
        let slots = vec![KeySlot::new("dorsalmail.x25519", vec![0x11; 32]).unwrap()];
        let (full, _) = serialize(&slots);
        for cut in [0usize, 1, 4, 5, 6, 7, 8, full.len() - 1] {
            if cut < full.len() {
                assert!(
                    matches!(deserialize(&full[..cut]), Err(BlobError::TooShort)),
                    "cut {cut}"
                );
            }
        }
    }

    #[test]
    fn key_blob_parse_rejects_oversized_data_len() {
        let mut blob = vec![BLOB_VERSION];
        blob.extend_from_slice(&1u32.to_be_bytes());
        blob.extend_from_slice(&(4u16).to_be_bytes());
        blob.extend_from_slice(b"abcd");
        blob.extend_from_slice(&1000u32.to_be_bytes());
        assert!(matches!(deserialize(&blob), Err(BlobError::TooShort)));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn prop_blob_roundtrip_idempotent(data in prop::collection::vec(any::<u8>(), 0..64)) {
            let slots = vec![
                KeySlot::new("dorsalmail.x25519", data).unwrap(),
            ];
            let (pt, _) = serialize(&slots);
            let (rt, aad_a) = deserialize(&pt).unwrap();
            let (_, aad_b) = serialize(&rt);
            prop_assert_eq!(aad_a, aad_b);
            prop_assert_eq!(&*rt[0].id, "dorsalmail.x25519");
        }
    }
}
