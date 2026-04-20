//! AES-256-GCM with the AEAD suite byte folded into the AAD.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::domain::DomainTag;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SuiteId {
    X25519HkdfSha256Aes256Gcm = 0x01,
    /// Second wire AAD prefix byte for `cargo test` only — never emitted on the real ECIES wire.
    #[cfg(test)]
    TestWrongWireAadByte = 0x02,
}

impl SuiteId {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::X25519HkdfSha256Aes256Gcm),
            #[cfg(test)]
            0x02 => Some(Self::TestWrongWireAadByte),
            _ => None,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AeadError {
    #[error("aes-gcm key init failed")]
    KeyInit,
    #[error("aes-gcm authentication tag mismatch")]
    AuthTagMismatch,
    #[error("aes-gcm encrypt failed")]
    EncryptFailed,
}

pub enum AeadAad<'a> {
    Tag(&'a DomainTag),
    Bytes(&'a [u8]),
    Empty,
}

impl<'a> AeadAad<'a> {
    fn raw(&self) -> &[u8] {
        match self {
            Self::Tag(tag) => tag.as_bytes(),
            Self::Bytes(bytes) => bytes,
            Self::Empty => &[],
        }
    }
}

fn build_wire_aad(suite: SuiteId, aad: AeadAad<'_>) -> Vec<u8> {
    let raw = aad.raw();
    let mut out = Vec::with_capacity(1 + raw.len());
    out.push(suite as u8);
    out.extend_from_slice(raw);
    out
}

pub fn aes_gcm_encrypt(
    suite: SuiteId,
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: AeadAad<'_>,
) -> Result<Vec<u8>, AeadError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AeadError::KeyInit)?;
    let wire_aad = build_wire_aad(suite, aad);
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &wire_aad,
            },
        )
        .map_err(|_| AeadError::EncryptFailed)
}

pub fn aes_gcm_decrypt(
    suite: SuiteId,
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: AeadAad<'_>,
) -> Result<Zeroizing<Vec<u8>>, AeadError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AeadError::KeyInit)?;
    let wire_aad = build_wire_aad(suite, aad);
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &wire_aad,
            },
        )
        .map_err(|_| AeadError::AuthTagMismatch)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn roundtrip_with_tag_aad() {
        let tag = DomainTag::new("dorsalmail", "transit", 1).unwrap();
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let ct = aes_gcm_encrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            b"hello",
            AeadAad::Tag(&tag),
        )
        .unwrap();
        let pt = aes_gcm_decrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            &ct,
            AeadAad::Tag(&tag),
        )
        .unwrap();
        assert_eq!(pt.as_slice(), b"hello");
    }

    #[test]
    fn confidentiality_fails_when_aes_gcm_suite_id_mismatch() {
        let tag = DomainTag::new("dorsalmail", "transit", 1).unwrap();
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let ct = aes_gcm_encrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            b"hi",
            AeadAad::Tag(&tag),
        )
        .unwrap();
        let err = aes_gcm_decrypt(
            SuiteId::TestWrongWireAadByte,
            &key,
            &nonce,
            &ct,
            AeadAad::Tag(&tag),
        )
        .unwrap_err();
        assert_eq!(err, AeadError::AuthTagMismatch);
    }

    #[test]
    fn confidentiality_fails_when_aead_domain_tag_mismatches() {
        let tag_a = DomainTag::new("dorsalmail", "transit", 1).unwrap();
        let tag_b = DomainTag::new("dorsalmail", "transit", 2).unwrap();
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let ct = aes_gcm_encrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            b"payload",
            AeadAad::Tag(&tag_a),
        )
        .unwrap();
        let err = aes_gcm_decrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            &ct,
            AeadAad::Tag(&tag_b),
        )
        .unwrap_err();
        assert_eq!(err, AeadError::AuthTagMismatch);
    }

    #[test]
    fn aead_tag_bytes_encoding_matches_tag_when_bytes_identical() {
        let tag = DomainTag::new("dorsalmail", "transit", 1).unwrap();
        let key = [0x55u8; 32];
        let nonce = [0x66u8; 12];
        let ct = aes_gcm_encrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            b"x",
            AeadAad::Tag(&tag),
        )
        .unwrap();
        let pt_tag = aes_gcm_decrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            &ct,
            AeadAad::Tag(&tag),
        )
        .unwrap();
        let pt_bytes = aes_gcm_decrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            &ct,
            AeadAad::Bytes(tag.as_bytes()),
        )
        .unwrap();
        assert_eq!(pt_tag.as_slice(), pt_bytes.as_slice());
    }

    #[test]
    fn aes_gcm_decrypt_rejects_flipped_ciphertext_body_bit() {
        let tag = DomainTag::new("dorsalmail", "transit", 1).unwrap();
        let key = [0x77u8; 32];
        let nonce = [0x88u8; 12];
        let mut ct = aes_gcm_encrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            b"four",
            AeadAad::Tag(&tag),
        )
        .unwrap();
        ct[0] ^= 0x01;
        assert_eq!(
            aes_gcm_decrypt(
                SuiteId::X25519HkdfSha256Aes256Gcm,
                &key,
                &nonce,
                &ct,
                AeadAad::Tag(&tag),
            )
            .unwrap_err(),
            AeadError::AuthTagMismatch
        );
    }

    #[test]
    fn aes_gcm_decrypt_rejects_flipped_tag_bit() {
        let tag = DomainTag::new("dorsalmail", "transit", 1).unwrap();
        let key = [0x77u8; 32];
        let nonce = [0x88u8; 12];
        let mut ct = aes_gcm_encrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            b"four",
            AeadAad::Tag(&tag),
        )
        .unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert_eq!(
            aes_gcm_decrypt(
                SuiteId::X25519HkdfSha256Aes256Gcm,
                &key,
                &nonce,
                &ct,
                AeadAad::Tag(&tag),
            )
            .unwrap_err(),
            AeadError::AuthTagMismatch
        );
    }

    #[test]
    fn aes_gcm_decrypt_rejects_truncated_ciphertext() {
        let tag = DomainTag::new("dorsalmail", "transit", 1).unwrap();
        let key = [0x99u8; 32];
        let nonce = [0xaau8; 12];
        let ct = aes_gcm_encrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            b"pad",
            AeadAad::Tag(&tag),
        )
        .unwrap();
        let truncated = &ct[..ct.len() - 1];
        assert_eq!(
            aes_gcm_decrypt(
                SuiteId::X25519HkdfSha256Aes256Gcm,
                &key,
                &nonce,
                truncated,
                AeadAad::Tag(&tag),
            )
            .unwrap_err(),
            AeadError::AuthTagMismatch
        );
    }

    #[test]
    fn aes_gcm_decrypt_rejects_trailing_byte_after_tag() {
        let tag = DomainTag::new("dorsalmail", "transit", 1).unwrap();
        let key = [0x99u8; 32];
        let nonce = [0xaau8; 12];
        let mut ct = aes_gcm_encrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            b"pad",
            AeadAad::Tag(&tag),
        )
        .unwrap();
        ct.push(0x00);
        assert_eq!(
            aes_gcm_decrypt(
                SuiteId::X25519HkdfSha256Aes256Gcm,
                &key,
                &nonce,
                &ct,
                AeadAad::Tag(&tag),
            )
            .unwrap_err(),
            AeadError::AuthTagMismatch
        );
    }

    #[test]
    fn aes_gcm_decrypt_rejects_flipped_nonce_bit() {
        let tag = DomainTag::new("dorsalmail", "transit", 1).unwrap();
        let key = [0xbbu8; 32];
        let mut nonce = [0xccu8; 12];
        let ct = aes_gcm_encrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            b"n",
            AeadAad::Tag(&tag),
        )
        .unwrap();
        nonce[3] ^= 0x01;
        assert_eq!(
            aes_gcm_decrypt(
                SuiteId::X25519HkdfSha256Aes256Gcm,
                &key,
                &nonce,
                &ct,
                AeadAad::Tag(&tag),
            )
            .unwrap_err(),
            AeadError::AuthTagMismatch
        );
    }

    #[test]
    fn aes_gcm_decrypt_rejects_wrong_key() {
        let tag = DomainTag::new("dorsalmail", "transit", 1).unwrap();
        let mut key = [0xddu8; 32];
        let nonce = [0xeeu8; 12];
        let ct = aes_gcm_encrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            b"k",
            AeadAad::Tag(&tag),
        )
        .unwrap();
        key[0] ^= 0x01;
        assert_eq!(
            aes_gcm_decrypt(
                SuiteId::X25519HkdfSha256Aes256Gcm,
                &key,
                &nonce,
                &ct,
                AeadAad::Tag(&tag),
            )
            .unwrap_err(),
            AeadError::AuthTagMismatch
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn prop_decrypt_encrypt_roundtrip(pt in prop::collection::vec(any::<u8>(), 0..256)) {
            let tag = DomainTag::new("dorsalmail", "transit", 1).unwrap();
            let key = [0x11u8; 32];
            let nonce = [0x22u8; 12];
            let ct = aes_gcm_encrypt(
                SuiteId::X25519HkdfSha256Aes256Gcm,
                &key,
                &nonce,
                &pt,
                AeadAad::Tag(&tag),
            ).unwrap();
            let out = aes_gcm_decrypt(
                SuiteId::X25519HkdfSha256Aes256Gcm,
                &key,
                &nonce,
                &ct,
                AeadAad::Tag(&tag),
            ).unwrap();
            prop_assert_eq!(out.as_slice(), pt.as_slice());
        }

        #[test]
        fn prop_wrong_key_fails(
            key in any::<[u8; 32]>(),
            wrong_key in any::<[u8; 32]>(),
        ) {
            prop_assume!(key != wrong_key);
            let tag = DomainTag::new("dorsalmail", "transit", 1).unwrap();
            let nonce = [0x33u8; 12];
            let ct = aes_gcm_encrypt(
                SuiteId::X25519HkdfSha256Aes256Gcm,
                &key,
                &nonce,
                b"x",
                AeadAad::Tag(&tag),
            ).unwrap();
            prop_assert_eq!(
                aes_gcm_decrypt(
                    SuiteId::X25519HkdfSha256Aes256Gcm,
                    &wrong_key,
                    &nonce,
                    &ct,
                    AeadAad::Tag(&tag),
                ).unwrap_err(),
                AeadError::AuthTagMismatch
            );
        }
    }

    #[test]
    fn empty_aad_roundtrip() {
        let key = [0x55u8; 32];
        let nonce = [0x66u8; 12];
        let ct = aes_gcm_encrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            b"nope",
            AeadAad::Empty,
        )
        .unwrap();
        let pt = aes_gcm_decrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &key,
            &nonce,
            &ct,
            AeadAad::Empty,
        )
        .unwrap();
        assert_eq!(pt.as_slice(), b"nope");
    }
}
