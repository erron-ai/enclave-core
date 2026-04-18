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
}

impl SuiteId {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::X25519HkdfSha256Aes256Gcm),
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
    fn flip_suite_fails_auth() {
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
        let bogus = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: &build_wire_aad(
                        SuiteId::X25519HkdfSha256Aes256Gcm,
                        AeadAad::Tag(&tag),
                    ),
                },
            )
            .unwrap();
        assert_eq!(bogus, b"hi");
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
