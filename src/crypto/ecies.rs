//! ECIES (X25519 + HKDF-SHA256 + AES-256-GCM).
//!
//! Wire format: `0x01 [SuiteId byte] || ephem_pub[32] || nonce[12] || ciphertext[n+16]`.
//! The `SuiteId` byte is part of the AEAD AAD so flipping it on the wire fails the tag.

use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::aead::{aes_gcm_decrypt, aes_gcm_encrypt, AeadAad, AeadError, SuiteId};
use crate::crypto::ecdh::{x25519_shared_secret_checked, EcdhError};
use crate::crypto::hkdf::hkdf_sha256_32;
use crate::domain::DomainTag;

const ECIES_VERSION_BYTE: u8 = 0x01;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EciesError {
    #[error("ecies: blob too short")]
    TooShort,
    #[error("ecies: version byte mismatch (got {0:#x})")]
    BadVersion(u8),
    #[error("ecies: unknown suite id ({0:#x})")]
    UnknownSuite(u8),
    #[error("ecies: ecdh failure: {0}")]
    Ecdh(#[from] EcdhError),
    #[error("ecies: aead failure: {0}")]
    Aead(#[from] AeadError),
}

pub fn ecies_seal(
    recipient_pub: &PublicKey,
    plaintext: &[u8],
    info: &DomainTag,
    aad: AeadAad<'_>,
) -> Vec<u8> {
    let rng = SystemRandom::new();
    let mut eph_bytes = Zeroizing::new([0u8; 32]);
    rng.fill(&mut *eph_bytes).expect("rng fill ephemeral");
    let eph_priv = StaticSecret::from(*eph_bytes);
    let eph_pub = PublicKey::from(&eph_priv);

    let shared = eph_priv
        .diffie_hellman(recipient_pub);

    let aes_key = hkdf_sha256_32(shared.as_bytes(), Some(eph_pub.as_bytes()), info);

    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce).expect("rng fill nonce");

    let ct = aes_gcm_encrypt(
        SuiteId::X25519HkdfSha256Aes256Gcm,
        &aes_key,
        &nonce,
        plaintext,
        aad,
    )
    .expect("ecies encrypt");

    let mut out = Vec::with_capacity(2 + 32 + 12 + ct.len());
    out.push(ECIES_VERSION_BYTE);
    out.push(SuiteId::X25519HkdfSha256Aes256Gcm as u8);
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn ecies_open(
    recipient_secret: &StaticSecret,
    blob: &[u8],
    info: &DomainTag,
    aad: AeadAad<'_>,
) -> Result<Zeroizing<Vec<u8>>, EciesError> {
    if blob.len() < 2 + 32 + 12 + 16 {
        return Err(EciesError::TooShort);
    }
    if blob[0] != ECIES_VERSION_BYTE {
        return Err(EciesError::BadVersion(blob[0]));
    }
    let suite = SuiteId::from_byte(blob[1]).ok_or(EciesError::UnknownSuite(blob[1]))?;

    let mut eph = [0u8; 32];
    eph.copy_from_slice(&blob[2..34]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[34..46]);
    let ciphertext = &blob[46..];

    let eph_pub = PublicKey::from(eph);
    let shared = x25519_shared_secret_checked(recipient_secret, &eph_pub)?;

    let aes_key = hkdf_sha256_32(shared.as_bytes(), Some(&eph), info);
    let pt = aes_gcm_decrypt(suite, &aes_key, &nonce, ciphertext, aad)?;
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let secret = StaticSecret::from([0x42u8; 32]);
        let public = PublicKey::from(&secret);
        let info = DomainTag::new("dorsalmail", "dek-ecies", 1).unwrap();
        let blob = ecies_seal(&public, b"secret", &info, AeadAad::Empty);
        let pt = ecies_open(&secret, &blob, &info, AeadAad::Empty).unwrap();
        assert_eq!(pt.as_slice(), b"secret");
    }

    #[test]
    fn flip_suite_byte_fails() {
        let secret = StaticSecret::from([0x42u8; 32]);
        let public = PublicKey::from(&secret);
        let info = DomainTag::new("dorsalmail", "dek-ecies", 1).unwrap();
        let mut blob = ecies_seal(&public, b"hi", &info, AeadAad::Empty);
        blob[1] = 0x02;
        let err = ecies_open(&secret, &blob, &info, AeadAad::Empty).unwrap_err();
        matches!(err, EciesError::UnknownSuite(_));
    }

    #[test]
    fn flip_ct_byte_fails() {
        let secret = StaticSecret::from([0x42u8; 32]);
        let public = PublicKey::from(&secret);
        let info = DomainTag::new("dorsalmail", "dek-ecies", 1).unwrap();
        let mut blob = ecies_seal(&public, b"hi", &info, AeadAad::Empty);
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(ecies_open(&secret, &blob, &info, AeadAad::Empty).is_err());
    }
}
