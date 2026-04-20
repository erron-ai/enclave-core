//! ECIES binding tests (S2): header, AAD, short blob, ephemeral key tampering.
//!
//! Trailing bytes after the ciphertext: `ecies_open` uses `blob[46..]` as the full
//! AES-GCM blob; extra bytes change the tag position and decryption fails. Snapshot
//! current behavior (strictly length-sensitive AEAD parse).

use enclave_core::crypto::ecies::{ecies_open, ecies_seal, EciesError};
use enclave_core::crypto::aead::AeadError;
use enclave_core::domain::DomainTag;
use enclave_core::crypto::aead::AeadAad;
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn ecies_open_rejects_aad_mismatch() {
    let secret = StaticSecret::from([0x42u8; 32]);
    let public = PublicKey::from(&secret);
    let info = DomainTag::new("dorsalmail", "dek-ecies", 1).unwrap();
    let aad_wrong = DomainTag::new("dorsalmail", "dek-ecies", 2).unwrap();
    let blob = ecies_seal(&public, b"x", &info, AeadAad::Tag(&info));
    let err = ecies_open(&secret, &blob, &info, AeadAad::Tag(&aad_wrong)).unwrap_err();
    assert!(matches!(err, EciesError::Aead(AeadError::AuthTagMismatch)));
}

#[test]
fn ecies_open_rejects_short_blob() {
    let secret = StaticSecret::from([0x42u8; 32]);
    let public = PublicKey::from(&secret);
    let info = DomainTag::new("dorsalmail", "dek-ecies", 1).unwrap();
    let mut blob = ecies_seal(&public, b"x", &info, AeadAad::Empty);
    blob.truncate(61);
    assert_eq!(ecies_open(&secret, &blob, &info, AeadAad::Empty).unwrap_err(), EciesError::TooShort);
}

#[test]
fn ecies_open_rejects_bad_version() {
    let secret = StaticSecret::from([0x42u8; 32]);
    let public = PublicKey::from(&secret);
    let info = DomainTag::new("dorsalmail", "dek-ecies", 1).unwrap();
    let mut blob = ecies_seal(&public, b"x", &info, AeadAad::Empty);
    blob[0] = 0x02;
    assert!(matches!(
        ecies_open(&secret, &blob, &info, AeadAad::Empty).unwrap_err(),
        EciesError::BadVersion(0x02)
    ));
}

#[test]
fn ecies_open_rejects_tampered_ephemeral_pubkey() {
    let secret = StaticSecret::from([0x42u8; 32]);
    let public = PublicKey::from(&secret);
    let info = DomainTag::new("dorsalmail", "dek-ecies", 1).unwrap();
    let mut blob = ecies_seal(&public, b"secret", &info, AeadAad::Empty);
    blob[10] ^= 0x01;
    assert!(ecies_open(&secret, &blob, &info, AeadAad::Empty).is_err());
}

#[test]
fn ecies_open_fails_when_wire_eph_replaced_with_other_valid_point() {
    let recipient = StaticSecret::from([0x42u8; 32]);
    let recipient_pub = PublicKey::from(&recipient);
    let info = DomainTag::new("dorsalmail", "dek-ecies", 1).unwrap();
    let mut blob = ecies_seal(&recipient_pub, b"msg", &info, AeadAad::Empty);
    let other_pub = PublicKey::from(&StaticSecret::from([0x99u8; 32]));
    blob[2..34].copy_from_slice(other_pub.as_bytes());
    assert!(ecies_open(&recipient, &blob, &info, AeadAad::Empty).is_err());
}

#[test]
fn ecies_open_rejects_wrong_domain_tag_at_open() {
    let secret = StaticSecret::from([0x42u8; 32]);
    let public = PublicKey::from(&secret);
    let seal_info = DomainTag::new("dorsalmail", "dek-ecies", 1).unwrap();
    let open_info = DomainTag::new("dorsalmail", "dek-ecies", 2).unwrap();
    let blob = ecies_seal(&public, b"z", &seal_info, AeadAad::Empty);
    assert!(ecies_open(&secret, &blob, &open_info, AeadAad::Empty).is_err());
}

#[test]
fn ecies_inner_ciphertext_vs_tag_flip() {
    let secret = StaticSecret::from([0x42u8; 32]);
    let public = PublicKey::from(&secret);
    let info = DomainTag::new("dorsalmail", "dek-ecies", 1).unwrap();
    let mut blob = ecies_seal(&public, b"plaintext", &info, AeadAad::Empty);
    let ct_start = 46;
    if blob.len() > ct_start + 2 {
        blob[ct_start] ^= 0x01;
        assert!(ecies_open(&secret, &blob, &info, AeadAad::Empty).is_err());
    }
    let mut blob2 = ecies_seal(&public, b"plaintext", &info, AeadAad::Empty);
    let last = blob2.len() - 1;
    blob2[last] ^= 0x01;
    assert!(ecies_open(&secret, &blob2, &info, AeadAad::Empty).is_err());
}

#[test]
fn ecies_trailing_byte_after_blob_current_behavior() {
    let secret = StaticSecret::from([0x42u8; 32]);
    let public = PublicKey::from(&secret);
    let info = DomainTag::new("dorsalmail", "dek-ecies", 1).unwrap();
    let mut blob = ecies_seal(&public, b"x", &info, AeadAad::Empty);
    blob.push(0x00);
    assert!(ecies_open(&secret, &blob, &info, AeadAad::Empty).is_err());
}
