use enclave_core::crypto::aead::AeadAad;
use enclave_core::crypto::ecies::{ecies_open, ecies_seal};
use enclave_core::DomainTag;
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn roundtrip_ok() {
    let secret = StaticSecret::from([0x55u8; 32]);
    let public = PublicKey::from(&secret);
    let info = DomainTag::new("dorsalmail", "dek-ecies", 1).unwrap();

    let blob = ecies_seal(&public, b"top secret", &info, AeadAad::Empty);
    let pt = ecies_open(&secret, &blob, &info, AeadAad::Empty).unwrap();
    assert_eq!(pt.as_slice(), b"top secret");
}

#[test]
fn flipping_suite_byte_fails() {
    let secret = StaticSecret::from([0x55u8; 32]);
    let public = PublicKey::from(&secret);
    let info = DomainTag::new("dorsalmail", "dek-ecies", 1).unwrap();

    let mut blob = ecies_seal(&public, b"secret", &info, AeadAad::Empty);
    blob[1] = 0x02;
    assert!(ecies_open(&secret, &blob, &info, AeadAad::Empty).is_err());
}

#[test]
fn flipping_ciphertext_fails() {
    let secret = StaticSecret::from([0x55u8; 32]);
    let public = PublicKey::from(&secret);
    let info = DomainTag::new("dorsalmail", "dek-ecies", 1).unwrap();

    let mut blob = ecies_seal(&public, b"secret", &info, AeadAad::Empty);
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    assert!(ecies_open(&secret, &blob, &info, AeadAad::Empty).is_err());
}
