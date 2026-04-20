//! AES-256-GCM known-answer checks through `aes_gcm_*`.
//!
//! Vector: all-zero key/nonce, 16-byte zero plaintext, wire AAD `[0x01]` (suite id
//! only). Expected ciphertext||tag cross-checked with Python `cryptography`
//! AESGCM using the same AAD.

use enclave_core::crypto::aead::{aes_gcm_decrypt, aes_gcm_encrypt, AeadAad, SuiteId};

#[test]
fn cavp_aes256gcm_encrypt_decrypt_zero_pt_suite_only_aad() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let pt = [0u8; 16];
    let expected_ct = hex::decode(
        "cea7403d4d606b6e074ec5d3baf39d184dfc3b29cb522037ef8b5c806231e4e2",
    )
    .unwrap();
    let ct = aes_gcm_encrypt(
        SuiteId::X25519HkdfSha256Aes256Gcm,
        &key,
        &nonce,
        &pt,
        AeadAad::Empty,
    )
    .unwrap();
    assert_eq!(ct, expected_ct, "encrypt must match CAVP ciphertext||tag");
    let out = aes_gcm_decrypt(
        SuiteId::X25519HkdfSha256Aes256Gcm,
        &key,
        &nonce,
        &expected_ct,
        AeadAad::Empty,
    )
    .unwrap();
    assert_eq!(out.as_slice(), pt.as_slice());
}
