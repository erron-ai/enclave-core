//! Attestation bundle, challenge preimage, HMAC, replay TTL, NSM/mock behavior.

use enclave_core::attest::bundle::PublicKeyBundle;
use enclave_core::attest::challenge::{
    sign_attestation_challenge, AttestationReplayStore, AttestError, MIN_CHALLENGE_BYTES,
};
use enclave_core::attest::{mock_pcrs, nsm_runtime_available};
use enclave_core::config::env::Environment;
use enclave_core::crypto::hmac::hmac_sha256;
use std::collections::BTreeMap;

#[test]
fn public_key_bundle_canonical_bytes_match_frozen_v1() {
    let b = PublicKeyBundle::new("dorsalmail");
    assert_eq!(
        b.canonical_bytes().as_slice(),
        include_bytes!("fixtures/public_key_bundle_v1.bin").as_slice()
    );
}

#[test]
fn public_key_bundle_independent_of_insertion_order() {
    let mut a = PublicKeyBundle::new("dorsalmail");
    a.insert("x25519", vec![0x11; 4]);
    a.insert("dek_ecies", vec![0x22; 4]);
    let mut b = PublicKeyBundle::new("dorsalmail");
    b.insert("dek_ecies", vec![0x22; 4]);
    b.insert("x25519", vec![0x11; 4]);
    assert_eq!(a.canonical_bytes(), b.canonical_bytes());
}

#[test]
fn sign_attestation_challenge_rejects_short_challenge() {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[0xabu8; 32]);
    let nonce = [0u8; 16];
    let bundle = PublicKeyBundle::new("t");
    let err = sign_attestation_challenge(
        &key,
        "dorsal",
        "mock",
        &[0u8; MIN_CHALLENGE_BYTES - 1],
        &nonce,
        &BTreeMap::new(),
        &bundle,
    )
    .unwrap_err();
    assert!(matches!(err, AttestError::ChallengeTooShort(_)));
}

#[test]
fn attest_hmac_raw_matches_rfc4231() {
    let key = [0x0bu8; 20];
    let msg = b"Hi There";
    let tag = hmac_sha256(&key, msg);
    let expected = hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").unwrap();
    assert_eq!(tag.as_slice(), expected.as_slice());
}

#[test]
fn attest_preimage_flips_change_mac() {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[0x11u8; 32]);
    let nonce = [0xabu8; 16];
    let mut pcrs = BTreeMap::new();
    pcrs.insert("PCR0".into(), "0".repeat(64));
    let challenge = [0xeeu8; 32];
    let bundle = PublicKeyBundle::new("dorsalmail");
    let sig_a = sign_attestation_challenge(
        &key, "dorsalmail", "mock", &challenge, &nonce, &pcrs, &bundle,
    )
    .unwrap();
    let sig_b = sign_attestation_challenge(
        &key, "dorsalfile", "mock", &challenge, &nonce, &pcrs, &bundle,
    )
    .unwrap();
    assert_ne!(sig_a, sig_b);
}

#[test]
fn attest_replay_store_respects_ttl_boundary() {
    let store = AttestationReplayStore::new(10);
    let n = [0x01u8; 16];
    assert!(store.check_and_insert(&n, 1_000_000));
    assert!(!store.check_and_insert(&n, 1_000_009));
    assert!(store.check_and_insert(&n, 1_000_010));
}

#[test]
fn nsm_runtime_available_false_without_nitro() {
    #[cfg(not(feature = "nitro"))]
    assert!(!nsm_runtime_available());
    #[cfg(feature = "nitro")]
    {
        let _ = nsm_runtime_available();
    }
}

#[test]
fn mock_pcrs_non_development_documented() {
    let m = mock_pcrs(Environment::Development);
    assert_eq!(m.len(), 2);
    let r = std::panic::catch_unwind(|| mock_pcrs(Environment::Production));
    assert!(r.is_err());
}
