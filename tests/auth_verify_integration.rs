//! Signed-request verifier: skew, nonce cache, canonical bytes, opaque release messages.

use enclave_core::auth::{
    verify_signed_request, NonceError, NonceReplayCache, VerifyError,
};
#[cfg(all(not(debug_assertions), not(feature = "auth-verbose-errors")))]
use enclave_core::auth::VERIFY_RELEASE_USER_MESSAGE;
use enclave_core::Error;
use hex;
use ring::hmac;

fn sign_hex(key: &hmac::Key, product: &str, method: &str, path: &str, ts: i64, nonce: &str, body: &[u8]) -> String {
    let canon = enclave_core::auth::verify::canonical_request(product, method, path, ts, nonce, body);
    let tag = hmac::sign(key, &canon);
    hex::encode(tag.as_ref())
}

#[test]
fn signed_request_maps_full_cache_to_nonce_error() {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &[0xeeu8; 32]);
    let cache = NonceReplayCache::new(600, 0, "dorsalmail.".into());
    let now = 1_700_000_000_i64;
    let sig = sign_hex(&key, "dorsalmail", "GET", "/", now, "sixteencharssxx1", b"");
    let err = verify_signed_request(
        &key,
        "dorsalmail",
        "GET",
        "/",
        now,
        "sixteencharssxx1",
        b"",
        &sig,
        300,
        now,
        &cache,
    )
    .unwrap_err();
    assert!(matches!(err, VerifyError::Nonce(NonceError::AtCapacity)));
}

#[test]
fn signed_request_skew_boundary_matches_policy() {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &[0xddu8; 32]);
    let cache = NonceReplayCache::new(600, 100, "dorsalmail.".into());
    let now = 1_700_000_000_i64;
    let max_skew = 60_i64;
    let nonce = "skewboundary1234";
    let ts_ok = now - max_skew;
    let sig_ok = sign_hex(&key, "dorsalmail", "GET", "/", ts_ok, nonce, b"");
    verify_signed_request(
        &key,
        "dorsalmail",
        "GET",
        "/",
        ts_ok,
        nonce,
        b"",
        &sig_ok,
        max_skew,
        now,
        &cache,
    )
    .unwrap();

    let ts_stale = now - max_skew - 1;
    let sig_stale = sign_hex(&key, "dorsalmail", "GET", "/", ts_stale, "sixteencharssxx2", b"");
    let err = verify_signed_request(
        &key,
        "dorsalmail",
        "GET",
        "/",
        ts_stale,
        "sixteencharssxx2",
        b"",
        &sig_stale,
        max_skew,
        now,
        &cache,
    )
    .unwrap_err();
    assert_eq!(err, VerifyError::StaleTimestamp);
}

#[test]
fn canonical_request_bytes_match_frozen_fixture() {
    let got = enclave_core::auth::verify::canonical_request(
        "DorsalMail",
        "POST",
        "/v1/x",
        1_700_000_000,
        "sixteencharssxx1",
        b"{}",
    );
    let expected = include_bytes!("fixtures/canonical_request_v1.bin");
    assert_eq!(got.as_slice(), expected.as_slice());
}

#[cfg(all(not(debug_assertions), not(feature = "auth-verbose-errors")))]
#[test]
fn release_error_message_equals_const_for_all_verify_errors_in_release() {
    use enclave_core::auth::NonceError;
    let cases: Vec<VerifyError> = vec![
        VerifyError::MissingHeader,
        VerifyError::MissingTimestamp,
        VerifyError::MissingNonce,
        VerifyError::InvalidTimestamp,
        VerifyError::StaleTimestamp,
        VerifyError::InvalidNonce,
        VerifyError::ReplayDetected,
        VerifyError::BadSignature,
        VerifyError::Nonce(NonceError::Replay),
        VerifyError::Nonce(NonceError::AtCapacity),
    ];
    for e in cases {
        assert_eq!(
            enclave_core::auth::verify::release_error_message(&e),
            VERIFY_RELEASE_USER_MESSAGE
        );
        let msg = enclave_core::auth::verify::release_error_message(&e);
        assert!(!msg.contains("VerifyError"));
    }
}

#[test]
fn nonce_string_rejects_wrong_length_and_chars() {
    assert!(!enclave_core::auth::verify::is_nonce_valid("fifteencharsxxx"));
    assert!(!enclave_core::auth::verify::is_nonce_valid(&"a".repeat(129)));
    assert!(enclave_core::auth::verify::is_nonce_valid(&"a".repeat(16)));
    assert!(enclave_core::auth::verify::is_nonce_valid(&"a".repeat(128)));
    assert!(!enclave_core::auth::verify::is_nonce_valid("sixteencharssxx!"));
}

#[test]
fn error_types_wrap_verify_and_nonce() {
    let v = VerifyError::BadSignature;
    let e: Error = v.into();
    assert!(matches!(e, Error::Verify(VerifyError::BadSignature)));
    use enclave_core::auth::NonceError;
    let n: Error = NonceError::Replay.into();
    assert!(matches!(n, Error::Nonce(NonceError::Replay)));
}
