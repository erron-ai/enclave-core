//! Signed-request verification with product-scoped canonical bytes.
//!
//! Canonical request layout (single format, no compatibility shim):
//!
//! ```text
//! <product>\n<METHOD>\n<PATH>\n<TIMESTAMP>\n<NONCE>\n<BODY>
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use ring::hmac;
use thiserror::Error;

use crate::auth::nonce_cache::{NonceError, NonceReplayCache};

pub const MIN_NONCE_LEN: usize = 16;
pub const MAX_NONCE_LEN: usize = 128;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("missing X-Vault-Sig header")]
    MissingHeader,
    #[error("missing X-Vault-Timestamp header")]
    MissingTimestamp,
    #[error("missing X-Vault-Nonce header")]
    MissingNonce,
    #[error("invalid X-Vault-Timestamp")]
    InvalidTimestamp,
    #[error("stale request timestamp")]
    StaleTimestamp,
    #[error("invalid X-Vault-Nonce")]
    InvalidNonce,
    #[error("replayed nonce")]
    ReplayDetected,
    #[error("HMAC signature mismatch")]
    BadSignature,
    #[error("nonce cache: {0}")]
    Nonce(NonceError),
}

#[allow(clippy::too_many_arguments)]
pub fn verify_signed_request(
    key: &hmac::Key,
    product: &str,
    method: &str,
    path: &str,
    timestamp_secs: i64,
    nonce: &str,
    body: &[u8],
    hex_sig: &str,
    max_skew_secs: i64,
    now_secs: i64,
    replay_cache: &NonceReplayCache,
) -> Result<(), VerifyError> {
    if !is_nonce_valid(nonce) {
        return Err(VerifyError::InvalidNonce);
    }

    if (now_secs - timestamp_secs).abs() > max_skew_secs {
        return Err(VerifyError::StaleTimestamp);
    }

    let canonical = canonical_request(product, method, path, timestamp_secs, nonce, body);
    let tag = hex::decode(hex_sig).map_err(|_| VerifyError::BadSignature)?;
    hmac::verify(key, &canonical, &tag).map_err(|_| VerifyError::BadSignature)?;

    match replay_cache.check_and_insert(nonce, now_secs) {
        Ok(()) => Ok(()),
        Err(NonceError::Replay) => Err(VerifyError::ReplayDetected),
        Err(e) => Err(VerifyError::Nonce(e)),
    }
}

pub fn unix_timestamp_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn canonical_request(
    product: &str,
    method: &str,
    path: &str,
    timestamp_secs: i64,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    let product_lower = product.to_ascii_lowercase();
    let mut out =
        Vec::with_capacity(product_lower.len() + method.len() + path.len() + nonce.len() + body.len() + 64);
    out.extend_from_slice(product_lower.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(method.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(path.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(timestamp_secs.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(nonce.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(body);
    out
}

pub fn is_nonce_valid(nonce: &str) -> bool {
    if nonce.len() < MIN_NONCE_LEN || nonce.len() > MAX_NONCE_LEN {
        return false;
    }
    nonce
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Collapse every [`VerifyError`] variant to a single opaque string in
/// release builds, and keep the variant-specific message in debug builds.
///
/// Why: the per-variant strings (`"missing X-Vault-Sig header"`, `"stale
/// request timestamp"`, etc.) are precise error oracles on an unauthenticated
/// endpoint. An attacker probing signature construction gets a free hint
/// about which header was missing or wrong, and about the accepted skew
/// window. Release callers should surface only `"unauthorized"` so every
/// failure looks identical on the wire.
///
/// Enable per-variant messages in release via the
/// `auth-verbose-errors` feature flag — useful when debugging a live
/// environment, off by default.
pub const VERIFY_RELEASE_USER_MESSAGE: &str = "unauthorized";

pub fn release_error_message(_err: &VerifyError) -> &'static str {
    #[cfg(any(debug_assertions, feature = "auth-verbose-errors"))]
    {
        return match _err {
            VerifyError::MissingHeader => "missing X-Vault-Sig header",
            VerifyError::MissingTimestamp => "missing X-Vault-Timestamp header",
            VerifyError::MissingNonce => "missing X-Vault-Nonce header",
            VerifyError::InvalidTimestamp => "invalid X-Vault-Timestamp",
            VerifyError::StaleTimestamp => "stale request timestamp",
            VerifyError::InvalidNonce => "invalid X-Vault-Nonce",
            VerifyError::ReplayDetected => "replayed nonce",
            VerifyError::BadSignature => "invalid signature",
            VerifyError::Nonce(_) => "nonce cache error",
        };
    }
    #[cfg(not(any(debug_assertions, feature = "auth-verbose-errors")))]
    {
        VERIFY_RELEASE_USER_MESSAGE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn canonical_includes_product_first() {
        let bytes = canonical_request("DorsalMail", "POST", "/transit", 1_700_000_000, "abc_nonce_1234567", b"{}");
        assert!(bytes.starts_with(b"dorsalmail\n"));
    }

    #[test]
    fn nonce_must_be_min_len() {
        assert!(!is_nonce_valid("short"));
        assert!(is_nonce_valid("sixteencharssxx1"));
    }

    #[test]
    fn release_error_message_collapses_variants_when_not_verbose() {
        // Default dev builds have debug_assertions, so this test exercises
        // the verbose path. The release-mode collapse is covered separately
        // in a #[cfg(not(debug_assertions))] block below. This test pins
        // the debug behaviour: one message per variant, never empty.
        let variants = [
            VerifyError::MissingHeader,
            VerifyError::MissingTimestamp,
            VerifyError::MissingNonce,
            VerifyError::InvalidTimestamp,
            VerifyError::StaleTimestamp,
            VerifyError::InvalidNonce,
            VerifyError::ReplayDetected,
            VerifyError::BadSignature,
        ];
        for v in &variants {
            let msg = release_error_message(v);
            assert!(!msg.is_empty(), "empty message for {:?}", v);
        }
    }

    #[cfg(all(not(debug_assertions), not(feature = "auth-verbose-errors")))]
    #[test]
    fn release_error_message_opaque_in_release() {
        // Only compiled in release-without-verbose builds. Every variant
        // must collapse to the same "unauthorized" literal so the error
        // oracle disappears.
        let variants = [
            VerifyError::MissingHeader,
            VerifyError::MissingTimestamp,
            VerifyError::BadSignature,
            VerifyError::StaleTimestamp,
        ];
        for v in &variants {
            assert_eq!(release_error_message(v), "unauthorized");
        }
    }

    proptest! {
        #[test]
        fn prop_canonical_len_monotonic_in_body(len_a in 0usize..128, len_b in 0usize..128) {
            prop_assume!(len_a <= len_b);
            let body_a = vec![0u8; len_a];
            let body_b = vec![0u8; len_b];
            let la = canonical_request("dorsalmail", "GET", "/", 1, "sixteencharssxx1", &body_a).len();
            let lb = canonical_request("dorsalmail", "GET", "/", 1, "sixteencharssxx1", &body_b).len();
            prop_assert!(la <= lb);
        }
    }
}
