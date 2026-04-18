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

#[cfg(test)]
mod tests {
    use super::*;

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
}
