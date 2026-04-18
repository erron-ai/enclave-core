//! Attestation challenge signing.

use std::collections::BTreeMap;

use ring::hmac;
use thiserror::Error;

use crate::attest::bundle::PublicKeyBundle;

pub const MIN_CHALLENGE_BYTES: usize = 32;

#[derive(Debug, Error)]
pub enum AttestError {
    #[error("challenge must be >= {0} bytes")]
    ChallengeTooShort(usize),
}

pub fn sign_attestation_challenge(
    key: &hmac::Key,
    product: &str,
    mode: &str,
    challenge: &[u8],
    pcrs: &BTreeMap<String, String>,
    bundle: &PublicKeyBundle,
) -> Result<String, AttestError> {
    if challenge.len() < MIN_CHALLENGE_BYTES {
        return Err(AttestError::ChallengeTooShort(MIN_CHALLENGE_BYTES));
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(b"att-v1\n");
    payload.extend_from_slice(b"product=");
    payload.extend_from_slice(product.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(b"mode=");
    payload.extend_from_slice(mode.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(b"challenge=");
    payload.extend_from_slice(hex::encode(challenge).as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(b"pcrs:\n");
    for (k, v) in pcrs {
        payload.extend_from_slice(k.as_bytes());
        payload.push(b'=');
        payload.extend_from_slice(v.as_bytes());
        payload.push(b'\n');
    }
    payload.extend_from_slice(b"bundle:\n");
    payload.extend_from_slice(&bundle.canonical_bytes());

    let tag = hmac::sign(key, &payload);
    Ok(hex::encode(tag.as_ref()))
}
