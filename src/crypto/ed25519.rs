//! Ed25519 verification.

use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Ed25519Error {
    #[error("ed25519: signature verification failed")]
    BadSignature,
}

pub fn verify(
    verify_key: &VerifyingKey,
    message: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), Ed25519Error> {
    let sig = Signature::from_bytes(signature_bytes);
    verify_key
        .verify_strict(message, &sig)
        .map_err(|_| Ed25519Error::BadSignature)
}
