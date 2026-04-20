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

#[cfg(test)]
mod tests {
    use super::*;

    /// Wycheproof `ed25519_test.json`, tcId 63 — malleated `s` must fail `verify_strict`.
    #[test]
    fn ed25519_verify_strict_rejects_noncanonical_signature_wycheproof_tc63() {
        let pk_bytes = hex::decode("7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa")
            .unwrap();
        let vk = VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap());
        let vk = vk.unwrap();
        let msg = hex::decode("54657374").unwrap();
        let sig = hex::decode(
            "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab067654bce3832c2d76f8f6f5dafc08d9339d4eef676573336a5c51eb6f946b31d",
        )
        .unwrap();
        let sig_arr: [u8; 64] = sig.try_into().unwrap();
        assert_eq!(verify(&vk, &msg, &sig_arr), Err(Ed25519Error::BadSignature));
    }
}
