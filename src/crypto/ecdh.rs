//! X25519 ECDH with RFC 7748 §5 small-subgroup rejection.

use thiserror::Error;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EcdhError {
    #[error("ecdh produced degenerate (all-zero) shared secret")]
    DegeneratePoint,
}

pub fn x25519_shared_secret_checked(
    secret: &StaticSecret,
    peer: &PublicKey,
) -> Result<SharedSecret, EcdhError> {
    let shared = secret.diffie_hellman(peer);
    if shared.as_bytes().iter().all(|&b| b == 0) {
        return Err(EcdhError::DegeneratePoint);
    }
    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_pair_ok() {
        let a = StaticSecret::from([1u8; 32]);
        let b = StaticSecret::from([2u8; 32]);
        let ap = PublicKey::from(&a);
        let bp = PublicKey::from(&b);
        let s1 = x25519_shared_secret_checked(&a, &bp).unwrap();
        let s2 = x25519_shared_secret_checked(&b, &ap).unwrap();
        assert_eq!(s1.as_bytes(), s2.as_bytes());
    }
}
