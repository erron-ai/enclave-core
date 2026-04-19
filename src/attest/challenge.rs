//! Attestation challenge signing and replay detection.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use ring::hmac;
use thiserror::Error;

use crate::attest::bundle::PublicKeyBundle;

pub const MIN_CHALLENGE_BYTES: usize = 32;

#[derive(Debug, Error)]
pub enum AttestError {
    #[error("challenge must be >= {0} bytes")]
    ChallengeTooShort(usize),
}

/// Tracks recently-issued attestation nonces. The verifier (client-side SDK
/// or Go trust layer) uses this to reject a captured attestation response
/// replayed after the fact — the nonce is server-generated and bound into the
/// HMAC preimage, so a replay of the response carries the same nonce and will
/// be found in the store.
pub struct AttestationReplayStore {
    entries: Mutex<HashMap<[u8; 16], i64>>,
    ttl_secs: i64,
}

impl AttestationReplayStore {
    pub fn new(ttl_secs: i64) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl_secs,
        }
    }

    /// Returns `true` and records the nonce if it is fresh (not seen within
    /// `ttl_secs`). Returns `false` if the nonce was already present — the
    /// caller should treat this as a replay and reject the response.
    pub fn check_and_insert(&self, nonce: &[u8; 16], now_secs: i64) -> bool {
        let mut map = self.entries.lock().unwrap();
        map.retain(|_, &mut ts| now_secs - ts < self.ttl_secs);
        if map.contains_key(nonce) {
            return false;
        }
        map.insert(*nonce, now_secs);
        true
    }
}

/// Sign a mock attestation challenge.
///
/// `nonce` is a server-generated 16-byte random value bound into the preimage
/// so that replaying a captured response fails the `AttestationReplayStore`
/// check on the verifier side.
///
/// Preimage: `att-v1 | product= | mode= | challenge= | nonce= | pcrs: | bundle:`
pub fn sign_attestation_challenge(
    key: &hmac::Key,
    product: &str,
    mode: &str,
    challenge: &[u8],
    nonce: &[u8; 16],
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
    payload.extend_from_slice(b"nonce=");
    payload.extend_from_slice(hex::encode(nonce).as_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;
    use ring::hmac;

    fn test_key() -> hmac::Key {
        hmac::Key::new(
            hmac::HMAC_SHA256,
            &[0xabu8; 32],
        )
    }

    fn dummy_bundle() -> PublicKeyBundle {
        PublicKeyBundle::new("dorsaltest")
    }

    fn challenge_32() -> Vec<u8> {
        vec![0xffu8; 32]
    }

    fn pcrs() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("PCR0".to_owned(), "0".repeat(64));
        m.insert("PCR1".to_owned(), "1".repeat(64));
        m
    }

    #[test]
    fn sign_challenge_too_short_fails() {
        let key = test_key();
        let nonce = [0u8; 16];
        let err = sign_attestation_challenge(
            &key, "dorsal", "mock", &[0u8; 31], &nonce, &pcrs(), &dummy_bundle(),
        )
        .unwrap_err();
        assert!(matches!(err, AttestError::ChallengeTooShort(32)));
    }

    #[test]
    fn sign_challenge_exact_min_succeeds() {
        let key = test_key();
        let nonce = [0u8; 16];
        sign_attestation_challenge(
            &key, "dorsal", "mock", &challenge_32(), &nonce, &pcrs(), &dummy_bundle(),
        )
        .expect("min-length challenge must succeed");
    }

    #[test]
    fn different_nonces_produce_different_signatures() {
        let key = test_key();
        let challenge = challenge_32();
        let bundle = dummy_bundle();
        let pcrs = pcrs();
        let nonce_a = [0u8; 16];
        let nonce_b = [1u8; 16];
        let sig_a = sign_attestation_challenge(&key, "dorsal", "mock", &challenge, &nonce_a, &pcrs, &bundle).unwrap();
        let sig_b = sign_attestation_challenge(&key, "dorsal", "mock", &challenge, &nonce_b, &pcrs, &bundle).unwrap();
        assert_ne!(sig_a, sig_b, "different nonces must produce different signatures");
    }

    #[test]
    fn replay_store_accepts_fresh_nonce() {
        let store = AttestationReplayStore::new(300);
        let nonce = [0xaau8; 16];
        assert!(store.check_and_insert(&nonce, 1_000_000));
    }

    #[test]
    fn replay_store_rejects_duplicate_nonce() {
        let store = AttestationReplayStore::new(300);
        let nonce = [0xbbu8; 16];
        assert!(store.check_and_insert(&nonce, 1_000_000));
        assert!(!store.check_and_insert(&nonce, 1_000_100), "duplicate nonce must be rejected");
    }

    #[test]
    fn replay_store_accepts_nonce_after_expiry() {
        let store = AttestationReplayStore::new(60);
        let nonce = [0xccu8; 16];
        assert!(store.check_and_insert(&nonce, 1_000_000));
        assert!(!store.check_and_insert(&nonce, 1_000_059)); // still within TTL
        assert!(store.check_and_insert(&nonce, 1_000_061), "nonce must be accepted after TTL expiry");
    }

    #[test]
    fn replay_store_distinct_nonces_all_accepted() {
        let store = AttestationReplayStore::new(300);
        let now = 1_000_000;
        for i in 0u8..10 {
            let nonce = [i; 16];
            assert!(store.check_and_insert(&nonce, now), "nonce {i} must be accepted");
        }
    }
}
