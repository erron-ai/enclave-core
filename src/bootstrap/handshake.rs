//! Two-RPC encrypted bootstrap.
//!
//! Step 1: `/bootstrap/setup` accepts `server_ephem_pub`, returns
//!         `{ enclave_ephem_pub, session_id }`. Server and enclave derive a
//!         `channel_key`; the enclave stores `(session_id → channel_key)` for
//!         up to 30 seconds.
//! Step 2: `/bootstrap` accepts `session_id`, returns the `request_auth_key`
//!         AES-GCM-encrypted under `channel_key`. Session is deleted after
//!         use; one-shot guard prevents replay.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::aead::{aes_gcm_encrypt, AeadAad, AeadError, SuiteId};
use crate::crypto::ecdh::{x25519_shared_secret_checked, EcdhError};
use crate::crypto::hkdf::hkdf_sha256_32;
use crate::domain::DomainTag;

const SESSION_TTL_SECS: i64 = 30;

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("bootstrap already completed")]
    AlreadyCompleted,
    #[error("unknown session_id")]
    UnknownSession,
    #[error("session expired")]
    SessionExpired,
    #[error("ecdh: {0}")]
    Ecdh(#[from] EcdhError),
    #[error("aead: {0}")]
    Aead(#[from] AeadError),
    #[error("rng failure")]
    Rng,
}

struct SessionEntry {
    channel_key: Zeroizing<[u8; 32]>,
    created_unix: i64,
}

pub struct BootstrapState {
    request_auth_key: Zeroizing<Vec<u8>>,
    sessions: DashMap<[u8; 16], SessionEntry>,
    consumed: Arc<AtomicBool>,
}

impl BootstrapState {
    pub fn new(request_auth_key: Vec<u8>) -> Self {
        Self {
            request_auth_key: Zeroizing::new(request_auth_key),
            sessions: DashMap::new(),
            consumed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The bootstrap transcript is product-neutral: Mail, Forms, Files etc.
    /// all share the same handshake, so the HKDF info tag uses the generic
    /// `"dorsal"` prefix rather than a Mail-specific one.
    fn channel_info(&self) -> DomainTag {
        DomainTag::new("dorsal", "bootstrap-channel", 1).expect("constant valid")
    }

    fn payload_aad(&self) -> DomainTag {
        DomainTag::new("dorsal", "bootstrap-payload", 1).expect("constant valid")
    }

    /// True if a successful `bootstrap()` has been observed. Exposed so
    /// callers (and tests) can distinguish "retriable failure" from
    /// "enclave sealed" after a bootstrap error.
    pub fn is_consumed(&self) -> bool {
        self.consumed.load(Ordering::SeqCst)
    }
}

pub struct BootstrapSetupResponse {
    pub enclave_ephem_pub: [u8; 32],
    pub session_id: [u8; 16],
}

pub struct BootstrapResponse {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub async fn bootstrap_setup(
    state: &BootstrapState,
    server_ephem_pub: [u8; 32],
    now_unix: i64,
) -> Result<BootstrapSetupResponse, BootstrapError> {
    if state.consumed.load(Ordering::SeqCst) {
        return Err(BootstrapError::AlreadyCompleted);
    }

    let rng = SystemRandom::new();
    let mut eph_bytes = Zeroizing::new([0u8; 32]);
    rng.fill(&mut *eph_bytes).map_err(|_| BootstrapError::Rng)?;
    let eph_priv = StaticSecret::from(*eph_bytes);
    let eph_pub = PublicKey::from(&eph_priv);

    let peer = PublicKey::from(server_ephem_pub);
    let shared = x25519_shared_secret_checked(&eph_priv, &peer)?;
    let info = state.channel_info();
    let channel_key = hkdf_sha256_32(shared.as_bytes(), Some(eph_pub.as_bytes()), &info);

    let mut session_id = [0u8; 16];
    rng.fill(&mut session_id).map_err(|_| BootstrapError::Rng)?;

    // Evict expired sessions.
    state
        .sessions
        .retain(|_, e| now_unix.saturating_sub(e.created_unix) <= SESSION_TTL_SECS);

    state.sessions.insert(
        session_id,
        SessionEntry {
            channel_key: Zeroizing::new(channel_key),
            created_unix: now_unix,
        },
    );

    Ok(BootstrapSetupResponse {
        enclave_ephem_pub: *eph_pub.as_bytes(),
        session_id,
    })
}

pub async fn bootstrap(
    state: &BootstrapState,
    session_id: [u8; 16],
    now_unix: i64,
) -> Result<BootstrapResponse, BootstrapError> {
    // Fast-reject duplicate calls. Real mutual exclusion happens below via
    // `sessions.remove`: DashMap guarantees at most one caller can claim a
    // given session_id, so two racers both past this load cannot both
    // succeed. `consumed.store(true)` is executed exactly once, on the
    // success branch, so any error above leaves the state retriable.
    if state.consumed.load(Ordering::SeqCst) {
        return Err(BootstrapError::AlreadyCompleted);
    }

    let Some((_, entry)) = state.sessions.remove(&session_id) else {
        return Err(BootstrapError::UnknownSession);
    };
    if now_unix.saturating_sub(entry.created_unix) > SESSION_TTL_SECS {
        return Err(BootstrapError::SessionExpired);
    }

    let rng = SystemRandom::new();
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce).map_err(|_| BootstrapError::Rng)?;

    let payload_aad = state.payload_aad();
    let ct = aes_gcm_encrypt(
        SuiteId::X25519HkdfSha256Aes256Gcm,
        &entry.channel_key,
        &nonce,
        &state.request_auth_key,
        AeadAad::Tag(&payload_aad),
    )?;

    // Single writer, success-only state transition. No error path above
    // reaches this line, so a failed bootstrap always leaves `consumed`
    // unset and the server can retry from `bootstrap_setup`.
    state.consumed.store(true, Ordering::SeqCst);

    Ok(BootstrapResponse {
        nonce,
        ciphertext: ct,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::{aes_gcm_decrypt, AeadAad, SuiteId};
    use crate::crypto::hkdf::hkdf_sha256_32;
    use x25519_dalek::{PublicKey, StaticSecret};

    const AUTH_KEY: [u8; 32] = [0xAA; 32];

    fn new_state() -> BootstrapState {
        BootstrapState::new(AUTH_KEY.to_vec())
    }

    fn server_keypair(seed: u8) -> (StaticSecret, PublicKey) {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        let sk = StaticSecret::from(bytes);
        let pk = PublicKey::from(&sk);
        (sk, pk)
    }

    async fn setup_once(state: &BootstrapState, now: i64, seed: u8) -> (StaticSecret, [u8; 16], [u8; 32]) {
        let (server_sk, server_pk) = server_keypair(seed);
        let resp = bootstrap_setup(state, *server_pk.as_bytes(), now)
            .await
            .expect("setup");
        (server_sk, resp.session_id, resp.enclave_ephem_pub)
    }

    fn decrypt_response(
        state: &BootstrapState,
        server_sk: &StaticSecret,
        enclave_pub: [u8; 32],
        resp: &BootstrapResponse,
    ) -> Vec<u8> {
        let peer = PublicKey::from(enclave_pub);
        let shared = server_sk.diffie_hellman(&peer);
        let info = state.channel_info();
        let channel_key = hkdf_sha256_32(shared.as_bytes(), Some(&enclave_pub), &info);
        let aad = state.payload_aad();
        let pt = aes_gcm_decrypt(
            SuiteId::X25519HkdfSha256Aes256Gcm,
            &channel_key,
            &resp.nonce,
            &resp.ciphertext,
            AeadAad::Tag(&aad),
        )
        .expect("decrypt");
        pt.to_vec()
    }

    #[tokio::test]
    async fn happy_path_reveals_auth_key_and_sets_consumed() {
        let state = new_state();
        let now = 1_700_000_000;
        let (server_sk, session_id, enclave_pub) = setup_once(&state, now, 7).await;

        assert!(!state.is_consumed());
        let resp = bootstrap(&state, session_id, now).await.expect("ok");
        assert!(state.is_consumed());
        let pt = decrypt_response(&state, &server_sk, enclave_pub, &resp);
        assert_eq!(pt, AUTH_KEY.to_vec());
    }

    fn expect_err(res: Result<BootstrapResponse, BootstrapError>) -> BootstrapError {
        match res {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        }
    }

    fn expect_setup_err(
        res: Result<BootstrapSetupResponse, BootstrapError>,
    ) -> BootstrapError {
        match res {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        }
    }

    #[tokio::test]
    async fn unknown_session_does_not_consume_and_retry_succeeds() {
        let state = new_state();
        let now = 1_700_000_000;

        let err = expect_err(bootstrap(&state, [0u8; 16], now).await);
        assert!(matches!(err, BootstrapError::UnknownSession));
        assert!(!state.is_consumed(), "consumed must stay false after UnknownSession");

        let (server_sk, session_id, enclave_pub) = setup_once(&state, now, 9).await;
        let resp = bootstrap(&state, session_id, now).await.expect("retry ok");
        assert!(state.is_consumed());
        let pt = decrypt_response(&state, &server_sk, enclave_pub, &resp);
        assert_eq!(pt, AUTH_KEY.to_vec());
    }

    #[tokio::test]
    async fn expired_session_does_not_consume_and_retry_succeeds() {
        let state = new_state();
        let now = 1_700_000_000;
        let (_, session_id, _) = setup_once(&state, now, 11).await;

        let future = now + SESSION_TTL_SECS + 1;
        let err = expect_err(bootstrap(&state, session_id, future).await);
        assert!(matches!(err, BootstrapError::SessionExpired));
        assert!(!state.is_consumed(), "consumed must stay false after SessionExpired");

        let (server_sk, session_id2, enclave_pub2) = setup_once(&state, future, 13).await;
        let resp = bootstrap(&state, session_id2, future).await.expect("retry ok");
        assert!(state.is_consumed());
        let pt = decrypt_response(&state, &server_sk, enclave_pub2, &resp);
        assert_eq!(pt, AUTH_KEY.to_vec());
    }

    #[tokio::test]
    async fn setup_rejects_after_consumed() {
        let state = new_state();
        let now = 1_700_000_000;
        let (_, session_id, _) = setup_once(&state, now, 17).await;
        bootstrap(&state, session_id, now).await.expect("ok");

        let (_, peer) = server_keypair(19);
        let err = expect_setup_err(bootstrap_setup(&state, *peer.as_bytes(), now).await);
        assert!(matches!(err, BootstrapError::AlreadyCompleted));
    }

    #[tokio::test]
    async fn second_bootstrap_is_rejected_even_with_fresh_session() {
        let state = new_state();
        let now = 1_700_000_000;

        let (_, session_id1, _) = setup_once(&state, now, 21).await;
        bootstrap(&state, session_id1, now).await.expect("ok");
        assert!(state.is_consumed());

        let err = expect_err(bootstrap(&state, [0u8; 16], now).await);
        assert!(matches!(err, BootstrapError::AlreadyCompleted));
    }

    #[tokio::test]
    async fn setup_rejects_low_order_peer_and_does_not_consume() {
        let state = new_state();
        let now = 1_700_000_000;

        // All-zero peer pubkey produces an all-zero shared secret, which
        // the RFC 7748 §5 check in `x25519_shared_secret_checked` rejects.
        let err = expect_setup_err(bootstrap_setup(&state, [0u8; 32], now).await);
        assert!(matches!(err, BootstrapError::Ecdh(_)));
        assert!(!state.is_consumed(), "consumed must stay false after Ecdh error");

        let (server_sk, session_id, enclave_pub) = setup_once(&state, now, 23).await;
        let resp = bootstrap(&state, session_id, now).await.expect("retry ok");
        let pt = decrypt_response(&state, &server_sk, enclave_pub, &resp);
        assert_eq!(pt, AUTH_KEY.to_vec());
    }
}
