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
    product: String,
    request_auth_key: Zeroizing<Vec<u8>>,
    sessions: DashMap<[u8; 16], SessionEntry>,
    consumed: Arc<AtomicBool>,
}

impl BootstrapState {
    pub fn new(product: String, request_auth_key: Vec<u8>) -> Self {
        Self {
            product,
            request_auth_key: Zeroizing::new(request_auth_key),
            sessions: DashMap::new(),
            consumed: Arc::new(AtomicBool::new(false)),
        }
    }

    fn channel_info(&self) -> DomainTag {
        DomainTag::new(&self.product, "bootstrap-channel", 1).expect("product valid")
    }

    fn payload_aad(&self) -> DomainTag {
        DomainTag::new(&self.product, "bootstrap-payload", 1).expect("product valid")
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
    if state
        .consumed
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(BootstrapError::AlreadyCompleted);
    }

    let Some((_, entry)) = state.sessions.remove(&session_id) else {
        // Restore consumed flag since we're rejecting this call.
        state.consumed.store(false, Ordering::SeqCst);
        return Err(BootstrapError::UnknownSession);
    };
    if now_unix.saturating_sub(entry.created_unix) > SESSION_TTL_SECS {
        state.consumed.store(false, Ordering::SeqCst);
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

    Ok(BootstrapResponse {
        nonce,
        ciphertext: ct,
    })
}
