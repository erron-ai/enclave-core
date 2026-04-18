//! Top-level error type for the crate. Every module exports its own typed
//! error and we re-export them under the crate root. Programmer-error
//! invariants still `panic!`; validation / hot-path runtime errors come back
//! as `Result<T, Error>`.

use thiserror::Error;

use crate::attest::{AttestError, NsmError};
use crate::auth::{NonceError, RedisInitError, VerifyError};
use crate::bootstrap::BootstrapError;
use crate::config::ConfigError;
use crate::crypto::aead::AeadError;
use crate::crypto::ecdh::EcdhError;
use crate::crypto::ecies::EciesError;
use crate::crypto::ed25519::Ed25519Error;
use crate::crypto::hmac::HmacError;
use crate::domain::DomainTagError;
use crate::keys::blob::BlobError;
use crate::keys::sealing::KeyStoreError;
use crate::keys::slot::SlotError;
use crate::server::ListenerError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("domain tag: {0}")]
    DomainTag(#[from] DomainTagError),
    #[error("aead: {0}")]
    Aead(#[from] AeadError),
    #[error("ecdh: {0}")]
    Ecdh(#[from] EcdhError),
    #[error("ecies: {0}")]
    Ecies(#[from] EciesError),
    #[error("ed25519: {0}")]
    Ed25519(#[from] Ed25519Error),
    #[error("hmac: {0}")]
    Hmac(#[from] HmacError),
    #[error("key slot: {0}")]
    Slot(#[from] SlotError),
    #[error("sealed blob: {0}")]
    Blob(#[from] BlobError),
    #[error("key store: {0}")]
    KeyStore(#[from] KeyStoreError),
    #[error("nsm: {0}")]
    Nsm(#[from] NsmError),
    #[error("attest: {0}")]
    Attest(#[from] AttestError),
    #[error("verify: {0}")]
    Verify(#[from] VerifyError),
    #[error("nonce: {0}")]
    Nonce(#[from] NonceError),
    #[error("redis init: {0}")]
    RedisInit(#[from] RedisInitError),
    #[error("bootstrap: {0}")]
    Bootstrap(#[from] BootstrapError),
    #[error("listener: {0}")]
    Listener(#[from] ListenerError),
    #[error("config: {0}")]
    Config(#[from] ConfigError),
}

pub type Result<T> = std::result::Result<T, Error>;
