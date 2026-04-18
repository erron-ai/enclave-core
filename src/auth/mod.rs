//! Request authentication: canonical request format, nonce replay cache,
//! optional Redis persistence.

pub mod nonce_cache;
pub mod redis_nonce;
pub mod verify;

pub use nonce_cache::{NonceError, NonceReplayCache, RedisInitError};
pub use verify::{unix_timestamp_now, verify_signed_request, VerifyError, MAX_NONCE_LEN, MIN_NONCE_LEN};
