//! Primitive crypto surface. Every primitive is `DomainTag`-parameterised so
//! product consumers can't confuse tags at call sites.

pub mod aead;
pub mod ecdh;
pub mod ecies;
pub mod ed25519;
pub mod hkdf;
pub mod hmac;
pub mod otp;
#[cfg(feature = "stream-aead")]
pub mod stream_aead;
pub mod zeroize_ext;

pub use aead::{aes_gcm_decrypt, aes_gcm_encrypt, AeadAad, AeadError, SuiteId};
pub use ecdh::{x25519_shared_secret_checked, EcdhError};
pub use ecies::{ecies_open, ecies_seal, EciesError};
pub use ed25519::{verify as ed25519_verify, Ed25519Error};
pub use hkdf::hkdf_sha256_32;
pub use hmac::{ct_eq, hmac_sha256, hmac_sha256_verify, HmacError};
pub use otp::{derive_otp, derive_otp_mac, rfc6238_truncate, OtpCommit};
