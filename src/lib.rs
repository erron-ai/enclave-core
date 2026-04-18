//! `enclave-core` — shared cryptographic + runtime library used by DorsalMail
//! (and future DorsalForms / DorsalFiles / DorsalSocket / DorsalChat) Nitro
//! Enclave binaries. Product-parameterised; no product-specific semantics live
//! here. See `infra/architecture.md` and `infra/plan.md` for the authoritative
//! reference.

pub mod attest;
pub mod auth;
pub mod bootstrap;
pub mod config;
pub mod crypto;
pub mod domain;
pub mod error;
pub mod keys;
pub mod server;

pub use domain::{DomainTag, DomainTagError};
pub use error::{Error, Result};
