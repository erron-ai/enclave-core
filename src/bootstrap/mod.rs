//! Encrypted bootstrap handshake (two-RPC). Replaces the legacy plaintext-hex
//! path. See §3.19.

pub mod handshake;

pub use handshake::{
    bootstrap, bootstrap_setup, BootstrapError, BootstrapResponse, BootstrapSetupResponse,
    BootstrapState,
};
