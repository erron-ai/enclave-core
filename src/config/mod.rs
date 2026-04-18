//! Environment-based startup configuration and validation.

pub mod env;
pub mod validator;

pub use env::{Environment, EnvironmentError};
pub use validator::{validate_startup, ConfigError, StartupContext};
