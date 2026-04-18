//! Execution environment.

use thiserror::Error;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Environment {
    Development,
    Production,
}

#[derive(Debug, Error)]
pub enum EnvironmentError {
    #[error("ENVIRONMENT not set (expected 'development' or 'production')")]
    NotSet,
    #[error("ENVIRONMENT={0:?} invalid; expected 'development' or 'production'")]
    Invalid(String),
}

impl Environment {
    pub fn from_env() -> Result<Self, EnvironmentError> {
        let raw = std::env::var("ENVIRONMENT").map_err(|_| EnvironmentError::NotSet)?;
        match raw.trim().to_ascii_lowercase().as_str() {
            "development" | "dev" => Ok(Self::Development),
            "production" | "prod" => Ok(Self::Production),
            other => Err(EnvironmentError::Invalid(other.to_owned())),
        }
    }

    pub fn allow_dev_only<T>(&self, feature: &str, value: T) -> Result<T, EnvironmentError> {
        if *self == Environment::Production {
            return Err(EnvironmentError::Invalid(format!(
                "dev-only feature {feature} rejected in production"
            )));
        }
        Ok(value)
    }
}
