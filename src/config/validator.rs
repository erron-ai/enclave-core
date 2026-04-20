//! Single grep-auditable production-rejection table.

use thiserror::Error;

use crate::config::env::Environment;
use crate::server::listener::ListenerKind;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("attestation mode 'mock' rejected in production")]
    MockAttestationInProduction,
    #[error("request-auth key missing")]
    AuthKeyMissing,
    #[error("kms key arn missing in production")]
    KmsKeyArnMissing,
    #[error("ssm parameter name missing in production")]
    SsmParameterMissing,
    #[error("nonce redis prefix missing in production")]
    NonceRedisPrefixMissing,
    #[error("nonce redis prefix must start with product prefix {0:?}")]
    NonceRedisPrefixMismatch(String),
    #[error("TCP listener forbidden in production")]
    TcpForbiddenInProduction,
    #[error("ses endpoint override forbidden in production")]
    SesEndpointOverrideInProduction,
    #[error("attestation mode {0:?} invalid (expected mock or nsm)")]
    InvalidAttestationMode(String),
}

pub struct StartupContext<'a> {
    pub env: Environment,
    pub product: &'a str,
    pub attestation_mode: &'a str,
    pub auth_key_present: bool,
    pub kms_key_arn: Option<&'a str>,
    pub ssm_param_name: Option<&'a str>,
    pub nonce_redis_prefix: Option<&'a str>,
    pub listener_kind: ListenerKind,
    pub ses_endpoint_override: Option<&'a str>,
}

pub fn validate_startup(ctx: &StartupContext) -> Result<(), ConfigError> {
    match ctx.attestation_mode {
        "mock" | "nsm" => {}
        other => return Err(ConfigError::InvalidAttestationMode(other.to_owned())),
    }

    if !ctx.auth_key_present {
        return Err(ConfigError::AuthKeyMissing);
    }

    if ctx.env == Environment::Production {
        if ctx.attestation_mode == "mock" {
            return Err(ConfigError::MockAttestationInProduction);
        }
        if ctx.kms_key_arn.is_none() {
            return Err(ConfigError::KmsKeyArnMissing);
        }
        if ctx.ssm_param_name.is_none() {
            return Err(ConfigError::SsmParameterMissing);
        }
        let product_prefix = format!("{}.", ctx.product);
        match ctx.nonce_redis_prefix {
            None => return Err(ConfigError::NonceRedisPrefixMissing),
            Some(p) if !p.starts_with(&product_prefix) => {
                return Err(ConfigError::NonceRedisPrefixMismatch(product_prefix));
            }
            _ => {}
        }
        if matches!(ctx.listener_kind, ListenerKind::Tcp { .. }) {
            return Err(ConfigError::TcpForbiddenInProduction);
        }
        if ctx.ses_endpoint_override.is_some() {
            return Err(ConfigError::SesEndpointOverrideInProduction);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev_ctx() -> StartupContext<'static> {
        StartupContext {
            env: Environment::Development,
            product: "dorsalmail",
            attestation_mode: "mock",
            auth_key_present: true,
            kms_key_arn: None,
            ssm_param_name: None,
            nonce_redis_prefix: None,
            listener_kind: ListenerKind::Tcp {
                addr: "127.0.0.1:7000".parse().unwrap(),
            },
            ses_endpoint_override: None,
        }
    }

    #[test]
    fn dev_ok() {
        validate_startup(&dev_ctx()).unwrap();
    }

    #[test]
    fn prod_rejects_mock_attestation() {
        let mut ctx = dev_ctx();
        ctx.env = Environment::Production;
        assert_eq!(
            validate_startup(&ctx).unwrap_err(),
            ConfigError::MockAttestationInProduction
        );
    }

    #[test]
    fn prod_rejects_tcp() {
        let mut ctx = dev_ctx();
        ctx.env = Environment::Production;
        ctx.attestation_mode = "nsm";
        ctx.kms_key_arn = Some("arn:...");
        ctx.ssm_param_name = Some("/dorsalmail/enclave/sealed-keys");
        ctx.nonce_redis_prefix = Some("dorsalmail.nonce:");
        assert_eq!(
            validate_startup(&ctx).unwrap_err(),
            ConfigError::TcpForbiddenInProduction
        );
    }

    fn prod_ok_ctx() -> StartupContext<'static> {
        StartupContext {
            env: Environment::Production,
            product: "dorsalmail",
            attestation_mode: "nsm",
            auth_key_present: true,
            kms_key_arn: Some("arn:aws:kms:example"),
            ssm_param_name: Some("/dorsalmail/p"),
            nonce_redis_prefix: Some("dorsalmail.nonce:"),
            listener_kind: ListenerKind::Vsock { port: 16 },
            ses_endpoint_override: None,
        }
    }

    #[test]
    fn validate_startup_rejects_invalid_attestation_mode() {
        let mut ctx = dev_ctx();
        ctx.attestation_mode = "off";
        assert_eq!(
            validate_startup(&ctx).unwrap_err(),
            ConfigError::InvalidAttestationMode("off".into())
        );
    }

    #[test]
    fn validate_startup_rejects_missing_auth_key() {
        let mut ctx = dev_ctx();
        ctx.auth_key_present = false;
        assert_eq!(
            validate_startup(&ctx).unwrap_err(),
            ConfigError::AuthKeyMissing
        );
    }

    #[test]
    fn validate_startup_production_rejects_missing_kms() {
        let mut ctx = prod_ok_ctx();
        ctx.kms_key_arn = None;
        assert_eq!(
            validate_startup(&ctx).unwrap_err(),
            ConfigError::KmsKeyArnMissing
        );
    }

    #[test]
    fn validate_startup_production_rejects_missing_ssm() {
        let mut ctx = prod_ok_ctx();
        ctx.ssm_param_name = None;
        assert_eq!(
            validate_startup(&ctx).unwrap_err(),
            ConfigError::SsmParameterMissing
        );
    }

    #[test]
    fn validate_startup_production_rejects_bad_nonce_prefix() {
        let mut ctx = prod_ok_ctx();
        ctx.nonce_redis_prefix = Some("wrong.nonce:");
        assert_eq!(
            validate_startup(&ctx).unwrap_err(),
            ConfigError::NonceRedisPrefixMismatch("dorsalmail.".into())
        );
    }

    #[test]
    fn validate_startup_production_rejects_missing_nonce_prefix() {
        let mut ctx = prod_ok_ctx();
        ctx.nonce_redis_prefix = None;
        assert_eq!(
            validate_startup(&ctx).unwrap_err(),
            ConfigError::NonceRedisPrefixMissing
        );
    }

    #[test]
    fn validate_startup_production_rejects_ses_override() {
        let mut ctx = prod_ok_ctx();
        ctx.ses_endpoint_override = Some("http://localhost:9999");
        assert_eq!(
            validate_startup(&ctx).unwrap_err(),
            ConfigError::SesEndpointOverrideInProduction
        );
    }

    #[test]
    fn validate_startup_production_ok_with_vsock() {
        validate_startup(&prod_ok_ctx()).unwrap();
    }
}
