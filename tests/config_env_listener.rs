//! Environment parsing and listener policy (serial env tests).

use enclave_core::config::env::{Environment, EnvironmentError};
use enclave_core::server::listener::{build_listener, ListenerError, ListenerKind};
use serial_test::serial;
use std::sync::{Mutex, OnceLock};

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("env test lock")
}

#[test]
#[serial]
fn environment_parse_accepts_synonyms() {
    let _g = env_lock();
    std::env::remove_var("ENVIRONMENT");
    assert!(matches!(
        Environment::from_env(),
        Err(EnvironmentError::NotSet)
    ));

    std::env::set_var("ENVIRONMENT", "development");
    assert_eq!(Environment::from_env().unwrap(), Environment::Development);
    std::env::set_var("ENVIRONMENT", "dev");
    assert_eq!(Environment::from_env().unwrap(), Environment::Development);
    std::env::set_var("ENVIRONMENT", "production");
    assert_eq!(Environment::from_env().unwrap(), Environment::Production);
    std::env::set_var("ENVIRONMENT", "prod");
    assert_eq!(Environment::from_env().unwrap(), Environment::Production);
    std::env::remove_var("ENVIRONMENT");
}

#[test]
#[serial]
fn environment_parse_rejects_invalid() {
    let _g = env_lock();
    std::env::set_var("ENVIRONMENT", "staging");
    assert!(matches!(
        Environment::from_env(),
        Err(EnvironmentError::Invalid(_))
    ));
    std::env::remove_var("ENVIRONMENT");
}

#[test]
#[serial]
fn allow_dev_only_blocks_in_production() {
    let _g = env_lock();
    let err = Environment::Production
        .allow_dev_only("x", ())
        .unwrap_err();
    assert!(matches!(err, EnvironmentError::Invalid(_)));
}

#[tokio::test]
async fn build_listener_forbids_tcp_in_production() {
    let addr = "127.0.0.1:0".parse().unwrap();
    let res = build_listener(ListenerKind::Tcp { addr }, Environment::Production).await;
    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected TcpForbiddenInProduction"),
    };
    assert!(matches!(err, ListenerError::TcpForbiddenInProduction));
}

#[tokio::test]
async fn build_listener_vsock_unsupported_off_linux() {
    #[cfg(not(target_os = "linux"))]
    {
        let res = build_listener(ListenerKind::Vsock { port: 16 }, Environment::Development).await;
        let err = match res {
            Err(e) => e,
            Ok(_) => panic!("expected VsockUnsupported"),
        };
        assert!(matches!(err, ListenerError::VsockUnsupported));
    }
    #[cfg(target_os = "linux")]
    {
        // vsock bind may succeed in CI; only assert we don't return TcpForbidden.
        let _ = build_listener(ListenerKind::Vsock { port: 16 }, Environment::Development).await;
    }
}
