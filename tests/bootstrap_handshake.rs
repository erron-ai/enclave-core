use enclave_core::bootstrap::{bootstrap, bootstrap_setup, BootstrapState};
use x25519_dalek::{PublicKey, StaticSecret};

#[tokio::test]
async fn happy_path() {
    let state = BootstrapState::new("dorsalmail".into(), vec![0xEEu8; 32]);
    let server_priv = StaticSecret::from([0x33u8; 32]);
    let server_pub = PublicKey::from(&server_priv);

    let setup = bootstrap_setup(&state, *server_pub.as_bytes(), 1_000)
        .await
        .unwrap();
    let resp = bootstrap(&state, setup.session_id, 1_001).await.unwrap();
    assert_eq!(resp.nonce.len(), 12);
    assert!(!resp.ciphertext.is_empty());
}

#[tokio::test]
async fn second_bootstrap_rejected() {
    let state = BootstrapState::new("dorsalmail".into(), vec![0xEEu8; 32]);
    let server_priv = StaticSecret::from([0x33u8; 32]);
    let server_pub = PublicKey::from(&server_priv);

    let setup = bootstrap_setup(&state, *server_pub.as_bytes(), 1_000)
        .await
        .unwrap();
    bootstrap(&state, setup.session_id, 1_001).await.unwrap();

    let setup2 = bootstrap_setup(&state, *server_pub.as_bytes(), 1_002).await;
    assert!(setup2.is_err());
}
