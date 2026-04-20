//! Bootstrap adversarial coverage: TTL, wrong server key decrypt, concurrent bootstrap.

use enclave_core::bootstrap::{bootstrap, bootstrap_setup, BootstrapError, BootstrapState};
use enclave_core::crypto::aead::{aes_gcm_decrypt, AeadAad, SuiteId};
use enclave_core::crypto::hkdf::hkdf_sha256_32;
use enclave_core::domain::DomainTag;
use x25519_dalek::{PublicKey, StaticSecret};

const SESSION_TTL_SECS: i64 = 30;

fn channel_info() -> DomainTag {
    DomainTag::new("dorsal", "bootstrap-channel", 1).unwrap()
}

fn payload_aad() -> DomainTag {
    DomainTag::new("dorsal", "bootstrap-payload", 1).unwrap()
}

#[tokio::test]
async fn bootstrap_rejects_session_after_ttl() {
    let state = BootstrapState::new(vec![0xAAu8; 32]);
    let server_sk = StaticSecret::from([0x77u8; 32]);
    let server_pk = PublicKey::from(&server_sk);
    let t0 = 1_700_000_000_i64;
    let setup = bootstrap_setup(&state, *server_pk.as_bytes(), t0)
        .await
        .unwrap();
    let late = t0 + SESSION_TTL_SECS + 1;
    let err = match bootstrap(&state, setup.session_id, late).await {
        Err(e) => e,
        Ok(_) => panic!("expected SessionExpired"),
    };
    assert!(matches!(err, BootstrapError::SessionExpired));
    assert!(!state.is_consumed());
}

#[tokio::test]
async fn bootstrap_payload_decrypt_fails_with_wrong_server_key() {
    let state = BootstrapState::new(vec![0xCCu8; 32]);
    let server_sk = StaticSecret::from([0x11u8; 32]);
    let server_pk = PublicKey::from(&server_sk);
    let now = 1_700_000_100_i64;
    let setup = bootstrap_setup(&state, *server_pk.as_bytes(), now)
        .await
        .unwrap();
    let resp = bootstrap(&state, setup.session_id, now).await.unwrap();

    let wrong_sk = StaticSecret::from([0x22u8; 32]);
    let peer = PublicKey::from(setup.enclave_ephem_pub);
    let shared = wrong_sk.diffie_hellman(&peer);
    let channel_key = hkdf_sha256_32(shared.as_bytes(), Some(&setup.enclave_ephem_pub), &channel_info());
    let aad = payload_aad();
    let err = aes_gcm_decrypt(
        SuiteId::X25519HkdfSha256Aes256Gcm,
        &channel_key,
        &resp.nonce,
        &resp.ciphertext,
        AeadAad::Tag(&aad),
    )
    .unwrap_err();
    assert_eq!(
        err,
        enclave_core::crypto::aead::AeadError::AuthTagMismatch
    );
}

#[tokio::test]
async fn bootstrap_at_most_one_success_per_session_id_under_concurrency() {
    let state = std::sync::Arc::new(BootstrapState::new(vec![0xDDu8; 32]));
    let server_sk = StaticSecret::from([0x55u8; 32]);
    let server_pk = PublicKey::from(&server_sk);
    let now = 1_700_000_200_i64;
    let setup = bootstrap_setup(&state.as_ref(), *server_pk.as_bytes(), now)
        .await
        .unwrap();
    let sid = setup.session_id;
    let a = {
        let st = state.clone();
        tokio::spawn(async move { bootstrap(&st, sid, now).await })
    };
    let b = {
        let st = state.clone();
        tokio::spawn(async move { bootstrap(&st, sid, now).await })
    };
    let ra = a.await.unwrap();
    let rb = b.await.unwrap();
    let oks = [ra, rb].iter().filter(|r| r.is_ok()).count();
    assert!(oks <= 1, "at most one bootstrap Ok for same session_id");
}
