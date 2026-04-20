//! Requires Redis on localhost:6379. Run manually: `cargo test --test redis_integration -- --ignored`.

use enclave_core::auth::redis_nonce::seed_from_redis;
use redis::AsyncCommands;
use serial_test::serial;

#[tokio::test]
#[ignore = "requires local Redis"]
#[serial]
async fn seed_from_redis_returns_empty_on_connection_refused() {
    let client = redis::Client::open("redis://127.0.0.1:1").expect("redis url");
    let v = seed_from_redis(&client, "dorsalmail.test.").await;
    assert!(v.is_empty());
}

#[tokio::test]
#[ignore = "requires local Redis"]
#[serial]
async fn redis_roundtrip_nonce_seed_skips_bad_values() {
    let client = redis::Client::open("redis://127.0.0.1:6379").expect("redis url");
    let mut conn = match client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(_) => return,
    };
    let prefix = "dorsalmail.itest.";
    let key_ok = format!("{prefix}oknonce12345678");
    let key_bad = format!("{prefix}badval");
    let _: () = redis::cmd("SET")
        .arg(&key_ok)
        .arg(42_i64)
        .query_async(&mut conn)
        .await
        .expect("set ok");
    let _: () = redis::cmd("SET")
        .arg(&key_bad)
        .arg("not-an-int")
        .query_async(&mut conn)
        .await
        .expect("set bad");

    let seed = seed_from_redis(&client, prefix).await;
    assert!(seed.iter().any(|(n, _)| n == "oknonce12345678"));
    assert!(!seed.iter().any(|(n, _)| n == "badval"));

    let _: () = conn.del(&key_ok).await.expect("del");
    let _: () = conn.del(&key_bad).await.expect("del");
}
