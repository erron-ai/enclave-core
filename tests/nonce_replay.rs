use enclave_core::auth::{NonceError, NonceReplayCache};

#[test]
fn duplicate_rejected() {
    let cache = NonceReplayCache::new(600, 100, "dorsalmail.".into());
    cache.check_and_insert("aaaaaaaaaaaaaaaa", 100).unwrap();
    assert_eq!(
        cache
            .check_and_insert("aaaaaaaaaaaaaaaa", 110)
            .unwrap_err(),
        NonceError::Replay
    );
}

#[test]
fn capacity_rejects_new() {
    let cache = NonceReplayCache::new(600, 2, "dorsalmail.".into());
    cache.check_and_insert("aaaaaaaaaaaaaaaa", 100).unwrap();
    cache.check_and_insert("bbbbbbbbbbbbbbbb", 100).unwrap();
    assert_eq!(
        cache
            .check_and_insert("cccccccccccccccc", 100)
            .unwrap_err(),
        NonceError::AtCapacity
    );
}

#[test]
fn expiry_frees_space() {
    let cache = NonceReplayCache::new(10, 2, "dorsalmail.".into());
    cache.check_and_insert("aaaaaaaaaaaaaaaa", 100).unwrap();
    cache.check_and_insert("bbbbbbbbbbbbbbbb", 100).unwrap();
    // Advance past TTL so evictions happen.
    cache.check_and_insert("cccccccccccccccc", 120).unwrap();
}
