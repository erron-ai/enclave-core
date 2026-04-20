#![cfg(feature = "stream-aead")]

//! Stream AEAD framing (S4): duplicate final, ordering, short stream_id, nonce distinctness, chunk flips.

use enclave_core::crypto::stream_aead::{
    stream_chunk_nonce, stream_open_chunk, stream_seal_chunk, StreamError, StreamReceiver,
};
use enclave_core::DomainTag;

#[test]
fn stream_receiver_rejects_second_chunk_after_final() {
    let mut r = StreamReceiver::new(vec![0x33u8; 16]);
    r.deliver(0, true, b"a".to_vec()).unwrap();
    let err = r.deliver(1, true, b"b".to_vec()).unwrap_err();
    // `DoubleFinal` exists on the enum; `deliver` maps this case to `BadIndex`.
    assert_eq!(err, StreamError::BadIndex);
}

#[test]
fn stream_receiver_rejects_out_of_order_chunk() {
    let mut r = StreamReceiver::new(vec![0x33u8; 16]);
    let err = r.deliver(1, false, b"x".to_vec()).unwrap_err();
    assert_eq!(err, StreamError::BadIndex);
}

#[test]
fn stream_open_rejects_short_stream_id() {
    let info = DomainTag::new("dorsalfiles", "stream", 1).unwrap();
    let nk = [0x11u8; 32];
    let ak = [0x22u8; 32];
    let sid15 = [0x55u8; 15];
    let ct = vec![0u8; 32];
    let err = stream_open_chunk(&nk, &ak, &sid15, 0, false, &ct, &info).unwrap_err();
    assert_eq!(err, StreamError::StreamIdTooShort);
}

#[test]
fn stream_chunk_nonces_distinct_for_index_and_final() {
    let nk = [0xabu8; 32];
    let sid = [0x01u8; 16];
    let a = stream_chunk_nonce(&nk, &sid, 0, false);
    let b = stream_chunk_nonce(&nk, &sid, 0, true);
    assert_ne!(a, b);
}

#[test]
fn stream_inner_chunk_ct_and_tag_flip_fail() {
    let info = DomainTag::new("dorsalfiles", "stream", 1).unwrap();
    let nk = [0x11u8; 32];
    let ak = [0x22u8; 32];
    let sid = [0x33u8; 16];
    let mut ct = stream_seal_chunk(&nk, &ak, &sid, 0, false, b"data", &info).unwrap();
    ct[0] ^= 1;
    assert!(stream_open_chunk(&nk, &ak, &sid, 0, false, &ct, &info).is_err());
    let mut ct2 = stream_seal_chunk(&nk, &ak, &sid, 1, true, b"z", &info).unwrap();
    let last = ct2.len() - 1;
    ct2[last] ^= 1;
    assert!(stream_open_chunk(&nk, &ak, &sid, 1, true, &ct2, &info).is_err());
}
