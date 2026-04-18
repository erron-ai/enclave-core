#![cfg(feature = "stream-aead")]

use enclave_core::crypto::stream_aead::{
    stream_open_chunk, stream_seal_chunk, StreamError, StreamReceiver,
};
use enclave_core::DomainTag;

#[test]
fn drop_final_chunk_fails() {
    let info = DomainTag::new("dorsalfiles", "stream", 1).unwrap();
    let nonce_key = [0x11u8; 32];
    let aead_key = [0x22u8; 32];
    let stream_id = [0x33u8; 16];

    let chunks: Vec<Vec<u8>> = (0..3u64)
        .map(|i| {
            stream_seal_chunk(
                &nonce_key,
                &aead_key,
                &stream_id,
                i,
                i == 2,
                b"payload",
                &info,
            )
            .unwrap()
        })
        .collect();

    let mut recv = StreamReceiver::new(stream_id.to_vec());
    for (i, ct) in chunks.iter().take(2).enumerate() {
        let pt = stream_open_chunk(
            &nonce_key,
            &aead_key,
            &stream_id,
            i as u64,
            false,
            ct,
            &info,
        )
        .unwrap();
        recv.deliver(i as u64, false, pt.to_vec()).unwrap();
    }
    assert!(matches!(recv.finish(), Err(StreamError::MissingFinal)));
}

#[test]
fn swap_adjacent_fails() {
    let info = DomainTag::new("dorsalfiles", "stream", 1).unwrap();
    let nonce_key = [0x11u8; 32];
    let aead_key = [0x22u8; 32];
    let stream_id = [0x33u8; 16];

    let c0 = stream_seal_chunk(&nonce_key, &aead_key, &stream_id, 0, false, b"a", &info)
        .unwrap();
    let c1 = stream_seal_chunk(&nonce_key, &aead_key, &stream_id, 1, true, b"b", &info)
        .unwrap();

    // Swapped: try to open index 0 as if it's index 1 — nonce differs, AEAD fails.
    assert!(
        stream_open_chunk(&nonce_key, &aead_key, &stream_id, 1, true, &c0, &info).is_err(),
    );
    // Sanity: correct path works.
    let _ = stream_open_chunk(&nonce_key, &aead_key, &stream_id, 1, true, &c1, &info)
        .unwrap();
}
