use enclave_core::keys::blob::{deserialize, serialize};
use enclave_core::keys::slot::KeySlot;

#[test]
fn header_bytes_match_on_roundtrip() {
    let slots = vec![
        KeySlot::new("dorsalmail.x25519", vec![0x11; 32]).unwrap(),
        KeySlot::new("dorsalmail.otp_hmac", vec![0x22; 32]).unwrap(),
    ];
    let (pt, aad_a) = serialize(&slots);
    let (_slots, aad_b) = deserialize(&pt).unwrap();
    assert_eq!(aad_a, aad_b);
}

#[test]
fn duplicate_ids_rejected() {
    let slots = vec![
        KeySlot::new("dorsalmail.x25519", vec![0x11; 32]).unwrap(),
        KeySlot::new("dorsalmail.x25519", vec![0x22; 32]).unwrap(),
    ];
    let (pt, _) = serialize(&slots);
    assert!(deserialize(&pt).is_err());
}
