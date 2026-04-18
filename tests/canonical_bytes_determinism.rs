use enclave_core::attest::bundle::PublicKeyBundle;

#[test]
fn insertion_order_invariant() {
    let mut a = PublicKeyBundle::new("dorsalmail");
    a.insert("x25519", vec![0x11; 32]);
    a.insert("dek_ecies", vec![0x22; 32]);

    let mut b = PublicKeyBundle::new("dorsalmail");
    b.insert("dek_ecies", vec![0x22; 32]);
    b.insert("x25519", vec![0x11; 32]);

    assert_eq!(a.canonical_bytes(), b.canonical_bytes());
}

#[test]
fn starts_with_pkb_v1() {
    let b = PublicKeyBundle::new("dorsalmail");
    let bytes = b.canonical_bytes();
    assert!(bytes.starts_with(b"pkb-v1\n"));
}
