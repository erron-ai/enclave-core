//! HKDF-SHA256 checks through `hkdf_sha256_32` (RFC 5869–style empty IKM).

use enclave_core::crypto::hkdf::hkdf_sha256_32;
use enclave_core::domain::DomainTag;

#[test]
fn rfc5869_empty_ikm_distinct_info_distinct_okm() {
    let ikm: &[u8] = &[];
    let salt = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info_a = DomainTag::new("dorsalmail", "transit", 1).unwrap();
    let info_b = DomainTag::new("dorsalmail", "transit", 2).unwrap();
    let a = hkdf_sha256_32(ikm, Some(&salt), &info_a);
    let b = hkdf_sha256_32(ikm, Some(&salt), &info_b);
    assert_ne!(a, b);
    assert_eq!(a, hkdf_sha256_32(ikm, Some(&salt), &info_a));
}
