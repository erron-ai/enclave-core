//! HKDF-SHA256 with a typed `DomainTag` info parameter.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::domain::DomainTag;

pub fn hkdf_sha256_32(ikm: &[u8], salt: Option<&[u8]>, info: &DomainTag) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = [0u8; 32];
    hk.expand(info.as_bytes(), &mut out)
        .expect("32-byte expand cannot fail with SHA-256");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DomainTag;

    #[test]
    fn hkdf_is_deterministic() {
        let info = DomainTag::new("dorsalmail", "transit", 1).unwrap();
        let a = hkdf_sha256_32(&[0xAA; 32], None, &info);
        let b = hkdf_sha256_32(&[0xAA; 32], None, &info);
        assert_eq!(a, b);
    }

    #[test]
    fn hkdf_differs_by_info() {
        let i1 = DomainTag::new("dorsalmail", "transit", 1).unwrap();
        let i2 = DomainTag::new("dorsalmail", "transit", 2).unwrap();
        let a = hkdf_sha256_32(&[0xAA; 32], None, &i1);
        let b = hkdf_sha256_32(&[0xAA; 32], None, &i2);
        assert_ne!(a, b);
    }

    #[test]
    fn hkdf_differs_by_salt() {
        let info = DomainTag::new("dorsalmail", "transit", 1).unwrap();
        let a = hkdf_sha256_32(&[0xAA; 32], None, &info);
        let b = hkdf_sha256_32(&[0xAA; 32], Some(&[0x55; 32]), &info);
        assert_ne!(a, b);
    }
}
