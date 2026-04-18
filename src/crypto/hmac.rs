//! HMAC-SHA256 helpers and constant-time compare.

use ring::hmac as ring_hmac;
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HmacError {
    #[error("hmac verify failed")]
    BadTag,
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let k = ring_hmac::Key::new(ring_hmac::HMAC_SHA256, key);
    let tag = ring_hmac::sign(&k, msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

pub fn hmac_sha256_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), HmacError> {
    let k = ring_hmac::Key::new(ring_hmac::HMAC_SHA256, key);
    ring_hmac::verify(&k, msg, tag).map_err(|_| HmacError::BadTag)
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    #[test]
    fn hmac_roundtrip() {
        let t = hmac_sha256(b"key", b"msg");
        hmac_sha256_verify(b"key", b"msg", &t).unwrap();
        assert!(hmac_sha256_verify(b"key", b"msg2", &t).is_err());
    }
}
