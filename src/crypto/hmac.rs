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

    /// RFC 4231 test case 1 (20-byte key, "Hi There").
    #[test]
    fn hmac_sha256_matches_rfc4231_case1() {
        let key = [0x0bu8; 20];
        let msg = b"Hi There";
        let tag = hmac_sha256(&key, msg);
        let expected = hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
            .unwrap();
        assert_eq!(tag.as_slice(), expected.as_slice());
    }

    #[test]
    fn hmac_verify_rejects_wrong_tag_length() {
        let tag = hmac_sha256(b"k", b"m");
        assert_eq!(
            hmac_sha256_verify(b"k", b"m", &tag[..31]),
            Err(HmacError::BadTag)
        );
        let mut long = tag.to_vec();
        long.push(0);
        assert_eq!(
            hmac_sha256_verify(b"k", b"m", &long),
            Err(HmacError::BadTag)
        );
    }
}
