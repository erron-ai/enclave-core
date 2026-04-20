//! Domain-separation tags. Every HKDF info, AEAD AAD, signing-message prefix
//! etc. flows through a validated `DomainTag` so product names and purposes
//! can't silently collide.

use thiserror::Error;

const MAX_TAG_BYTES: usize = 96;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainTagError {
    #[error("product must match ^[a-z][a-z0-9]{{2,23}}$, got {0:?}")]
    InvalidProduct(String),
    #[error("purpose must match ^[a-z][a-z0-9-]{{0,63}}$, got {0:?}")]
    InvalidPurpose(String),
    #[error("version must be >= 1, got {0}")]
    InvalidVersion(u32),
    #[error("encoded tag is {got} bytes, max {max}")]
    TooLong { got: usize, max: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainTag(Vec<u8>);

impl DomainTag {
    pub fn new(product: &str, purpose: &str, version: u32) -> Result<Self, DomainTagError> {
        validate_product(product)?;
        validate_purpose(purpose)?;
        if version < 1 {
            return Err(DomainTagError::InvalidVersion(version));
        }
        let encoded = format!("{product}-{purpose}-v{version}").into_bytes();
        if encoded.len() > MAX_TAG_BYTES {
            return Err(DomainTagError::TooLong {
                got: encoded.len(),
                max: MAX_TAG_BYTES,
            });
        }
        Ok(Self(encoded))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn validate_product(s: &str) -> Result<(), DomainTagError> {
    let bytes = s.as_bytes();
    if bytes.len() < 3 || bytes.len() > 24 {
        return Err(DomainTagError::InvalidProduct(s.to_owned()));
    }
    if !bytes[0].is_ascii_lowercase() {
        return Err(DomainTagError::InvalidProduct(s.to_owned()));
    }
    if !bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(DomainTagError::InvalidProduct(s.to_owned()));
    }
    Ok(())
}

fn validate_purpose(s: &str) -> Result<(), DomainTagError> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return Err(DomainTagError::InvalidPurpose(s.to_owned()));
    }
    if !bytes[0].is_ascii_lowercase() {
        return Err(DomainTagError::InvalidPurpose(s.to_owned()));
    }
    if !bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(DomainTagError::InvalidPurpose(s.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn accepts_valid_tag() {
        let tag = DomainTag::new("dorsalmail", "transit", 1).unwrap();
        assert_eq!(tag.as_bytes(), b"dorsalmail-transit-v1");
    }

    #[test]
    fn rejects_empty_purpose() {
        assert!(DomainTag::new("dorsalmail", "", 1).is_err());
    }

    #[test]
    fn rejects_uppercase_product() {
        assert!(DomainTag::new("DorsalMail", "transit", 1).is_err());
    }

    #[test]
    fn rejects_zero_version() {
        assert!(DomainTag::new("dorsalmail", "transit", 0).is_err());
    }

    #[test]
    fn rejects_too_short_product() {
        assert!(DomainTag::new("ab", "transit", 1).is_err());
    }

    #[test]
    fn distinct_inputs_distinct_bytes() {
        let a = DomainTag::new("dorsalmail", "transit", 1).unwrap();
        let b = DomainTag::new("dorsalmail", "transit", 2).unwrap();
        let c = DomainTag::new("dorsalfiles", "transit", 1).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn domain_tag_rejects_invalid_construction() {
        assert_eq!(
            DomainTag::new("DorsalMail", "x", 1).unwrap_err(),
            DomainTagError::InvalidProduct("DorsalMail".into())
        );
        assert_eq!(
            DomainTag::new("dorsalmail", "", 1).unwrap_err(),
            DomainTagError::InvalidPurpose("".into())
        );
        assert_eq!(
            DomainTag::new("dorsalmail", "transit", 0).unwrap_err(),
            DomainTagError::InvalidVersion(0)
        );
        let p24 = "abcdefghijklmnopqrstuvwx";
        let purpose64 = "a".repeat(64);
        assert!(matches!(
            DomainTag::new(p24, &purpose64, 4_294_967_295),
            Err(DomainTagError::TooLong { .. })
        ));
    }

    proptest! {
        #[test]
        fn prop_valid_domain_tag_stable_as_bytes(ver in 1u32..10_000u32) {
            let tag = DomainTag::new("dorsalmail", "transit", ver).unwrap();
            let expected = format!("dorsalmail-transit-v{ver}");
            prop_assert_eq!(tag.as_bytes(), expected.as_bytes());
        }
    }
}
