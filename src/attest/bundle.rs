//! Canonical public-key bundle.
//!
//! Wire format `pkb-v1`:
//!
//! ```text
//! "pkb-v1\n"
//! "product=" || product || "\n"
//! for each (name, key) in keys (BTreeMap iteration order = lex by name):
//!     name || "=" || hex_lower(key) || "\n"
//! ```

use std::collections::BTreeMap;

pub struct PublicKeyBundle {
    pub product: String,
    pub keys: BTreeMap<String, Vec<u8>>,
}

impl PublicKeyBundle {
    pub fn new(product: &str) -> Self {
        Self {
            product: product.to_owned(),
            keys: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, name: &str, key: Vec<u8>) {
        debug_assert!(is_valid_name(name), "invalid key name");
        self.keys.insert(name.to_owned(), key);
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"pkb-v1\n");
        out.extend_from_slice(b"product=");
        out.extend_from_slice(self.product.as_bytes());
        out.push(b'\n');
        for (name, key) in &self.keys {
            out.extend_from_slice(name.as_bytes());
            out.push(b'=');
            out.extend_from_slice(hex::encode(key).as_bytes());
            out.push(b'\n');
        }
        out
    }
}

fn is_valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return false;
    }
    if !b[0].is_ascii_lowercase() {
        return false;
    }
    b[1..]
        .iter()
        .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_order() {
        let mut a = PublicKeyBundle::new("dorsalmail");
        a.insert("x25519", vec![0x11; 4]);
        a.insert("dek_ecies", vec![0x22; 4]);
        let mut b = PublicKeyBundle::new("dorsalmail");
        b.insert("dek_ecies", vec![0x22; 4]);
        b.insert("x25519", vec![0x11; 4]);
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }
}
