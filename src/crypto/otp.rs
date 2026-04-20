//! OTP derivation and envelope MAC.
//!
//! The OTP MAC binds the full unlock envelope (DEK blob, encrypted-to blob,
//! ciphertext blob) so a compromised relay cannot substitute any one of them.
//! Canonical message bytes:
//!
//! ```text
//! "otp-mac-v1"
//! || u16_be(subject.len()) || subject
//! || u16_be(token.len())   || token
//! || i64_be(window)
//! || u32_be(commits.len()) || for each: u8(kind) || [u8; 32] hash
//! ```

use crate::crypto::hmac::hmac_sha256;

const MAC_PREFIX: &[u8] = b"otp-mac-v1";

pub struct OtpCommit {
    pub kind: u8,
    pub hash: [u8; 32],
}

pub fn derive_otp(key: &[u8; 32], subject: &[u8], token: &[u8], window: i64) -> String {
    let mut msg =
        Vec::with_capacity(subject.len() + token.len() + std::mem::size_of::<i64>() + 2);
    msg.extend_from_slice(subject);
    msg.push(b'|');
    msg.extend_from_slice(token);
    msg.push(b'|');
    msg.extend_from_slice(window.to_string().as_bytes());
    let tag = hmac_sha256(key, &msg);
    rfc6238_truncate(&tag)
}

pub fn derive_otp_mac(
    key: &[u8; 32],
    subject: &[u8],
    token: &[u8],
    window: i64,
    commits: &[OtpCommit],
) -> [u8; 32] {
    let mut msg = Vec::with_capacity(
        MAC_PREFIX.len()
            + 2 + subject.len()
            + 2 + token.len()
            + 8
            + 4
            + commits.len() * (1 + 32),
    );
    msg.extend_from_slice(MAC_PREFIX);
    msg.extend_from_slice(&(subject.len() as u16).to_be_bytes());
    msg.extend_from_slice(subject);
    msg.extend_from_slice(&(token.len() as u16).to_be_bytes());
    msg.extend_from_slice(token);
    msg.extend_from_slice(&window.to_be_bytes());
    msg.extend_from_slice(&(commits.len() as u32).to_be_bytes());
    for c in commits {
        msg.push(c.kind);
        msg.extend_from_slice(&c.hash);
    }
    hmac_sha256(key, &msg)
}

pub fn rfc6238_truncate(hmac_bytes: &[u8; 32]) -> String {
    let offset = (hmac_bytes[hmac_bytes.len() - 1] & 0x0f) as usize;
    let binary = ((hmac_bytes[offset] as u32 & 0x7f) << 24)
        | ((hmac_bytes[offset + 1] as u32) << 16)
        | ((hmac_bytes[offset + 2] as u32) << 8)
        | (hmac_bytes[offset + 3] as u32);
    let code = binary % 1_000_000;
    format!("{code:06}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn otp_is_six_digits() {
        let code = derive_otp(&[0xBBu8; 32], b"a@b.com", b"msg-token", 1);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn mac_changes_with_commits() {
        let key = [0xBBu8; 32];
        let commits_a = vec![OtpCommit {
            kind: 0x01,
            hash: [0xAA; 32],
        }];
        let commits_b = vec![OtpCommit {
            kind: 0x01,
            hash: [0xBB; 32],
        }];
        let a = derive_otp_mac(&key, b"s", b"t", 42, &commits_a);
        let b = derive_otp_mac(&key, b"s", b"t", 42, &commits_b);
        assert_ne!(a, b);
    }

    #[test]
    fn otp_and_otp_mac_outputs_are_not_interchangeable() {
        let key = [0xCCu8; 32];
        let otp = derive_otp(&key, b"subj", b"tok", 7);
        let mac = derive_otp_mac(&key, b"subj", b"tok", 7, &[]);
        assert_ne!(otp.len(), mac.len());
        assert_ne!(hex::encode(mac), otp);
    }
}
