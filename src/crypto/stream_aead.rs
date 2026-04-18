//! Chunked AEAD for stream-oriented payloads. Feature-gated; DorsalMail does
//! not call this but we build it and test it so the API doesn't rot.

use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::aead::{aes_gcm_decrypt, aes_gcm_encrypt, AeadAad, AeadError, SuiteId};
use crate::crypto::hmac::hmac_sha256;
use crate::domain::DomainTag;

pub const STREAM_ID_MIN_BYTES: usize = 16;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StreamError {
    #[error("stream_id must be >= {STREAM_ID_MIN_BYTES} bytes")]
    StreamIdTooShort,
    #[error("unexpected chunk index")]
    BadIndex,
    #[error("duplicate final chunk")]
    DoubleFinal,
    #[error("missing final chunk")]
    MissingFinal,
    #[error("aead failure: {0}")]
    Aead(#[from] AeadError),
}

pub fn stream_chunk_nonce(
    chunk_nonce_key: &[u8; 32],
    stream_id: &[u8],
    chunk_index: u64,
    is_final: bool,
) -> [u8; 12] {
    let mut msg = Vec::with_capacity(stream_id.len() + 8 + 1);
    msg.extend_from_slice(stream_id);
    msg.extend_from_slice(&chunk_index.to_be_bytes());
    msg.push(if is_final { 0x01 } else { 0x00 });
    let tag = hmac_sha256(chunk_nonce_key, &msg);
    let mut n = [0u8; 12];
    n.copy_from_slice(&tag[..12]);
    n
}

pub fn stream_seal_chunk(
    chunk_nonce_key: &[u8; 32],
    chunk_aead_key: &[u8; 32],
    stream_id: &[u8],
    chunk_index: u64,
    is_final: bool,
    plaintext: &[u8],
    info: &DomainTag,
) -> Result<Vec<u8>, StreamError> {
    if stream_id.len() < STREAM_ID_MIN_BYTES {
        return Err(StreamError::StreamIdTooShort);
    }
    let nonce = stream_chunk_nonce(chunk_nonce_key, stream_id, chunk_index, is_final);
    let ct = aes_gcm_encrypt(
        SuiteId::X25519HkdfSha256Aes256Gcm,
        chunk_aead_key,
        &nonce,
        plaintext,
        AeadAad::Tag(info),
    )?;
    Ok(ct)
}

pub fn stream_open_chunk(
    chunk_nonce_key: &[u8; 32],
    chunk_aead_key: &[u8; 32],
    stream_id: &[u8],
    chunk_index: u64,
    is_final: bool,
    ciphertext: &[u8],
    info: &DomainTag,
) -> Result<Zeroizing<Vec<u8>>, StreamError> {
    if stream_id.len() < STREAM_ID_MIN_BYTES {
        return Err(StreamError::StreamIdTooShort);
    }
    let nonce = stream_chunk_nonce(chunk_nonce_key, stream_id, chunk_index, is_final);
    let pt = aes_gcm_decrypt(
        SuiteId::X25519HkdfSha256Aes256Gcm,
        chunk_aead_key,
        &nonce,
        ciphertext,
        AeadAad::Tag(info),
    )?;
    Ok(pt)
}

pub struct StreamReceiver {
    stream_id: Vec<u8>,
    next_index: u64,
    final_seen: bool,
    buffer: Vec<Vec<u8>>,
}

impl StreamReceiver {
    pub fn new(stream_id: Vec<u8>) -> Self {
        Self {
            stream_id,
            next_index: 0,
            final_seen: false,
            buffer: Vec::new(),
        }
    }

    pub fn stream_id(&self) -> &[u8] {
        &self.stream_id
    }

    pub fn deliver(
        &mut self,
        index: u64,
        is_final: bool,
        plaintext: Vec<u8>,
    ) -> Result<(), StreamError> {
        if index != self.next_index {
            return Err(StreamError::BadIndex);
        }
        if self.final_seen {
            return Err(StreamError::BadIndex);
        }
        if is_final {
            self.final_seen = true;
        }
        self.buffer.push(plaintext);
        self.next_index += 1;
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<Vec<u8>>, StreamError> {
        if !self.final_seen {
            return Err(StreamError::MissingFinal);
        }
        Ok(self.buffer)
    }
}
