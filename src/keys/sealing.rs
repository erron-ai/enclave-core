//! KMS + SSM sealed key store.
//!
//! * `boot_key_store` — production boot path. SSM missing = hard error.
//! * `init_key_store` — one-shot seeding (rejects if the SSM parameter already
//!    exists).
//! * `mock_dev_key_store` — dev-only sentinel keys, panics outside
//!    `Environment::Development`.

use aws_sdk_kms::Client as KmsClient;
use aws_sdk_ssm::Client as SsmClient;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
#[cfg(feature = "nitro")]
use rsa::pkcs8::EncodePublicKey;
#[cfg(feature = "nitro")]
use rsa::rand_core::OsRng as RsaOsRng;
#[cfg(feature = "nitro")]
use rsa::{Oaep, RsaPrivateKey};
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use crate::config::env::Environment;
use crate::crypto::aead::{aes_gcm_decrypt, aes_gcm_encrypt, AeadAad, SuiteId};
use crate::domain::DomainTag;
use crate::keys::blob::{deserialize, serialize};
use crate::keys::slot::KeySlot;

#[derive(Debug, Error)]
pub enum KeyStoreError {
    #[error("ssm parameter missing in production")]
    SsmParameterMissing,
    #[error("attestation recipient unavailable (mock build)")]
    AttestationUnavailable,
    #[error("slot id {0:?} does not start with product prefix")]
    CrossProductSlot(String),
    #[error("kms: {0}")]
    Kms(String),
    #[error("ssm: {0}")]
    Ssm(String),
    #[error("blob: {0}")]
    Blob(String),
    #[error("aes-gcm: {0}")]
    Aead(String),
    #[error("rng: {0}")]
    Rng(String),
    #[error("parameter already initialized")]
    AlreadyInitialized,
}

pub struct KeyStoreConfig {
    pub product: String,
    pub kms_key_arn: String,
    pub ssm_param_name: String,
    pub aad_prefix: DomainTag,
}

pub struct SealedKeyStore {
    pub product: String,
    pub slots: Vec<KeySlot>,
}

impl SealedKeyStore {
    pub fn find(&self, slot_id: &str) -> Option<&KeySlot> {
        self.slots.iter().find(|s| s.id == slot_id)
    }
}

fn pack_ssm_blob(
    encrypted_data_key: &[u8],
    aad_suffix: &[u8],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Vec<u8> {
    let edk_len = encrypted_data_key.len() as u32;
    let aad_len = aad_suffix.len() as u32;
    let mut out =
        Vec::with_capacity(4 + edk_len as usize + 4 + aad_len as usize + 12 + ciphertext.len());
    out.extend_from_slice(&edk_len.to_be_bytes());
    out.extend_from_slice(encrypted_data_key);
    out.extend_from_slice(&aad_len.to_be_bytes());
    out.extend_from_slice(aad_suffix);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out
}

fn unpack_ssm_blob(blob: &[u8]) -> Result<(&[u8], &[u8], [u8; 12], &[u8]), KeyStoreError> {
    if blob.len() < 8 {
        return Err(KeyStoreError::Blob("too short for length prefix".into()));
    }
    let edk_len = u32::from_be_bytes(blob[0..4].try_into().unwrap()) as usize;
    if blob.len() < 4 + edk_len + 4 {
        return Err(KeyStoreError::Blob("too short for aad length".into()));
    }
    let aad_len = u32::from_be_bytes(blob[4 + edk_len..8 + edk_len].try_into().unwrap()) as usize;
    if blob.len() < 8 + edk_len + aad_len + 12 {
        return Err(KeyStoreError::Blob("too short".into()));
    }
    let edk = &blob[4..4 + edk_len];
    let aad_suffix = &blob[8 + edk_len..8 + edk_len + aad_len];
    let mut nonce = [0u8; 12];
    let nonce_start = 8 + edk_len + aad_len;
    nonce.copy_from_slice(&blob[nonce_start..nonce_start + 12]);
    let ct = &blob[nonce_start + 12..];
    Ok((edk, aad_suffix, nonce, ct))
}

fn build_blob_aad(cfg: &KeyStoreConfig, aad_suffix: &[u8]) -> Vec<u8> {
    let prefix = cfg.aad_prefix.as_bytes();
    let mut out = Vec::with_capacity(prefix.len() + aad_suffix.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(aad_suffix);
    out
}

struct KmsRecipient {
    info: aws_sdk_kms::types::RecipientInfo,
    #[cfg(feature = "nitro")]
    private_key: RsaPrivateKey,
}

impl KmsRecipient {
    fn info(&self) -> aws_sdk_kms::types::RecipientInfo {
        self.info.clone()
    }

    #[cfg(feature = "nitro")]
    fn decrypt_ciphertext_for_recipient(&self, ciphertext: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        self.private_key
            .decrypt(Oaep::new::<sha2::Sha256>(), ciphertext)
            .map_err(|e| KeyStoreError::Kms(format!("recipient decrypt: {e}")))
    }

    #[cfg(not(feature = "nitro"))]
    fn decrypt_ciphertext_for_recipient(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        Err(KeyStoreError::AttestationUnavailable)
    }
}

#[cfg(feature = "nitro")]
fn build_kms_recipient() -> Result<KmsRecipient, KeyStoreError> {
    if !crate::attest::nsm_runtime_available() {
        return Err(KeyStoreError::AttestationUnavailable);
    }

    let mut rng = RsaOsRng;
    let private_key =
        RsaPrivateKey::new(&mut rng, 2048).map_err(|e| KeyStoreError::Kms(format!("rsa keygen: {e}")))?;
    let public_key_der = private_key
        .to_public_key()
        .to_public_key_der()
        .map_err(|e| KeyStoreError::Kms(format!("rsa public key der: {e}")))?;
    let attestation_document = crate::attest::nsm_attestation_doc_for_recipient(public_key_der.as_ref())
        .map_err(|e| KeyStoreError::Kms(format!("recipient attestation: {e}")))?;

    Ok(KmsRecipient {
        info: aws_sdk_kms::types::RecipientInfo::builder()
            .key_encryption_algorithm(aws_sdk_kms::types::KeyEncryptionMechanism::RsaesOaepSha256)
            .attestation_document(aws_sdk_kms::primitives::Blob::new(attestation_document))
            .build(),
        private_key,
    })
}

#[cfg(not(feature = "nitro"))]
fn build_kms_recipient() -> Result<KmsRecipient, KeyStoreError> {
    Err(KeyStoreError::AttestationUnavailable)
}

pub async fn boot_key_store(
    kms: &KmsClient,
    ssm: &SsmClient,
    cfg: KeyStoreConfig,
) -> Result<SealedKeyStore, KeyStoreError> {
    let resp = ssm
        .get_parameter()
        .name(&cfg.ssm_param_name)
        .with_decryption(true)
        .send()
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("ParameterNotFound") || msg.contains("does not exist") {
                KeyStoreError::SsmParameterMissing
            } else {
                KeyStoreError::Ssm(msg)
            }
        })?;

    let value = resp
        .parameter()
        .and_then(|p| p.value())
        .unwrap_or_default()
        .trim()
        .to_owned();

    if value.is_empty() || value == "UNINITIALIZED" {
        return Err(KeyStoreError::SsmParameterMissing);
    }

    let blob_bytes = B64
        .decode(&value)
        .map_err(|e| KeyStoreError::Blob(format!("base64: {e}")))?;

    unseal(kms, &cfg, &blob_bytes).await
}

async fn unseal(
    kms: &KmsClient,
    cfg: &KeyStoreConfig,
    blob_bytes: &[u8],
) -> Result<SealedKeyStore, KeyStoreError> {
    let (encrypted_data_key, aad_suffix, nonce_bytes, ciphertext) = unpack_ssm_blob(blob_bytes)?;
    let recipient = build_kms_recipient()?;

    let dk = kms
        .decrypt()
        .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(
            encrypted_data_key.to_vec(),
        ))
        .recipient(recipient.info())
        .send()
        .await
        .map_err(|e| KeyStoreError::Kms(e.to_string()))?;

    let ciphertext_for_recipient = dk
        .ciphertext_for_recipient()
        .ok_or_else(|| KeyStoreError::Kms("no ciphertext_for_recipient".into()))?;
    let plaintext_key =
        Zeroizing::new(recipient.decrypt_ciphertext_for_recipient(ciphertext_for_recipient.as_ref())?);

    if plaintext_key.len() != 32 {
        return Err(KeyStoreError::Kms(format!(
            "data key wrong length: {}",
            plaintext_key.len()
        )));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&plaintext_key);

    let aad = build_blob_aad(cfg, aad_suffix);
    let pt = aes_gcm_decrypt(
        SuiteId::X25519HkdfSha256Aes256Gcm,
        &key_arr,
        &nonce_bytes,
        ciphertext,
        AeadAad::Bytes(&aad),
    )
    .map_err(|e| KeyStoreError::Aead(e.to_string()))?;

    let (slots, aad_suffix) =
        deserialize(&pt).map_err(|e| KeyStoreError::Blob(e.to_string()))?;
    finalize(cfg, slots, aad_suffix)
}

fn finalize(
    cfg: &KeyStoreConfig,
    slots: Vec<KeySlot>,
    _aad_suffix: Vec<u8>,
) -> Result<SealedKeyStore, KeyStoreError> {
    let expected_prefix = format!("{}.", cfg.product);
    for slot in &slots {
        if !slot.id.starts_with(&expected_prefix) {
            return Err(KeyStoreError::CrossProductSlot(slot.id.clone()));
        }
    }
    Ok(SealedKeyStore {
        product: cfg.product.clone(),
        slots,
    })
}

pub async fn init_key_store(
    kms: &KmsClient,
    ssm: &SsmClient,
    cfg: KeyStoreConfig,
) -> Result<SealedKeyStore, KeyStoreError> {
    // Refuse to overwrite.
    match ssm
        .get_parameter()
        .name(&cfg.ssm_param_name)
        .with_decryption(false)
        .send()
        .await
    {
        Ok(r) => {
            let v = r
                .parameter()
                .and_then(|p| p.value())
                .unwrap_or_default()
                .trim()
                .to_owned();
            if !v.is_empty() && v != "UNINITIALIZED" {
                return Err(KeyStoreError::AlreadyInitialized);
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if !(msg.contains("ParameterNotFound") || msg.contains("does not exist")) {
                return Err(KeyStoreError::Ssm(msg));
            }
        }
    }

    let rng = SystemRandom::new();
    let make = |len: usize| -> Result<Vec<u8>, KeyStoreError> {
        let mut out = vec![0u8; len];
        rng.fill(&mut out).map_err(|_| KeyStoreError::Rng("fill".into()))?;
        Ok(out)
    };

    let x25519 = make(32)?;
    let otp = make(32)?;
    let dek = make(32)?;
    let auth = make(32)?;
    // round-trip through StaticSecret for RFC 7748 clamping awareness
    let _ = StaticSecret::from({
        let mut a = [0u8; 32];
        a.copy_from_slice(&x25519);
        a
    });

    let slots = vec![
        KeySlot::new(format!("{}.x25519", cfg.product), x25519)
            .map_err(|e| KeyStoreError::Blob(e.to_string()))?,
        KeySlot::new(format!("{}.otp_hmac", cfg.product), otp)
            .map_err(|e| KeyStoreError::Blob(e.to_string()))?,
        KeySlot::new(format!("{}.dek_ecies", cfg.product), dek)
            .map_err(|e| KeyStoreError::Blob(e.to_string()))?,
        KeySlot::new(format!("{}.request_auth", cfg.product), auth)
            .map_err(|e| KeyStoreError::Blob(e.to_string()))?,
    ];

    let (plaintext, aad_suffix) = serialize(&slots);
    let recipient = build_kms_recipient()?;

    let gdk = kms
        .generate_data_key()
        .key_id(&cfg.kms_key_arn)
        .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
        .recipient(recipient.info())
        .send()
        .await
        .map_err(|e| KeyStoreError::Kms(e.to_string()))?;

    let plaintext_key = Zeroizing::new(
        recipient.decrypt_ciphertext_for_recipient(
            gdk.ciphertext_for_recipient()
                .ok_or_else(|| KeyStoreError::Kms("no ciphertext_for_recipient".into()))?
                .as_ref(),
        )?,
    );
    if plaintext_key.len() != 32 {
        return Err(KeyStoreError::Kms("data key wrong length".into()));
    }
    let edk = gdk
        .ciphertext_blob()
        .ok_or_else(|| KeyStoreError::Kms("no edk".into()))?
        .as_ref()
        .to_vec();

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&plaintext_key);

    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce)
        .map_err(|_| KeyStoreError::Rng("fill nonce".into()))?;

    let aad = build_blob_aad(&cfg, &aad_suffix);
    let ct = aes_gcm_encrypt(
        SuiteId::X25519HkdfSha256Aes256Gcm,
        &key_arr,
        &nonce,
        &plaintext,
        AeadAad::Bytes(&aad),
    )
    .map_err(|e| KeyStoreError::Aead(e.to_string()))?;

    let blob = pack_ssm_blob(&edk, &aad_suffix, &nonce, &ct);
    let b64 = B64.encode(&blob);

    ssm.put_parameter()
        .name(&cfg.ssm_param_name)
        .value(&b64)
        .r#type(aws_sdk_ssm::types::ParameterType::SecureString)
        .overwrite(false)
        .send()
        .await
        .map_err(|e| KeyStoreError::Ssm(e.to_string()))?;

    Ok(SealedKeyStore {
        product: cfg.product,
        slots,
    })
}

pub fn mock_dev_key_store(env: Environment, product: &str) -> SealedKeyStore {
    if env != Environment::Development {
        panic!("mock_dev_key_store called in non-development environment");
    }
    let slots = vec![
        KeySlot::new(format!("{}.x25519", product), vec![0xAA; 32]).unwrap(),
        KeySlot::new(format!("{}.otp_hmac", product), vec![0xBB; 32]).unwrap(),
        KeySlot::new(format!("{}.dek_ecies", product), vec![0xCC; 32]).unwrap(),
        KeySlot::new(format!("{}.request_auth", product), vec![0xDD; 32]).unwrap(),
    ];
    SealedKeyStore {
        product: product.to_owned(),
        slots,
    }
}

#[cfg(test)]
mod ssm_blob_tests {
    use super::*;

    #[test]
    fn ssm_blob_roundtrip_matches_published_layout() {
        let edk = [0xabu8; 32];
        let aad_suffix = b"\x01\x00\x00\x00slot";
        let nonce = [0x11u8; 12];
        let ciphertext = [0x22u8; 48];
        let packed = pack_ssm_blob(&edk, aad_suffix, &nonce, &ciphertext);
        let (e2, a2, n2, c2) = unpack_ssm_blob(&packed).unwrap();
        assert_eq!(e2, edk.as_slice());
        assert_eq!(a2, aad_suffix.as_slice());
        assert_eq!(n2, nonce);
        assert_eq!(c2, ciphertext.as_slice());
    }
}

#[cfg(test)]
mod finalize_tests {
    use super::*;
    use crate::domain::DomainTag;

    #[test]
    fn key_finalize_rejects_cross_product_slot() {
        let cfg = KeyStoreConfig {
            product: "dorsalmail".into(),
            kms_key_arn: "arn:x".into(),
            ssm_param_name: "/p".into(),
            aad_prefix: DomainTag::new("dorsalmail", "sealed-keys", 1).unwrap(),
        };
        let slots = vec![KeySlot::new("otherproduct.x25519", vec![0u8; 8]).unwrap()];
        let err = match finalize(&cfg, slots, vec![]) {
            Err(e) => e,
            Ok(_) => panic!("expected CrossProductSlot"),
        };
        assert!(matches!(
            err,
            KeyStoreError::CrossProductSlot(ref id) if id == "otherproduct.x25519"
        ));
    }
}
