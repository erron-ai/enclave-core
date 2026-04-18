//! Key slots, sealed blob format, KMS+SSM sealing boot path.

pub mod blob;
pub mod generation;
pub mod sealing;
pub mod slot;

pub use blob::{deserialize, serialize, BlobError};
pub use sealing::{
    boot_key_store, init_key_store, mock_dev_key_store, KeyStoreConfig, KeyStoreError,
    SealedKeyStore,
};
pub use slot::{KeySlot, SlotError};
