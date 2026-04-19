//! Attestation: NSM integration, mock PCRs, public-key bundle, challenge
//! signing.

pub mod bundle;
pub mod challenge;
pub mod mock;
pub mod nsm;

pub use bundle::PublicKeyBundle;
pub use challenge::{sign_attestation_challenge, AttestError, AttestationReplayStore, MIN_CHALLENGE_BYTES};
pub use mock::mock_pcrs;
pub use nsm::{nsm_runtime_available, NsmError};

#[cfg(feature = "nitro")]
pub use nsm::{nsm_attestation_doc, nsm_attestation_doc_for_recipient, nsm_pcrs};
