//! AWS Nitro Security Module integration.

#[cfg(feature = "nitro")]
use std::collections::BTreeMap;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NsmError {
    #[error("nsm device not available (build with --features nitro)")]
    Unavailable,
    #[error("nsm_init failed: {0}")]
    InitFailed(i32),
    #[error("DescribePCR[{0}] error: {1}")]
    DescribePcr(u16, String),
    #[error("nsm request failed: {0}")]
    RequestFailed(String),
}

pub fn nsm_runtime_available() -> bool {
    #[cfg(feature = "nitro")]
    {
        std::path::Path::new("/dev/nsm").exists()
    }
    #[cfg(not(feature = "nitro"))]
    {
        false
    }
}

#[cfg(feature = "nitro")]
pub fn nsm_pcrs() -> Result<BTreeMap<String, String>, NsmError> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

    let fd = nsm_init();
    if fd < 0 {
        return Err(NsmError::InitFailed(fd));
    }
    let mut pcrs = BTreeMap::new();
    for index in 0u16..=2 {
        let req = Request::DescribePCR { index };
        match nsm_process_request(fd, req) {
            Response::DescribePCR { lock: _, data } => {
                pcrs.insert(format!("PCR{index}"), hex::encode(data));
            }
            Response::Error(e) => {
                nsm_exit(fd);
                return Err(NsmError::DescribePcr(index, format!("{:?}", e)));
            }
            other => {
                nsm_exit(fd);
                return Err(NsmError::DescribePcr(index, format!("{:?}", other)));
            }
        }
    }
    nsm_exit(fd);
    Ok(pcrs)
}

#[cfg(feature = "nitro")]
pub fn nsm_attestation_doc(
    bundle: &crate::attest::bundle::PublicKeyBundle,
    challenge: &[u8],
) -> Result<Vec<u8>, NsmError> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

    if challenge.len() < crate::attest::challenge::MIN_CHALLENGE_BYTES {
        return Err(NsmError::RequestFailed("challenge too short".into()));
    }

    let fd = nsm_init();
    if fd < 0 {
        return Err(NsmError::InitFailed(fd));
    }
    let req = Request::Attestation {
        public_key: None,
        user_data: Some(bundle.canonical_bytes().into()),
        nonce: Some(challenge.to_vec().into()),
    };
    let out = match nsm_process_request(fd, req) {
        Response::Attestation { document } => Ok(document),
        Response::Error(e) => Err(NsmError::RequestFailed(format!("{:?}", e))),
        other => Err(NsmError::RequestFailed(format!("{:?}", other))),
    };
    nsm_exit(fd);
    out
}

#[cfg(feature = "nitro")]
pub fn nsm_attestation_doc_for_recipient(public_key_der: &[u8]) -> Result<Vec<u8>, NsmError> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

    let fd = nsm_init();
    if fd < 0 {
        return Err(NsmError::InitFailed(fd));
    }
    let req = Request::Attestation {
        public_key: Some(public_key_der.to_vec().into()),
        user_data: None,
        nonce: None,
    };
    let out = match nsm_process_request(fd, req) {
        Response::Attestation { document } => Ok(document),
        Response::Error(e) => Err(NsmError::RequestFailed(format!("{:?}", e))),
        other => Err(NsmError::RequestFailed(format!("{:?}", other))),
    };
    nsm_exit(fd);
    out
}
