//! Per-process resource limits.

pub const DEFAULT_MAX_BODY_BYTES: usize = 40 * 1024 * 1024;
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 8;
pub const DEFAULT_DRAIN_SECS: u64 = 30;
