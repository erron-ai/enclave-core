# enclave-core

Shared Rust library for DorsalMail's AWS Nitro Enclave binaries: crypto primitives, sealed key management, NSM attestation, request authentication, encrypted bootstrap, and a vsock/TCP server runtime. Product-agnostic — all cross-cutting state is keyed by a validated `DomainTag`.

Target: `aarch64-unknown-linux-musl`, rustc pinned via [rust-toolchain.toml](rust-toolchain.toml). Crate manifest, deps, and feature flags (`nitro`, `stream-aead`, `key-generation`, `auth-verbose-errors`) in [Cargo.toml](Cargo.toml). Public module graph re-exported from [src/lib.rs](src/lib.rs).

## Core types

- **[domain.rs](src/domain.rs)** — `DomainTag` (`{product}-{purpose}-v{version}`, ≤96B) used as HKDF info / AEAD AAD / signing prefix to prevent cross-product collisions.
- **[error.rs](src/error.rs)** — crate-wide `Error` enum (`thiserror`) aggregating every module's error via `#[from]`; `Result<T>` alias.

## crypto/ — primitives, all `DomainTag`-parameterised

- **[mod.rs](src/crypto/mod.rs)** — re-export facade.
- **[aead.rs](src/crypto/aead.rs)** — AES-256-GCM with `SuiteId` byte prepended to AAD.
- **[stream_aead.rs](src/crypto/stream_aead.rs)** — chunked AEAD with HMAC-derived nonces + final-chunk marker (feature-gated).
- **[ecdh.rs](src/crypto/ecdh.rs)** — X25519 DH with RFC 7748 small-subgroup rejection.
- **[ecies.rs](src/crypto/ecies.rs)** — hybrid seal/open: ephemeral X25519 + HKDF + AES-GCM, versioned wire blob.
- **[ed25519.rs](src/crypto/ed25519.rs)** — strict (non-malleable) signature verification.
- **[hkdf.rs](src/crypto/hkdf.rs)** — HKDF-SHA256 → exactly 32 bytes, `DomainTag` as info.
- **[hmac.rs](src/crypto/hmac.rs)** — HMAC-SHA256 sign/verify + constant-time compare.
- **[otp.rs](src/crypto/otp.rs)** — RFC 6238 OTP + envelope-binding MAC (`OtpCommit`).

## keys/ — sealed multi-slot key store

- **[mod.rs](src/keys/mod.rs)** — facade.
- **[slot.rs](src/keys/slot.rs)** — `KeySlot`: move-only, `Zeroizing`, product-scoped ASCII id.
- **[blob.rs](src/keys/blob.rs)** — versioned (`0x01`) plaintext layout + AAD binding version/slot-count/ids.
- **[sealing.rs](src/keys/sealing.rs)** — boot path: fetch SSM blob → KMS-decrypt data key to attestation-bound RSA recipient → AES-GCM unseal → `SealedKeyStore`. Also exposes `mock_dev_key_store`.
- **[generation.rs](src/keys/generation.rs)** — `KeySet`/`KeyGeneration` rotation scaffold (feature `key-generation`).

## attest/ — Nitro NSM attestation

- **[mod.rs](src/attest/mod.rs)** — facade.
- **[bundle.rs](src/attest/bundle.rs)** — `PublicKeyBundle` canonical `pkb-v1` encoding signed by attestation.
- **[challenge.rs](src/attest/challenge.rs)** — HMAC-signed `att-v1` preimage + `AttestationReplayStore`.
- **[nsm.rs](src/attest/nsm.rs)** — real PCR reads & COSE attestation docs (feature `nitro`).
- **[mock.rs](src/attest/mock.rs)** — deterministic dev-only PCRs.

## auth/ — request authentication

- **[mod.rs](src/auth/mod.rs)** — facade.
- **[verify.rs](src/auth/verify.rs)** — HMAC-verifies canonical `product\nMETHOD\nPATH\nTS\nNONCE\nBODY`, enforces skew + nonce format; collapses to `"unauthorized"` in release.
- **[nonce_cache.rs](src/auth/nonce_cache.rs)** — TTL/capacity-bounded in-memory replay cache.
- **[redis_nonce.rs](src/auth/redis_nonce.rs)** — lossy async Redis writer + startup `seed_from_redis` for cross-instance replay protection.

## bootstrap/ — one-shot encrypted secret delivery

- **[mod.rs](src/bootstrap/mod.rs)** — facade.
- **[handshake.rs](src/bootstrap/handshake.rs)** — two-RPC X25519+HKDF+AES-GCM handshake; `bootstrap_setup` derives 30s session key, `bootstrap` delivers the `request_auth_key` and atomically seals so it can never be re-issued.

## server/ — transport & lifecycle

- **[mod.rs](src/server/mod.rs)** — facade.
- **[listener.rs](src/server/listener.rs)** — unified vsock/TCP listener enum (`ConcreteListener`, `ConnStream`); TCP forbidden in production.
- **[limits.rs](src/server/limits.rs)** — body-size / concurrency / drain-window constants.
- **[shutdown.rs](src/server/shutdown.rs)** — Ctrl+C / SIGTERM → graceful drain.

## config/ — environment & startup validation

- **[mod.rs](src/config/mod.rs)** — facade.
- **[env.rs](src/config/env.rs)** — `Environment` (Development/Production) from `ENVIRONMENT` env var.
- **[validator.rs](src/config/validator.rs)** — grep-auditable `validate_startup` table: rejects prod boots missing KMS ARN, SSM param, product nonce prefix, auth key, real attestation, or using TCP/mock/SES overrides.
