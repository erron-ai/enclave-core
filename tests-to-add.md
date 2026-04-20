# Proposed unit and integration tests for `enclave-core`

This document lists **deliberate, high-signal** tests to add for the shared Nitro-enclave library (`enclave-core`). It was produced after a full read of the crate layout plus **three parallel codebase investigations** (cryptography primitives, auth/bootstrap/keys/server/config, attestation).

Goals:

- Catch **regressions in cryptographic binding** (domain separation, AAD, suite bytes, truncation).
- Lock in **security-relevant state machines** (bootstrap one-shot, nonce replay, session TTL).
- Exercise **configuration and environment** rules that gate production deployments.
- Add **verifier-side** tests where the crate only exposes “sign” or “encode” today (via test-only helpers or golden vectors).

Suggested locations use existing patterns: `#[cfg(test)]` in `src/`, integration tests under `tests/`, optional `proptest` where property checks add confidence without flakiness.

---

## What is already covered (do not duplicate blindly)

- **Domain tags**: validation and distinct tuples (`src/domain.rs`, `tests/domain_separation.rs`).
- **ECIES**: basic roundtrip, unknown suite byte, ciphertext bit-flip (`src/crypto/ecies.rs`, `tests/ecies_roundtrip.rs`).
- **AEAD**: roundtrip with `Tag` and `Empty`; note the test named `flip_suite_fails_auth` in `aead.rs` currently **decrypts with matching wire AAD** (sanity of GCM only)—it does **not** assert that passing a wrong `SuiteId` to `aes_gcm_decrypt` fails; that gap is listed below.
- **Bootstrap**: happy path, unknown/expired session, consumed flag, second bootstrap rejected, low-order peer on setup (`src/bootstrap/handshake.rs` unit tests, `tests/bootstrap_handshake.rs`).
- **Nonce replay cache**: duplicate, capacity, TTL eviction (`tests/nonce_replay.rs`, `nonce_cache` behavior).
- **Stream AEAD** (feature `stream-aead`): truncation, index swap, missing final (`tests/stream_aead_truncation.rs`).
- **Low-order X25519 points**: spot-check (`tests/low_order_point.rs`).
- **Config validator**: partial coverage in `src/config/validator.rs` tests.

---

## Priority P0 — Cryptographic correctness and binding

These tests target bugs that silently break confidentiality or authentication.

| # | Test focus | Scenario | Expected | Suggested location |
|---|------------|----------|----------|-------------------|
| 1 | **AEAD suite byte in decrypt API** | Encrypt with `SuiteId::X25519HkdfSha256Aes256Gcm`; call `aes_gcm_decrypt` with correct key/nonce/ciphertext but **wrong `suite` argument** (wire AAD first byte wrong). | `AeadError::AuthTagMismatch` (or documented behavior). | `src/crypto/aead.rs` or `tests/aead_suite_binding.rs` |
| 2 | **AEAD domain separation (`Tag`)** | Same key/nonce/ciphertext; decrypt with **different** `AeadAad::Tag` (different `DomainTag`). | Fails authentication. | `tests/aead_domain_separation.rs` |
| 3 | **`Tag` vs `Bytes` equivalence** | When `Bytes` slice equals `tag.as_bytes()`, behavior matches `AeadAad::Tag` for encrypt/decrypt. | Roundtrip success; documents API contract. | `src/crypto/aead.rs` |
| 4 | **AEAD truncation** | Ciphertext shortened by 1 byte (body); tag shortened by 1 byte; extra trailing byte after tag. | All reject decrypt. | `tests/aead_truncation.rs` |
| 5 | **ECIES AAD mismatch** | `ecies_seal` with `AeadAad::Tag` or `Bytes`; `ecies_open` with different AAD not byte-identical. | `EciesError::Aead(AuthTagMismatch)` (or consistent error). | `tests/ecies_aad_mismatch.rs` |
| 6 | **ECIES length boundaries** | Blob length exactly `2+32+12+16-1` (too short); minimal valid empty plaintext. | `TooShort` vs success at boundary. | `src/crypto/ecies.rs` |
| 7 | **ECIES version byte** | `blob[0] != 0x01`. | `EciesError::BadVersion`. | `src/crypto/ecies.rs` |
| 8 | **ECIES ephemeral key tampering** | Flip byte(s) in `blob[2..34]`; still valid length. | Open fails (wrong key / AEAD). | `tests/ecies_wire_tampering.rs` |
| 9 | **ECIES HKDF salt = wire bytes** | Assert HKDF salt equals **raw** `eph` bytes from wire, not a re-canonicalized form (regression if `PublicKey` encoding ever diverges). | Golden or property: salt slice `== &blob[2..34]`. | `src/crypto/ecies.rs` (internal assert or test-only helper) |
|10 | **Seal-side ECDH vs open-side check** | Document and test: `ecies_seal` uses unchecked DH on recipient; `ecies_open` uses `x25519_shared_secret_checked`. Add tests for **malformed/recipient** scenarios that matter for downstream misuse (e.g. all-zero recipient public key in seal if API allows). | Defined error or panic-free failure; no silent acceptance of degenerate keys where policy requires rejection. | `tests/ecies_degenerate_recipient.rs` |
|11 | **HKDF empty IKM** | `hkdf_sha256_32` with `ikm = []` and distinct `DomainTag` `info`. | Deterministic, distinct outputs; no panic. | `src/crypto/hkdf.rs` |
|12 | **HKDF domain tag collision resistance** | Pairs that differ in product/purpose/version produce different `info` bytes; invalid tags rejected at `DomainTag::new`. | Strengthen with edge cases (hyphen in field, version 0 invalid, etc.) aligned with `DomainTag` rules. | `src/domain.rs` / `src/crypto/hkdf.rs` |
|13 | **HMAC verify wrong tag length** | `hmac_sha256_verify` with 31- or 33-byte tag. | `BadTag` / false verification per API. | `src/crypto/hmac.rs` or `tests/hmac_verify.rs` |
|14 | **Ed25519 strict verification** | Signature malleability / non-canonical S (use `ed25519-dalek` test vectors): `verify_strict` rejects where legacy verify might accept. | Failure on bad signatures. | `src/crypto/ed25519.rs` |
|15 | **OTP vs MAC encoding** | `derive_otp` vs `derive_otp_mac` use different serializations by design; golden test proving they are **not** interchangeable for the same logical inputs. | Distinct outputs; no accidental cross-protocol use. | `src/crypto/otp.rs` |
|16 | **Stream AEAD** (feature `stream-aead`) | `stream_id` length 15 vs 16; **duplicate final chunk**; **out-of-order** chunk index; same chunk index with `is_final` flipped. | Correct `StreamError` variants; no decrypt success on reorder. | `tests/stream_aead_chunk_boundary.rs` |
|17 | **Stream nonce uniqueness** | Small exhaustive range: distinct `(chunk_index, is_final)` → distinct derived nonces for fixed keys/stream id. | No collisions in tested range. | `src/crypto/stream_aead.rs` (feature) |

---

## Priority P1 — Auth, bootstrap edge cases, keys, errors

| # | Test focus | Scenario | Expected | Suggested location |
|---|------------|----------|----------|-------------------|
| 1 | **Nonce TTL boundary** | `ttl_secs = T`, insert at `ts`, call `check_and_insert` at `ts + T` vs `ts + T + 1`. | At `+T`: entry still valid → **Replay** on same nonce; at `+T+1`: evicted, insert ok. Aligns with `retain` using `<= ttl_secs`. | `src/auth/nonce_cache.rs` |
| 2 | **Capacity after eviction** | Fill to `max_entries`, advance `now` past TTL, insert new. | Succeeds (not `AtCapacity`). | `src/auth/nonce_cache.rs` |
| 3 | **`verify_signed_request` + `AtCapacity`** | Valid HMAC path but cache at capacity **before** insert. | `VerifyError::Nonce(NonceError::AtCapacity)` (not `ReplayDetected`). | `src/auth/verify.rs` |
| 4 | **Skew boundary** | `(now_secs - timestamp).abs() == max_skew_secs` vs `max_skew_secs + 1`. | Accept vs `StaleTimestamp`. | `src/auth/verify.rs` |
| 5 | **Canonical request stability** | Golden bytes for fixed `(product, method, path, timestamp, nonce, body)` including product case normalization. | Byte-exact match (prevents accidental format drift). | `src/auth/verify.rs` or `tests/canonical_request_golden.rs` |
| 6 | **`release_error_message`** | Under `not(debug_assertions)` with `auth-verbose-errors` off, every `VerifyError` maps to opaque string (existing pattern in module—extend for any new variants). | Single stable client-facing string. | `src/auth/verify.rs` + CI matrix note |
| 7 | **Bootstrap session map eviction** | `bootstrap_setup` at `now`, wait simulated `now + SESSION_TTL + 1`, old `session_id` not in map; bootstrap old id → `UnknownSession`. | No leak of stale sessions past TTL. | `src/bootstrap/handshake.rs` |
| 8 | **Concurrent `bootstrap` same `session_id`** | Two concurrent tasks call `bootstrap` with same id (single-threaded poll or `tokio::join!`). | At most one success; other gets `UnknownSession` or `AlreadyCompleted` per ordering. | `src/bootstrap/handshake.rs` |
| 9 | **Wrong server ECDH key decrypt** | Setup with server key A; decrypt channel payload with key B. | AEAD failure. | `src/bootstrap/handshake.rs` or integration test |
|10 | **Key blob AAD** | `keys/blob` serialize/deserialize, duplicate slot id, AAD suffix equality (extends `tests/sealed_blob_aad.rs`). | `BlobError` / stable AAD. | `src/keys/blob.rs` |
|11 | **`finalize` cross-product slot** | Slot id not prefixed with `{product}.`. | `KeyStoreError::CrossProductSlot` (or current variant). | `src/keys/sealing.rs` |
|12 | **SSM pack/unpack roundtrip** | If functions are test-accessible, known `edk`, `aad_suffix`, `nonce`, `ct`. | Bytes roundtrip. | `src/keys/sealing.rs` |
|13 | **`Error` / `VerifyError` taxonomy** | `From` impls and `Display` do not regress when adding variants. | Compile-time + snapshot optional. | `src/error.rs` |

---

## Priority P2 — Config, environment, server surfaces

| # | Test focus | Scenario | Expected | Suggested location |
|---|------------|----------|----------|-------------------|
| 1 | **`validate_startup` invalid mode** | `attestation_mode = "off"` in dev context. | `ConfigError::InvalidAttestationMode`. | `src/config/validator.rs` |
| 2 | **Production matrix** | Missing KMS; missing SSM; nonce prefix wrong; TCP listener; SES override. | Each returns the specific `ConfigError`. | `src/config/validator.rs` |
| 3 | **`Environment::from_env`** | Unset `ENVIRONMENT`; `prod`; invalid string; `allow_dev_only` in production. | Documented `EnvironmentError` / `Environment` variants. | `src/config/env.rs` |
| 4 | **`build_listener` TCP in production** | `ListenerKind::Tcp`, `Environment::Production`. | `TcpForbiddenInProduction` without binding. | `src/server/listener.rs` |
| 5 | **`build_listener` vsock on non-Linux** | If CI runs on macOS, vsock returns `VsockUnsupported`. | Consistent error. | `src/server/listener.rs` |
| 6 | **Bind failure** | Invalid address/port (platform-specific) yields `BindFailed` with message. | Error path smoke test. | `src/server/listener.rs` |
| 7 | **`RedisInitError::PrefixMissingProduct`** | If constructor paths exist that should validate prefix, assert error; if **never constructed**, track as dead code / add validation. | Matches product policy. | `src/auth/nonce_cache.rs`, `src/auth/redis_nonce.rs` |

---

## Priority P3 — Redis nonce writer (integration)

These need a **real Redis** or testcontainer (`redis` on localhost or CI service). They validate persistence semantics that in-memory tests cannot.

| # | Test focus | Scenario | Expected |
|---|------------|----------|----------|
| 1 | **SET shape** | `RedisWriter::push` with `expires_at = ts + 60`. | Key `{prefix}{nonce}`, TTL ≈ 60, value encodes timestamp. |
| 2 | **TTL ≤ 0 skipped** | `expires_at <= ts`. | No key (or no write). |
| 3 | **`seed_from_redis`** | Pre-seed keys matching prefix; value parses as `i64`. | Parsed `(nonce, ts)` correct. |
| 4 | **Malformed GET** | Key matches pattern but value not `i64`. | Omitted from seed; no panic. |
| 5 | **Connection refused** | Invalid URL / no server. | Empty seed or documented error path (match implementation). |

---

## Priority P4 — Attestation bundle and challenge (sign + golden vectors)

The crate **encodes** `PublicKeyBundle` and **signs** attestation challenges; there is **no** public parse/verify API. Tests should still lock formats and enable downstream verifiers to stay compatible.

| # | Test focus | Scenario | Expected | Notes |
|---|------------|----------|----------|--------|
| 1 | **Canonical bytes stability** | Fixed product + sorted key map → **frozen** `canonical_bytes()` output in test. | Byte-exact match; any intentional format change updates the vector. | `src/attest/bundle.rs` |
| 2 | **Ordering** | Insert keys in different orders; output identical (BTree order). | Same bytes. | `src/attest/bundle.rs` |
| 3 | **Challenge too short** | `challenge.len() < MIN_CHALLENGE_BYTES`. | `AttestError::ChallengeTooShort`. | `src/attest/challenge.rs` |
| 4 | **HMAC sign golden** | Fixed key + fixed inputs → fixed hex signature string. | Snapshot hex. | `src/attest/challenge.rs` |
| 5 | **Preimage sensitivity** | Flip one byte in product, mode, challenge hex, PCR line, or embedded bundle bytes → different MAC (or add `verify` test helper using `ring::hmac::verify`). | Verification fails vs golden. | `src/attest/challenge.rs` |
| 6 | **Attestation replay store** | Same 16-byte nonce within TTL vs after TTL; boundary `now - ts == ttl`. | Replay rejected vs accepted per `AttestationReplayStore` rules. | `src/attest/challenge.rs` |
| 7 | **`nsm_runtime_available`** | Without `nitro` feature: always `false`. | Unit test. | `src/attest/nsm.rs` |
| 8 | **Mock PCR panic policy** | `mock_pcrs` in non-Development (if still panics). | Document; prefer `Result` in API evolution + test. | `src/attest/mock.rs` |

Optional follow-up (product decision): expose **`verify_attestation_challenge`** mirroring `sign_attestation_challenge`, or document that verifiers **must** duplicate preimage layout—tests then call the same helper as production verifiers will.

---

## Test tooling and CI matrix

- **Unit tests**: default features; run on every PR.
- **`--features stream-aead`**: run stream AEAD tests.
- **`--features nitro` on Linux**: compile NSM code paths; hardware-dependent calls may stay mocked or `cfg`-skipped with explicit `#[ignore]` for enclave-only.
- **`cargo test --release`** (optional job): `release_error_message` / `not(debug_assertions)` paths for auth.
- **Redis**: gated integration tests `#[ignore]` unless `REDIS_TEST_URL` set, or use `testcontainers`.

---

## Meta: fixing misleading tests

- Rename or replace **`flip_suite_fails_auth`** in `src/crypto/aead.rs` so the name matches behavior, and add a test that **fails** when the **public API** `aes_gcm_decrypt` is called with the wrong `suite` (see P0 #1).

---

## Summary

This list is **intentionally not random**: it maps each proposed test to a **specific failure mode** (wrong binding, TTL off-by-one, concurrent session claim, format drift, Redis persistence). Implement P0 first for cryptographic guarantees, then P1–P2 for operational correctness, then Redis and attestation golden vectors as infrastructure allows.
