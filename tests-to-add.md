# Proposed unit and integration tests for `enclave-core`

This document lists **deliberate, high-signal** tests to add for the shared Nitro-enclave library (`enclave-core`). It was produced after a full read of the crate layout plus **three parallel codebase investigations** (cryptography primitives, auth/bootstrap/keys/server/config, attestation).

## Testing philosophy (must-read)

Good tests start from the **adversary’s perspective**, not the developer’s. When designing a case, ask first: *how would this API be misused, fed malformed input, or attacked?* Happy-path byte equality is necessary but **never sufficient**.

- **Determinism**: Seed RNGs explicitly (`StdRng::seed_from_u64`, `SystemRandom` only where the API requires it and the test asserts structure, not bytes). **Never** use the wall clock in unit tests—thread `now_secs` / `now_unix` from the test. **Never** hit the network in default `cargo test`; Redis and similar are **opt-in** (`#[ignore]`, env-gated CI job, or in-process fakes).
- **Naming**: Structure tests around **behaviors**, not function names. One primary assertion per behavior where practical. Names should make CI failures self-explanatory: `aes_gcm_decrypt_rejects_flipped_ciphertext_bit` beats `test_decrypt_2`. Prefer minimal setup; **no shared mutable fixtures** between tests (parallel `cargo test` must stay safe).
- **AEAD siblings**: Every AEAD success test should have adversarial siblings that flip **one bit** (or one byte) in the **ciphertext**, **tag**, **AAD** (including suite/wire prefix), and **nonce**, and assert **rejection** with the correct error **type** (not string matching on secret-dependent paths).
- **Parser siblings**: Every decoder should see **truncated** input, **oversized** garbage, **non-canonical** encodings (padding, extra fields, wrong order if applicable), and **empty** input where allowed. Fuzzing catches classes of bugs example tests miss—see below.
- **Anchors**: Prefer **published** known-answer vectors—**RFC test vectors**, **NIST CAVP**, **Wycheproof** JSON—for primitives we implement or wrap (AES-GCM, HKDF, HMAC, Ed25519, X25519). Where the crate defines its own wire format (`pkb-v1`, `att-v1`, canonical request bytes), use **frozen fixture bytes** checked into the repo; those are “external” to the implementation under test even if we authored them once, and they must change only when the format version changes.
- **Self-consistency is not proof**: A test that only checks “encrypt then decrypt matches” using values generated in the same test mostly shows the code agrees with itself. Cross-check critical outputs against **independent** vectors or reference implementations when feasible.
- **Property tests**: Use `proptest` for algebraic invariants: encrypt/decrypt round-trip over random plaintexts (with fixed seed strategies), serialize/parse idempotence, “wrong key fails,” monotonicity of lengths, etc.
- **Unsafe and parsers**: Run **Miri** (`cargo miri test`) in CI on code paths using `unsafe` (or on the whole crate if affordable). Add **`cargo fuzz`** targets for every hand-written parser and binary decoder; keep corpora from fuzz failures as regression seeds.
- **What unit tests are not**: Do **not** assert **constant-time** behavior in ordinary tests—use **dudect** or a dedicated statistical harness if you need timing guarantees. Do **not** match error **strings** for crypto/auth failures if those strings could encode oracle or secret-adjacent detail; assert **`PartialEq` error enums** or stable public error kinds only.
- **Flakiness**: A flaky crypto test is worse than a failing one—it trains people to retry CI. If a test is nondeterministic, delete or fix it before merge.

Suggested locations use existing patterns: `#[cfg(test)]` in `src/`, integration tests under `tests/`, `proptest` behind explicit strategies with fixed seeds where helpful.

---

## Goals

- Catch **regressions in cryptographic binding** (domain separation, AAD, suite bytes, truncation).
- Lock in **security-relevant state machines** (bootstrap one-shot, nonce replay, session TTL).
- Exercise **configuration and environment** rules that gate production deployments.
- Add **verifier-side** tests where the crate only exposes “sign” or “encode” today (via test-only helpers or frozen vectors).

---

## What is already covered (do not duplicate blindly)

- **Domain tags**: validation and distinct tuples (`src/domain.rs`, `tests/domain_separation.rs`).
- **ECIES**: basic roundtrip, unknown suite byte, ciphertext bit-flip (`src/crypto/ecies.rs`, `tests/ecies_roundtrip.rs`).
- **AEAD**: roundtrip with `Tag` and `Empty`; the test named `flip_suite_fails_auth` in `aead.rs` currently **decrypts with matching wire AAD** (GCM sanity only)—it does **not** assert rejection when the **public** `aes_gcm_decrypt` is given a wrong `SuiteId`; treat as **misleading name** (see Meta).
- **Bootstrap**: happy path, unknown/expired session, consumed flag, second bootstrap rejected, low-order peer on setup (`src/bootstrap/handshake.rs` unit tests, `tests/bootstrap_handshake.rs`).
- **Nonce replay cache**: duplicate, capacity, TTL eviction (`tests/nonce_replay.rs`, `nonce_cache` behavior).
- **Stream AEAD** (feature `stream-aead`): truncation, index swap, missing final (`tests/stream_aead_truncation.rs`).
- **Low-order X25519 points**: spot-check (`tests/low_order_point.rs`).
- **Config validator**: partial coverage in `src/config/validator.rs` tests.

---

## AEAD adversarial matrix (apply to every AES-GCM call site)

For each encrypt/decrypt pair (raw `aes_gcm_*`, ECIES-open path, bootstrap payload decrypt helpers):

| Mutation | Expect |
|----------|--------|
| Flip one bit in ciphertext body | `AeadError::AuthTagMismatch` (or equivalent) |
| Flip one bit in tag | Reject |
| Flip one bit in AAD / wire AAD (incl. suite byte) | Reject when decrypt uses wrong binding |
| Flip one bit in nonce | Reject |
| Truncate / extend ciphertext | Reject |
| Wrong key (neighbor byte) | Reject |

ECIES additionally: flip bits in **version byte**, **suite byte**, **ephemeral pubkey**, **nonce field**, and **HKDF info** mismatch (wrong `DomainTag`).

---

## Parser / decoder adversarial matrix

For every layout: `DomainTag` parsing (if extended), `keys/blob`, ECIES blob prefix, stream framing, env parsing, hex fields in bundles/challenges:

| Input class | Expect |
|-------------|--------|
| Empty, minimal valid, maximal valid | Defined `Ok` or `Err` |
| Truncated at each offset | `TooShort` / parse error—no panic, no partial success |
| Buffer longer than declared payload | Reject or ignore only per spec—document |
| Non-canonical encodings (e.g. alternate hex case, extra whitespace) | Reject unless explicitly allowed |
| Invalid UTF-8 where strings claimed | `Err`, no panic |

**Fuzz** targets should exercise these automatically; keep minimized crashes as regression tests.

---

## External known-answer vectors (anchor checklist)

| Primitive | Source | Notes |
|-----------|--------|--------|
| AES-256-GCM | NIST CAVP or RFC 8452 test vectors | Use keys/nonce/pt/ct/aad from published JSON; verify encrypt and decrypt paths. |
| HKDF-SHA256 | RFC 5869 test cases | `info`/`salt`/`IKM`/`OKM` vectors. |
| HMAC-SHA256 | RFC 4231 | Known MACs. |
| X25519 / Ed25519 | RFC 7748 / 8032 or Wycheproof | Low-order and edge cases already partially covered—complete with vectors. |
| Custom wire formats | Frozen `tests/fixtures/*.bin` | Versioned; changelog when bytes change. |

Protocol-specific HMAC preimages (`att-v1`, canonical request) should use **checked-in golden bytes** plus bit-flip tampering tests.

---

## Priority P0 — Cryptographic correctness and binding

These tests target bugs that silently break confidentiality or authentication. Implement the **AEAD matrix** rows for each row below where applicable.

| # | Behavior (test name should reflect this) | Adversary / scenario | Expected | Suggested location |
|---|------------------------------------------|----------------------|----------|-------------------|
| 1 | `aes_gcm_decrypt_rejects_wrong_suite_id` | Correct key/nonce/ct; **wrong `SuiteId`** arg → wrong wire AAD | `AeadError::AuthTagMismatch` (or documented) | `src/crypto/aead.rs` |
| 2 | `aes_gcm_decrypt_rejects_mismatched_domain_tag_aad` | Same ct; **different** `AeadAad::Tag` | Reject | `tests/aead_domain_separation.rs` |
| 3 | `aes_gcm_tag_bytes_matches_tag_when_bytes_equal` | `AeadAad::Bytes` == `tag.as_bytes()` vs `Tag` | Same outcome as Tag path | `src/crypto/aead.rs` |
| 4 | `aes_gcm_decrypt_rejects_truncated_and_padded_ciphertext` | −1 byte, +1 garbage byte after tag | Reject | `tests/aead_truncation.rs` |
| 5 | `ecies_open_rejects_aad_mismatch` | Seal with one AAD; open with non–byte-identical AAD | `EciesError::Aead(...)` | `tests/ecies_aad_mismatch.rs` |
| 6 | `ecies_open_rejects_short_blob` | Len `2+32+12+15` vs `2+32+12+16` | `TooShort` at boundary | `src/crypto/ecies.rs` |
| 7 | `ecies_open_rejects_bad_version` | `blob[0] != 0x01` | `BadVersion` | `src/crypto/ecies.rs` |
| 8 | `ecies_open_rejects_tampered_ephemeral_pubkey` | Flip bits in `blob[2..34]` | Reject | `tests/ecies_wire_tampering.rs` |
| 9 | `ecies_hkdf_uses_wire_eph_bytes_as_salt` | Internal: salt `== &blob[2..34]` | Holds | `src/crypto/ecies.rs` |
|10 | `ecies_seal_behavior_documented_for_degenerate_recipient` | Misuse / all-zero peer if representable | No silent “success” where policy forbids | `tests/ecies_degenerate_recipient.rs` |
|11 | `hkdf_sha256_32_empty_ikm_deterministic` | `ikm = []`, varied `info` | Deterministic distinct outputs | `src/crypto/hkdf.rs` |
|12 | `domain_tag_rejects_ambiguous_or_invalid_construction` | Invalid product/purpose/version | `DomainTagError` | `src/domain.rs` |
|13 | `hmac_verify_rejects_wrong_tag_length` | 31- and 33-byte tags | `false` / `BadTag` per API | `src/crypto/hmac.rs` |
|14 | `ed25519_verify_strict_rejects_noncanonical_signature` | Wycheproof / dalek vectors | Reject | `src/crypto/ed25519.rs` |
|15 | `otp_and_otp_mac_are_not_interchangeable` | Same logical inputs, different serialization | Distinct outputs | `src/crypto/otp.rs` |
|16 | `stream_receiver_rejects_duplicate_final_out_of_order_and_short_stream_id` | feature `stream-aead` | Correct `StreamError` | `tests/stream_aead_chunk_boundary.rs` |
|17 | `stream_chunk_nonces_distinct_for_index_final_pairs` | Small exhaustive range | No collision | `src/crypto/stream_aead.rs` |

---

## Priority P1 — Auth, bootstrap edge cases, keys, errors

Use **fixed** `now_secs` / `timestamp_secs` for all skew and replay tests. Assert `VerifyError` / `NonceError` **variants**, not display strings, unless testing the deliberate opaque `release_error_message` contract.

| # | Behavior | Adversary / scenario | Expected | Suggested location |
|---|----------|----------------------|----------|-------------------|
| 1 | `nonce_cache_treats_ttl_boundary_as_documented` | Same nonce at `ts+T` vs `ts+T+1` | Replay vs evict | `src/auth/nonce_cache.rs` |
| 2 | `nonce_cache_accepts_insert_after_ttl_eviction` | At capacity then time advances | Ok | `src/auth/nonce_cache.rs` |
| 3 | `verify_signed_request_maps_cache_at_capacity_to_nonce_error` | Valid MAC; cache full | `VerifyError::Nonce(AtCapacity)` | `src/auth/verify.rs` |
| 4 | `verify_signed_request_skew_boundary_inclusive_or_exclusive` | `abs(delta) == max_skew` vs `+1` | Document + assert | `src/auth/verify.rs` |
| 5 | `canonical_request_bytes_match_frozen_fixture` | Fixed tuple | Byte-equal to checked-in vector | `tests/fixtures/…` |
| 6 | `release_error_message_collapses_all_variants_in_release` | `not(debug_assertions)` | Opaque string contract | `src/auth/verify.rs` |
| 7 | `bootstrap_rejects_expired_session_after_ttl` | Simulated clock | `SessionExpired` / unknown | `src/bootstrap/handshake.rs` |
| 8 | `bootstrap_concurrent_same_session_id_at_most_one_success` | `join!` | One Ok | `src/bootstrap/handshake.rs` |
| 9 | `bootstrap_payload_decrypt_fails_with_wrong_server_static_key` | Wrong ECDH | AEAD fail | `src/bootstrap/handshake.rs` |
|10 | `key_blob_rejects_truncated_oversized_duplicate_id` | Parser matrix | `BlobError` variants | `src/keys/blob.rs` |
|11 | `key_finalize_rejects_cross_product_slot_id` | Bad prefix | `CrossProductSlot` | `src/keys/sealing.rs` |
|12 | `ssm_blob_pack_unpack_roundtrip` | Known vector | Bytes equal | `src/keys/sealing.rs` |
|13 | `error_wrapping_stable_for_verify_and_nonce` | Variant coverage | Type-level asserts | `src/error.rs` |

---

## Priority P2 — Config, environment, server surfaces

| # | Behavior | Adversary / scenario | Expected | Suggested location |
|---|----------|----------------------|----------|-------------------|
| 1 | `validate_startup_rejects_invalid_attestation_mode` | `"off"` | `InvalidAttestationMode` | `src/config/validator.rs` |
| 2 | `validate_startup_production_rejects_each_violation` | KMS/SSM/prefix/TCP/SES | Specific `ConfigError` | `src/config/validator.rs` |
| 3 | `environment_parse_rejects_invalid_and_dev_only_in_prod` | Env strings | Documented errors | `src/config/env.rs` |
| 4 | `build_listener_forbids_tcp_in_production` | No actual bind needed | Error before bind | `src/server/listener.rs` |
| 5 | `build_listener_vsock_unsupported_off_linux` | If CI covers macOS | `VsockUnsupported` | `src/server/listener.rs` |
| 6 | `build_listener_bind_fails_cleanly_invalid_addr` | Platform-specific bad addr | `BindFailed` | `src/server/listener.rs` |
| 7 | `redis_prefix_validation_or_dead_code_resolved` | Prefix vs product | Policy | `src/auth/nonce_cache.rs` |

---

## Priority P3 — Redis nonce writer (network — opt-in only)

**Do not** run these in default CI unless the job starts Redis or uses testcontainers. No wall-clock timing assertions—use **synthetic** `ts` / `expires_at`.

| # | Behavior | Scenario | Expected |
|---|----------|----------|----------|
| 1 | `redis_writer_sets_key_ttl_and_value` | Known inputs | Key/value/TTL shape |
| 2 | `redis_writer_skips_nonpositive_ttl` | `expires_at <= ts` | No write |
| 3 | `seed_from_redis_parses_prefixed_keys` | Pre-seeded | Parsed pairs |
| 4 | `seed_from_redis_ignores_unparseable_values` | Bad value | Skip, no panic |
| 5 | `seed_from_redis_connection_refused` | Bad URL | Documented empty/error | 

---

## Priority P4 — Attestation bundle and challenge

The crate **encodes** `PublicKeyBundle` and **signs** challenges; verifiers may live elsewhere—still freeze **preimage bytes** and use **HMAC verify** in tests with the same key as sign (independent check vs implementation details).

| # | Behavior | Scenario | Expected | Notes |
|---|----------|----------|----------|--------|
| 1 | `public_key_bundle_canonical_bytes_match_frozen_v1_fixture` | Fixed map | Byte snapshot | Version bump updates fixture |
| 2 | `public_key_bundle_order_independent_of_insert_order` | Permuted inserts | Identical bytes | |
| 3 | `sign_attestation_challenge_rejects_short_challenge` | `< MIN` | `ChallengeTooShort` | |
| 4 | `attestation_challenge_hmac_matches_rfc4231_vector_pipeline` | HKDF/HMAC components as applicable | Use NIST/RFC vectors for raw HMAC; combine with our preimage as **second** check | |
| 5 | `attestation_preimage_bit_flip_changes_mac` | Flip one byte in each section | Different tag | |
| 6 | `attestation_replay_store_respects_ttl_boundary` | Fixed `now_secs` | Replay vs ok | |
| 7 | `nsm_runtime_available_false_without_nitro_feature` | | `false` | |
| 8 | `mock_pcrs_non_development_behavior` | | Document panic or Result | |

Optional: add **`verify_attestation_challenge`** in-crate so tests and production share one preimage implementation.

---

## CI matrix: unit, Miri, fuzz, release

| Job | Purpose |
|-----|---------|
| `cargo test` (default features) | Fast gate |
| `cargo test --features stream-aead` | Stream AEAD |
| `cargo test --features nitro` (Linux) | Compile NSM paths; enclave-only tests `#[ignore]` |
| `cargo test --release` | Opaque error strings, `not(debug_assertions)` |
| `cargo miri test` | Memory safety for `unsafe` and parsers |
| `cargo fuzz run <target>` (scheduled or pre-release) | Decoders and parsers |
| Redis job (optional) | `#[ignore]` or dedicated workflow with service container |

Maintain **`fuzz/corpus/`** or checked-in minimized inputs from past findings.

---

## Meta: misleading tests

- Rename **`flip_suite_fails_auth`** in `src/crypto/aead.rs` to reflect actual behavior **or** replace with `aes_gcm_decrypt_rejects_incorrect_suite_wire_aad` that fails decryption when the **suite** passed to the public API does not match encryption.

---

## Summary

This plan is **adversarial-first**: every happy path has **tampering siblings**, every parser has **length and canonicalization siblings**, and cryptographic confidence is **anchored** to published vectors where possible and **frozen fixtures** for custom formats. Tests are **deterministic**, **network-free** by default, and **named** so CI failures identify the broken behavior without opening the file. **Miri** and **fuzz** cover classes of bugs unit examples cannot. **Constant-time** properties stay out of default unit tests.
