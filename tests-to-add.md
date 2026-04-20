# Proposed unit and integration tests for `enclave-core`

This document lists **deliberate, high-signal** tests for the shared Nitro-enclave library (`enclave-core`). Earlier drafts were **critically reviewed** against the adversarial-testing principles below (four parallel review passes: AEAD/parser completeness vs “where applicable,” external KAT traceability, determinism/Miri/fuzz realism, and naming/error-string discipline). This revision **tightens scope** so claims in the Summary match what the tables require.

## Testing philosophy (must-read)

Good tests start from the **adversary’s perspective**, not the developer’s. When designing a case, ask first: *how would this API be misused, fed malformed input, or attacked?* Happy-path byte equality is necessary but **never sufficient**.

- **Determinism**: Seed RNGs explicitly (`StdRng::seed_from_u64`, `SystemRandom` only where the API requires it and the test asserts structure, not bytes). **Never** use the wall clock in unit tests—thread `now_secs` / `now_unix` from the test. Do **not** route tests through `unix_timestamp_now()` unless that helper is the explicit subject. **Never** hit the network in default `cargo test`; Redis and similar are **opt-in** (`#[ignore]`, env-gated CI job, in-process fakes, or testcontainers in a **separate** job).
- **Naming**: Structure tests around **behaviors** and **security properties** where possible (e.g. “confidentiality fails if suite byte is wrong”), not only around today’s function names. One **primary** outcome per test where practical; split rows that bundle unrelated outcomes (truncation vs padding; duplicate-final vs out-of-order). Names should make CI failures self-explanatory: `aes_gcm_decrypt_rejects_flipped_ciphertext_bit` beats `test_decrypt_2`. Prefer minimal setup; **no shared mutable fixtures** between tests (parallel `cargo test` must stay safe).
- **AEAD siblings (mandatory per surface)**: For each **AEAD surface** listed below, tests must cover the **full** mutation set: flip one bit (or byte) in **ciphertext body**, **tag**, **wire AAD** (including suite byte / `SuiteId` argument mismatch), and **nonce**; plus truncate/extend ciphertext and wrong key. The numbered P0 rows **add** binding-specific cases; they do **not** replace the matrix. If the library collapses several failures into one `AeadError` variant, assert that discriminant (or the documented public mapping)—do not require distinguishable variants for ciphertext vs tag tampering unless the API exposes them.
- **Parser siblings**: For each row in **Parser inventory**, supply truncated, oversized, non-canonical, and (where applicable) empty inputs; assert **concrete error variants** or documented “any reject” rules—avoid bare “Reject” without a type.
- **Anchors**: Prefer **published** known-answer vectors—**RFC**, **NIST CAVP**, **Wycheproof** JSON—for primitives we implement or wrap. Priority tables should use a **KAT** tag per row (`CAVP`, `RFC5869#…`, `Wycheproof tcId`, `Fixture-v1`, or `Adv-only`) so missing external anchors are visible in review. Where the crate defines wire format (`pkb-v1`, `att-v1`, canonical request), use **frozen** `tests/fixtures/*_v1.bin` with a **governance** rule (see below); treat them as format contracts, not as proofs that a primitive matches NIST unless combined with KATs.
- **Self-consistency is not proof**: Encrypt/decrypt round-trips and `proptest` invariants catch regressions but do not prove standards compliance. Pair them with **at least one** imported vector per primitive where feasible (minimums in **Minimum KAT policy**).
- **Property tests**: Use `proptest` for algebraic invariants (round-trip over random plaintext with fixed seed strategies, wrong-key failure, length monotonicity). See **Proptest backlog**; set `PROPTEST_CASES` explicitly in CI or accept longer local runs.
- **Unsafe, Miri, fuzz**: This crate’s `src/` currently has **no `unsafe` blocks**; Miri still validates unsafe **dependencies** and pointer/aliasing assumptions if run on the full test suite—document exclusions (e.g. tests that cannot run under Miri). Add **`cargo fuzz`** targets for **each** hand-written parser/binary decoder; track **inventory** (parser module → fuzz target name → corpus path). Fuzzing supplements example tests; it does not remove the parser matrix for critical paths.
- **What unit tests are not**: Do **not** assert **constant-time** behavior in ordinary tests—use **dudect** or a dedicated statistical harness. Do **not** match error **strings** for crypto/auth failures if that creates an oracle; assert **`PartialEq` enums** or stable public kinds.
- **Opaque user-facing messages**: For `release_error_message` and similar, assert equality to a **single** `pub const` next to the function (or one snapshot per release build), and assert the message does not embed inner `Debug` / variant names—not substring hunts over formatted errors.
- **Flakiness**: A flaky crypto test is worse than a failing one. If a test is nondeterministic, fix or delete it before merge.

Suggested locations: `#[cfg(test)]` in `src/`, integration tests under `tests/`.

---

## Critical review integration (summary of four passes)

| Theme | Main finding | Response in this doc |
|-------|----------------|----------------------|
| AEAD “every sibling” vs P0 rows | Matrix + numbered rows could be read as optional per-row siblings | **AEAD surfaces** subsection: matrix is **mandatory once per surface**; P0 rows are extra |
| Parser matrix vs priorities | Generic matrix without per-module trace | **Parser inventory** table |
| External KATs vs adversarial tests | Tables were mostly Adv-only; easy to ship without CAVP | **KAT** column + **Minimum KAT policy** + ECIES composition note |
| Determinism / Miri / fuzz | Proptest not assigned; no `fuzz/` yet; Miri needs scope | **Proptest backlog**, **Fuzz policy**, **Miri scope** |
| Naming / errors | Some rows bundle behaviors; `release_error_message` vague | Split rows; **opaque message** bullet; P1 #6 tightened |
| Redis | Opt-in OK; clarify default CI can test prefix **without** Redis | **Redis: two tracks** |

---

## Goals

- Catch **regressions in cryptographic binding** (domain separation, AAD, suite bytes, truncation).
- Lock in **security-relevant state machines** (bootstrap one-shot, nonce replay, session TTL).
- Exercise **configuration and environment** rules that gate production deployments.
- Encode **verifier-side** behavior where the crate only exposes sign/encode (frozen vectors + optional shared verify helper).

---

## What is already covered (do not duplicate blindly)

- **Domain tags**: validation and distinct tuples (`src/domain.rs`, `tests/domain_separation.rs`).
- **ECIES**: basic roundtrip, unknown suite byte, ciphertext bit-flip (`src/crypto/ecies.rs`, `tests/ecies_roundtrip.rs`).
- **AEAD**: roundtrip with `Tag` and `Empty`; the test named `flip_suite_fails_auth` in `aead.rs` **decrypts successfully** with matching wire AAD—it does **not** prove `aes_gcm_decrypt` rejects a wrong `SuiteId`; rename or replace (see Meta).
- **Bootstrap**: happy path, unknown/expired session, consumed flag, second bootstrap rejected, low-order peer on setup (`src/bootstrap/handshake.rs`, `tests/bootstrap_handshake.rs`).
- **Nonce replay cache**: duplicate, capacity, TTL eviction (`tests/nonce_replay.rs`).
- **Stream AEAD** (feature `stream-aead`): truncation, index swap, missing final (`tests/stream_aead_truncation.rs`).
- **Low-order X25519 points**: spot-check (`tests/low_order_point.rs`).
- **Config validator**: partial coverage in `src/config/validator.rs` tests.

---

## AEAD surfaces (run the full sibling matrix on each)

| Surface | Where | Matrix applies |
|---------|--------|----------------|
| S1 | `aes_gcm_encrypt` / `aes_gcm_decrypt` | Yes |
| S2 | `ecies_open` (after layout parse) | Yes + ECIES header flips |
| S3 | Bootstrap response decrypt (server-side helpers in tests) | Yes |
| S4 | Stream AEAD chunk decrypt (feature `stream-aead`) | Yes + chunk index / final flag |

**Rule:** Implementing only P0 rows **without** running S1–S4 through the bit-flip/truncation/wrong-key matrix is incomplete for this plan.

---

## AEAD adversarial matrix (per surface)

| Mutation | Expect |
|----------|--------|
| Flip one bit in ciphertext body | Auth failure (library’s unified variant is OK) |
| Flip one bit in tag | Auth failure |
| Flip one bit in wire AAD / wrong `SuiteId` arg | Auth failure when decrypt binding differs |
| Flip one bit in nonce | Auth failure |
| Truncate / extend ciphertext | Reject |
| Wrong key | Auth failure |

ECIES additionally: **version byte**, **suite byte**, **ephemeral pubkey bytes**, **nonce field**, **HKDF info** (`DomainTag`) mismatch.

---

## Parser inventory (truncated / oversized / non-canonical / empty)

For each row, require **no panic**; expect **typed** errors (or one documented catch-all for “any parse failure”).

| Format | Module | Truncated | Oversized | Non-canonical | Empty |
|--------|--------|-----------|-----------|---------------|-------|
| `DomainTag` construction | `domain.rs` | N/A (API) | N/A | Invalid chars, uppercase product, empty purpose | invalid |
| ECIES blob prefix | `ecies.rs` | `< 46 + 16` bytes | Extra trailing bytes policy | Bad version/suite | too short |
| Key blob / slots | `keys/blob.rs` | Per-field | Declared len vs buffer | Duplicate id, bad UTF-8 | count 0 if allowed |
| Env / `Environment` | `config/env.rs` | N/A | N/A | Invalid `ENVIRONMENT` string | unset handling |
| Hex in attest bundle keys | `attest/bundle.rs` (encode-only today) | If parser added | odd hex, uppercase | document |
| Canonical request bytes | `auth/verify.rs` | N/A (builder) | N/A | Product case normalized via API | — |

**Fuzz:** each row with a **decoder** in the future gets a `cargo fuzz` target; encode-only paths rely on frozen fixtures + tampering until a parser exists.

---

## External vectors and traceability

### Minimum KAT policy (merge gates)

| Primitive | Minimum imported coverage |
|-----------|---------------------------|
| AES-256-GCM | ≥1 **encrypt** and ≥1 **decrypt** case from CAVP or RFC 8452 vectors through the **public** AEAD API |
| HKDF-SHA256 | ≥1 RFC 5869 case including **empty IKM** if supported |
| HMAC-SHA256 | ≥1 RFC 4231 case through public verify |
| X25519 / Ed25519 | Wycheproof or RFC vectors for **verify** / shared-secret edge cases |

**ECIES composition:** standards compliance for AES-GCM + HKDF individually does not prove the **composition** (salt/IKM/AAD order). Either: (a) add **staged** tests (HKDF output matches RFC vector; feed that OKM into AES-GCM decrypt vector), or (b) document a **composite** fixture from an independent tool and check `ecies_open` against it.

### Priority table KAT column

Use: **`CAVP`**, **`RFC5869`**, **`RFC4231`**, **`Wycheproof`**, **`Fixture`**, or **`Adv-only`** (adversarial / binding only).

---

## Proptest backlog (explicit)

| Property | Module | Notes |
|----------|--------|--------|
| `aes_gcm` decrypt(encrypt(pt)) == pt for random pt | `aead.rs` | Fixed RNG seed |
| Wrong key → always Err | `aead.rs`, `ecies.rs` | |
| `DomainTag::new` valid → `as_bytes` stable | `domain.rs` | |
| ECIES seal/open round-trip random pt | `ecies.rs` | Seed `SystemRandom` usage is harder—prefer deterministic stub if API allows |
| Blob serialize/deserialize idempotence | `keys/blob.rs` | Random valid slots within size limits |
| Canonical request length monotonicity | `verify.rs` | Longer body → longer canonical |

---

## Miri scope

- **Current:** no `unsafe` in `src/`; Miri is for **dependency** behavior and future `unsafe`.
- **Policy:** run `cargo miri test` on the default suite with documented `#[ignore]` for tests that require unsupported syscalls or FFI; revisit when adding `unsafe` or `tokio-vsock` tests.

---

## Fuzz policy (inventory-first)

| Decoder / entry | Fuzz target (planned) | Corpus |
|-----------------|----------------------|--------|
| `keys/blob` deserialize | `fuzz_targets/blob.rs` | `fuzz/corpus/blob/` |
| ECIES blob `ecies_open` | `fuzz_targets/ecies.rs` | `fuzz/corpus/ecies/` |
| Env / config bytes (if binary path added) | TBD | — |

**CI:** short smoke (e.g. 60s) on main optional; nightly longer runs; minimized crashes checked in as **regression seeds** (`tests/fuzz_regressions/` or corpus).

---

## Redis: two tracks

| Track | Scope | Default CI? |
|-------|--------|-------------|
| **A — Unit / policy** | `NonceReplayCache`, prefix validation, `RedisInitError` paths **without** a socket | Yes |
| **B — Integration** | `RedisWriter`, `seed_from_redis`, connection failure | No—`#[ignore]` or dedicated job |

**Adversarial B:** malformed RESP / wrong types / SCAN edge cases **if** the client parses untrusted data—justify per code path. **Forbidden:** `sleep` for TTL; assert **numeric** TTL or **synthetic** timestamps only.

---

## Fixture governance (frozen bytes)

- Naming: `tests/fixtures/<name>_v1.bin`; bump version when format changes.
- Each fixture has a **one-paragraph spec** in the same PR (what each byte range means).
- Prefer generating fixtures from a **small deterministic script** (committed) rather than hand-edited hex—reduces “buggy generator + matching test.”

---

## Priority P0 — Cryptographic correctness and binding

| # | Behavior (name reflects property) | KAT | Adversary / scenario | Expected | Where |
|---|-----------------------------------|-----|----------------------|----------|-------|
| 1 | `confidentiality_fails_when_aes_gcm_suite_id_mismatch` | Adv-only | Correct key/nonce/ct; wrong `SuiteId` → wrong wire AAD | `AeadError::AuthTagMismatch` (or documented) | `src/crypto/aead.rs` |
| 2 | `confidentiality_fails_when_aead_domain_tag_mismatches` | Adv-only | Same ct; different `AeadAad::Tag` | Same as above | `tests/aead_domain_separation.rs` |
| 3 | `aead_tag_bytes_encoding_matches_tag_when_bytes_identical` | Adv-only | `AeadAad::Bytes` vs `Tag` when bytes equal | Both decrypt Ok | `src/crypto/aead.rs` |
| 4a | `aes_gcm_decrypt_rejects_truncated_ciphertext` | Adv-only | Len −1 | Auth failure / error | `tests/aead_truncation.rs` |
| 4b | `aes_gcm_decrypt_rejects_trailing_byte_after_tag` | Adv-only | +1 garbage byte after tag | Auth failure / error | `tests/aead_truncation.rs` |
| 5 | `ecies_open_rejects_aad_mismatch` | Adv-only | Seal vs open AAD not byte-identical | `EciesError::Aead(...)` | `tests/ecies_aad_mismatch.rs` |
| 6 | `ecies_open_rejects_short_blob` | Adv-only | Len `2+32+12+15` vs `2+32+12+16` | `TooShort` at boundary | `src/crypto/ecies.rs` |
| 7 | `ecies_open_rejects_bad_version` | Adv-only | `blob[0] != 0x01` | `BadVersion` | `src/crypto/ecies.rs` |
| 8 | `ecies_open_rejects_tampered_ephemeral_pubkey` | Adv-only | Flip bits in `blob[2..34]` | `EciesError::…` / AEAD | `tests/ecies_wire_tampering.rs` |
| 9 | `ecies_open_fails_when_salt_bytes_replaced_with_valid_alternate_eph` | Adv-only | Replace `blob[2..34]` with another valid X25519 pubkey (wrong ephemeral) | Failure (not silent success) | `tests/ecies_wire_tampering.rs` |
|10 | `ecies_seal_documented_for_degenerate_recipient_pubkey` | Adv-only | All-zero or policy-defined bad recipient | No silent success | `tests/ecies_degenerate_recipient.rs` |
|11 | `hkdf_sha256_32_empty_ikm_deterministic` | RFC5869 | `ikm = []`, distinct `info` | Deterministic distinct OKMs | `src/crypto/hkdf.rs` |
|12 | `domain_tag_rejects_invalid_construction` | Adv-only | Invalid product/purpose/version | `DomainTagError` | `src/domain.rs` |
|13 | `hmac_verify_rejects_wrong_tag_length` | RFC4231 + Adv | 31- and 33-byte tags | `false` / `BadTag` | `src/crypto/hmac.rs` |
|14 | `ed25519_verify_strict_rejects_noncanonical_signature` | Wycheproof | Vectors | Reject | `src/crypto/ed25519.rs` |
|15 | `otp_and_otp_mac_outputs_are_not_interchangeable` | Fixture/Adv | Same logical inputs | Distinct outputs | `src/crypto/otp.rs` |
|16a | `stream_receiver_rejects_duplicate_final_chunk` | Adv-only | feature `stream-aead` | `StreamError::…` | `tests/stream_aead_chunk_boundary.rs` |
|16b | `stream_receiver_rejects_out_of_order_chunk` | Adv-only | | `StreamError::…` | same |
|16c | `stream_open_rejects_short_stream_id` | Adv-only | len 15 vs 16 | `StreamError::…` | same |
|17 | `stream_chunk_nonces_distinct_for_index_and_final` | Adv-only | Exhaust small range | No collision | `src/crypto/stream_aead.rs` |

**Imported vectors (add explicit rows or `tests/kats/`):** AES-GCM CAVP round-trip; HKDF RFC5869; HMAC RFC4231 through public APIs.

---

## Priority P1 — Auth, bootstrap, keys, errors

Use **fixed** `now_secs` / `timestamp_secs`. Assert **variants**, not strings, except **`VERIFY_RELEASE_USER_MESSAGE`** equality.

| # | Behavior | KAT | Adversary / scenario | Expected | Where |
|---|----------|-----|----------------------|----------|-------|
| 1 | `nonce_cache_ttl_boundary_matches_retention_rule` | Adv-only | Same nonce at `ts+T` vs `ts+T+1` | Replay vs evict | `src/auth/nonce_cache.rs` |
| 2 | `nonce_cache_inserts_after_ttl_eviction_when_at_capacity` | Adv-only | Fill, advance time, insert | Ok | `src/auth/nonce_cache.rs` |
| 3 | `signed_request_maps_full_cache_to_nonce_error` | Adv-only | Valid MAC; cache full | `VerifyError::Nonce(AtCapacity)` | `src/auth/verify.rs` |
| 4 | `signed_request_skew_boundary_matches_policy` | Adv-only | `abs(delta) == max_skew` vs `+1` | Accept vs `StaleTimestamp` | `src/auth/verify.rs` |
| 5 | `canonical_request_bytes_match_frozen_fixture` | Fixture | Fixed tuple | Byte-equal | `tests/fixtures/…` |
| 6 | `release_error_message_equals_const_for_all_verify_errors_in_release` | Adv-only | `not(debug_assertions)`; each `VerifyError` | `msg == VERIFY_RELEASE_USER_MESSAGE`; no inner `Debug` leak | `src/auth/verify.rs` |
| 7 | `bootstrap_rejects_session_after_ttl` | Adv-only | Simulated `now_unix` | `SessionExpired` / `UnknownSession` | `src/bootstrap/handshake.rs` |
| 8 | `bootstrap_at_most_one_success_per_session_id_under_concurrency` | Adv-only | Concurrent `bootstrap` | ≤1 Ok | `src/bootstrap/handshake.rs` |
| 9 | `bootstrap_payload_decrypt_fails_with_wrong_server_key` | Adv-only | Wrong ECDH | AEAD failure | `src/bootstrap/handshake.rs` |
|10 | `key_blob_parse_rejects_truncated_oversized_duplicate` | Adv-only | Parser inventory | `BlobError::…` | `src/keys/blob.rs` |
|11 | `key_finalize_rejects_cross_product_slot` | Adv-only | Wrong prefix | `CrossProductSlot` | `src/keys/sealing.rs` |
|12 | `ssm_blob_roundtrip_matches_published_or_scripted_vector` | Fixture/CAVP | Vector from spec/script, not only pack/unpack | Bytes match | `src/keys/sealing.rs` |
|13 | `error_types_wrap_verify_and_nonce` | Adv-only | Variant coverage | Typed equality | `src/error.rs` |

---

## Priority P2 — Config, environment, server

| # | Behavior | KAT | Adversary / scenario | Expected | Where |
|---|----------|-----|----------------------|----------|-------|
| 1 | `validate_startup_rejects_invalid_attestation_mode` | Adv-only | `"off"` | `InvalidAttestationMode` | `src/config/validator.rs` |
| 2 | `validate_startup_production_rejects_each_config_violation` | Adv-only | One violation per test (split rows) | Specific `ConfigError` | `src/config/validator.rs` |
| 3 | `environment_parse_rejects_invalid_and_blocks_dev_only_in_prod` | Adv-only | Env strings | **Enum variant per case**; no `msg.contains` on secrets | `src/config/env.rs` |
| 4 | `build_listener_forbids_tcp_in_production` | Adv-only | | Error before bind | `src/server/listener.rs` |
| 5 | `build_listener_vsock_unsupported_off_linux` | Adv-only | | `VsockUnsupported` | `src/server/listener.rs` |
| 6 | `build_listener_reports_bind_failed_for_invalid_addr` | Adv-only | Platform-specific | `BindFailed` | `src/server/listener.rs` |
| 7a | `nonce_redis_prefix_validated_against_product` | Adv-only | Unit-only, **no Redis** | Resolved policy / error | `src/auth/nonce_cache.rs` |
| 7b | `redis_init_prefix_error_paths_exercised_or_removed` | Adv-only | Dead code audit | Constructor returns `PrefixMissingProduct` when applicable, or code removed | same / `redis_nonce.rs` |

---

## Priority P3 — Redis integration (opt-in only)

Do not assert wall-clock TTL; use **synthetic** `ts` / `expires_at` and, where needed, **numeric** TTL from Redis responses.

| # | Behavior | KAT | Scenario | Expected |
|---|----------|-----|----------|----------|
| 1 | `redis_writer_sets_key_and_ttl_seconds` | Adv-only | Known inputs | Key/value/TTL **numeric** |
| 2 | `redis_writer_skips_nonpositive_ttl` | Adv-only | `expires_at <= ts` | No write |
| 3 | `seed_from_redis_parses_prefixed_keys` | Adv-only | Pre-seeded | Parsed pairs |
| 4 | `seed_from_redis_skips_unparseable_values` | Adv-only | Bad value | No panic; skip |
| 5 | `seed_from_redis_handles_connection_refused` | Adv-only | Bad URL | Documented empty/error |
| — | *Optional adversarial* | Adv-only | Malformed replies if parser exists | Typed error / no panic |

---

## Priority P4 — Attestation bundle and challenge

| # | Behavior | KAT | Scenario | Expected | Notes |
|---|----------|-----|----------|----------|--------|
| 1 | `public_key_bundle_canonical_bytes_match_frozen_v1` | Fixture | Fixed map | Byte snapshot | Version bump updates fixture |
| 2 | `public_key_bundle_independent_of_insertion_order` | Adv-only | Permuted inserts | Identical bytes | |
| 3 | `sign_attestation_challenge_rejects_short_challenge` | Adv-only | `< MIN` | `ChallengeTooShort` | |
| 4 | `attestation_hmac_raw_primitive_matches_rfc4231` | RFC4231 | Raw HMAC | Matches vector | **Plus** full preimage test |
| 5 | `attestation_preimage_byte_change_changes_mac` | Adv-only | Flip one byte per section | Different tag | |
| 6 | `attestation_replay_store_respects_ttl_boundary` | Adv-only | Fixed `now_secs` | Replay vs ok | |
| 7 | `nsm_runtime_available_false_without_nitro` | Adv-only | | `false` | |
| 8 | `mock_pcrs_non_development_behavior` | Adv-only | | Document panic or `Result` | |

Optional: **`verify_attestation_challenge`** in-crate so preimage construction is single-sourced.

---

## CI matrix (wire in parent repo / workspace if no workflow here)

| Job | Purpose |
|-----|---------|
| `cargo test` (default features) | Fast gate |
| `cargo test --features stream-aead` | Stream AEAD |
| `cargo test --features nitro` (Linux) | Compile NSM paths |
| `cargo test --release` | Opaque message const, `not(debug_assertions)` |
| `cargo test --features auth-verbose-errors` | Optional: error oracle behavior differs—do not gate release on verbose strings |
| `cargo miri test` | See **Miri scope** |
| `cargo fuzz` (smoke / nightly) | See **Fuzz policy** |
| Redis job | Optional; Track B only |

---

## Meta: misleading tests

- Rename **`flip_suite_fails_auth`** in `src/crypto/aead.rs` or replace with a test that **`aes_gcm_decrypt` fails** when the **`SuiteId` argument** does not match encryption.

---

## Summary

This plan is **adversarial-first** for AEAD and parsers: **each AEAD surface** runs the **full** mutation matrix; **each parser row** in the inventory gets truncated/oversized/non-canonical coverage. **Imported KATs** are **mandatory** for core primitives per **Minimum KAT policy**; adversarial and frozen-fixture tests **supplement** them, not replace them. **ECIES** composition needs an explicit **staged or composite** anchor. Tests stay **deterministic** (no wall clock in unit tests; no network in the default gate). **Proptest**, **Miri**, and **fuzz** have **explicit** scope so they are checkable, not aspirational. **Constant-time** stays out of unit tests; **error checks** use **types** and, for opaque messages, a **single `const`**. State-machine, config, and Redis **Track B** tests are **not** described as having “AEAD tampering siblings”—only AEAD surfaces are.
