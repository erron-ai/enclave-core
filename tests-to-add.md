# Proposed unit and integration tests for `enclave-core`

This document lists **deliberate, high-signal** tests for the shared Nitro-enclave library (`enclave-core`). It was refined after adversarial review (AEAD/parser completeness, external KAT traceability, determinism, naming/error discipline).

**Scope of this plan:** **Unit and integration tests only**—what to implement in `#[cfg(test)]` and `tests/`. It does **not** prescribe continuous integration jobs, release gates, or scheduled fuzz/Miri runs. Operators may run optional tools **locally** (see end).

---

## Testing philosophy (must-read)

Good tests start from the **adversary’s perspective**, not the developer’s. When designing a case, ask first: *how would this API be misused, fed malformed input, or attacked?* Happy-path byte equality is necessary but **never sufficient**.

- **Determinism**: Seed RNGs explicitly (`StdRng::seed_from_u64`, `SystemRandom` only where the API requires it and the test asserts structure, not random bytes). **Never** use the wall clock in unit tests—thread `now_secs` / `now_unix` from the test. Do **not** route tests through `unix_timestamp_now()` unless that helper is the explicit subject. **Do not** open real network connections in the default test binary: test Redis-backed code with **`#[ignore]`** integration tests run manually when a broker is available, or with in-process fakes if you add them later.
- **Naming**: Structure tests around **behaviors** and **security properties** (e.g. “confidentiality fails if suite byte is wrong”), not only current function names. One **primary** outcome per test where practical; split rows that bundle unrelated outcomes (truncation vs padding; duplicate-final vs out-of-order). Names should make failures self-explanatory: `aes_gcm_decrypt_rejects_flipped_ciphertext_bit` beats `test_decrypt_2`. Prefer minimal setup; **no shared mutable fixtures** between tests (parallel `cargo test` must stay safe).
- **AEAD siblings (mandatory per surface)**: For each **AEAD surface** in §Wire layouts, tests must cover the **full** mutation set in §AEAD adversarial matrix. The numbered **Priority P0** rows **add** binding-specific cases; they do **not** replace the matrix. If the library collapses several failures into one `AeadError` variant, assert that discriminant (or the documented public mapping)—do not require distinguishable variants for ciphertext vs tag tampering unless the API exposes them.
- **Parser siblings**: For each row in **Parser inventory**, supply truncated, oversized, non-canonical, and (where applicable) empty inputs; assert **concrete error variants** or documented “any reject” rules.
- **Anchors**: Prefer **published** known-answer vectors—**RFC**, **NIST CAVP**, **Wycheproof** JSON—for primitives we implement or wrap. Priority tables use a **KAT** tag per row (`CAVP`, `RFC5869`, `RFC4231`, `Wycheproof`, `Fixture-v1`, or `Adv-only`). Custom wire formats use **frozen** `tests/fixtures/*_v1.bin` with **fixture governance** (§Fixture governance).
- **Self-consistency is not proof**: Encrypt/decrypt round-trips and `proptest` invariants catch regressions but do not prove standards compliance. Pair them with **at least one** imported vector per primitive where feasible (§Minimum KAT policy).
- **Property tests**: Use `proptest` for algebraic invariants; cap case counts for fast local runs (e.g. `PROPTEST_CASES` in a `#[cfg(test)]` module or default proptest config)—no automation required here.
- **Unsafe, Miri, fuzz (optional tooling, not part of this test list)**: Miri (`cargo miri test`) and `cargo fuzz` can find classes of bugs unit tests miss; this document **does not** require automation for them. If you add fuzz targets later, keep a **decoder inventory** (§Optional fuzz inventory) so coverage is intentional.
- **What unit tests are not**: Do **not** assert **constant-time** behavior in ordinary tests—use **dudect** or a dedicated statistical harness. Do **not** match error **strings** for crypto/auth failures if that creates an oracle; assert **`PartialEq` enums** or stable public kinds.
- **Opaque user-facing messages**: For `release_error_message` and similar, assert equality to a **single** `pub const` next to the function (or one assertion under `not(debug_assertions)` builds), and assert the message does not embed inner `Debug` / variant names.
- **Flakiness**: A flaky crypto test is worse than a failing one. If a test is nondeterministic, fix or delete it before merge.

**Suggested locations:** `#[cfg(test)]` in `src/`, integration tests under `tests/`.

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
- **AEAD**: roundtrip with `Tag` and `Empty`; the test named `flip_suite_fails_auth` in `aead.rs` **decrypts successfully** with matching wire AAD—it does **not** prove `aes_gcm_decrypt` rejects a wrong `SuiteId`; rename or replace (§Meta).
- **Bootstrap**: happy path, unknown/expired session, consumed flag, second bootstrap rejected, low-order peer on setup (`src/bootstrap/handshake.rs`, `tests/bootstrap_handshake.rs`).
- **Nonce replay cache**: duplicate, capacity, TTL eviction (`tests/nonce_replay.rs`).
- **Stream AEAD** (feature `stream-aead`): truncation, index swap, missing final (`tests/stream_aead_truncation.rs`).
- **Low-order X25519 points**: spot-check (`tests/low_order_point.rs`).
- **Config validator**: partial coverage in `src/config/validator.rs` tests.

---

## Wire layouts (reference for test design)

These are the byte-level contracts adversarial tests should mutate at **known offsets**.

### S1 — Raw AES-GCM (`src/crypto/aead.rs`)

- **Key:** 32 bytes. **Nonce:** 12 bytes.
- **Wire AAD** passed to `aes_gcm_*`: `build_wire_aad(suite, aad) = [suite as u8] || raw_aad`, where `raw_aad` comes from `AeadAad::Tag` / `Bytes` / `Empty`.
- **SuiteId:** currently only `0x01` (`X25519HkdfSha256Aes256Gcm`).
- **Ciphertext:** AES-GCM output (plaintext length + 16-byte tag). Tampering tests must flip bits in **body** vs **tag** regions separately when the API returns a single blob.

### S2 — ECIES blob (`src/crypto/ecies.rs`)

```text
[0]       = 0x01 (ECIES_VERSION_BYTE)
[1]       = SuiteId byte (must match SuiteId used in decrypt)
[2..34)   = ephemeral X25519 public key (32 bytes)
[34..46)  = AES-GCM nonce (12 bytes)
[46..]    = AES-GCM ciphertext (includes 16-byte tag for non-empty plaintext)
```

- Minimum length for non-empty plaintext path: `2 + 32 + 12 + 16 = 62` bytes (empty plaintext would be `2+32+12+16` = 62 as well—tests should use boundary cases from `ecies_open`).
- **HKDF:** `ikm = shared secret bytes`, `salt = Some(&eph_pub_bytes_from_wire)` (32 bytes copied from `[2..34]`), `info = DomainTag`.
- **AEAD AAD:** user-supplied `AeadAad` folded with suite byte as in S1.

### S3 — Bootstrap encrypted payload (tests / helpers)

- **Channel key:** HKDF over X25519 shared secret with `DomainTag` `dorsal/bootstrap-channel/v1` (see `BootstrapState::channel_info`).
- **Response:** `nonce` (12) + `ciphertext` from `aes_gcm_encrypt` over `request_auth_key` with `AeadAad::Tag(dorsal/bootstrap-payload/v1)`.
- Server-side decrypt in tests must use the **same** suite and AAD; adversarial tests flip nonce, ct, tag, or AAD binding as in S1.

### S4 — Stream AEAD (`src/crypto/stream_aead.rs`, feature `stream-aead`)

- Chunk nonces derived via HMAC from `(stream_id, chunk_index, is_final)`; receiver enforces order and a single final chunk. Adversarial tests: wrong index, duplicate final, short `stream_id`, bit flips in ciphertext/tag per chunk.

### Key blob plaintext (`src/keys/blob.rs`)

```text
[0]           = 0x01 (BLOB_VERSION)
[1..5]        = u32_be slot_count
repeat slot_count times:
  [0..2]      = u16_be id_len
  [2..2+L]    = id utf-8 (L = id_len)
  [..4]       = u32_be data_len
  [..D]       = data bytes (D = data_len)
```

- **Truncation points:** after byte 0; after bytes 1–4; in the middle of `id_len`; mid-id; mid-`data_len`; mid-data; declaring `data_len` larger than remaining buffer (§`deserialize` cursor checks).
- **AAD suffix** for sealing is `version || count || (id_len||id)*` (no payload lengths in AAD—see module docs).

### Domain tag (`src/domain.rs`)

- Valid **product:** `^[a-z][a-z0-9]{2,23}$` (length 3–24).
- Valid **purpose:** `^[a-z][a-z0-9-]{0,63}$`, non-empty, max 64 bytes.
- **Version:** integer `>= 1`.
- Encoded bytes: `{product}-{purpose}-v{version}` (ASCII), max 96 bytes total.

### Canonical signed request (`src/auth/verify.rs`)

```text
<product_lower>\n
<METHOD>\n
<PATH>\n
<TIMESTAMP_DECIMAL>\n
<NONCE>\n
<BODY>
```

- **Nonce:** length 16–128; charset `alphanumeric` plus `-` and `_` (`is_nonce_valid`).

---

## AEAD surfaces (full sibling matrix required on each)

| ID | Surface | Entry points | Notes |
|----|---------|--------------|--------|
| S1 | Raw AES-GCM | `aes_gcm_encrypt`, `aes_gcm_decrypt` | Baseline for wire AAD + suite byte |
| S2 | ECIES | `ecies_seal` / `ecies_open` | Include header + HKDF + S1 inside open |
| S3 | Bootstrap payload | decrypt helper mirroring server in `bootstrap/handshake` tests | Same as S1 with fixed domain tags |
| S4 | Stream chunk | `stream_aead` encrypt/decrypt paths | Chunk metadata + S1 per chunk |

**Rule:** Priority P0 rows **supplement** these surfaces; they do **not** replace running the §AEAD adversarial matrix on S1–S4.

### Per-surface checklist (each test name should encode one mutation)

For **S1** (given one valid encrypt output: fixed key, nonce, plaintext, `AeadAad`):

1. Decrypt **ok** with matching `SuiteId` and AAD.
2. Flip **one bit** in ciphertext body (not tag) → assert `AeadError::AuthTagMismatch` (or documented variant).
3. Flip **one bit** in last 16 bytes (tag) → assert auth failure.
4. Pass decrypt with **wrong `SuiteId` enum** (wire AAD first byte wrong) → assert auth failure.
5. Flip **one bit** in `raw_aad` domain (e.g. different `DomainTag` for `Tag`) → assert auth failure.
6. Flip **one bit** in nonce → assert auth failure.
7. Truncate ciphertext by 1 byte → assert failure.
8. Append 1 byte after ciphertext → assert failure (if API passes full slice to GCM).
9. Wrong 32-byte key (single bit flip) → assert failure.

For **S2**: build a valid `ecies_seal` blob; in **separate** tests, apply mutations at offsets **0, 1, 2..33, 34..45, 46+** per matrix; plus open with wrong `DomainTag` / `AeadAad` while holding blob fixed.

For **S3**: after a successful `bootstrap_setup` + `bootstrap` in tests, mutate `nonce` and `ciphertext` independently; wrong `channel_key` derived from wrong server secret.

For **S4** (with `--features stream-aead`): combine chunk-level bit flips with **wrong chunk index** and **wrong `is_final`** as already partially covered—extend to full S1-style bit flips **per chunk**.

---

## AEAD adversarial matrix (reference)

| Mutation | Expect |
|----------|--------|
| Flip one bit in ciphertext body | Auth failure |
| Flip one bit in tag | Auth failure |
| Flip one bit in wire AAD / wrong `SuiteId` arg | Auth failure when decrypt binding differs |
| Flip one bit in nonce | Auth failure |
| Truncate / extend ciphertext | Auth failure |
| Wrong key | Auth failure |

ECIES additionally: **version byte**, **suite byte**, **ephemeral pubkey bytes**, **HKDF info** (`DomainTag`) mismatch at open.

---

## Parser inventory (truncated / oversized / non-canonical / empty)

For each row: **no panic**; assert **typed** `Err` matching the module’s public enums.

| Format | Module | Truncated | Oversized / inconsistent lengths | Non-canonical | Empty / edge |
|--------|--------|-----------|-----------------------------------|---------------|--------------|
| `DomainTag::new` | `domain.rs` | N/A | N/A | Uppercase product, empty purpose, purpose starting non-`a-z`, version `0`, product len 2 or 25 | encoded len > 96 |
| ECIES blob | `ecies.rs` | `< 62` bytes (see layout); cut inside eph, nonce, ct | Extra trailing bytes: define whether `ecies_open` ignores tail or fails—assert current behavior | Wrong version byte; unknown suite byte | N/A |
| Key blob | `keys/blob.rs` | 0–4 bytes; mid-slot after `id_len`; `data_len` larger than remaining bytes | `count` huge with short buffer | Duplicate slot id; invalid UTF-8 id | `count = 0` if supported |
| `Environment` / env | `config/env.rs` | N/A | N/A | `ENVIRONMENT` typo; `prod` vs `production` per actual API | unset |
| Attest bundle keys | `attest/bundle.rs` | decode-only if parser added | odd-length hex; non-hex | uppercase hex policy | — |
| Nonce string | `auth/verify.rs` | len `< 16` or `> 128` | N/A | disallowed chars | boundary 16 and 128 |

---

## External vectors and traceability

### Minimum KAT policy (recommended bar for a trustworthy primitive layer)

| Primitive | Minimum imported coverage |
|-----------|---------------------------|
| AES-256-GCM | ≥1 **encrypt** and ≥1 **decrypt** case from CAVP or RFC 8452 through the **public** `aes_gcm_*` API |
| HKDF-SHA256 | ≥1 RFC 5869 case including **empty IKM** if supported |
| HMAC-SHA256 | ≥1 RFC 4231 case through public verify |
| X25519 / Ed25519 | Wycheproof or RFC vectors for **verify** / shared-secret edge cases |

**ECIES composition:** AES-GCM + HKDF KATs alone do not prove **composition** (salt/IKM/AAD order). Prefer **staged** tests: HKDF output matches RFC vector → feed OKM into AES-GCM vector decrypt; **or** a **composite** blob from an independent generator checked by `ecies_open`.

### KAT column in priority tables

**`CAVP`** | **`RFC5869`** | **`RFC4231`** | **`Wycheproof`** | **`Fixture-v1`** | **`Adv-only`**

---

## Proptest backlog (explicit properties)

| Property | Module | Strategy notes |
|----------|--------|----------------|
| `decrypt(encrypt(pt)) == pt` for random `pt` | `aead.rs` | Fixed-seed RNG for key/nonce |
| Wrong key ⇒ `Err` | `aead.rs`, `ecies.rs` | |
| Valid `DomainTag` ⇒ stable `as_bytes` | `domain.rs` | |
| ECIES seal/open round-trip | `ecies.rs` | If RNG is `SystemRandom`, scope proptest only to **open** with fixed blobs from table tests |
| Blob serialize/deserialize idempotent | `keys/blob.rs` | Generate valid `KeySlot` list under size limits |
| `len(canonical_request(..., body))` monotonic in `body.len()` | `verify.rs` | Fixed other fields |

---

## Miri scope (optional local tool)

- **`src/`** currently has **no** `unsafe` blocks; Miri is mainly for **dependencies** and any future `unsafe`.
- Run **`cargo miri test`** locally when changing unsafe-heavy deps or adding `unsafe`; exclude tests that need unsupported syscalls via `#[ignore]` if needed.

---

## Optional fuzz inventory (if you add `cargo fuzz` later)

| Decoder | Suggested target name | Input |
|---------|----------------------|--------|
| `keys/blob` `deserialize` | `blob` | raw bytes |
| `ecies_open` | `ecies` | blob bytes |
| Future binary env parser | TBD | — |

Store minimized crashes under `tests/fuzz_regressions/` or `fuzz/corpus/` as regression seeds. **Not required** for the unit-test plan itself.

---

## Redis: two tracks

| Track | Scope | When to run |
|-------|--------|-------------|
| **A — Unit / policy** | `NonceReplayCache`, prefix validation, `RedisInitError` paths **without** a socket | Always in `cargo test` |
| **B — Integration** | `RedisWriter`, `seed_from_redis`, connection failure | **`#[ignore]`** or manual run against a real/dev Redis |

**Track B adversarial ideas:** malformed values on `GET`, type confusion if the client exposes it, `SCAN` edge cases—only where the code parses untrusted server data. **Do not** use `sleep` to wait for TTL; use **synthetic** `ts` / `expires_at` and assert numeric TTL when read back.

---

## Fixture governance (frozen bytes)

- Paths: `tests/fixtures/<name>_v1.bin`; bump `v2` when the format changes.
- Each new fixture: **short spec** in the commit message or a adjacent `README` (byte ranges and meaning).
- Prefer a **deterministic generator** (small script or `build.rs` output) over hand-pasted hex.

---

## Priority P0 — Cryptographic correctness and binding

| # | Suggested test name | KAT | Setup (concise) | Mutate / assert | Expected |
|---|---------------------|-----|-------------------|-----------------|----------|
| 1 | `confidentiality_fails_when_aes_gcm_suite_id_mismatch` | Adv-only | Encrypt with `SuiteId::X25519HkdfSha256Aes256Gcm` | Decrypt with wrong `SuiteId` (only enum path that changes wire AAD byte) | `AeadError::AuthTagMismatch` or documented mapping |
| 2 | `confidentiality_fails_when_aead_domain_tag_mismatches` | Adv-only | Valid ct | Same ct, different `AeadAad::Tag` | Auth failure |
| 3 | `aead_tag_bytes_encoding_matches_tag_when_bytes_identical` | Adv-only | Same key/nonce/ct | `AeadAad::Bytes(slice)` vs `Tag` where `slice == tag.as_bytes()` | Both `Ok` and same plaintext |
| 4a | `aes_gcm_decrypt_rejects_truncated_ciphertext` | Adv-only | Valid ct | Remove last byte | Auth failure |
| 4b | `aes_gcm_decrypt_rejects_trailing_byte_after_tag` | Adv-only | Valid ct | Append `0x00` | Auth failure |
| 5 | `ecies_open_rejects_aad_mismatch` | Adv-only | `ecies_seal` with `AeadAad::Tag(A)` | `ecies_open` with `Tag(B)` | `EciesError::Aead(...)` |
| 6 | `ecies_open_rejects_short_blob` | Adv-only | Truncate sealed blob to `61` bytes | | `EciesError::TooShort` |
| 7 | `ecies_open_rejects_bad_version` | Adv-only | Flip `blob[0]` to `0x02` | | `EciesError::BadVersion` |
| 8 | `ecies_open_rejects_tampered_ephemeral_pubkey` | Adv-only | Valid blob | XOR one bit in `blob[2..34]` | Failure (not plaintext) |
| 9 | `ecies_open_fails_when_wire_eph_replaced_with_other_valid_point` | Adv-only | Valid seal | Replace `blob[2..34]` with another valid 32-byte pubkey; re-seal not run | Decrypt fails |
|10 | `ecies_seal_behavior_with_degenerate_recipient_pubkey` | Adv-only | Document whether all-zero recipient is constructible | If seal returns blob, open must not yield silent success if policy forbids | Documented |
|11 | `hkdf_sha256_32_empty_ikm_deterministic` | RFC5869 | `ikm=[]`, two `info` tags | | Distinct deterministic 32-byte outputs |
|12 | `domain_tag_rejects_invalid_construction` | Adv-only | Examples: `InvalidProduct`, empty purpose, `v0` | | Matching `DomainTagError` variants |
|13 | `hmac_verify_rejects_wrong_tag_length` | RFC4231+Adv | Valid MAC | 31- and 33-byte buffers | `false` / `BadTag` |
|14 | `ed25519_verify_strict_rejects_noncanonical_signature` | Wycheproof | Import vectors | | Verify returns `Err` |
|15 | `otp_and_otp_mac_outputs_are_not_interchangeable` | Fixture/Adv | Same logical inputs to both APIs | | Different outputs |
|16a | `stream_receiver_rejects_duplicate_final_chunk` | Adv-only | `--features stream-aead` | Two finals | `StreamError` variant |
|16b | `stream_receiver_rejects_out_of_order_chunk` | Adv-only | Deliver chunk 1 before 0 | | `StreamError` |
|16c | `stream_open_rejects_short_stream_id` | Adv-only | `stream_id` length 15 vs 16 | | Error |
|17 | `stream_chunk_nonces_distinct_for_index_and_final` | Adv-only | Small index range | | No nonce collision |

**Add explicit test module(s)** (e.g. `tests/kats_aes_gcm.rs`, `tests/kats_hkdf.rs`) importing **one encrypt + one decrypt** vector each from CAVP/RFC for S1 and HKDF, wired through public APIs.

---

## Priority P1 — Auth, bootstrap, keys, errors

Use **fixed** `now_secs` / `timestamp_secs`. Assert **enum variants**; for `release_error_message`, assert equality to **`VERIFY_RELEASE_USER_MESSAGE`** `const` under `not(debug_assertions)`.

| # | Suggested test name | KAT | Setup | Assert |
|---|---------------------|-----|-------|--------|
| 1 | `nonce_cache_ttl_boundary_matches_retention_rule` | Adv-only | `ttl=T`, insert at `ts`, same nonce at `ts+T` and at `ts+T+1` | First: `Replay`; second: insert succeeds if evicted |
| 2 | `nonce_cache_inserts_after_ttl_eviction_when_at_capacity` | Adv-only | `max_entries=2`, fill, advance `now` beyond TTL, insert third | `Ok` |
| 3 | `signed_request_maps_full_cache_to_nonce_error` | Adv-only | Valid HMAC; cache `max_entries=0` or prefilled | `VerifyError::Nonce(AtCapacity)` |
| 4 | `signed_request_skew_boundary_matches_policy` | Adv-only | `timestamp = now - max_skew` vs `now - max_skew - 1` | Ok vs `StaleTimestamp` per `verify_signed_request` |
| 5 | `canonical_request_bytes_match_frozen_fixture` | Fixture-v1 | Fixed tuple | `canonical_request(...) == include_bytes!(...)` |
| 6 | `release_error_message_equals_const_for_all_verify_errors_in_release` | Adv-only | Construct each `VerifyError`; call `release_error_message` | Same string; no substring of variant debug |
| 7 | `bootstrap_rejects_session_after_ttl` | Adv-only | `setup` at `t0`; `bootstrap` at `t0 + SESSION_TTL_SECS + 1` | `SessionExpired`; `consumed` false |
| 8 | `bootstrap_at_most_one_success_per_session_id_under_concurrency` | Adv-only | `tokio::join!` two `bootstrap` same id | At most one `Ok` |
| 9 | `bootstrap_payload_decrypt_fails_with_wrong_server_key` | Adv-only | Wrong `StaticSecret` on decrypt side | AEAD error |
|10 | `key_blob_parse_rejects_truncated_at_each_stage` | Adv-only | Blobs cut at offsets 1,4,5,… per §Wire layouts | `BlobError::TooShort` |
|11 | `key_blob_parse_rejects_oversized_data_len` | Adv-only | `data_len` past end of buffer | `TooShort` |
|12 | `key_blob_parse_rejects_duplicate_slot_id` | Adv-only | Two identical ids serialized | `DuplicateId` |
|13 | `key_finalize_rejects_cross_product_slot` | Adv-only | Slot id without `{product}.` prefix | `KeyStoreError::CrossProductSlot` |
|14 | `ssm_blob_roundtrip_matches_published_or_scripted_vector` | Fixture | Vector from spec/tool | Pack/unpack bytes equal |
|15 | `error_types_wrap_verify_and_nonce` | Adv-only | Map `VerifyError` / `NonceError` to `crate::Error` | Variant preserved |

---

## Priority P2 — Config, environment, server

| # | Suggested test name | KAT | Inputs | Expected |
|---|---------------------|-----|--------|----------|
| 1 | `validate_startup_rejects_invalid_attestation_mode` | Adv-only | `attestation_mode = "off"` | `InvalidAttestationMode` |
| 2a–2e | `validate_startup_production_rejects_missing_kms` (etc.) | Adv-only | **Separate** test per violation: missing KMS, missing SSM, bad nonce prefix, TCP listener, SES override | One `ConfigError` variant each |
| 3 | `environment_parse_rejects_invalid_and_blocks_dev_only_in_prod` | Adv-only | Table of env strings | Matching enum per case |
| 4 | `build_listener_forbids_tcp_in_production` | Adv-only | `ListenerKind::Tcp`, `Environment::Production` | `TcpForbiddenInProduction` before bind |
| 5 | `build_listener_vsock_unsupported_off_linux` | Adv-only | On macOS (or any non-Linux host in scope) | `VsockUnsupported` |
| 6 | `build_listener_reports_bind_failed_for_invalid_addr` | Adv-only | Choose addr that fails bind on that OS | `BindFailed` |
| 7a | `nonce_redis_prefix_validation_without_network` | Adv-only | Construct `NonceReplayCache` / validator inputs | Matches product rules |
| 7b | `redis_init_prefix_error_constructible_or_removed` | Adv-only | Audit `PrefixMissingProduct` | Either reachable from API or variant removed |

---

## Priority P3 — Redis integration (manual / `#[ignore]`)

| # | Behavior | Setup | Expected |
|---|----------|-------|----------|
| 1 | Writer sets key and TTL | Real Redis; synthetic `ts`, `expires_at` | Key name prefix + value parseable + TTL seconds as integer |
| 2 | Writer skips nonpositive TTL | `expires_at <= ts` | No key |
| 3 | Seed parses keys | Pre-populate keys | Parsed `(nonce, ts)` |
| 4 | Seed skips bad values | Value not `i64` | Omitted, no panic |
| 5 | Connection refused | Bad port | Documented empty or error |

---

## Priority P4 — Attestation bundle and challenge

| # | Suggested test name | KAT | Setup | Assert |
|---|---------------------|-----|-------|--------|
| 1 | `public_key_bundle_canonical_bytes_match_frozen_v1` | Fixture-v1 | Fixed `BTreeMap` | `canonical_bytes() == include_bytes!(...)` |
| 2 | `public_key_bundle_independent_of_insertion_order` | Adv-only | Same map, different insert order | Equal `canonical_bytes()` |
| 3 | `sign_attestation_challenge_rejects_short_challenge` | Adv-only | `challenge.len() < MIN` | `ChallengeTooShort` |
| 4 | `attestation_hmac_raw_matches_rfc4231` | RFC4231 | Feed raw HMAC with vector key/msg | Tag equals vector |
| 5 | `attestation_preimage_flips_change_mac` | Adv-only | Flip byte in product line, PCR line, bundle embed | MAC differs |
| 6 | `attestation_replay_store_respects_ttl_boundary` | Adv-only | Fixed `now_secs` | Same as nonce cache TTL tests |
| 7 | `nsm_runtime_available_false_without_nitro` | Adv-only | Default features | `false` |
| 8 | `mock_pcrs_non_development_documented` | Adv-only | Call mock in non-dev if API allows | Panic or `Result` per code |

Optional: add **`verify_attestation_challenge`** helper beside `sign_*` so preimage bytes are defined once.

---

## Meta: misleading tests

- Rename **`flip_suite_fails_auth`** in `src/crypto/aead.rs` or replace with a test where **`aes_gcm_decrypt`** fails because the **`SuiteId`** passed in does not match encryption.

---

## Summary

The plan is **adversarial-first**: run the full §AEAD matrix on **S1–S4**; pair parser tests with **truncation / length inconsistency / duplicates** per §Wire layouts; anchor primitives with §Minimum KAT policy and **Fixture-v1** for custom formats. Tests are **deterministic** (injected clocks, seeded RNGs, no live network in the default suite). **Proptest** covers algebraic invariants. **Redis Track B**, **Miri**, and **fuzz** are **optional** and not prescribed as automated gates in this document. **Constant-time** is out of scope for unit tests; assert **error enums**, not secret-dependent strings.

---

## Optional local commands

Developers may run, as needed:

- `cargo test` — default unit and integration tests.
- `cargo test --features stream-aead` — stream AEAD tests.
- `cargo test --features nitro` — compile NSM-related code on Linux.
- `cargo test --release` — e.g. `release_error_message` under `not(debug_assertions)`.
- `cargo test --features auth-verbose-errors` — verbose error strings (do not rely on them for security assertions).
- `cargo miri test` — optional memory checks.
- `cargo fuzz run <target>` — optional, if fuzz targets exist.

Mark any test that needs Redis or a real enclave with **`#[ignore]`** and document the reason in a comment on the test function.
