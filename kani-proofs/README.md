# Kani Bounded Model Checking — paraxiom-qssh

Tier 1 formal verification using [Kani](https://model-checking.github.io/kani/)
for panic-freedom, integer safety, and memory safety of the highest-risk code paths.

## Setup

```bash
cargo install kani-verifier
cargo kani setup
```

## Running

```bash
# Run all harnesses
cargo kani

# Run a specific harness
cargo kani --harness proof_quantum_frame_size

# Run harnesses in a specific file
cargo kani --harness proof_quantum_frame_size --harness proof_frame_roundtrip
```

## Harness Inventory (30 harnesses)

### Step 2: QuantumFrame Layout (CRITICAL) — `src/transport/quantum_resistant.rs`

These prove the unsafe `from_raw_parts` / `ptr::read` transmutes in
`send_frame` (line 257) and `receive_frame` (line 289) are sound.

| # | Harness | What it proves |
|---|---------|---------------|
| 1 | `proof_quantum_frame_size` | `size_of::<QuantumFrame>() == 768` |
| 2 | `proof_quantum_frame_alignment` | `align_of::<QuantumFrame>() == 1` (no padding) |
| 3 | `proof_frame_roundtrip` | Symbolic QuantumFrame → bytes → QuantumFrame preserves all fields |

### Step 3: Frame Parsing Panic-Freedom (HIGH) — `src/transport/quantum_resistant.rs`

| # | Harness | What it proves |
|---|---------|---------------|
| 4 | `proof_build_frame_no_panic` | Core data-packing logic never panics for any input 0..=719 bytes |
| 5 | `proof_payload_bounds` | `payload_len` from `u16::from_be_bytes` checked ≤ 717 before slice access |
| 6 | `proof_frame_type_exhaustive` | All 256 values of `frame_type` byte handled (4 valid + 252 rejected) |

### Step 4: ML-KEM Unwrap Safety (MEDIUM) — `src/crypto/mlkem.rs`

| # | Harness | What it proves |
|---|---------|---------------|
| 7 | `proof_mlkem768_decapsulate_no_panic` | After length check, `.unwrap()` at line 95 is safe |
| 8 | `proof_mlkem1024_decapsulate_no_panic` | After length check, `.unwrap()` at line 157 is safe |
| 9 | `proof_mlkem768_encapsulate_no_panic` | Wrong-size EK → Err, never panic |
| 10 | `proof_mlkem1024_encapsulate_no_panic` | Wrong-size EK → Err, never panic |

### Step 5: KDF and Crypto Bounds (MEDIUM) — `src/crypto/kdf.rs`

| # | Harness | What it proves |
|---|---------|---------------|
| 11 | `proof_derive_keys_no_panic` | Salt construction is exactly 64 bytes |
| 12 | `proof_mix_quantum_classical_no_panic` | XOR loop bounded by min(lengths), output = 32 bytes |
| 13 | `proof_kdf_output_lengths` | SessionKeys fields are exactly [32, 32, 12, 12] bytes |
| 14 | `proof_mix_quantum_classical_mismatched_sizes` | Mismatched input sizes handled safely |

### Step 6: Integer Cast Safety (MEDIUM) — various files

| # | Harness | File | What it proves |
|---|---------|------|---------------|
| 15 | `proof_payload_len_cast` | quantum_resistant.rs | `data_len as u16` after `.min(717)` never truncates |
| 16 | `proof_sequence_no_overflow` | quantum_resistant.rs | u64 sequence counter can't overflow in 2^48 frames |
| 17 | `proof_sequence_from_be_bytes` | quantum_resistant.rs | `u64::from_be_bytes` is total (all byte patterns valid) |
| 18 | `proof_transport_frame_length_cast` | transport/mod.rs | `(nonce + ciphertext) as u32` fits within MAX_MESSAGE_SIZE bounds |
| 19 | `proof_handshake_send_raw_no_truncation` | transport/mod.rs | `data.len() as u32` doesn't truncate within MAX_MESSAGE_SIZE |
| 20 | `proof_send_raw_u32_cast` | handshake.rs | `data.len() as u32` in send_raw doesn't truncate |
| 21 | `proof_compression_stats_no_overflow` | compression.rs | `len() as u64` casts and accumulation safe |
| 22 | `proof_compression_bytes_saved_no_overflow` | compression.rs | `bytes_saved()` i64 subtraction safe |
| 23 | `proof_sftp_u32_casts` | subsystems/sftp/protocol.rs | write_string/write_data u32 casts safe |

### Step 7: Message Size Bounds (HIGH) — various files

These verify the **fixes** to previously-unbounded allocations.

| # | Harness | File | What it proves |
|---|---------|------|---------------|
| 24 | `proof_transport_receive_bounded` | transport/mod.rs | `frame_length > MAX_MESSAGE_SIZE` check exists |
| 25 | `proof_client_receive_raw_bounded` | handshake.rs | **FIXED**: `receive_raw()` now rejects len > 1 MB |
| 26 | `proof_server_receive_raw_bounded` | handshake.rs | **FIXED**: `receive_raw()` now rejects len > 1 MB |
| 27 | `proof_agent_receive_bounded` | agent/mod.rs | **FIXED**: agent protocol rejects len > 64 KB |

### Step 8: Deserialization Safety (LOW) — `src/crypto/quantum_kem.rs`

| # | Harness | What it proves |
|---|---------|---------------|
| 28 | `proof_quantum_kem_encapsulate_validates` | Empty/wrong-size peer_pk rejected before crypto ops |
| 29 | `proof_quantum_kem_decapsulate_validates` | Empty/wrong-size ciphertext rejected, slice parsing in-bounds |
| 30 | `proof_derive_shared_secret_ordering` | Identity sort is total (all orderings handled) |

## Bugs Fixed

### 1. Unbounded allocation in `handshake.rs:receive_raw()` (OOM DoS)

**Before**: `u32::from_be_bytes(len_bytes) as usize` → `vec![0u8; len]` with no
bounds check. Attacker sends `0xFFFFFFFF` → 4 GB allocation → OOM crash.

**After**: Added `MAX_RAW_MESSAGE_SIZE` (1 MB) check. Returns `Err` for oversized
messages before allocating.

**Harnesses**: `proof_client_receive_raw_bounded`, `proof_server_receive_raw_bounded`

### 2. Unbounded allocation in `agent/mod.rs:handle_client()` (OOM DoS)

**Before**: `u32::from_be_bytes` → no check against buffer size. Attacker sends
length > 64 KB → buffer overrun or OOM.

**After**: Added `MAX_AGENT_MESSAGE_SIZE` (64 KB) check. Returns `Err` for
oversized messages.

**Harness**: `proof_agent_receive_bounded`

### 3. Missing compile-time assertion for QuantumFrame layout

**Before**: The unsafe transmutes between `QuantumFrame` and `[u8; 768]` relied
on `#[repr(C)]` layout being exactly 768 bytes with no compile-time check.

**After**: Added `const_assert!` that fails compilation if the invariant breaks.

## Compile-Time Assertions

Added to `src/transport/quantum_resistant.rs`:

```rust
const _: () = assert!(std::mem::size_of::<QuantumFrame>() == QUANTUM_FRAME_SIZE);
const _: () = assert!(std::mem::size_of::<EncryptedHeader>() == 17);
```

## What Kani Cannot Verify (Deferred to Tier 2/3)

- **Cryptographic correctness**: ML-KEM/SPHINCS+/Falcon produce correct outputs → Verus or hax
- **Async behavior**: Kani doesn't support `async/await` → sync core logic extracted for proofs
- **Protocol state machine**: Handshake follows correct sequence → Verus
- **Side-channel resistance**: Constant-time guarantees → specialized tools
- **Concurrency**: Tokio mutex/RwLock correctness → Loom
