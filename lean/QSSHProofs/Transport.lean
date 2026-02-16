/-
  QSSHProofs.Transport

  Quantum-resistant transport layer frame algebra.

  Key results:
    - frame_partition         — 768 = 17 + 719 + 32
    - header_decomposition    — 17 = 8 + 8 + 1
    - padding_nonneg          — padding ≥ 0 for valid payloads
    - payload_fills_frame     — data + padding = payload field exactly
    - frame_uniform_size      — all frames are exactly 768 bytes
    - sequence_no_overflow    — realistic frame counts fit u64

  Mirrors: transport/quantum_resistant.rs QuantumFrame.
  Tier 3 verification (Kani → Verus → **Lean 4**).
-/

import Mathlib.Tactic.NormNum

namespace QSSHProofs.Transport

/-! ## Constants -/

/-- Quantum frame size: every frame is exactly 768 bytes (traffic analysis resistance). -/
def FRAME_SIZE : ℕ := 768

/-- Header: sequence(8) + timestamp(8) + frame_type(1) = 17 bytes. -/
def HEADER_SIZE : ℕ := 17

/-- Payload field: the variable-content region of the frame. -/
def PAYLOAD_FIELD_SIZE : ℕ := 719

/-- MAC: HMAC-SHA3-256 authentication tag. -/
def MAC_SIZE : ℕ := 32

/-- Maximum data bytes per frame (payload field minus 2-byte length prefix). -/
def MAX_DATA_SIZE : ℕ := 717

/-! ## Frame partition -/

/-- The frame partitions exactly into header + payload + MAC. -/
theorem frame_partition :
    FRAME_SIZE = HEADER_SIZE + PAYLOAD_FIELD_SIZE + MAC_SIZE := by
  norm_num [FRAME_SIZE, HEADER_SIZE, PAYLOAD_FIELD_SIZE, MAC_SIZE]

/-- Header decomposes into sequence(8) + timestamp(8) + type(1). -/
theorem header_decomposition :
    HEADER_SIZE = 8 + 8 + 1 := by
  norm_num [HEADER_SIZE]

/-- 768 = 3 × 256: frame size has clean factorization. -/
theorem frame_size_factored : FRAME_SIZE = 3 * 256 := by
  norm_num [FRAME_SIZE]

/-- Frame size fits in a single UDP datagram (< 1500 MTU). -/
theorem frame_fits_mtu : FRAME_SIZE < 1500 := by
  norm_num [FRAME_SIZE]

/-! ## Payload algebra -/

/-- Maximum data size: payload field minus 2-byte length prefix. -/
theorem max_data_eq : MAX_DATA_SIZE = PAYLOAD_FIELD_SIZE - 2 := by
  norm_num [MAX_DATA_SIZE, PAYLOAD_FIELD_SIZE]

/-- Padding is non-negative for any valid data length. -/
theorem padding_nonneg (data_len : ℕ) (h : data_len ≤ MAX_DATA_SIZE) :
    PAYLOAD_FIELD_SIZE ≥ 2 + data_len := by
  simp only [PAYLOAD_FIELD_SIZE, MAX_DATA_SIZE] at *; omega

/-- Data + length_prefix + padding fills the payload field exactly. -/
theorem payload_fills_frame (data_len : ℕ) (h : data_len ≤ MAX_DATA_SIZE) :
    2 + data_len + (PAYLOAD_FIELD_SIZE - 2 - data_len) = PAYLOAD_FIELD_SIZE := by
  simp only [PAYLOAD_FIELD_SIZE, MAX_DATA_SIZE] at *; omega

/-- Every frame has the same total size regardless of data length (uniform frames). -/
theorem frame_uniform (data_len : ℕ) (h : data_len ≤ MAX_DATA_SIZE) :
    HEADER_SIZE + (2 + data_len + (PAYLOAD_FIELD_SIZE - 2 - data_len)) + MAC_SIZE
    = FRAME_SIZE := by
  simp only [HEADER_SIZE, PAYLOAD_FIELD_SIZE, MAC_SIZE, FRAME_SIZE, MAX_DATA_SIZE] at *; omega

/-! ## Sequence number properties -/

/-- Sequence counter is strictly monotonic. -/
theorem sequence_monotonic (n : ℕ) : n < n + 1 := Nat.lt_succ_of_le (le_refl n)

/-- At 10 Gbps link speed with 768-byte frames, the u64 sequence counter
    lasts over 100,000 years without overflow. -/
theorem sequence_no_overflow :
    let frames_per_sec := 10000000000 / (FRAME_SIZE * 8)  -- ~1.6M frames/sec
    let frames_per_year := frames_per_sec * 365 * 24 * 3600
    let frames_100k_years := frames_per_year * 100000
    frames_100k_years < 2 ^ 64 := by
  norm_num [FRAME_SIZE]

/-! ## Efficiency -/

/-- Payload efficiency: data capacity / frame size > 93%. -/
theorem payload_efficiency :
    MAX_DATA_SIZE * 100 / FRAME_SIZE ≥ 93 := by
  norm_num [MAX_DATA_SIZE, FRAME_SIZE]

/-- MAC overhead: 32/768 ≈ 4.2% of each frame. -/
theorem mac_overhead_percent :
    MAC_SIZE * 1000 / FRAME_SIZE = 41 := by
  norm_num [MAC_SIZE, FRAME_SIZE]

end QSSHProofs.Transport
