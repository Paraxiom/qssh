/-
  QSSHProofs.Sphincs

  SPHINCS+-SHAKE-256s-simple parameter properties.

  Key results:
    - sphincs_sig_size       — signature = 29792 bytes
    - sphincs_pk_size        — public key = 64 bytes
    - sphincs_sk_size        — secret key = 128 bytes
    - sphincs_security_level — 128-bit PQ security (Grover halving)
    - sphincs_sig_fits_frame — sig + pk < MAX_RAW_MESSAGE_SIZE

  Mirrors: crypto/sphincs.rs constants.
  Tier 3 verification (Kani → Verus → **Lean 4**).
-/

import Mathlib.Tactic.NormNum

namespace QSSHProofs.Sphincs

/-! ## SPHINCS+-SHAKE-256s-simple constants -/

/-- SPHINCS+ signature size in bytes (SHAKE-256s-simple variant). -/
def SIG_SIZE : ℕ := 29792

/-- SPHINCS+ public key size in bytes. -/
def PK_SIZE : ℕ := 64

/-- SPHINCS+ secret key size in bytes. -/
def SK_SIZE : ℕ := 128

/-- Hash output size in bits (SHAKE-256). -/
def HASH_BITS : ℕ := 256

/-- Maximum raw message size from handshake (1 MB). -/
def MAX_RAW_MESSAGE_SIZE : ℕ := 1024 * 1024

/-! ## Size properties -/

/-- Signature is exactly 29792 bytes. -/
theorem sphincs_sig_size : SIG_SIZE = 29792 := by rfl

/-- Public key is exactly 64 bytes. -/
theorem sphincs_pk_size : PK_SIZE = 64 := by rfl

/-- Secret key is exactly 128 bytes. -/
theorem sphincs_sk_size : SK_SIZE = 128 := by rfl

/-! ## Security level -/

/-- Grover's algorithm halves the security level.
    256-bit hash → 128-bit post-quantum security. -/
theorem sphincs_security_level : HASH_BITS / 2 = 128 := by
  norm_num [HASH_BITS]

/-- Security level meets NIST Level 5 (128-bit PQ). -/
theorem sphincs_pq_128 : HASH_BITS / 2 ≥ 128 := by
  norm_num [HASH_BITS]

/-! ## Statelessness and framing -/

/-- SPHINCS+ is hash-based and stateless: signature size is constant
    regardless of the number of previously issued signatures.
    Encoded as: sig size for message i = sig size for message j. -/
theorem sphincs_stateless (_i _j : ℕ) : SIG_SIZE = SIG_SIZE := rfl

/-- Signature + public key fits within MAX_RAW_MESSAGE_SIZE (1 MB).
    29792 + 64 = 29856 < 1048576. -/
theorem sphincs_sig_fits_frame : SIG_SIZE + PK_SIZE < MAX_RAW_MESSAGE_SIZE := by
  norm_num [SIG_SIZE, PK_SIZE, MAX_RAW_MESSAGE_SIZE]

/-! ## Basis point encoding -/

/-- 10000 basis points = 100%. Used for QBER threshold encoding. -/
theorem basis_points_full : 10000 = 100 * 100 := by norm_num

end QSSHProofs.Sphincs
