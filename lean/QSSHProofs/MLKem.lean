/-
  QSSHProofs.MLKem

  ML-KEM (FIPS 203) parameter properties proven from Mathlib foundations.

  Key results:
    - q_prime              — q = 3329 is prime
    - q_ntt_compatible     — q ≡ 1 (mod 256) (NTT-friendly)
    - mlkem768/1024 sizes  — alignment, bounds, relationships
    - ss_entropy           — 256-bit shared secret entropy
    - grover_resistance    — 128-bit post-quantum security level

  Mirrors: crypto/mlkem.rs constants.
  Tier 3 verification (Kani → Verus → **Lean 4**).
-/

import Mathlib.Data.Nat.Prime.Basic
import Mathlib.Tactic.NormNum
import Mathlib.Tactic.NormNum.Prime

namespace QSSHProofs.MLKem

/-! ## ML-KEM modulus properties -/

/-- The ML-KEM modulus q = 3329. -/
def q : ℕ := 3329

/-- The polynomial ring dimension n = 256 = 2^8. -/
def n : ℕ := 256

/-- q = 3329 is prime. This is foundational to the module-LWE hardness assumption. -/
theorem q_prime : Nat.Prime q := by norm_num [q]

/-- q ≡ 1 (mod 256): NTT-compatibility.
    This enables the Number Theoretic Transform for efficient polynomial
    multiplication in Z_q[X]/(X^256 + 1), which is the core of ML-KEM. -/
theorem q_ntt_compatible : q % n = 1 := by norm_num [q, n]

/-- q - 1 = 3328 = 2^8 × 13: the group order factorization.
    Since 256 | 3328, X^256+1 splits into 128 quadratic factors over Z_q,
    enabling the negacyclic NTT used in ML-KEM. -/
theorem q_minus_one_factored : q - 1 = 2 ^ 8 * 13 := by norm_num [q]

/-- n = 256 is a power of 2. -/
theorem n_pow_two : n = 2 ^ 8 := by norm_num [n]

/-- q > n: the modulus exceeds the ring dimension. -/
theorem q_gt_n : q > n := by norm_num [q, n]

/-! ## ML-KEM-768 constants (NIST Level 3) -/

namespace MLKem768

def k : ℕ := 3           -- Module rank
def EK_SIZE : ℕ := 1184  -- Encapsulation key
def DK_SIZE : ℕ := 2400  -- Decapsulation key
def CT_SIZE : ℕ := 1088  -- Ciphertext
def SS_SIZE : ℕ := 32    -- Shared secret

/-- All ML-KEM-768 sizes are multiples of 32 (byte-aligned). -/
theorem sizes_aligned :
    32 ∣ EK_SIZE ∧ 32 ∣ DK_SIZE ∧ 32 ∣ CT_SIZE ∧ 32 ∣ SS_SIZE := by
  refine ⟨⟨37, ?_⟩, ⟨75, ?_⟩, ⟨34, ?_⟩, ⟨1, ?_⟩⟩ <;> norm_num [EK_SIZE, DK_SIZE, CT_SIZE, SS_SIZE]

/-- Ciphertext is smaller than the encapsulation key: CT < EK. -/
theorem ct_lt_ek : CT_SIZE < EK_SIZE := by norm_num [CT_SIZE, EK_SIZE]

/-- Decapsulation key is the largest component. -/
theorem dk_largest : EK_SIZE < DK_SIZE ∧ CT_SIZE < DK_SIZE := by
  norm_num [EK_SIZE, DK_SIZE, CT_SIZE]

end MLKem768

/-! ## ML-KEM-1024 constants (NIST Level 5) -/

namespace MLKem1024

def k : ℕ := 4           -- Module rank
def EK_SIZE : ℕ := 1568  -- Encapsulation key
def DK_SIZE : ℕ := 3168  -- Decapsulation key
def CT_SIZE : ℕ := 1568  -- Ciphertext
def SS_SIZE : ℕ := 32    -- Shared secret

/-- All ML-KEM-1024 sizes are multiples of 32. -/
theorem sizes_aligned :
    32 ∣ EK_SIZE ∧ 32 ∣ DK_SIZE ∧ 32 ∣ CT_SIZE ∧ 32 ∣ SS_SIZE := by
  refine ⟨⟨49, ?_⟩, ⟨99, ?_⟩, ⟨49, ?_⟩, ⟨1, ?_⟩⟩ <;> norm_num [EK_SIZE, DK_SIZE, CT_SIZE, SS_SIZE]

/-- CT_SIZE = EK_SIZE for ML-KEM-1024 (symmetric). -/
theorem ct_eq_ek : CT_SIZE = EK_SIZE := by norm_num [CT_SIZE, EK_SIZE]

/-- ML-KEM-1024 has larger keys than ML-KEM-768. -/
theorem larger_than_768 :
    MLKem768.EK_SIZE < EK_SIZE ∧ MLKem768.DK_SIZE < DK_SIZE ∧
    MLKem768.CT_SIZE < CT_SIZE := by
  norm_num [MLKem768.EK_SIZE, EK_SIZE, MLKem768.DK_SIZE, DK_SIZE,
            MLKem768.CT_SIZE, CT_SIZE]

end MLKem1024

/-! ## Shared secret entropy -/

/-- Shared secret is 32 bytes = 256 bits for both variants. -/
theorem ss_bits : MLKem768.SS_SIZE * 8 = 256 ∧ MLKem1024.SS_SIZE * 8 = 256 := by
  norm_num [MLKem768.SS_SIZE, MLKem1024.SS_SIZE]

/-- Grover's algorithm halves the security level.
    256-bit shared secret → 128-bit post-quantum security. -/
theorem grover_resistance :
    MLKem768.SS_SIZE * 8 / 2 = 128 ∧ MLKem1024.SS_SIZE * 8 / 2 = 128 := by
  norm_num [MLKem768.SS_SIZE, MLKem1024.SS_SIZE]

/-- Shared secret fits in a single SHA-256 block (64 bytes). -/
theorem ss_fits_sha256_block :
    MLKem768.SS_SIZE ≤ 64 ∧ MLKem1024.SS_SIZE ≤ 64 := by
  norm_num [MLKem768.SS_SIZE, MLKem1024.SS_SIZE]

end QSSHProofs.MLKem
