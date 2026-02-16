/-
  QSSHProofs.Falcon

  Falcon signature scheme parameter properties.

  Key results:
    - falcon_q_prime       — q = 12289 is prime
    - falcon_q_ntt         — q ≡ 1 (mod 512) (NTT-compatible)
    - falcon512/1024 sizes — signature and key size bounds
    - falcon_sig_vs_sphincs — Falcon-1024 sig < SPHINCS+ sig

  Mirrors: crypto/falcon.rs constants.
  Tier 3 verification (Kani → Verus → **Lean 4**).
-/

import Mathlib.Data.Nat.Prime.Basic
import Mathlib.Tactic.NormNum
import Mathlib.Tactic.NormNum.Prime

namespace QSSHProofs.Falcon

/-! ## Falcon modulus properties -/

/-- The Falcon modulus q = 12289. -/
def q : ℕ := 12289

/-- Falcon ring dimension n = 512 (Falcon-512) or 1024 (Falcon-1024).
    We use 512 as the base dimension. -/
def n : ℕ := 512

/-- q = 12289 is prime. Foundational to the NTRU lattice hardness assumption. -/
theorem falcon_q_prime : Nat.Prime q := by norm_num [q]

/-- q ≡ 1 (mod 512): NTT-compatibility for efficient polynomial multiplication.
    12289 = 24 × 512 + 1. -/
theorem falcon_q_ntt : q % n = 1 := by norm_num [q, n]

/-- q - 1 = 12288 = 2^12 × 3. The group order factorization enables
    NTT with 512-th roots of unity. -/
theorem falcon_q_minus_one_factored : q - 1 = 2 ^ 12 * 3 := by norm_num [q]

/-- q > n: the modulus exceeds the ring dimension. -/
theorem falcon_q_gt_n : q > n := by norm_num [q, n]

/-! ## Falcon-512 sizes -/

namespace Falcon512

/-- Falcon-512 maximum signature size in bytes. -/
def SIG_SIZE : ℕ := 666

/-- Falcon-512 public key size in bytes. -/
def PK_SIZE : ℕ := 897

/-- Falcon-512 signature fits well under 1 KB. -/
theorem sig_lt_1kb : SIG_SIZE < 1024 := by norm_num [SIG_SIZE]

/-- Falcon-512 public key fits under 1 KB. -/
theorem pk_lt_1kb : PK_SIZE < 1024 := by norm_num [PK_SIZE]

end Falcon512

/-! ## Falcon-1024 sizes -/

namespace Falcon1024

/-- Falcon-1024 maximum signature size in bytes. -/
def SIG_SIZE : ℕ := 1280

/-- Falcon-1024 public key size in bytes. -/
def PK_SIZE : ℕ := 1793

/-- Falcon-1024 signature under 2 KB. -/
theorem sig_lt_2kb : SIG_SIZE < 2048 := by norm_num [SIG_SIZE]

end Falcon1024

/-! ## Cross-scheme comparisons -/

/-- SPHINCS+-SHAKE-256s-simple signature size for comparison. -/
def SPHINCS_SIG_SIZE : ℕ := 29792

/-- Falcon-1024 signature is dramatically smaller than SPHINCS+.
    1280 < 29792 — a 23x+ advantage. -/
theorem falcon_sig_vs_sphincs : Falcon1024.SIG_SIZE < SPHINCS_SIG_SIZE := by
  norm_num [Falcon1024.SIG_SIZE, SPHINCS_SIG_SIZE]

/-- SPHINCS+ / Falcon sig ratio > 23x. -/
theorem falcon_sig_ratio : SPHINCS_SIG_SIZE / Falcon1024.SIG_SIZE ≥ 23 := by
  norm_num [SPHINCS_SIG_SIZE, Falcon1024.SIG_SIZE]

end QSSHProofs.Falcon
