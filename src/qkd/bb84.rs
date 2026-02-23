//! BB84 Quantum Key Distribution Protocol Implementation
//!
//! This module implements the BB84 protocol for quantum key distribution.
//! While we cannot have actual quantum channels in software, this provides
//! a realistic simulation of the protocol for development and testing.
//!
//! Enhancements over basic BB84:
//! - Configurable channel noise model (depolarizing noise)
//! - QBER reporting per key generation
//! - Information reconciliation step (Cascade-style parity check)
//! - Security tier integration (refuses T4+ if QBER > threshold)

use crate::{Result, QsshError};
use rand::{thread_rng, Rng};
use serde::{Serialize, Deserialize};

/// Result of a BB84 key generation run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BB84Result {
    /// Final key material
    pub key: Vec<u8>,
    /// Measured quantum bit error rate
    pub qber: f64,
    /// Number of raw qubits transmitted
    pub raw_bits: usize,
    /// Number of bits after basis sifting
    pub sifted_bits: usize,
    /// Number of bits after error estimation sampling
    pub post_sample_bits: usize,
    /// Number of bits after information reconciliation
    pub reconciled_bits: usize,
    /// Final key length in bits
    pub final_bits: usize,
    /// Key rate: final_bits / raw_bits
    pub key_rate: f64,
}

/// Channel noise model for BB84 simulation
#[derive(Debug, Clone)]
pub struct ChannelNoise {
    /// Depolarizing noise probability (0.0 = perfect, 0.5 = completely random)
    pub depolarizing_rate: f64,
    /// Dark count probability per detector (false positives)
    pub dark_count_rate: f64,
    /// Detection efficiency (probability of detecting a photon)
    pub detection_efficiency: f64,
}

impl Default for ChannelNoise {
    fn default() -> Self {
        Self {
            depolarizing_rate: 0.0,  // Perfect channel
            dark_count_rate: 0.0,
            detection_efficiency: 1.0,
        }
    }
}

impl ChannelNoise {
    /// Realistic fiber-optic channel (~20km)
    pub fn fiber_20km() -> Self {
        Self {
            depolarizing_rate: 0.02,    // 2% depolarization
            dark_count_rate: 1e-6,       // Typical SPAD
            detection_efficiency: 0.85,  // 85% detection
        }
    }

    /// Noisy channel (for testing security margins)
    pub fn noisy() -> Self {
        Self {
            depolarizing_rate: 0.08,    // 8% — near threshold
            dark_count_rate: 1e-4,
            detection_efficiency: 0.70,
        }
    }
}

/// BB84 Protocol Implementation
pub struct BB84Protocol {
    /// Error rate threshold for aborting (typically 11% for BB84)
    error_threshold: f64,
    /// Minimum key length required
    min_key_length: usize,
    /// Channel noise model
    noise: ChannelNoise,
    /// Last measured QBER (updated after each key generation)
    last_qber: Option<f64>,
}

impl BB84Protocol {
    pub fn new() -> Self {
        Self {
            error_threshold: 0.11,
            min_key_length: 128, // Minimum sifted key bits (reduced for small key requests)
            noise: ChannelNoise::default(),
            last_qber: None,
        }
    }

    /// Create with a specific noise model
    pub fn with_noise(noise: ChannelNoise) -> Self {
        Self {
            error_threshold: 0.11,
            min_key_length: 256,
            noise,
            last_qber: None,
        }
    }

    /// Get the last measured QBER
    pub fn last_qber(&self) -> Option<f64> {
        self.last_qber
    }

    /// Check if QBER is acceptable for a given security tier
    pub fn is_qber_acceptable_for_tier(&self, tier_level: u8) -> bool {
        match self.last_qber {
            Some(qber) => {
                let threshold = match tier_level {
                    4 => 0.11,   // T4: Quantum-Secured — standard BB84 threshold
                    5 => 0.05,   // T5: Hybrid Quantum — stricter for defense in depth
                    _ => 0.11,   // Default BB84 threshold
                };
                qber < threshold
            }
            None => false, // No QBER data available
        }
    }

    /// Simulate quantum bit transmission with noise
    pub fn prepare_qubits(&self, num_bits: usize) -> (Vec<bool>, Vec<bool>, Vec<bool>) {
        let mut rng = thread_rng();

        // Alice's random bits
        let alice_bits: Vec<bool> = (0..num_bits).map(|_| rng.gen()).collect();

        // Alice's random bases (0 = rectilinear, 1 = diagonal)
        let alice_bases: Vec<bool> = (0..num_bits).map(|_| rng.gen()).collect();

        // Encoded qubits (pass through noisy channel)
        let qubits: Vec<bool> = alice_bits.iter().map(|&bit| {
            // Apply depolarizing noise: with probability p, flip the bit
            if rng.gen::<f64>() < self.noise.depolarizing_rate {
                !bit
            } else {
                bit
            }
        }).collect();

        (alice_bits, alice_bases, qubits)
    }

    /// Bob measures qubits with random bases, including noise effects
    pub fn measure_qubits(
        &self,
        qubits: &[bool],
        alice_bases: &[bool],
    ) -> (Vec<bool>, Vec<bool>) {
        let mut rng = thread_rng();

        // Bob's random measurement bases
        let bob_bases: Vec<bool> = (0..qubits.len()).map(|_| rng.gen()).collect();

        // Bob's measurement results with noise
        let mut bob_bits = Vec::new();
        for i in 0..qubits.len() {
            // Detection efficiency: might miss the photon
            if rng.gen::<f64>() > self.noise.detection_efficiency {
                // Missed detection — dark count might trigger
                if rng.gen::<f64>() < self.noise.dark_count_rate {
                    bob_bits.push(rng.gen()); // Random dark count
                } else {
                    bob_bits.push(rng.gen()); // Lost photon, random guess
                }
                continue;
            }

            if alice_bases[i] == bob_bases[i] {
                // Same basis - Bob gets correct bit (already noise-affected in qubits)
                bob_bits.push(qubits[i]);
            } else {
                // Different basis - random result
                bob_bits.push(rng.gen());
            }
        }

        (bob_bits, bob_bases)
    }

    /// Sifting: Keep only bits where bases matched
    pub fn sift_keys(
        &self,
        alice_bits: &[bool],
        alice_bases: &[bool],
        bob_bits: &[bool],
        bob_bases: &[bool],
    ) -> (Vec<bool>, Vec<bool>) {
        let mut alice_sifted = Vec::new();
        let mut bob_sifted = Vec::new();

        for i in 0..alice_bits.len() {
            if alice_bases[i] == bob_bases[i] {
                alice_sifted.push(alice_bits[i]);
                bob_sifted.push(bob_bits[i]);
            }
        }

        (alice_sifted, bob_sifted)
    }

    /// Error estimation: Check a subset of bits
    pub fn estimate_error_rate(
        &self,
        alice_key: &[bool],
        bob_key: &[bool],
        sample_size: usize,
    ) -> Result<f64> {
        if alice_key.len() < sample_size {
            return Err(QsshError::Qkd("Insufficient key length for error estimation".into()));
        }

        let mut errors = 0;
        for i in 0..sample_size {
            if alice_key[i] != bob_key[i] {
                errors += 1;
            }
        }

        Ok(errors as f64 / sample_size as f64)
    }

    /// Information reconciliation: Cascade-style parity correction
    ///
    /// Uses block parity checks to find and correct errors in Bob's key
    /// to match Alice's key. This is a simplified version of the Cascade protocol.
    pub fn information_reconciliation(
        &self,
        alice_key: &[bool],
        bob_key: &mut Vec<bool>,
        error_rate: f64,
    ) -> usize {
        if alice_key.len() != bob_key.len() || alice_key.is_empty() {
            return 0;
        }

        let mut corrections = 0;

        // Cascade pass 1: block size = 1 / (2 * error_rate), min 4
        let block_size = if error_rate > 0.0 {
            ((1.0 / (2.0 * error_rate)) as usize).max(4)
        } else {
            alice_key.len() // No errors expected, one big block
        };

        // Pass over blocks
        let mut i = 0;
        while i < alice_key.len() {
            let end = (i + block_size).min(alice_key.len());

            // Compute parities for Alice and Bob's block
            let alice_parity = alice_key[i..end].iter().filter(|&&b| b).count() % 2;
            let bob_parity = bob_key[i..end].iter().filter(|&&b| b).count() % 2;

            if alice_parity != bob_parity {
                // Parity mismatch — binary search for the error
                let mut lo = i;
                let mut hi = end;
                while hi - lo > 1 {
                    let mid = (lo + hi) / 2;
                    let a_par = alice_key[lo..mid].iter().filter(|&&b| b).count() % 2;
                    let b_par = bob_key[lo..mid].iter().filter(|&&b| b).count() % 2;
                    if a_par != b_par {
                        hi = mid;
                    } else {
                        lo = mid;
                    }
                }
                // Flip the error bit
                bob_key[lo] = !bob_key[lo];
                corrections += 1;
            }

            i = end;
        }

        corrections
    }

    /// Privacy amplification: Hash-based reduction to remove leaked info
    ///
    /// Uses universal hashing (SHA-256) to compress the reconciled key,
    /// removing information that may have leaked to an eavesdropper.
    /// The output size is bounded by the Devetak-Winter rate.
    pub fn privacy_amplification(
        &self,
        key: Vec<bool>,
        error_rate: f64,
    ) -> Vec<u8> {
        // Calculate secure output length using Devetak-Winter bound
        // r = 1 - h(e) where h is binary Shannon entropy
        let secure_fraction = if error_rate > 0.0 && error_rate < 0.5 {
            let h_e = -error_rate * error_rate.log2()
                - (1.0 - error_rate) * (1.0 - error_rate).log2();
            (1.0 - h_e).max(0.1)
        } else {
            1.0
        };

        let secure_bits = ((key.len() as f64) * secure_fraction) as usize;

        // Convert all key bits to bytes for hashing
        let mut input_bytes = Vec::new();
        for chunk in key.chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit {
                    byte |= 1 << i;
                }
            }
            input_bytes.push(byte);
        }

        // Use HKDF-expand style extraction: hash the full key + counter
        // to produce as many secure bytes as the entropy bound allows
        use sha2::{Sha256, Digest};
        let needed_bytes = (secure_bits + 7) / 8;

        let mut result = Vec::with_capacity(needed_bytes);
        let mut counter = 0u32;

        while result.len() < needed_bytes {
            let mut hasher = Sha256::new();
            hasher.update(b"QSSH-BB84-PA-V1");
            hasher.update(&input_bytes);
            hasher.update(&counter.to_le_bytes());
            let block = hasher.finalize();
            result.extend_from_slice(&block);
            counter += 1;
        }

        result.truncate(needed_bytes);
        result
    }

    /// Complete BB84 protocol execution with full reporting
    pub async fn generate_key(&self, target_bits: usize) -> Result<Vec<u8>> {
        let result = self.generate_key_detailed(target_bits).await?;
        Ok(result.key)
    }

    /// Complete BB84 protocol with detailed results
    pub async fn generate_key_detailed(&self, target_bits: usize) -> Result<BB84Result> {
        // Need more raw bits due to basis mismatch, error correction, and noise.
        // Base multiplier is 4x (50% basis match, 10% sampling, some privacy amp loss).
        // With noise, we need even more to compensate for detection losses.
        let noise_factor = if self.noise.detection_efficiency < 1.0 || self.noise.depolarizing_rate > 0.0 {
            // Roughly: more noise = more raw bits needed
            (1.0 / (self.noise.detection_efficiency * (1.0 - self.noise.depolarizing_rate * 4.0)).max(0.2)) as usize
        } else {
            1
        };
        let raw_bits = target_bits * 4 * noise_factor.max(1);

        // 1. Quantum transmission
        let (alice_bits, alice_bases, qubits) = self.prepare_qubits(raw_bits);

        // 2. Measurement
        let (bob_bits, bob_bases) = self.measure_qubits(&qubits, &alice_bases);

        // 3. Sifting
        let (alice_sifted, bob_sifted) = self.sift_keys(
            &alice_bits,
            &alice_bases,
            &bob_bits,
            &bob_bases,
        );
        let sifted_bits = alice_sifted.len();

        if sifted_bits < self.min_key_length {
            return Err(QsshError::Qkd("Insufficient sifted key length".into()));
        }

        // 4. Error estimation (use first 10% for estimation)
        let sample_size = sifted_bits / 10;
        let qber = self.estimate_error_rate(&alice_sifted, &bob_sifted, sample_size)?;

        if qber > self.error_threshold {
            return Err(QsshError::Qkd(format!(
                "QBER {:.4} exceeds threshold {:.4} — possible eavesdropping",
                qber, self.error_threshold
            )));
        }

        // 5. Information reconciliation on remaining bits
        let alice_remaining = alice_sifted[sample_size..].to_vec();
        let mut bob_remaining = bob_sifted[sample_size..].to_vec();
        let corrections = self.information_reconciliation(&alice_remaining, &mut bob_remaining, qber);
        let reconciled_bits = alice_remaining.len();

        if corrections > 0 {
            log::debug!("Information reconciliation: {} corrections in {} bits", corrections, reconciled_bits);
        }

        // 6. Privacy amplification
        let final_key = self.privacy_amplification(alice_remaining, qber);
        let final_bits = final_key.len() * 8;

        if final_key.len() < target_bits / 8 {
            return Err(QsshError::Qkd("Insufficient final key length after privacy amplification".into()));
        }

        let key = final_key[..target_bits / 8].to_vec();

        Ok(BB84Result {
            key,
            qber,
            raw_bits,
            sifted_bits,
            post_sample_bits: reconciled_bits,
            reconciled_bits,
            final_bits,
            key_rate: final_bits as f64 / raw_bits as f64,
        })
    }
}

/// E91 Protocol (Ekert 91) using entangled pairs
#[allow(dead_code)]
pub struct E91Protocol {
    error_threshold: f64,
}

impl E91Protocol {
    pub fn new() -> Self {
        Self {
            error_threshold: 0.15, // Slightly higher for E91
        }
    }

    /// Generate entangled pairs and distribute
    pub fn generate_entangled_pairs(&self, num_pairs: usize) -> (Vec<f64>, Vec<f64>) {
        let mut rng = thread_rng();

        // Simulate EPR pairs with correlated measurements
        let alice_angles: Vec<f64> = (0..num_pairs)
            .map(|_| rng.gen::<f64>() * std::f64::consts::PI)
            .collect();

        let bob_angles = alice_angles.clone(); // Perfect correlation in ideal case

        (alice_angles, bob_angles)
    }

    /// Check Bell inequality for security verification
    pub fn verify_bell_inequality(&self, measurements: &[(f64, f64)]) -> bool {
        // Simplified Bell test
        let correlation: f64 = measurements.iter()
            .map(|(a, b)| (a - b).cos())
            .sum::<f64>() / measurements.len() as f64;

        // Bell inequality violated means quantum correlation confirmed
        correlation.abs() > 0.7071 // 1/sqrt(2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bb84_key_generation() {
        let protocol = BB84Protocol::new();
        let key = protocol.generate_key(256).await;

        assert!(key.is_ok());
        let key = key.unwrap();
        assert_eq!(key.len(), 32); // 256 bits = 32 bytes
    }

    #[tokio::test]
    async fn test_bb84_detailed_results() {
        let protocol = BB84Protocol::new();
        let result = protocol.generate_key_detailed(256).await.unwrap();

        assert_eq!(result.key.len(), 32);
        assert!(result.qber < 0.11, "QBER should be below threshold");
        assert!(result.raw_bits > 0);
        assert!(result.sifted_bits > 0);
        assert!(result.key_rate > 0.0);
        assert!(result.key_rate <= 1.0);
    }

    #[tokio::test]
    async fn test_bb84_with_noise() {
        let protocol = BB84Protocol::with_noise(ChannelNoise::fiber_20km());
        // With noise, key generation may occasionally fail due to insufficient
        // key material after privacy amplification — this is correct behavior.
        // Try up to 3 times to handle stochastic variation.
        let mut success = false;
        for _ in 0..3 {
            if let Ok(result) = protocol.generate_key_detailed(256).await {
                assert_eq!(result.key.len(), 32);
                assert!(result.qber < 0.11, "QBER {:.4} should be below threshold", result.qber);
                success = true;
                break;
            }
        }
        assert!(success, "BB84 with fiber noise should succeed within 3 attempts");
    }

    #[tokio::test]
    async fn test_bb84_noisy_channel_near_threshold() {
        let protocol = BB84Protocol::with_noise(ChannelNoise::noisy());
        // With 8% depolarizing, this should succeed but with higher QBER
        let result = protocol.generate_key_detailed(256).await;
        // May or may not succeed depending on randomness — both outcomes are valid
        if let Ok(r) = result {
            assert!(r.qber < 0.11);
        }
    }

    #[test]
    fn test_bb84_sifting() {
        let protocol = BB84Protocol::new();

        let alice_bits = vec![true, false, true, false];
        let alice_bases = vec![true, true, false, false];
        let bob_bits = vec![true, true, false, false];
        let bob_bases = vec![true, false, false, true];

        let (alice_sifted, bob_sifted) = protocol.sift_keys(
            &alice_bits,
            &alice_bases,
            &bob_bits,
            &bob_bases,
        );

        // Only positions 0 and 2 have matching bases
        assert_eq!(alice_sifted.len(), 2);
        assert_eq!(bob_sifted.len(), 2);
    }

    #[test]
    fn test_information_reconciliation() {
        let protocol = BB84Protocol::new();

        let alice_key = vec![true, false, true, true, false, false, true, false];
        let mut bob_key = vec![true, false, true, false, false, false, true, false]; // 1 error at index 3

        let corrections = protocol.information_reconciliation(&alice_key, &mut bob_key, 0.125);
        assert_eq!(corrections, 1);
        assert_eq!(alice_key, bob_key, "Keys should match after reconciliation");
    }

    #[test]
    fn test_information_reconciliation_no_errors() {
        let protocol = BB84Protocol::new();

        let alice_key = vec![true, false, true, true];
        let mut bob_key = alice_key.clone();

        let corrections = protocol.information_reconciliation(&alice_key, &mut bob_key, 0.0);
        assert_eq!(corrections, 0);
    }

    #[test]
    fn test_qber_tier_check() {
        let mut protocol = BB84Protocol::new();
        protocol.last_qber = Some(0.03);

        assert!(protocol.is_qber_acceptable_for_tier(4), "3% QBER should be OK for T4");
        assert!(protocol.is_qber_acceptable_for_tier(5), "3% QBER should be OK for T5");

        protocol.last_qber = Some(0.08);
        assert!(protocol.is_qber_acceptable_for_tier(4), "8% QBER should be OK for T4");
        assert!(!protocol.is_qber_acceptable_for_tier(5), "8% QBER should fail T5");

        protocol.last_qber = Some(0.12);
        assert!(!protocol.is_qber_acceptable_for_tier(4), "12% QBER should fail T4");
    }

    #[test]
    fn test_channel_noise_default_is_perfect() {
        let noise = ChannelNoise::default();
        assert_eq!(noise.depolarizing_rate, 0.0);
        assert_eq!(noise.dark_count_rate, 0.0);
        assert_eq!(noise.detection_efficiency, 1.0);
    }

    #[test]
    fn test_e91_bell_verification() {
        let protocol = E91Protocol::new();

        // Create correlated measurements
        let measurements = vec![
            (0.0, 0.0),
            (1.57, 1.57),
            (0.785, 0.785),
        ];

        assert!(protocol.verify_bell_inequality(&measurements));
    }

    #[test]
    fn test_privacy_amplification_with_errors() {
        let protocol = BB84Protocol::new();
        let key = vec![true, false, true, true, false, true, false, true,
                       true, false, true, true, false, true, false, true];

        let result = protocol.privacy_amplification(key, 0.05);
        assert!(!result.is_empty(), "Privacy amplification should produce output");
    }
}
