//! BB84 Quantum Key Distribution Protocol Implementation
//!
//! This module implements the BB84 protocol for quantum key distribution.
//! While we cannot have actual quantum channels in software, this provides
//! a realistic simulation of the protocol for development and testing.

use crate::{Result, QsshError};
use rand::{thread_rng, Rng, RngCore};
use std::collections::HashMap;

/// BB84 Protocol Implementation
pub struct BB84Protocol {
    /// Error rate threshold for aborting (typically 11% for BB84)
    error_threshold: f64,
    /// Minimum key length required
    min_key_length: usize,
}

impl BB84Protocol {
    pub fn new() -> Self {
        Self {
            error_threshold: 0.11,
            min_key_length: 256, // 256 bits minimum
        }
    }

    /// Simulate quantum bit transmission with basis
    pub fn prepare_qubits(&self, num_bits: usize) -> (Vec<bool>, Vec<bool>, Vec<bool>) {
        let mut rng = thread_rng();

        // Alice's random bits
        let alice_bits: Vec<bool> = (0..num_bits).map(|_| rng.gen()).collect();

        // Alice's random bases (0 = rectilinear, 1 = diagonal)
        let alice_bases: Vec<bool> = (0..num_bits).map(|_| rng.gen()).collect();

        // Encoded qubits (in reality would be quantum states)
        let qubits = alice_bits.clone();

        (alice_bits, alice_bases, qubits)
    }

    /// Bob measures qubits with random bases
    pub fn measure_qubits(
        &self,
        qubits: &[bool],
        alice_bases: &[bool],
    ) -> (Vec<bool>, Vec<bool>) {
        let mut rng = thread_rng();

        // Bob's random measurement bases
        let bob_bases: Vec<bool> = (0..qubits.len()).map(|_| rng.gen()).collect();

        // Bob's measurement results
        let mut bob_bits = Vec::new();
        for i in 0..qubits.len() {
            if alice_bases[i] == bob_bases[i] {
                // Same basis - Bob gets correct bit
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

    /// Privacy amplification: Reduce key to remove information leakage
    pub fn privacy_amplification(
        &self,
        key: Vec<bool>,
        error_rate: f64,
    ) -> Vec<u8> {
        // Calculate how much to reduce based on error rate
        let reduction_factor = 1.0 - error_rate * 2.0;
        let final_length = ((key.len() as f64) * reduction_factor) as usize;

        // Convert to bytes
        let mut result = Vec::new();
        for chunk in key[..final_length].chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit {
                    byte |= 1 << i;
                }
            }
            result.push(byte);
        }

        result
    }

    /// Complete BB84 protocol execution
    pub async fn generate_key(&self, target_bits: usize) -> Result<Vec<u8>> {
        // Need more raw bits due to basis mismatch and error correction
        let raw_bits = target_bits * 4;

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

        if alice_sifted.len() < self.min_key_length {
            return Err(QsshError::Qkd("Insufficient sifted key length".into()));
        }

        // 4. Error estimation (use first 10% for estimation)
        let sample_size = alice_sifted.len() / 10;
        let error_rate = self.estimate_error_rate(&alice_sifted, &bob_sifted, sample_size)?;

        if error_rate > self.error_threshold {
            return Err(QsshError::Qkd(format!(
                "Error rate {} exceeds threshold {}",
                error_rate, self.error_threshold
            )));
        }

        // 5. Privacy amplification
        let final_key = self.privacy_amplification(
            alice_sifted[sample_size..].to_vec(),
            error_rate,
        );

        if final_key.len() < target_bits / 8 {
            return Err(QsshError::Qkd("Insufficient final key length".into()));
        }

        Ok(final_key[..target_bits / 8].to_vec())
    }
}

/// E91 Protocol (Ekert 91) using entangled pairs
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
}