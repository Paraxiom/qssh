//! Security tier system for QSSH
//!
//! Provides clear, progressive security levels based on threat model

use serde::{Deserialize, Serialize};
use std::fmt;

/// Security tiers for different threat models
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityTier {
    /// Tier 0: Classical (NOT RECOMMENDED)
    /// - RSA/ECDSA (for compatibility only)
    /// - Vulnerable to quantum computers
    /// - Use only for legacy systems
    #[deprecated(note = "Vulnerable to quantum attacks")]
    Classical,

    /// Tier 1: Post-Quantum Crypto
    /// - Falcon-512 + SPHINCS+ algorithms
    /// - Quantum-resistant mathematics
    /// - Variable packet sizes (some traffic analysis possible)
    /// - Good for: Quick migration from classical SSH
    PostQuantum,

    /// Tier 2: Hardened Post-Quantum
    /// - PQC + uniform 768-byte frames
    /// - Traffic analysis resistance
    /// - Timing obfuscation
    /// - Good for: Most security-conscious users
    HardenedPQ,

    /// Tier 3: Entropy-Enhanced
    /// - Hardened PQ + quantum entropy (QRNG)
    /// - True random numbers from quantum sources
    /// - Stronger nonces and key generation
    /// - Good for: High-security environments
    EntropyEnhanced,

    /// Tier 4: Quantum-Secured
    /// - All above + QKD key distribution
    /// - Information-theoretic security for keys
    /// - Requires quantum hardware
    /// - Good for: Critical infrastructure
    QuantumSecured,

    /// Tier 5: Hybrid Quantum
    /// - QKD + PQC + classical (defense in depth)
    /// - Multiple algorithm families
    /// - Future-proof against all attacks
    /// - Good for: Nation-state level threats
    HybridQuantum,
}

impl SecurityTier {
    /// Get recommended tier based on available resources
    pub fn detect_available() -> Self {
        // Check what's available in order of preference
        if std::env::var("QSSH_QKD_ENDPOINT").is_ok() {
            SecurityTier::QuantumSecured
        } else if std::env::var("QSSH_QRNG_ENDPOINT").is_ok() {
            SecurityTier::EntropyEnhanced
        } else {
            SecurityTier::HardenedPQ // Safe default
        }
    }

    /// Check if this tier requires quantum hardware
    pub fn requires_quantum_hardware(&self) -> bool {
        matches!(self, SecurityTier::QuantumSecured | SecurityTier::HybridQuantum)
    }

    /// Check if this tier requires QRNG
    pub fn requires_qrng(&self) -> bool {
        matches!(self,
            SecurityTier::EntropyEnhanced |
            SecurityTier::QuantumSecured |
            SecurityTier::HybridQuantum
        )
    }

    /// Get frame size for this tier
    pub fn frame_size(&self) -> Option<usize> {
        match self {
            SecurityTier::Classical | SecurityTier::PostQuantum => None, // Variable
            _ => Some(768), // Fixed frames for T2+
        }
    }

    /// Get algorithms for this tier
    pub fn algorithms(&self) -> Vec<&'static str> {
        match self {
            SecurityTier::Classical => vec!["RSA-2048", "ECDSA-P256"],
            SecurityTier::PostQuantum => vec!["Falcon-512", "SPHINCS+"],
            SecurityTier::HardenedPQ => vec!["Falcon-512", "SPHINCS+", "AES-256-GCM"],
            SecurityTier::EntropyEnhanced => vec!["Falcon-512", "SPHINCS+", "AES-256-GCM", "QRNG"],
            SecurityTier::QuantumSecured => vec!["QKD", "Falcon-512", "SPHINCS+", "AES-256-GCM"],
            SecurityTier::HybridQuantum => vec!["QKD", "Falcon-512", "SPHINCS+", "RSA-3072", "AES-256-GCM"],
        }
    }

    /// Estimate performance impact
    pub fn performance_factor(&self) -> f32 {
        match self {
            SecurityTier::Classical => 1.0,      // Baseline
            SecurityTier::PostQuantum => 0.95,   // 5% slower
            SecurityTier::HardenedPQ => 0.85,     // 15% slower (framing)
            SecurityTier::EntropyEnhanced => 0.80, // 20% slower (QRNG)
            SecurityTier::QuantumSecured => 0.70,  // 30% slower (QKD)
            SecurityTier::HybridQuantum => 0.60,   // 40% slower (everything)
        }
    }

    /// Get security level (bits of security)
    pub fn security_bits(&self) -> &'static str {
        match self {
            SecurityTier::Classical => "112 bits (breakable by quantum)",
            SecurityTier::PostQuantum => "128 bits (quantum-resistant)",
            SecurityTier::HardenedPQ => "128 bits + traffic analysis resistance",
            SecurityTier::EntropyEnhanced => "128 bits + true randomness",
            SecurityTier::QuantumSecured => "Information-theoretic (unbreakable keys)",
            SecurityTier::HybridQuantum => "Maximum available (belt & suspenders)",
        }
    }
}

impl fmt::Display for SecurityTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityTier::Classical => write!(f, "T0: Classical (DEPRECATED)"),
            SecurityTier::PostQuantum => write!(f, "T1: Post-Quantum"),
            SecurityTier::HardenedPQ => write!(f, "T2: Hardened PQ"),
            SecurityTier::EntropyEnhanced => write!(f, "T3: Entropy-Enhanced"),
            SecurityTier::QuantumSecured => write!(f, "T4: Quantum-Secured"),
            SecurityTier::HybridQuantum => write!(f, "T5: Hybrid Quantum"),
        }
    }
}

impl Default for SecurityTier {
    fn default() -> Self {
        SecurityTier::HardenedPQ // Safe, practical default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_ordering() {
        assert!(SecurityTier::Classical < SecurityTier::PostQuantum);
        assert!(SecurityTier::PostQuantum < SecurityTier::HardenedPQ);
        assert!(SecurityTier::HardenedPQ < SecurityTier::EntropyEnhanced);
        assert!(SecurityTier::EntropyEnhanced < SecurityTier::QuantumSecured);
        assert!(SecurityTier::QuantumSecured < SecurityTier::HybridQuantum);
    }

    #[test]
    fn test_frame_sizes() {
        assert_eq!(SecurityTier::Classical.frame_size(), None);
        assert_eq!(SecurityTier::PostQuantum.frame_size(), None);
        assert_eq!(SecurityTier::HardenedPQ.frame_size(), Some(768));
        assert_eq!(SecurityTier::EntropyEnhanced.frame_size(), Some(768));
    }

    #[test]
    fn test_performance_impact() {
        assert!(SecurityTier::Classical.performance_factor() >
                SecurityTier::HybridQuantum.performance_factor());
    }
}