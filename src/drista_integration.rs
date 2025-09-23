//! QSSH integration for Drista blockchain RPC
//!
//! Allows wallets to connect to Drista nodes with quantum-resistant security

use crate::security_tiers::SecurityTier;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Drista-specific security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DristaQsshConfig {
    /// Security tier based on wallet balance
    pub tier: SecurityTier,

    /// Node endpoint (can be localhost or remote)
    pub node_endpoint: String,

    /// Hardware capabilities detected
    pub hardware: HardwareCapabilities,

    /// Automatic tier escalation based on transaction value
    pub auto_escalate: bool,
}

/// Hardware detection for quantum devices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCapabilities {
    pub has_qrng: bool,
    pub has_qkd: bool,
    pub qrng_endpoint: Option<String>,
    pub qkd_endpoint: Option<String>,
    pub cpu_has_aes_ni: bool,
    pub available_memory_gb: u32,
}

impl HardwareCapabilities {
    /// Detect available quantum hardware
    pub async fn detect() -> Self {
        // Check for QRNG
        let has_qrng = std::env::var("QSSH_QRNG_ENDPOINT").is_ok() ||
                       std::path::Path::new("/dev/qrng").exists() ||
                       std::path::Path::new("/dev/hwrng").exists();

        // Check for QKD
        let has_qkd = std::env::var("QSSH_QKD_ENDPOINT").is_ok() ||
                      std::path::Path::new("/opt/qkd/client").exists();

        // Check CPU features
        #[cfg(target_arch = "x86_64")]
        let cpu_has_aes_ni = std::is_x86_feature_detected!("aes");
        #[cfg(not(target_arch = "x86_64"))]
        let cpu_has_aes_ni = false;

        // Get available memory
        let available_memory_gb = sys_info::mem_info()
            .map(|m| (m.avail / 1024 / 1024) as u32)
            .unwrap_or(1);

        Self {
            has_qrng,
            has_qkd,
            qrng_endpoint: std::env::var("QSSH_QRNG_ENDPOINT").ok(),
            qkd_endpoint: std::env::var("QSSH_QKD_ENDPOINT").ok(),
            cpu_has_aes_ni,
            available_memory_gb,
        }
    }

    /// Recommend best tier based on hardware
    pub fn recommended_tier(&self) -> SecurityTier {
        if self.has_qkd {
            SecurityTier::QuantumSecured
        } else if self.has_qrng {
            SecurityTier::EntropyEnhanced
        } else {
            SecurityTier::HardenedPQ
        }
    }
}

/// Wallet-based security tier selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSecurityPolicy {
    /// Thresholds for automatic tier selection (in smallest unit)
    pub tier_thresholds: TierThresholds,

    /// Override for specific operations
    pub operation_overrides: OperationOverrides,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierThresholds {
    pub tier1_max: u128,  // < $100 worth
    pub tier2_max: u128,  // < $10,000 worth
    pub tier3_max: u128,  // < $1,000,000 worth
    // Above tier3_max uses highest available tier
}

impl Default for TierThresholds {
    fn default() -> Self {
        Self {
            tier1_max: 100_000_000_000_000,      // ~$100 in planck
            tier2_max: 10_000_000_000_000_000,   // ~$10k in planck
            tier3_max: 1_000_000_000_000_000_000, // ~$1M in planck
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationOverrides {
    pub staking: SecurityTier,
    pub governance: SecurityTier,
    pub transfer: SecurityTier,
    pub contract_call: SecurityTier,
}

impl Default for OperationOverrides {
    fn default() -> Self {
        Self {
            staking: SecurityTier::HardenedPQ,      // T2: Important but not critical
            governance: SecurityTier::EntropyEnhanced, // T3: High importance
            transfer: SecurityTier::PostQuantum,      // T1: Speed matters
            contract_call: SecurityTier::HardenedPQ,  // T2: Balance
        }
    }
}

/// QSSH-wrapped JSON-RPC for Drista
pub struct QsshRpcClient {
    config: DristaQsshConfig,
    inner_client: jsonrpsee::http_client::HttpClient,
}

impl QsshRpcClient {
    /// Create new QSSH-secured RPC client
    pub async fn new(wallet_balance: u128, operation: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Detect hardware
        let hardware = HardwareCapabilities::detect().await;

        // Determine security tier based on balance and operation
        let tier = Self::select_tier(wallet_balance, operation, &hardware);

        println!("🔐 QSSH RPC Security: {} for {} operation", tier, operation);
        println!("   Balance: {} planck", wallet_balance);
        println!("   Hardware: QRNG={}, QKD={}", hardware.has_qrng, hardware.has_qkd);

        // Build QSSH tunnel based on tier
        let tunnel_endpoint = Self::establish_tunnel(tier, &hardware).await?;

        // Create JSON-RPC client over QSSH tunnel
        let inner_client = jsonrpsee::http_client::HttpClientBuilder::default()
            .build(&tunnel_endpoint)?;

        Ok(Self {
            config: DristaQsshConfig {
                tier,
                node_endpoint: tunnel_endpoint,
                hardware,
                auto_escalate: true,
            },
            inner_client,
        })
    }

    /// Select appropriate tier based on context
    fn select_tier(balance: u128, operation: &str, hardware: &HardwareCapabilities) -> SecurityTier {
        let thresholds = TierThresholds::default();
        let overrides = OperationOverrides::default();

        // Check operation-specific overrides first
        let operation_tier = match operation {
            "staking" => overrides.staking,
            "governance" => overrides.governance,
            "transfer" => overrides.transfer,
            "contract" => overrides.contract_call,
            _ => SecurityTier::PostQuantum,
        };

        // Balance-based tier
        let balance_tier = if balance < thresholds.tier1_max {
            SecurityTier::PostQuantum
        } else if balance < thresholds.tier2_max {
            SecurityTier::HardenedPQ
        } else if balance < thresholds.tier3_max {
            SecurityTier::EntropyEnhanced
        } else {
            hardware.recommended_tier()
        };

        // Use the higher of the two
        std::cmp::max(operation_tier, balance_tier)
    }

    /// Establish QSSH tunnel with selected tier
    async fn establish_tunnel(tier: SecurityTier, hardware: &HardwareCapabilities) -> Result<String, Box<dyn std::error::Error>> {
        let mut qssh_cmd = std::process::Command::new("qssh");

        // Base arguments
        qssh_cmd.arg("-N")  // No command, just tunnel
                .arg("-L").arg("9944:localhost:9944")  // Forward RPC port
                .arg("--tier").arg(format!("{}", tier as u8));

        // Add hardware-specific options
        if tier.requires_qrng() && hardware.has_qrng {
            if let Some(qrng) = &hardware.qrng_endpoint {
                qssh_cmd.arg("--qrng-endpoint").arg(qrng);
            }
        }

        if tier.requires_quantum_hardware() && hardware.has_qkd {
            if let Some(qkd) = &hardware.qkd_endpoint {
                qssh_cmd.arg("--qkd-endpoint").arg(qkd);
            }
        }

        // Add node endpoint
        qssh_cmd.arg("drista@node.example.com");

        // Start tunnel in background
        let _tunnel = qssh_cmd.spawn()?;

        // Wait for tunnel to establish
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Return local endpoint (tunneled through QSSH)
        Ok("http://127.0.0.1:9944".to_string())
    }
}

/// Substrate extrinsic for configuring QSSH
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QsshConfigExtrinsic {
    /// Account requesting the configuration
    pub account: String,

    /// Requested security tier
    pub tier: SecurityTier,

    /// Hardware proof (optional)
    pub hardware_attestation: Option<Vec<u8>>,
}

impl QsshConfigExtrinsic {
    /// Create pallet call for QSSH config
    pub fn create_call(&self) -> Vec<u8> {
        // This would encode as a Substrate extrinsic
        // pallet_qssh::Call::configure_security {
        //     tier: self.tier as u8,
        //     attestation: self.hardware_attestation.clone(),
        // }
        vec![
            0x1e, 0x00,  // Pallet index, call index
            self.tier as u8,  // Tier selection
            // ... encoded attestation
        ]
    }
}

/// Wallet UI component for tier selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTierSelector {
    pub current_tier: SecurityTier,
    pub available_tiers: Vec<SecurityTier>,
    pub hardware: HardwareCapabilities,
    pub estimated_cost: TierCosts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierCosts {
    pub performance_impact: f32,  // 0.0 - 1.0
    pub latency_ms: u32,
    pub throughput_mbps: f32,
}

impl WalletTierSelector {
    /// Get UI display for wallet
    pub fn display_options(&self) -> Vec<String> {
        self.available_tiers.iter().map(|tier| {
            format!(
                "{}: {} ({}% speed)",
                tier,
                tier.security_bits(),
                (tier.performance_factor() * 100.0) as u32
            )
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hardware_detection() {
        let hw = HardwareCapabilities::detect().await;
        println!("Detected hardware: {:?}", hw);
        assert!(hw.available_memory_gb > 0);
    }

    #[test]
    fn test_tier_selection() {
        let hw = HardwareCapabilities {
            has_qrng: true,
            has_qkd: false,
            qrng_endpoint: Some("https://qrng.test".into()),
            qkd_endpoint: None,
            cpu_has_aes_ni: true,
            available_memory_gb: 8,
        };

        // Small balance = Tier 1
        let tier = QsshRpcClient::select_tier(1000, "transfer", &hw);
        assert_eq!(tier, SecurityTier::PostQuantum);

        // Large balance = Higher tier
        let tier = QsshRpcClient::select_tier(10_000_000_000_000_000_000, "transfer", &hw);
        assert_eq!(tier, SecurityTier::EntropyEnhanced);

        // Governance always gets higher security
        let tier = QsshRpcClient::select_tier(1000, "governance", &hw);
        assert_eq!(tier, SecurityTier::EntropyEnhanced);
    }
}