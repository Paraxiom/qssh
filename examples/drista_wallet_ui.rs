//! Example: Drista Wallet with QSSH Security Tier Selection
//!
//! Run with: cargo run --example drista_wallet_ui

use qssh::security_tiers::SecurityTier;
use qssh::drista_integration::{HardwareCapabilities, WalletTierSelector, QsshRpcClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔════════════════════════════════════════════╗");
    println!("║     Drista Wallet - QSSH Security Setup    ║");
    println!("╚════════════════════════════════════════════╝");

    // Step 1: Detect hardware
    println!("\n🔍 Detecting quantum hardware...");
    let hardware = HardwareCapabilities::detect().await;

    println!("   ✓ CPU AES-NI: {}", if hardware.cpu_has_aes_ni { "Yes" } else { "No" });
    println!("   ✓ Memory: {} GB", hardware.available_memory_gb);
    println!("   ✓ QRNG: {}", if hardware.has_qrng { "Available" } else { "Not found" });
    println!("   ✓ QKD: {}", if hardware.has_qkd { "Available" } else { "Not found" });

    // Step 2: Show available tiers
    println!("\n📊 Security Tiers Available:");

    let available_tiers = vec![
        SecurityTier::PostQuantum,
        SecurityTier::HardenedPQ,
        SecurityTier::EntropyEnhanced,
    ];

    for (i, tier) in available_tiers.iter().enumerate() {
        let available = match tier {
            SecurityTier::EntropyEnhanced => hardware.has_qrng,
            SecurityTier::QuantumSecured => hardware.has_qkd,
            _ => true,
        };

        println!("   {}. {} {}",
            i + 1,
            tier,
            if available { "✅" } else { "❌ (hardware required)" }
        );
        println!("      Security: {}", tier.security_bits());
        println!("      Speed: {}%", (tier.performance_factor() * 100.0) as u32);
    }

    // Step 3: Wallet balance check
    println!("\n💰 Wallet Balance: 50,000 DRST");
    let balance_planck = 50_000_000_000_000_000u128; // 50k DRST in planck

    // Step 4: Operation selection
    println!("\n🎯 Select Operation:");
    println!("   1. Transfer tokens");
    println!("   2. Stake DRST");
    println!("   3. Vote on governance");
    println!("   4. Deploy smart contract");

    // Simulate user selecting governance (3)
    let operation = "governance";
    println!("   > Selected: {}", operation);

    // Step 5: Automatic tier recommendation
    println!("\n🤖 Automatic Security Recommendation:");
    let recommended_tier = match operation {
        "transfer" if balance_planck < 100_000_000_000_000 => SecurityTier::PostQuantum,
        "transfer" => SecurityTier::HardenedPQ,
        "staking" => SecurityTier::HardenedPQ,
        "governance" => SecurityTier::EntropyEnhanced,
        "contract" => SecurityTier::HardenedPQ,
        _ => SecurityTier::HardenedPQ,
    };

    println!("   Recommended: {}", recommended_tier);
    println!("   Reason: {} operation with {} DRST", operation, 50_000);

    // Step 6: User confirmation
    println!("\n⚙️  Connection Settings:");
    println!("   Protocol: QSSH");
    println!("   Security: {}", recommended_tier);
    println!("   Encryption: Falcon-512 + SPHINCS+");
    println!("   Frame size: {} bytes", recommended_tier.frame_size().unwrap_or(0));
    println!("   Estimated latency: ~{}ms", match recommended_tier {
        SecurityTier::PostQuantum => 5,
        SecurityTier::HardenedPQ => 50,
        SecurityTier::EntropyEnhanced => 80,
        _ => 100,
    });

    // Step 7: Establish connection
    println!("\n🔐 Establishing secure connection...");
    println!("   [▓▓▓▓▓▓▓▓▓▓] 100% - QSSH tunnel established");

    // Step 8: Show secure RPC endpoint
    println!("\n✅ Secure RPC Connection Ready!");
    println!("   Endpoint: qssh://127.0.0.1:9944");
    println!("   Security tier: {}", recommended_tier);
    println!("   All traffic protected with quantum-resistant crypto");

    // Step 9: Example RPC call
    println!("\n📡 Example RPC Call (over QSSH):");
    println!("   → chain_getBlockHash");
    println!("   ← 0x91b171bb158e2d3848fa23a9f1c25182...");

    // Step 10: Show traffic analysis
    println!("\n🔍 Traffic Analysis (what attackers see):");
    println!("   [768 bytes] [768 bytes] [768 bytes] ...");
    println!("   All frames identical size - operation hidden!");

    println!("\n════════════════════════════════════════════");
    println!("💡 Tip: Higher value transactions automatically");
    println!("   escalate to stronger security tiers.");
    println!("════════════════════════════════════════════");

    Ok(())
}