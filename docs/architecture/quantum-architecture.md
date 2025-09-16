# QSSH Quantum Architecture

## Overview

QSSH (Quantum Secure Shell) is designed to integrate seamlessly with QuantumHarmony's cryptographic infrastructure, providing quantum-resistant secure remote access with forward secrecy and one-time signature capabilities.

## Cryptographic Components

### 1. Post-Quantum Key Exchange
- **Algorithm**: Falcon-512 (NIST selected)
- **Purpose**: Quantum-resistant key agreement
- **Integration**: Direct support for QuantumHarmony's validator keys

### 2. Post-Quantum Signatures
- **Primary**: SPHINCS+ (hash-based, quantum-resistant)
- **Secondary**: Lamport OTS (one-time signatures for critical operations)
- **Use Cases**: 
  - Authentication
  - Command authorization
  - Validator attestations

### 3. Double Ratchet (Forward Secrecy)
- **Implementation**: Signal-inspired, SHA3-based
- **Benefits**:
  - Keys evolve with every message
  - Past messages remain secure even if current key compromised
  - Aligns with QuantumHarmony's forward-secure blockchain design

### 4. Quantum Vault
- **Purpose**: Secure key storage and management
- **Features**:
  - Hardware-backed when available (TPM 2.0)
  - One-time key enforcement
  - Ratchet state management
  - Lamport chain pre-generation

## QKD Integration

QSSH integrates with Quantum Key Distribution in multiple ways:

### Direct QKD
```rust
// When QKD hardware is available
let qkd_key = qkd_client.get_key("qssh-session-123").await?;
vault.store_key("session-root", &qkd_key, KeyType::QkdMaster, 1).await?;
```

### KIRQ Hub Integration
- Aggregates entropy from multiple quantum sources
- Provides high-quality randomness when direct QKD unavailable
- Used for:
  - Nonce generation
  - Key derivation seeds
  - Lamport keypair generation

### Crypto4A HSM
- Hardware security module with quantum RNG
- Provides root key protection
- Future: Could store post-quantum keys directly

## QuantumHarmony Integration Points

### 1. Validator Access
```rust
// Validators use QSSH with enhanced security
let validator_config = QsshConfig {
    pq_algorithm: PqAlgorithm::Falcon512,
    use_qkd: true, // Validators should have QKD access
    key_rotation_interval: 60, // Frequent rotation for validators
};
```

### 2. Consensus Operations
- Lamport signatures for block attestations
- Ratcheted keys for p2p communication
- QKD-derived randomness for VRF

### 3. Key Management
```rust
// Store validator keys in quantum vault
vault.store_key(
    "validator-signing-key",
    &falcon_private_key,
    KeyType::FalconPrivate,
    0, // Unlimited use for normal operations
).await?;

// One-time keys for critical consensus messages
vault.init_lamport_chain(
    "consensus-attestations",
    &qkd_seed,
    1000, // Pre-generate 1000 signatures
).await?;
```

## Security Properties

### Information-Theoretic Security
When QKD is available:
- Keys have true quantum randomness
- Eavesdropping is detectable
- Combined with computational security of Falcon/SPHINCS+

### Forward Secrecy
- Double ratchet ensures key evolution
- Compromise of current state doesn't affect past
- Critical for long-running validator connections

### Post-Quantum Resistance
- All algorithms resistant to known quantum attacks
- Falcon-512: Lattice-based
- SPHINCS+: Hash-based
- Lamport: Hash-based OTS

## Deployment Scenarios

### 1. Full Quantum (Ideal)
- Direct QKD link between nodes
- Hardware-backed vault (HSM/TPM)
- All features enabled

### 2. Hybrid Quantum
- KIRQ Hub for quantum entropy
- Software vault with TPM root
- QKD opportunistic

### 3. Post-Quantum Only
- No QKD available
- Pure algorithmic security
- Still quantum-resistant

## Performance Considerations

### Key Generation
- Falcon-512: ~1ms
- SPHINCS+: ~10ms
- Lamport chain (1000 keys): ~50ms

### Signature Operations
- Falcon sign: <1ms
- SPHINCS+ sign: ~5ms
- Lamport sign: <0.1ms (pre-generated)

### Ratchet Operations
- Next key: <0.1ms
- DH ratchet: ~1ms

## Future Enhancements

### 1. Hardware Acceleration
- FPGA/ASIC for Falcon operations
- Hardware ratchet engine
- Dedicated Lamport generator

### 2. Distributed Vault
- Multi-party computation for keys
- Threshold signatures
- Blockchain-backed audit trail

### 3. Quantum Network Integration
- Direct quantum channel setup
- Entanglement-based authentication
- Quantum teleportation protocols

## Conclusion

QSSH provides a quantum-secure replacement for SSH that aligns with QuantumHarmony's vision of a fully quantum-resistant blockchain ecosystem. By combining post-quantum algorithms, forward-secure ratcheting, and QKD integration, QSSH ensures that remote access remains secure even in the presence of large-scale quantum computers.