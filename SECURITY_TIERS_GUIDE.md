# QSSH Security Tiers Guide

## Quick Selection Guide

```bash
# Automatic tier selection based on available resources
qssh user@server --tier auto

# Explicit tier selection
qssh user@server --tier 2  # Hardened PQ (recommended default)
qssh user@server --tier 4  # Quantum-Secured (requires QKD hardware)
```

## The Six Security Tiers

### Tier 0: Classical (DEPRECATED) ⚠️
**DO NOT USE** - Only for legacy compatibility
```bash
qssh user@server --tier 0 --allow-vulnerable
```
- **Algorithms**: RSA-2048, ECDSA-P256
- **Security**: Broken by quantum computers
- **Performance**: 100% (baseline)
- **Use case**: Legacy systems that can't upgrade

### Tier 1: Post-Quantum 🔒
Basic quantum resistance
```bash
qssh user@server --tier 1
```
- **Algorithms**: Falcon-512, SPHINCS+
- **Security**: 128-bit quantum-resistant
- **Performance**: 95%
- **Weakness**: Traffic analysis possible
- **Use case**: Quick migration from OpenSSH

### Tier 2: Hardened PQ (DEFAULT) 🔒+
Quantum resistance + traffic analysis protection
```bash
qssh user@server --tier 2
```
- **Algorithms**: Falcon-512, SPHINCS+, AES-256-GCM
- **Features**: 768-byte uniform frames, timing obfuscation
- **Security**: 128-bit + traffic analysis resistant
- **Performance**: 85%
- **Use case**: Most security-conscious users

### Tier 3: Entropy-Enhanced 🔒++
Hardened PQ + quantum randomness
```bash
qssh user@server --tier 3 --qrng-endpoint https://qrng.example.com
```
- **Algorithms**: T2 + QRNG for all random numbers
- **Features**: True quantum entropy for keys/nonces
- **Security**: 128-bit + true randomness
- **Performance**: 80%
- **Use case**: High-security environments

### Tier 4: Quantum-Secured 🔒⚛️
Full quantum key distribution
```bash
qssh user@server --tier 4 --qkd-endpoint qkd://alice
```
- **Algorithms**: QKD, Falcon-512, SPHINCS+
- **Features**: Information-theoretic secure keys
- **Security**: Unbreakable key exchange
- **Performance**: 70%
- **Requirements**: QKD hardware
- **Use case**: Critical infrastructure

### Tier 5: Hybrid Quantum 🔒⚛️+
Maximum paranoia mode
```bash
qssh user@server --tier 5 --qkd-endpoint qkd://alice --hybrid
```
- **Algorithms**: QKD + PQC + Classical (all three!)
- **Features**: Belt, suspenders, and duct tape
- **Security**: Maximum available
- **Performance**: 60%
- **Use case**: Nation-state adversaries

## Tier Comparison Matrix

| Tier | Quantum Resistant | Traffic Analysis | True Random | Unbreakable Keys | Performance |
|------|------------------|------------------|-------------|------------------|-------------|
| T0   | ❌ | ❌ | ❌ | ❌ | 100% |
| T1   | ✅ | ❌ | ❌ | ❌ | 95% |
| T2   | ✅ | ✅ | ❌ | ❌ | 85% |
| T3   | ✅ | ✅ | ✅ | ❌ | 80% |
| T4   | ✅ | ✅ | ✅ | ✅ | 70% |
| T5   | ✅ | ✅ | ✅ | ✅ | 60% |

## Migration Path

### From OpenSSH
```bash
# Step 1: Test with Tier 1 (minimal changes)
qssh --tier 1 user@server

# Step 2: Move to Tier 2 (recommended)
qssh --tier 2 user@server

# Step 3: Add quantum entropy if available
qssh --tier 3 --qrng-endpoint $QRNG_URL user@server
```

### From QSSH v1
```bash
# Old v1 config
qssh --pq-algo falcon --use-qkd user@server

# New v2 with tiers
qssh --tier 4 user@server  # Automatically uses QKD if configured
```

## Environment Configuration

```bash
# Set default tier
export QSSH_DEFAULT_TIER=2

# Auto-detect best available tier
export QSSH_TIER=auto

# Configure quantum resources
export QSSH_QRNG_ENDPOINT=https://qrng.example.com
export QSSH_QKD_ENDPOINT=qkd://alice.quantum.net
```

## Performance Tuning

### For Speed (Less Security)
```bash
qssh --tier 1 --cipher aes128-gcm --no-compression user@server
```

### For Security (Less Speed)
```bash
qssh --tier 4 --cipher aes256-gcm --compression zstd user@server
```

### For Balance
```bash
qssh --tier 2 user@server  # The default
```

## Common Scenarios

### Corporate Network
```bash
# Tier 2: Good balance of security and performance
qssh --tier 2 admin@internal-server
```

### Public WiFi
```bash
# Tier 2 minimum, Tier 3 if QRNG available
qssh --tier 3 --qrng-endpoint https://qrng.company.com user@server
```

### Government/Military
```bash
# Tier 4 or 5 with quantum hardware
qssh --tier 5 --qkd-endpoint qkd://secure.gov user@classified-system
```

### IoT/Embedded
```bash
# Tier 1 for resource-constrained devices
qssh --tier 1 --lightweight pi@raspberry
```

## Troubleshooting

### "QKD endpoint not available"
- Tier 4/5 require quantum hardware
- Fall back to Tier 3 with QRNG
- Or use Tier 2 for software-only security

### "Performance too slow"
- Drop from Tier 2 to Tier 1
- Disable compression
- Use smaller key sizes (--pq-algo falcon512)

### "Not quantum-safe enough"
- Upgrade from Tier 1 to Tier 2 minimum
- Add QRNG for Tier 3
- Invest in QKD hardware for Tier 4/5

## Future Tiers (Research)

### Tier 6: Lattice-Homomorphic (Planned)
- Compute on encrypted data
- Zero-knowledge proofs
- Homomorphic encryption

### Tier 7: Quantum-Native (Theoretical)
- Direct qubit transmission
- Quantum teleportation
- Requires quantum internet