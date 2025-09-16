# Defense in Depth: Multi-Layer Post-Quantum Security

## Overview

This document describes how QSSH participates in a defense-in-depth strategy alongside other post-quantum security solutions, particularly PQConnect.

## Threat Model Evolution

### Current Threats (2024-2025)
- **Harvest Now, Decrypt Later**: Adversaries recording encrypted traffic
- **Quantum Timeline**: 5-10 years until cryptographically relevant quantum computers
- **Hybrid Attacks**: Classical + quantum algorithm combinations

### Defense Strategy
Multiple independent layers of post-quantum protection, each addressing different attack vectors.

## Security Layer Architecture

```
┌──────────────────────────────────────────────────────┐
│                   User Space                         │
│  Applications unaware of quantum threats             │
└────────────────┬─────────────────────────────────────┘
                 │
        ┌────────▼────────┐
        │   QSSH Layer    │ ← Application-specific PQ
        │  (Port 42)      │   QKD integration
        │  Falcon-512     │   Hardware tokens
        │  SPHINCS+       │   Explicit control
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │ PQConnect Layer │ ← Network-wide PQ
        │  (Transparent)   │   Automatic protection
        │  DNS Discovery   │   No configuration
        │  All protocols   │   Legacy support
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │  TCP/IP Stack   │
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │ Network Driver  │
        └─────────────────┘
```

## Layer Independence

### Cryptographic Independence
Each layer uses independent:
- Key generation
- Random number sources
- Algorithm implementations
- Session management

This ensures compromise of one layer doesn't affect others.

### Failure Isolation
- If PQConnect fails: QSSH continues working
- If QSSH unavailable: PQConnect protects other protocols
- If QKD exhausted: Both layers fall back to QRNG/system entropy

## Combined Security Properties

### When Both Layers Active

| Property | QSSH Alone | PQConnect Alone | Both Active |
|----------|------------|-----------------|-------------|
| **SSH Protection** | ✓ Full | ✓ Basic | ✓✓ Double |
| **Other Protocols** | ✗ | ✓ | ✓ |
| **QKD Integration** | ✓ | ✗ | ✓ |
| **Legacy Apps** | ✗ | ✓ | ✓ |
| **Explicit Control** | ✓ | ✗ | ✓ |
| **Automatic Protection** | ✗ | ✓ | ✓ |

### Attack Resistance

To break the combined system, an attacker must:
1. Break Falcon-512 at QSSH layer
2. AND break independent Falcon-512 at PQConnect layer
3. AND correlate sessions across layers
4. AND defeat timing/replay protections

Probability: P(break) = P(QSSH) × P(PQConnect) × P(correlation)

## Performance Considerations

### Overhead Analysis
```
Single Layer (QSSH only):
- Handshake: ~3.2ms
- Per-packet: ~0.1ms
- Memory: ~10MB

Double Layer (QSSH + PQConnect):
- Handshake: ~6.4ms (not 2x due to parallelism)
- Per-packet: ~0.15ms (optimized path)
- Memory: ~25MB (shared libraries)
```

### Optimization Strategies
1. **Crypto Bypass**: Detect redundant operations
2. **Key Caching**: Share ephemeral keys where safe
3. **Parallel Processing**: Overlapping handshakes
4. **Hardware Acceleration**: Shared AES-NI usage

## Deployment Scenarios

### Scenario 1: High-Security Environment
```
Configuration:
- QSSH: SPHINCS+ signatures, require QKD
- PQConnect: Maximum key size, strict peer verification
- PQ-QKD-Proxy: Audit all key requests

Use Case: Government, Financial, Healthcare
```

### Scenario 2: Performance-Sensitive
```
Configuration:
- QSSH: Falcon-512 only, optional QKD
- PQConnect: Standard settings
- Selective bypass for trusted local networks

Use Case: Data centers, CDNs
```

### Scenario 3: Gradual Migration
```
Phase 1: Deploy PQConnect (transparent, no changes)
Phase 2: Migrate SSH to QSSH (better features)
Phase 3: Add QKD when available
Phase 4: Application-specific PQ as needed

Use Case: Enterprises, Universities
```

## Integration with Quantum Networks

### QKD Key Distribution
```
   QKD Network
       │
       ▼
[PQ-QKD-Proxy]  ← Protected by PQ crypto
       │
   ┌───┴───┐
   │       │
[QSSH]  [Future PQConnect QKD support]
```

### QRNG Entropy Sharing
```
   QRNG Device
       │
   ┌───┴───┐
   │       │
[QSSH]  [System Entropy Pool]
           │
      [PQConnect]
```

## Security Monitoring

### Metrics to Track
1. **Layer Activity**
   - QSSH connections/sec
   - PQConnect tunnels active
   - QKD key consumption rate

2. **Attack Indicators**
   - Algorithm downgrade attempts
   - Timing anomalies between layers
   - Correlation attacks

3. **Performance**
   - Handshake latency per layer
   - Crypto operation throughput
   - Memory usage

### Audit Integration
```json
{
  "timestamp": "2025-01-10T14:30:00Z",
  "event": "connection_established",
  "layers": {
    "qssh": {
      "algorithm": "falcon-512",
      "qkd_used": true,
      "key_id": "alice-bob-2025-001"
    },
    "pqconnect": {
      "tunnel_id": "tun-42",
      "peer_verified": true
    }
  },
  "security_score": 0.95
}
```

## Future Considerations

### Emerging Threats
1. **Quantum attacks on lattices**: Both layers should upgrade together
2. **Side-channel attacks**: Independent implementations provide resilience
3. **AI-assisted cryptanalysis**: Diversity in algorithms helps

### Protocol Evolution
- QSSH: Adding new PQ algorithms via provider interface
- PQConnect: IETF standardization alignment
- Shared: Quantum-safe rekeying protocols

## Best Practices

### Do's
- ✓ Deploy both layers when possible
- ✓ Monitor each layer independently
- ✓ Keep both updated with latest PQ algorithms
- ✓ Test failover scenarios
- ✓ Document which layer provides which guarantee

### Don'ts
- ✗ Disable one layer assuming the other is sufficient
- ✗ Share keys between layers
- ✗ Assume perfect correlation protection
- ✗ Neglect performance monitoring
- ✗ Skip security updates on any layer

## Conclusion

The combination of QSSH and PQConnect provides:
1. **Immediate Protection**: PQConnect works today with no changes
2. **Advanced Features**: QSSH adds QKD and hardware support
3. **Defense in Depth**: Multiple independent security layers
4. **Future Proof**: Ready for quantum networks and new algorithms

This multi-layer approach ensures security even if one layer is compromised, while maintaining usability and performance.