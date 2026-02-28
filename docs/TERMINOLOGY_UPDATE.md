# Terminology Update: Quantum-Native → Quantum-Resistant

## Why This Change?

**"Quantum-Native"** incorrectly implies the use of actual quantum mechanics (qubits, entanglement, superposition). Only QKD (Quantum Key Distribution) hardware is truly quantum-native because it uses actual quantum physics.

**"Quantum-Resistant"** accurately describes what QSSH does:
- Uses post-quantum cryptography (math that resists quantum attacks)
- Implements traffic analysis resistance through uniform framing
- Integrates with quantum hardware when available

## What Was Changed

### Files Renamed
- `QUANTUM_NATIVE_TRANSPORT.md` → `QUANTUM_RESISTANT_TRANSPORT.md`
- `QUANTUM_NATIVE_PARADIGM.md` → `QUANTUM_RESISTANT_PARADIGM.md`
- `src/transport/quantum_native.rs` → `src/transport/quantum_resistant.rs`
- `tests/quantum_native_comprehensive.rs` → `tests/quantum_resistant_comprehensive.rs`

### Terminology Updates

#### Before:
- "Quantum-native protocol"
- "Quantum-native transport"
- "Indistinguishable from quantum noise"
- "Indistinguishable frames"

#### After:
- "Quantum-resistant protocol"
- "Quantum-resistant transport"
- "Uniform 768-byte frames"
- "Traffic analysis resistance"

### Key Claims Updated

❌ **Removed/Changed:**
- "Traffic indistinguishable from quantum noise" (too strong)
- "Quantum-native design" (misleading)
- "Indistinguishable frames" (debatable)

✅ **Now Using:**
- "Uniform 768-byte frames hide message boundaries"
- "Quantum-resistant design with post-quantum crypto"
- "Traffic analysis resistance through uniform framing"
- "Harder to analyze" (not "impossible to analyze")

## Technical Accuracy

### What QSSH Actually Provides:
1. **Post-Quantum Cryptography**: Falcon-512 + SPHINCS+ (mathematically quantum-resistant)
2. **Traffic Analysis Resistance**: All messages use 768-byte frames
3. **Timing Obfuscation**: Random delays between frames
4. **QRNG Integration**: Can use quantum entropy when available

### What Would Be "Quantum-Native":
- QKD (Quantum Key Distribution) - uses actual photons
- Quantum teleportation protocols
- Quantum entanglement for communication
- Actual manipulation of quantum states

## Summary

QSSH is now accurately described as a **quantum-resistant** protocol that uses:
- Post-quantum cryptography for mathematical security
- Uniform framing for traffic analysis resistance
- Integration points for true quantum hardware (QKD, QRNG)

This is still impressive and valuable - just technically accurate!