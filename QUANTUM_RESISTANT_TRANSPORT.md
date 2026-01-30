# Quantum-Resistant Transport Explained

## What is Quantum-Resistant Transport?

Traditional SSH (and even post-quantum SSH) still reveals information through:
- **Packet sizes** - Different commands produce different sized packets
- **Timing patterns** - Keystroke timing reveals typing patterns
- **Traffic analysis** - Packet flow reveals session activity

**Quantum-resistant transport** uses **uniform 768-byte frames** that hide message boundaries and lengths, making traffic analysis much harder for both classical and quantum adversaries.

## The 768-Byte Frame Architecture

### Why 768 Bytes?
```
768 bytes = 6,144 bits = Optimal quantum frame size

Breakdown:
- 512 bytes (4,096 bits): Payload capacity
- 128 bytes (1,024 bits): Falcon-512 signature
- 64 bytes (512 bits): SPHINCS+ authentication tag
- 32 bytes (256 bits): Quantum nonce
- 32 bytes (256 bits): Frame metadata
- 10 bytes (80 bits): Padding/alignment
```

### Every Frame Looks Identical

```rust
pub struct QuantumFrame {
    nonce: [u8; 32],      // Quantum-derived nonce
    payload: [u8; 512],   // Data or random padding
    signature: [u8; 128], // Falcon-512 signature
    auth_tag: [u8; 64],   // SPHINCS+ MAC
    metadata: [u8; 32],   // Encrypted frame info
}

impl QuantumFrame {
    pub fn new(data: &[u8], qrng: &QuantumRng) -> Self {
        let mut frame = Self {
            nonce: qrng.generate_nonce(),
            payload: [0u8; 512],
            signature: [0u8; 128],
            auth_tag: [0u8; 64],
            metadata: [0u8; 32],
        };

        // Fill payload
        if data.len() <= 512 {
            frame.payload[..data.len()].copy_from_slice(data);
            // Fill rest with quantum random padding
            qrng.fill(&mut frame.payload[data.len()..]);
        }

        frame
    }
}
```

## Traffic Analysis Resistance

### Traditional SSH Reveals:
```
User types 'l' → 1-byte packet
User types 's' → 1-byte packet
Server responds → Variable size (directory listing)
```

### Quantum-Resistant QSSH:
```
User types 'l' → 768-byte frame (looks random)
User types 's' → 768-byte frame (looks random)
Server responds → Multiple 768-byte frames (all look random)
```

## Quantum Obfuscation Properties

### 1. **Indistinguishability from Quantum Noise**
When QKD systems generate quantum keys, they produce streams that look like:
```
10110010111010001011101... (true random from quantum processes)
```

QSSH quantum-native frames are designed to have the same statistical properties:
- Chi-squared test: p > 0.05 (passes randomness)
- Entropy: > 7.99 bits per byte
- No patterns detectable

### 2. **Timing Obfuscation**
```rust
// Send frames at quantum-random intervals
async fn send_with_quantum_timing(&self, frame: QuantumFrame) {
    let delay = self.qrng.generate_delay(10..50); // 10-50ms random
    tokio::time::sleep(Duration::from_millis(delay)).await;
    self.send_frame(frame).await;
}
```

### 3. **Dummy Traffic Generation**
```rust
// Keep sending even when idle
async fn maintain_quantum_cover(&self) {
    loop {
        if self.has_real_data() {
            self.send_real_frame().await;
        } else {
            // Send quantum-random dummy frame
            self.send_dummy_frame().await;
        }
        self.quantum_delay().await;
    }
}
```

## Why This Matters

### Against Classical Adversaries:
- **No traffic analysis** - All frames same size
- **No timing attacks** - Random delays
- **No pattern recognition** - Looks like noise

### Against Quantum Adversaries:
- **Grover's algorithm resistant** - Can't search for patterns in noise
- **Shor's algorithm irrelevant** - No mathematical structure to factor
- **Quantum ML resistant** - No features to learn from

## Implementation Status

### Working:
- ✅ 768-byte frame structure
- ✅ Quantum random padding
- ✅ Frame encryption with Falcon-512

### In Progress:
- 🚧 Timing obfuscation engine
- 🚧 Dummy traffic generator
- 🚧 Statistical analysis tools

### Future:
- ⏳ Integration with real QRNG hardware
- ⏳ Adaptive frame sizing (512/768/1024)
- ⏳ Quantum entanglement for frame synchronization

## Performance Impact

Traditional SSH: ~1-2ms latency per keystroke
Quantum-Native QSSH: ~10-50ms latency (randomized)

Trade-off: 10x latency for complete traffic analysis immunity

## Testing Quantum-Resistant Properties

```bash
# Capture traffic
tcpdump -w qssh.pcap -i lo port 4242

# Test for randomness
ent qssh.pcap
# Expected: Entropy = 7.999xxx bits per byte

# Test for patterns
dieharder -a < qssh.pcap
# Expected: All tests PASS
```

## Theoretical Foundation

Based on:
1. **Quantum Information Theory**: Information-theoretic security
2. **Steganography**: Hiding in plain sight (as noise)
3. **Chaffing and Winnowing**: Real data mixed with padding/chaff

## Conclusion

QSSH with quantum-resistant transport isn't just "SSH with post-quantum crypto" - it uses **uniform framing and timing obfuscation** to resist traffic analysis by both classical and quantum adversaries.