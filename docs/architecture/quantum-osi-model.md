# Quantum OSI Model for QSSH

## Classical OSI vs Quantum OSI Layers

The quantum networking stack introduces new layers and modifies existing ones to handle quantum properties:

```
┌─────────────────────────────┬─────────────────────────────┐
│     Classical OSI Model     │    Quantum OSI Model        │
├─────────────────────────────┼─────────────────────────────┤
│ 7. Application Layer        │ 7. Application Layer        │
│    (HTTP, SSH, FTP)         │    (QSSH, Quantum Apps)     │
├─────────────────────────────┼─────────────────────────────┤
│ 6. Presentation Layer       │ 6. Presentation Layer       │
│    (SSL/TLS, Compression)   │    (PQC, QKD Integration)   │
├─────────────────────────────┼─────────────────────────────┤
│ 5. Session Layer            │ 5. Session Layer            │
│    (NetBIOS, SQL)           │    (Quantum Sessions)       │
├─────────────────────────────┼─────────────────────────────┤
│ 4. Transport Layer          │ 4. Transport Layer          │
│    (TCP, UDP)               │    (TCP + Quantum Channels) │
├─────────────────────────────┼─────────────────────────────┤
│ 3. Network Layer            │ 3. Network Layer            │
│    (IP, ICMP)               │    (Classical IP)           │
├─────────────────────────────┼─────────────────────────────┤
│ 2. Data Link Layer          │ 2. Data Link Layer          │
│    (Ethernet, PPP)          │    (Classical + Q-Sync)     │
├─────────────────────────────┼─────────────────────────────┤
│ 1. Physical Layer           │ 1. Physical Layer           │
│    (Cables, Hubs)           │    (Fiber, Photons)         │
├─────────────────────────────┼─────────────────────────────┤
│                             │ Q2. Quantum Link Layer      │
│         N/A                 │    (Entanglement, QKD)      │
├─────────────────────────────┼─────────────────────────────┤
│                             │ Q1. Quantum Physical Layer  │
│         N/A                 │    (Qubits, Photons)        │
└─────────────────────────────┴─────────────────────────────┘
```

## New Quantum Layers (Q1 & Q2)

### Q1. Quantum Physical Layer
- **Purpose**: Handle quantum states at the physical level
- **Components**:
  - Single photon sources
  - Quantum detectors
  - Quantum memories
  - Cryogenic systems (for some implementations)
- **QSSH Integration**: QKD hardware operates here

### Q2. Quantum Link Layer
- **Purpose**: Establish quantum channels and distribute entanglement
- **Protocols**:
  - BB84, E91 (QKD protocols)
  - Entanglement distribution
  - Quantum repeater protocols
- **QSSH Integration**: QKD key generation happens here

## Modified Classical Layers

### Layer 6 - Presentation Layer (Enhanced)
**Classical**: Encryption, compression, data formatting
**Quantum Enhancement**: 
- Post-quantum cryptography (SPHINCS+, Kyber)
- QKD key integration
- Quantum-classical key mixing

**QSSH Implementation**:
```rust
// Layer 6: Quantum-Enhanced Presentation
pub enum SecurityMethod {
    Classical(AES256),           // Traditional
    PostQuantum(SphincsPlus),    // PQC
    Hybrid(PQC + QKD),          // QSSH approach
    FullQuantum(QKD),           // Pure quantum
}
```

### Layer 4 - Transport Layer (Extended)
**Classical**: TCP/UDP reliability and flow control
**Quantum Enhancement**: 
- Quantum channel multiplexing
- QKD session management
- Entropy flow control

**QSSH Implementation**:
```rust
// Layer 4: Quantum Transport Management
pub struct QuantumTransport {
    tcp_stream: TcpStream,        // Classical transport
    qkd_channel: Option<QkdChannel>, // Quantum channel
    entropy_buffer: EntropyPool,   // Quantum entropy management
}
```

## QSSH Protocol Stack Visualization

```
┌──────────────────────────────────────────────┐
│            QSSH Application                  │ Layer 7
│         (qssh user@host.com)                │
├──────────────────────────────────────────────┤
│         Post-Quantum Crypto                  │ Layer 6
│     (SPHINCS+ signing, Kyber KEM)          │
├──────────────────────────────────────────────┤
│          Session Management                  │ Layer 5
│      (Key rotation, channel mux)            │
├──────────────────────────────────────────────┤
│       Enhanced Transport Layer               │ Layer 4
│         TCP + Quantum Channels               │
│  ┌─────────────┬──────────────────┐         │
│  │   TCP/IP    │  QKD Interface   │         │
│  │  (Classic)  │  (ETSI GS QKD)  │         │
│  └─────────────┴──────────────────┘         │
├──────────────────────────────────────────────┤
│            IP Networking                     │ Layer 3
├──────────────────────────────────────────────┤
│            Ethernet/WiFi                     │ Layer 2
├──────────────────────────────────────────────┤
│         Physical (Fiber/Copper)              │ Layer 1
└──────────────────────────────────────────────┘
                    │
    ┌───────────────┴───────────────┐
    │      Quantum Substrate        │
    ├───────────────────────────────┤
    │    QKD Protocol (BB84)        │ Layer Q2
    ├───────────────────────────────┤
    │  Quantum Physical (Photons)   │ Layer Q1
    └───────────────────────────────┘
```

## Data Flow Through Layers

### Establishing QSSH Connection:

1. **Application (L7)**: User runs `qssh user@quantum.host`

2. **Presentation (L6)**: 
   - Generate Kyber keypair
   - Request QKD keys (if available)
   - Mix quantum + classical entropy

3. **Session (L5)**: 
   - Establish session ID
   - Initialize key rotation timer

4. **Transport (L4)**: 
   - TCP connection on port 22222
   - Parallel: QKD channel establishment

5. **Network (L3)**: Standard IP routing

6. **Quantum Link (Q2)**: 
   - BB84 protocol executes
   - Quantum keys generated

7. **Quantum Physical (Q1)**: 
   - Photons transmitted
   - Measurements performed

## Inter-Layer Communication

```python
class QSSHLayerStack:
    def __init__(self):
        # Classical layers
        self.app_layer = ApplicationLayer()
        self.presentation = QuantumPresentationLayer()
        self.session = SessionLayer()
        self.transport = EnhancedTransportLayer()
        
        # Quantum layers (optional)
        self.quantum_link = None
        self.quantum_physical = None
        
    def send_data(self, data: bytes):
        # L7 → L6: Application data
        pqc_encrypted = self.presentation.encrypt(data)
        
        # L6 → Q2: Request quantum key (cross-layer)
        if self.quantum_link:
            qkd_key = self.quantum_link.get_key()
            pqc_encrypted = self.presentation.mix_keys(
                pqc_encrypted, qkd_key
            )
        
        # L6 → L5: Encrypted data
        session_data = self.session.add_headers(pqc_encrypted)
        
        # L5 → L4: Session data
        self.transport.send(session_data)
```

## Key Innovations in QSSH's Layer Model

1. **Cross-Layer Optimization**: 
   - Direct L6 ↔ Q2 communication for QKD integration
   - Bypasses unnecessary classical crypto when using QKD

2. **Parallel Stack Operation**:
   - Classical and quantum stacks run simultaneously
   - Automatic fallback if quantum unavailable

3. **Entropy Aggregation**:
   - Multiple entropy sources (Crypto4A, KIRQ, QKD)
   - Cross-layer entropy mixing at L6

4. **Hybrid Security**:
   - Both computational (PQC) and information-theoretic (QKD)
   - Layered defense across stack

## Implementation in QSSH

```rust
// QSSH implements both classical and quantum paths
impl QsshConnection {
    async fn establish(&mut self) -> Result<()> {
        // Classical path (always available)
        self.tcp_connect().await?;     // L1-L4
        
        // Quantum path (optional)
        if self.qkd_available {
            self.qkd_connect().await?;  // Q1-Q2
        }
        
        // Hybrid handshake at L6
        self.perform_pqc_handshake().await?;
        
        // Mix in quantum keys if available
        if let Some(qkd_key) = self.get_qkd_key().await? {
            self.enhance_with_quantum(qkd_key)?;
        }
        
        Ok(())
    }
}
```

This layered approach allows QSSH to:
- Work on classical networks (using only L1-L7)
- Enhance security with quantum layers (Q1-Q2) when available
- Provide seamless fallback and forward compatibility

## Reality Check: What QSSH Actually Does

### Current Reality (What QSSH Does Today)

```
┌─────────────────────────────────────────────┐
│              QSSH on Classical Computer      │
├─────────────────────────────────────────────┤
│ L7: Application (qssh command)              │
├─────────────────────────────────────────────┤
│ L6: Post-Quantum Crypto (SPHINCS+, Falcon)  │
│     - Runs on CPU                          │
│     - Quantum-RESISTANT, not quantum       │
├─────────────────────────────────────────────┤
│ L5: Session Management                      │
├─────────────────────────────────────────────┤
│ L4: TCP Transport                           │
├─────────────────────────────────────────────┤
│ L3: IP Network                              │
├─────────────────────────────────────────────┤
│ L2: Ethernet                                │
├─────────────────────────────────────────────┤
│ L1: Physical (Fiber/Copper)                 │
└─────────────────────────────────────────────┘
                    │
                    ├── To QKD Hardware (via HTTPS API)
                    │   └── Toshiba QKD at 192.168.0.4
                    │
                    └── To Entropy Sources (via HTTP)
                        ├── KIRQ Hub at localhost:8001
                        └── Crypto4A HSM at localhost:8106
```

### What's REALLY Happening:

1. **NO DIRECT QUANTUM STATES**: QSSH never touches actual qubits or photons
   - We receive classical bits from QKD systems via HTTPS API
   - These bits were generated using quantum processes, but we only see the classical output

2. **POST-QUANTUM ≠ QUANTUM**: 
   - SPHINCS+ and Falcon are classical algorithms that resist quantum attacks
   - They run on regular CPUs, no quantum hardware needed

3. **QKD Integration is API-Based**:
   ```python
   # What we do:
   response = https_get("https://192.168.0.4/api/v1/keys/get_key")
   classical_key = response.json()["key"]  # Regular bytes!
   
   # What we DON'T do:
   # quantum_state = |0⟩ + |1⟩  # We never handle actual quantum states
   ```

### The Actual Layer Stack for QSSH:

```
QSSH Classical Computer          External Quantum Hardware
─────────────────────           ─────────────────────────
                                          ┌─────────────┐
L7-L6: QSSH App & PQC                    │ Toshiba QKD │
         │                                │   System    │
         ├──── HTTPS/TLS ────────────────►│             │
         │     (ETSI GS QKD 014 API)     │ ┌─────────┐ │
         │                                │ │ Alice   │ │
L4-L3: TCP/IP                            │ └─────────┘ │
         │                                │      │      │
L2-L1: Ethernet/Fiber                    │   Photons   │
                                         │      │      │
                                         │ ┌─────────┐ │
                                         │ │  Bob    │ │
                                         │ └─────────┘ │
                                         └─────────────┘
                                         
   We operate here                    They handle Q1 & Q2
   (Classical only)                   (Actual quantum layers)
```

### What About CNT (Carbon Nanotube) Quantum Repeaters?

When CNT quantum repeaters are developed, they would:
1. Operate at the TRUE quantum layers (Q1 & Q2)
2. Handle actual quantum states
3. QSSH would still only interface via classical APIs

```
Future with CNT Repeaters:
─────────────────────────

QSSH ──HTTPS──► QKD API ──► CNT Repeater ──Quantum──► CNT Repeater ──► QKD System
     Classical             Q1/Q2 Layers              Q1/Q2 Layers      Q1/Q2 Layers
```

### Summary:

- **QSSH**: 100% classical software using quantum-resistant algorithms
- **Q1 & Q2 Layers**: Only exist in actual quantum hardware (QKD systems, future CNT repeaters)
- **Integration**: We get classical keys from quantum processes via REST APIs
- **No Quantum Computing Required**: QSSH runs on regular computers

The "quantum" in QSSH means:
1. **Quantum-resistant** (survives quantum computer attacks)
2. **Quantum-enhanced** (can use keys from quantum hardware)
3. **NOT quantum computing** (doesn't need quantum computer to run)