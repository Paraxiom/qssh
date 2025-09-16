# QSSH Protocol Design Document

## 1. Design Philosophy

### 1.1 Core Principles

1. **Simplicity First**: Avoid complexity that doesn't add security
2. **Quantum-First Design**: Built for quantum era, not retrofitted
3. **Fail Secure**: When in doubt, fail closed
4. **Transparency**: All security properties must be verifiable

### 1.2 Comparison with SSH

| Feature | SSH | QSSH |
|---------|-----|------|
| Key Exchange | DH/ECDH | Falcon-512 |
| Signatures | RSA/ECDSA/Ed25519 | SPHINCS+ |
| Encryption | AES/ChaCha20 | ChaCha20-Poly1305 |
| Quantum Resistance | No | Yes |
| QKD Support | No | Yes |
| Key Size | 256-4096 bits | 1312-2420 bytes |

## 2. Detailed Protocol Flow

### 2.1 Connection Establishment

```python
class QsshConnection:
    def __init__(self):
        self.state = ConnectionState.INITIAL
        self.crypto_state = None
        self.qkd_available = False
        
    async def connect(self, server: str, port: int = 22222):
        # 1. TCP connection
        self.socket = await tcp_connect(server, port)
        
        # 2. Protocol version exchange
        await self.send_version()
        server_version = await self.recv_version()
        
        # 3. Algorithm negotiation
        client_hello = self.create_client_hello()
        await self.send_message(client_hello)
        
        # 4. Proceed with handshake
        await self.perform_handshake()
```

### 2.2 Client Hello Message

```rust
struct ClientHello {
    // Protocol version (major.minor)
    version: (u8, u8),
    
    // Client random (32 bytes)
    random: [u8; 32],
    
    // Supported PQ key exchange algorithms
    kex_algorithms: Vec<KexAlgorithm>,
    
    // Supported PQ signature algorithms  
    sig_algorithms: Vec<SigAlgorithm>,
    
    // Supported symmetric ciphers
    ciphers: Vec<Cipher>,
    
    // QKD capability announcement
    qkd_capable: bool,
    
    // Extensions
    extensions: Vec<Extension>,
}

enum KexAlgorithm {
    Falcon512,
    Falcon1024,
    SphincsPlus,  // Can be used for key exchange too
}

enum SigAlgorithm {
    SphincsShake128s,
    SphincsShake256s,
    Falcon512,
    Dilithium2,
}
```

### 2.3 Server Hello Message

```rust
struct ServerHello {
    // Protocol version server will use
    version: (u8, u8),
    
    // Server random (32 bytes)
    random: [u8; 32],
    
    // Selected algorithms
    kex_algorithm: KexAlgorithm,
    sig_algorithm: SigAlgorithm,
    cipher: Cipher,
    
    // Server's Falcon public key and key share
    falcon_public_key: Vec<u8>,
    key_share: Vec<u8>,
    key_share_signature: Vec<u8>,
    
    // QKD endpoint if available
    qkd_endpoint: Option<String>,
    
    // Extensions
    extensions: Vec<Extension>,
}
```

### 2.4 Key Exchange Details

```python
class QuantumKeyExchange:
    def __init__(self, algorithm: KexAlgorithm):
        self.algorithm = algorithm
        self.private_key, self.public_key = self.generate_keypair()
        
    def generate_keypair(self):
        if self.algorithm == KexAlgorithm.Falcon512:
            return falcon512_keypair()
        # ... other algorithms
        
    def create_key_share(self) -> Tuple[bytes, bytes]:
        """
        Returns (key_share, signature)
        """
        key_share = generate_random_bytes(32)
        signature = falcon512_sign(key_share, self.private_key)
        return (key_share, signature)
        
    def verify_key_share(self, peer_public_key: bytes, key_share: bytes, signature: bytes) -> bool:
        """
        Verifies peer's key share signature
        """
        return falcon512_verify(key_share, signature, peer_public_key)
```

### 2.5 QKD Integration Flow

```python
class QkdIntegration:
    def __init__(self, endpoint: str, cert_path: str):
        self.endpoint = endpoint
        self.cert = load_certificate(cert_path)
        
    async def get_key(self, key_length: int = 256) -> bytes:
        # ETSI GS QKD 014 API call
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        body = {
            'key_length': key_length,
            'source_id': self.source_id,
            'target_id': self.target_id
        }
        
        response = await https_post(
            f"{self.endpoint}/api/v1/keys/get_key",
            headers=headers,
            json=body,
            cert=self.cert
        )
        
        if response.status == 200:
            key_data = response.json()
            return base64.b64decode(key_data['key'])
        else:
            raise QkdError(f"Failed to get QKD key: {response.status}")
```

## 3. Security Analysis

### 3.1 Attack Scenarios

#### 3.1.1 Quantum Computer Attack
- **Threat**: Adversary with large quantum computer
- **Defense**: All algorithms are NIST PQC winners/finalists
- **Result**: Security maintained

#### 3.1.2 Man-in-the-Middle Attack
- **Threat**: Active attacker between client and server
- **Defense**: SPHINCS+ signatures prevent impersonation
- **Result**: Attack detected during authentication

#### 3.1.3 Replay Attack
- **Threat**: Adversary replays captured messages
- **Defense**: Nonces and sequence numbers
- **Result**: Replayed messages rejected

#### 3.1.4 Side-Channel Attack
- **Threat**: Timing/power analysis of crypto operations
- **Defense**: Constant-time implementations required
- **Result**: No information leakage

### 3.2 Formal Security Properties

```coq
(* Formal verification sketch *)

Definition qssh_secure (protocol: Protocol) : Prop :=
  (* Post-quantum security *)
  ∀ (adversary: QuantumAdversary),
    breaks_security adversary protocol → 
    computational_power adversary > quantum_threshold ∧
    
  (* Forward secrecy *)
  ∀ (session: Session) (key: Key),
    compromised_key key →
    session.time < key.compromise_time →
    secure_session session ∧
    
  (* Authentication *)
  ∀ (client: Client) (server: Server),
    established_session client server →
    authenticated client ∧ authenticated server.
```

## 4. Implementation Architecture

### 4.1 Module Structure

```
qssh/
├── core/
│   ├── protocol.rs      # Core protocol state machine
│   ├── handshake.rs     # Handshake logic
│   └── transport.rs     # Encrypted transport
├── crypto/
│   ├── pqc.rs          # Post-quantum crypto
│   ├── kdf.rs          # Key derivation
│   └── symmetric.rs    # Symmetric encryption
├── qkd/
│   ├── client.rs       # QKD client implementation
│   ├── etsi_api.rs     # ETSI standard API
│   └── mock.rs         # Mock QKD for testing
├── net/
│   ├── tcp.rs          # TCP transport
│   └── multiplex.rs    # Channel multiplexing
└── app/
    ├── shell.rs        # Shell session
    ├── forward.rs      # Port forwarding
    └── sftp.rs         # File transfer
```

### 4.2 State Machine

```rust
enum ConnectionState {
    Initial,
    VersionExchanged,
    HelloSent,
    HelloReceived,
    KeyExchanged,
    Authenticated,
    Established,
    Rekeying,
    Closing,
    Closed,
}

impl ConnectionState {
    fn valid_transition(&self, next: &ConnectionState) -> bool {
        match (self, next) {
            (Initial, VersionExchanged) => true,
            (VersionExchanged, HelloSent) => true,
            (HelloSent, HelloReceived) => true,
            (HelloReceived, KeyExchanged) => true,
            (KeyExchanged, Authenticated) => true,
            (Authenticated, Established) => true,
            (Established, Rekeying) => true,
            (Rekeying, Established) => true,
            (_, Closing) => true,
            (Closing, Closed) => true,
            _ => false,
        }
    }
}
```

## 5. Performance Considerations

### 5.1 Latency Analysis

| Operation | SSH (ECDH) | QSSH (Kyber) | QSSH (Kyber+QKD) |
|-----------|------------|--------------|-------------------|
| Handshake | ~50ms | ~60ms | ~100ms |
| Key Generation | <1ms | ~1ms | N/A |
| Key Exchange | ~5ms | ~2ms | ~40ms (network) |
| Signature | <1ms | ~10ms | ~10ms |
| Verification | <1ms | ~3ms | ~3ms |

### 5.2 Bandwidth Requirements

```
ClientHello: ~200 bytes
ServerHello: ~1500 bytes (includes Kyber public key)
ClientKeyExchange: ~1200 bytes (Kyber ciphertext)
Total handshake: ~3KB (vs ~1KB for SSH)
```

### 5.3 Optimization Strategies

1. **Caching**: Cache QKD keys for faster reconnection
2. **Parallelization**: Parallel signature generation/verification
3. **Hardware Acceleration**: Use AES-NI for AES-GCM
4. **Connection Pooling**: Reuse connections for multiple channels

## 6. Deployment Scenarios

### 6.1 Enterprise Environment

```yaml
# qssh-server.yaml
server:
  listen: 0.0.0.0:22222
  host_key: /etc/qssh/host_key
  
crypto:
  kex_algorithms: [kyber512, kyber768]
  sig_algorithms: [sphincs_shake128s]
  
qkd:
  enabled: true
  endpoint: https://qkd.corp.example.com/api/v1
  cert: /etc/qssh/qkd_cert.pem
  
auth:
  methods: [publickey, password]
  password_backend: ldap
  ldap_server: ldap://auth.corp.example.com
```

### 6.2 Cloud Environment

```yaml
# qssh-client.yaml
client:
  known_hosts: ~/.qssh/known_hosts
  identity_files:
    - ~/.qssh/id_sphincs
    - ~/.qssh/id_falcon
    
connections:
  default:
    kex_algorithm: kyber512
    sig_algorithm: sphincs_shake128s
    
  high_security:
    kex_algorithm: kyber1024
    sig_algorithm: sphincs_shake256s
    require_qkd: true
```

### 6.3 Hybrid Deployment

For gradual migration from SSH to QSSH:

```bash
# SSH jumps to QSSH
ssh -J jumphost.example.com user@quantum-host.example.com

# QSSH configuration
Host quantum-*.example.com
  Port 22222
  PreferredAuthentications publickey
  IdentityFile ~/.qssh/id_sphincs
```

## 7. Future Extensions

### 7.1 Quantum State Tunneling

Extend protocol to tunnel quantum states:
```rust
enum QuantumMessage {
    QubitState { amplitude: Complex64, phase: f64 },
    EntangledPair { bell_state: BellState },
    QuantumCircuit { gates: Vec<QuantumGate> },
}
```

### 7.2 Multi-Party Quantum Communication

Support for quantum conference calls:
- Quantum secret sharing
- GHZ state distribution
- Quantum voting protocols

### 7.3 Integration with Quantum Internet

- Quantum repeater support
- Entanglement swapping
- Quantum memory integration