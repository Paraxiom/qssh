# KIRQ Network Operator Requirements for Quantum-Safe QKD Access

## The Architecture Reality

```
┌─────────────────────────┐         ┌──────────────────────────────┐
│   QSSH Users/Clients    │         │   KIRQ Network Operator      │
│                         │         │                              │
│  - Cannot modify QKD    │         │  - Controls QKD hardware     │
│  - Remote access only   │ ------> │  - Manages network infra     │
│  - Need quantum keys    │         │  - MUST implement PQ proxy   │
└─────────────────────────┘         └──────────────────────────────┘
                                                  |
                                                  | [Classical TLS]
                                                  ↓
                                    ┌──────────────────────────────┐
                                    │   QKD Hardware (Toshiba)     │
                                    │   - Vendor-controlled        │
                                    │   - Classical TLS only       │
                                    └──────────────────────────────┘
```

## Why KIRQ Operators Must Do This

1. **Physical Access**: Only they have access to QKD hardware location
2. **Network Control**: They manage the infrastructure between users and QKD
3. **Trust Boundary**: They're already trusted with the QKD keys
4. **Deployment Rights**: Only they can install software on QKD servers

## Proposed KIRQ Operator Setup

### Option 1: PQ-TLS Gateway (Recommended)
```yaml
# Deployed by KIRQ operator on their infrastructure
kirq-pq-gateway:
  listen: 0.0.0.0:8443  # Public-facing, PQC-secured
  upstream:
    - qkd1: localhost:443  # Toshiba QKD API
    - qkd2: localhost:444  # IDQ QKD API
  
  authentication:
    method: "sphincs+"
    client_certs: "/etc/kirq/authorized_clients/"
  
  encryption:
    kex: "kyber768"
    cipher: "chacha20-poly1305"
```

### Option 2: KIRQ Hub Enhancement
The existing KIRQ Hub at `localhost:8001` could be enhanced:

```rust
// Current KIRQ Hub API
GET /api/entropy/consume

// Enhanced with PQC transport
GET /api/v2/entropy/consume
Headers:
  X-Quantum-Auth: <SPHINCS+ signature>
  X-Key-Exchange: <Kyber768 ciphertext>
```

### Option 3: Dedicated Quantum Access Network
```
Internet ─────[PQC VPN]────→ KIRQ Quantum DMZ ────[Local]────→ QKD Devices
                                    │
                                    ├── PQ-TLS Proxy
                                    ├── HSM for key management
                                    └── Audit logging
```

## What QSSH Can Do Without Operator Support

If KIRQ operators don't implement PQ protection:

### 1. **Ephemeral Key Mixing**
```rust
// Mix multiple classical QKD retrievals
let key1 = get_qkd_key().await?;  // Vulnerable
wait_random_delay();
let key2 = get_qkd_key().await?;  // Vulnerable
wait_random_delay();
let key3 = get_qkd_key().await?;  // Vulnerable

// Even if one is compromised, others might not be
let final_key = sha3_256(key1 || key2 || key3);
```

### 2. **Time-Limited Exposure**
```rust
// Only retrieve QKD keys at the last possible moment
// Minimize window of vulnerability
pub async fn establish_session() {
    // Do all PQC handshaking first
    let pqc_shared_secret = kyber_key_exchange().await?;
    
    // Only now retrieve QKD key (minimal exposure time)
    let qkd_key = quick_qkd_retrieval().await?;
    
    // Immediately mix and destroy
    let session_key = mix_keys(pqc_shared_secret, qkd_key);
    qkd_key.zeroize();
}
```

### 3. **Multi-Path Retrieval**
```rust
// Use different networks/paths to different KIRQ nodes
let key1 = get_from_kirq_node_a().await?;  // Via ISP 1
let key2 = get_from_kirq_node_b().await?;  // Via ISP 2
let key3 = get_from_kirq_node_c().await?;  // Via VPN

// Attacker would need to compromise all paths
```

## Recommended Action for KIRQ Network

### Phase 1: Quick Win (Can deploy today)
```nginx
# Nginx config for PQ-TLS reverse proxy
server {
    listen 8443 ssl;
    ssl_protocols TLSv1.3;
    ssl_ciphers TLS_CHACHA20_POLY1305_SHA256;
    
    # Add post-quantum via BoringSSL fork
    ssl_ecdh_curve kyber768:x25519;
    
    location /qkd/ {
        # Only accept connections with client certs
        if ($ssl_client_verify != SUCCESS) {
            return 403;
        }
        
        # Proxy to QKD on localhost
        proxy_pass https://localhost:443/;
    }
}
```

### Phase 2: Proper Integration
- Implement full PQC authentication
- Add STARK proofs at the operator level
- Provide SDKs for clients

## Business Case for KIRQ Operators

Implementing PQ-TLS proxy provides:
1. **True Quantum Security**: No weak links in the chain
2. **Competitive Advantage**: First quantum-safe QKD network
3. **Future-Proof**: Ready for Q-Day
4. **Compliance**: Meets emerging quantum security standards

## What QSSH Should Document

```rust
// In QSSH connection setup
match qkd_endpoint.pq_capable() {
    true => {
        log::info!("✅ QKD endpoint supports PQC - full quantum security");
        self.use_pqc_transport()
    },
    false => {
        log::warn!("⚠️  QKD endpoint uses classical TLS - security degraded");
        log::warn!("⚠️  Contact KIRQ operator to enable PQ-TLS proxy");
        log::warn!("⚠️  Using time-limited key retrieval as mitigation");
        self.use_classical_with_mitigations()
    }
}
```

The ball is in the KIRQ operators' court. QSSH can only do so much from the client side!