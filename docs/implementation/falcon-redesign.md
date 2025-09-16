# QSSH Redesign: Falcon + SPHINCS+ (Following QuantumHarmony)

## Why Falcon + SPHINCS+ is Better

### Falcon-512 Advantages:
1. **Compact signatures**: 690 bytes vs Kyber's 1568 byte ciphertexts
2. **Fast verification**: Better for high-throughput scenarios
3. **No known timing attacks**: The Kyber vulnerability doesn't apply
4. **Already proven**: Working in QuantumHarmony blockchain

### SPHINCS+ for Long-term Keys:
1. **Hash-based**: Only relies on hash function security
2. **Stateless**: No synchronization issues
3. **Conservative**: Most confidence in long-term security

## New QSSH Architecture

```rust
// Instead of Kyber KEM, use Falcon signatures for key agreement
pub struct QsshKeyExchange {
    // Ephemeral Falcon key for this session
    falcon_sk: falcon512::SecretKey,
    falcon_pk: falcon512::PublicKey,
    
    // Long-term SPHINCS+ for identity
    sphincs_sk: sphincs::SecretKey,
    sphincs_pk: sphincs::PublicKey,
}

// Key agreement using signatures (like TLS 1.3)
impl QsshKeyExchange {
    pub fn create_key_share(&self) -> KeyShare {
        // Generate ephemeral secret
        let ephemeral_secret = rand::thread_rng().gen::<[u8; 32]>();
        
        // Sign it with Falcon
        let signature = falcon512::sign(&ephemeral_secret, &self.falcon_sk);
        
        KeyShare {
            ephemeral_secret,
            falcon_signature: signature,
            falcon_public_key: self.falcon_pk.clone(),
        }
    }
}
```

## Updated Protocol Flow

```
Client                                          Server
  |                                               |
  |------------- ClientHello ------------------>  |
  |   - Client Falcon ephemeral public key       |
  |   - Client SPHINCS+ identity public key      |
  |   - Client random (32 bytes)                 |
  |                                               |
  |<------------ ServerHello -------------------  |
  |   - Server Falcon ephemeral public key       |
  |   - Server SPHINCS+ identity public key      |
  |   - Server random (32 bytes)                 |
  |   - Signed key share (Falcon signature)      |
  |                                               |
  |----------- ClientKeyShare ----------------->  |
  |   - Client's signed key share               |
  |   - SPHINCS+ signature over handshake       |
  |                                               |
  |<---------- ServerFinished ------------------  |
  |   - SPHINCS+ signature for authentication   |
  |                                               |
```

## Key Derivation (No Kyber Needed!)

```rust
// Both sides compute shared secret
let shared_secret = {
    // Mix both ephemeral secrets
    let mut hasher = Sha3_256::new();
    hasher.update(b"QSSH-FALCON-v1");
    hasher.update(&client_ephemeral_secret);
    hasher.update(&server_ephemeral_secret);
    hasher.update(&client_random);
    hasher.update(&server_random);
    hasher.finalize()
};

// Derive session keys as before
let session_keys = SessionKeyDerivation::derive_keys(
    &shared_secret,
    &client_random,
    &server_random,
)?;
```

## Implementation Changes Needed

### 1. Replace Kyber with Falcon

```toml
# Cargo.toml
[dependencies]
# Remove
# pqcrypto-kyber = "0.7"

# Add
pqcrypto-falcon = "0.3"
# Or use the same as QuantumHarmony
falcon = { path = "../quantum-harmony/crypto/falcon" }
```

### 2. Update Crypto Module

```rust
// src/crypto/mod.rs
use pqcrypto_falcon::falcon512;
use pqcrypto_sphincsplus::sphincsshake128ssimple as sphincs;

pub struct PqKeyExchange {
    // Falcon for ephemeral operations (fast)
    pub falcon_sk: falcon512::SecretKey,
    pub falcon_pk: falcon512::PublicKey,
    
    // SPHINCS+ for identity (secure)
    pub sphincs_sk: sphincs::SecretKey,
    pub sphincs_pk: sphincs::PublicKey,
}
```

### 3. Signature-based Key Agreement

```rust
// No KEM needed - use signatures for authentication + key agreement
impl PqKeyExchange {
    pub fn perform_key_agreement(
        &self,
        peer_falcon_pk: &[u8],
        peer_share: &[u8],
        peer_signature: &[u8],
    ) -> Result<Vec<u8>> {
        // Verify peer's signature
        let pk = falcon512::PublicKey::from_bytes(peer_falcon_pk)?;
        let sig = falcon512::Signature::from_bytes(peer_signature)?;
        
        falcon512::verify(&sig, peer_share, &pk)
            .map_err(|_| QsshError::Crypto("Invalid Falcon signature".into()))?;
        
        // Generate our share
        let our_share = rand::thread_rng().gen::<[u8; 32]>();
        
        // Mix shares
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSH-SHARES");
        hasher.update(&our_share);
        hasher.update(peer_share);
        hasher.finalize().to_vec()
    }
}
```

## Benefits of This Approach

1. **Proven in Production**: Already working in QuantumHarmony
2. **No Kyber Timing Issues**: Completely avoids the vulnerability
3. **Smaller Messages**: Falcon signatures are compact
4. **Faster Operations**: Falcon verification is quick
5. **Consistent Stack**: Same crypto as your blockchain

## Migration Path

1. Keep current QSSH as `qssh-kyber` branch
2. Implement Falcon version as main
3. Both versions can coexist during transition
4. Eventually deprecate Kyber version

This aligns QSSH with your existing quantum infrastructure!