# QSSH P2P Implementation

## Overview

QSSH now supports a fully decentralized P2P mode that allows direct peer-to-peer connections without requiring a centralized daemon. This addresses the centralization concerns and enables truly distributed quantum-secure communications.

## Features

### 1. Direct P2P Connections
- No daemon required - peers connect directly
- Each peer generates a unique ID from their quantum-safe public key
- Automatic address discovery (local IPs, public IPs)
- Support for multiple connection modes (Direct, NAT Traversal, Relay)

### 2. Peer Discovery Mechanisms
- **Local Broadcast**: Automatic discovery on local network
- **DHT-based**: Distributed hash table for internet-wide discovery (stub)
- **Blockchain-based**: Use QuantumHarmony validators as registry (stub)
- **Manual**: Direct connection to known peer addresses

### 3. NAT Traversal
- STUN client implementation for NAT detection
- Support for multiple NAT types (Full Cone, Restricted, Symmetric)
- UDP hole punching for direct connections through NATs
- Fallback to relay mode for symmetric NATs

### 4. Security Properties
- All P2P connections use same post-quantum algorithms (Falcon-512, SPHINCS+)
- Peer identities derived from public keys (no central authority)
- Double Ratchet for forward secrecy (from main QSSH implementation)
- Optional QKD integration when available

## Usage

### Starting a P2P Listener
```bash
# Start listening for P2P connections
./target/debug/examples/p2p_demo listen

# Output:
# Starting P2P listener...
# Our peer info:
#   ID: a3f2b8c9d4e5f6a7
#   Name: alice
#   Addresses: ["192.168.1.100:22222", "10.0.0.5:22222"]
# Listening on 192.168.1.100:22222
```

### Connecting to a Peer
```bash
# Connect directly to a peer
./target/debug/examples/p2p_demo connect 192.168.1.100:22222

# Output:
# Connecting to peer at 192.168.1.100:22222...
# Connected to peer: alice
# Peer ID: a3f2b8c9d4e5f6a7
# Sent: Hello from bob!
# Received: Hello from alice!
# 
# Entering interactive mode. Type messages to send, or 'quit' to exit.
# > 
```

### Discovering Peers
```bash
# Discover peers on local network
./target/debug/examples/p2p_demo discover

# Output:
# Starting peer discovery...
# No peers discovered yet...
# 
# Discovered 2 peers:
#   - alice (a3f2b8c9d4e5f6a7)
#     Addresses: ["192.168.1.100:22222"]
#   - charlie (b8c9d4e5f6a7a3f2)
#     Addresses: ["192.168.1.101:22222"]
```

## Architecture

### P2P Session
```rust
pub struct P2pSession {
    our_info: PeerInfo,
    keypair: PqKeyExchange,
    peers: Arc<RwLock<Vec<PeerInfo>>>,
    connections: Arc<RwLock<Vec<P2pConnection>>>,
}
```

### Connection Flow
1. **Peer Exchange**: Peers exchange their `PeerInfo` (ID, name, public key)
2. **Key Exchange**: Perform Diffie-Hellman using Falcon-512
3. **Verification**: Verify signatures on key shares
4. **Transport**: Create encrypted transport using shared secret

### Message Protocol
- Uses same transport layer as client-server mode
- All messages are encrypted with AES-256-GCM
- Supports data channels for application protocols

## Integration with QuantumHarmony

The P2P mode is designed to integrate seamlessly with QuantumHarmony blockchain:

1. **Validator Discovery**: Validators can advertise as P2P peers
2. **Identity Registry**: Blockchain can store peer identities
3. **Reputation System**: Track peer reliability on-chain
4. **QKD Network**: Share QKD endpoints through blockchain

## Advantages Over Daemon Mode

1. **No Single Point of Failure**: Each peer is independent
2. **Better Privacy**: No central server logging connections
3. **Easier Deployment**: No need to run/manage daemons
4. **Natural Scaling**: Network grows organically
5. **Resilience**: Network continues even if some peers fail

## Future Enhancements

1. **Complete DHT Implementation**: Full Kademlia-style routing
2. **Blockchain Registry**: Store peer info in QuantumHarmony
3. **Multi-hop Routing**: Onion-like routing for privacy
4. **Mobile Support**: Optimize for mobile P2P connections
5. **WebRTC Transport**: Browser-based P2P connections

## Security Considerations

1. **Peer Authentication**: Always verify peer public keys out-of-band
2. **Man-in-the-Middle**: First connection vulnerable without PKI
3. **Eclipse Attacks**: Peer discovery can be manipulated
4. **Resource Usage**: P2P can use more bandwidth than client-server

## Conclusion

The P2P implementation provides a truly decentralized alternative to traditional SSH that aligns with the decentralized nature of blockchain technology. It maintains all the quantum-safe properties of QSSH while eliminating the need for central infrastructure.