# QSSH QKD Integration Guide

## Overview

QSSH now supports real Quantum Key Distribution (QKD) hardware devices for true quantum-secure communication. This guide explains how to configure and use QKD with QSSH.

## Supported QKD Devices

1. **Toshiba QKD Systems**
   - Endpoints: 192.168.0.4 (Alice), 192.168.0.2 (Bob)
   - Protocol: ETSI GS QKD 014 compliant API
   - Authentication: TLS with client certificates

2. **ID Quantique (IDQ) QKD Systems**
   - Endpoints: 192.168.101.202 (Alice), 192.168.101.207 (Bob)
   - Protocol: ETSI GS QKD 014 compliant API
   - Authentication: TLS with client certificates

3. **Basejump/Crypto4A QKD Systems**
   - Endpoints: 192.168.0.101 (Alice), 192.168.101.102 (Bob)
   - Protocol: ETSI GS QKD 014 compliant API
   - Authentication: TLS with client certificates

## Configuration

### 1. Enable QKD in Configuration File

Create or update your `~/.qssh/config` file:

```ssh-config
# Enable QKD globally
Host *
    UseQKD yes
    
# Toshiba QKD Configuration
Host toshiba-server
    Hostname your-server.com
    QkdEndpoint https://192.168.0.4/api/v1/keys
    QkdCertPath ~/qkd_client/certificate/Toshiba/certs/client_alice_crt.pem
    QkdKeyPath ~/qkd_client/certificate/Toshiba/certs/client_alice_key.pem
    QkdCaPath ~/qkd_client/certificate/Toshiba/certs/ca_crt.pem
```

### 2. Certificate Setup

Ensure your QKD certificates are properly installed:

```bash
# Toshiba certificates
ls -la ~/qkd_client/certificate/Toshiba/certs/
# Should contain: client_alice_crt.pem, client_alice_key.pem, ca_crt.pem

# IDQ certificates  
ls -la ~/qkd_client/certificate/IDQ/
# Should contain: ETSIA.pem, ETSIA-key.pem, ChrisCA.pem

# Basejump certificates
ls -la ~/qkd_client/certificate/Basejump/
# Should contain: USER_001.pem, decrypted_USER_001-key.pem, evq-root.pem
```

### 3. Build QSSH with QKD Support

```bash
# Build with QKD feature enabled
cargo build --release --features qkd
```

## Usage

### Basic Connection with QKD

```bash
# Connect using configuration file
qssh -F ~/.qssh/config toshiba-server

# Or specify QKD options directly
qssh user@server \
  --use-qkd \
  --qkd-endpoint https://192.168.0.4/api/v1/keys \
  --qkd-cert ~/certs/client.pem \
  --qkd-key ~/certs/client-key.pem
```

### Verbose Mode for QKD Debugging

```bash
# Enable debug logging
export RUST_LOG=qssh=debug,qkd=debug

# Connect with verbose output
qssh -v -F ~/.qssh/config toshiba-server
```

## How It Works

1. **Connection Initiation**
   - QSSH client connects to server and negotiates quantum-secure handshake
   - Server indicates QKD availability in ServerHello message

2. **QKD Key Retrieval**
   - Client connects to QKD device using TLS mutual authentication
   - Requests quantum key using ETSI QKD API
   - Key size: 256 bits (32 bytes) by default

3. **Hybrid Security**
   - QKD key is combined with post-quantum cryptography (Falcon-512/Kyber)
   - Provides defense-in-depth: secure even if one method is compromised
   - Session keys derived using SHA3-256

4. **Key Usage**
   - QKD keys used for initial key exchange
   - Session keys rotated periodically
   - Fallback to pure PQC if QKD unavailable

## Troubleshooting

### Certificate Issues

```bash
# Test certificate validity
openssl x509 -in client_cert.pem -text -noout

# Test QKD endpoint connectivity
curl -v --cert client_cert.pem --key client_key.pem https://192.168.0.4/api/v1/status
```

### Common Errors

1. **"QKD certificates not configured"**
   - Ensure QkdCertPath and QkdKeyPath are set in config
   - Check certificate file permissions

2. **"Failed to create QKD client"**
   - Verify QKD endpoint URL is correct
   - Check network connectivity to QKD device
   - Ensure certificates are valid

3. **"QKD key retrieval failed"**
   - Check QKD device has available keys
   - Verify QBER (Quantum Bit Error Rate) is within acceptable range
   - Check QKD link status

## Security Considerations

1. **Certificate Security**
   - Keep private keys secure (chmod 600)
   - Use hardware security modules (HSM) for production
   - Rotate certificates regularly

2. **Network Security**
   - QKD devices should be on isolated network
   - Use firewall rules to restrict access
   - Monitor QKD API access logs

3. **Key Management**
   - Keys are single-use (consumed after retrieval)
   - Automatic fallback to PQC if QKD fails
   - No key material logged or stored

## Testing

### Unit Tests
```bash
cargo test --features qkd qkd::
```

### Integration Test
```bash
# Start QSSH server with QKD
qsshd --use-qkd --qkd-endpoint https://192.168.0.2/api/v1/keys

# Connect from client
./test-qkd-connection.sh
```

## Future Enhancements

1. **QKD Network Support**
   - Multi-hop QKD routing
   - QKD network discovery
   - Load balancing across QKD links

2. **Advanced Features**
   - Continuous key distribution
   - QKD performance monitoring
   - Automatic QKD/PQC ratio adjustment

3. **Standards Compliance**
   - Full ETSI GS QKD 014 implementation
   - ETSI GS QKD 004 key delivery
   - ITU-T Y.3800 series support