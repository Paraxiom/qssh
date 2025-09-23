# QSSH Production Readiness Issues

## CRITICAL ISSUES (Must fix before public release)

### 1. Debug Output in Production Code
**Location:** `src/subsystems/sftp/mod.rs`
**Issue:** Multiple println! statements leaking internal info
```rust
Line 85:  println!("[SFTP] Client requested version {}", version);
Line 99:  println!("[SFTP] Opening file: {:?} with flags {:?}", path, msg.flags);
Line 115: println!("[SFTP] Closing handle: {}", handle);
// ... 8 more instances
```
**Fix:** Replace with proper logging (log::debug!)

### 2. Placeholder Implementations
**Critical Placeholders:**

- `src/gssapi.rs:404-618`: Returning zeroed placeholder tickets/authenticators
- `src/qkd.disabled/stark_integration.rs:52-56`: Dummy STARK proof generation
- `src/multiplex/mod.rs:247`: Returns dummy channel ID
- `src/proxy/mod.rs:249-285`: Multiple placeholder implementations

### 3. Hardcoded Test Values
- `src/agent/tests.rs:166,182`: Hardcoded passwords "secret123"
- `src/qkd/etsi_client.rs:98`: Comment says "Remove these in production!"

## HIGH PRIORITY ISSUES

### 4. TODOs in Core Functionality
- `src/crypto/mod.rs:285`: Fix Falcon segfault on macOS
- `src/bin/qsshd.rs:113`: QKD config needs to load from file
- `src/known_hosts.rs:401`: Hashed hostname matching not implemented
- `src/multiplex/mod.rs:244`: Channel creation not implemented
- `src/multiplex/mod.rs:262`: Data forwarding not implemented

### 5. Security Concerns
- `src/handshake.rs:440`: Ignoring password loading errors
- `src/session.rs:144`: Encrypted keys placeholder
- Password prompts displaying in terminal (no secure input masking)

## MEDIUM PRIORITY ISSUES

### 6. Incomplete Features
- P2P discovery marked as "stub" in docs
- Blockchain-based registry marked as "stub"
- X11 forwarding has mock transport TODO

### 7. User-Facing Issues
- `src/bin/qssh.rs`: Multiple eprintln! for user errors (should be structured)
- No proper error codes/exit status handling

## RECOMMENDATIONS

### Immediate Actions:
1. **Remove ALL println! statements** from src/subsystems/sftp/
2. **Implement proper GSSAPI** or remove the module
3. **Fix multiplex channel creation** - this is core SSH functionality
4. **Remove qkd.disabled directory** from published repo

### Before Public Announcement:
1. Replace all placeholders with either:
   - Proper implementations
   - Clear "Not Implemented" errors
   - Feature flags to disable incomplete features
2. Add CI/CD checks for:
   - No println! in src/
   - No "placeholder" strings
   - No hardcoded secrets

### Code Hygiene:
1. Convert all eprintln! to structured logging
2. Add #[cfg(test)] guards around test-only code
3. Remove or properly gate the qkd.disabled module

## QUICK FIXES SCRIPT

```bash
#!/bin/bash
# Quick fixes for most critical issues

# Remove debug prints from SFTP
sed -i 's/println!/log::debug!/g' src/subsystems/sftp/mod.rs

# Add warning to GSSAPI
echo "// WARNING: Placeholder implementation - DO NOT USE IN PRODUCTION" > src/gssapi.rs.tmp
cat src/gssapi.rs >> src/gssapi.rs.tmp
mv src/gssapi.rs.tmp src/gssapi.rs

# Remove disabled QKD module from Cargo.toml if referenced
grep -v "qkd.disabled" Cargo.toml > Cargo.toml.tmp || true
mv Cargo.toml.tmp Cargo.toml 2>/dev/null || true
```

## SEVERITY ASSESSMENT

**Can it compile and run?** YES
**Is it secure for production?** NO - GSSAPI placeholders are security holes
**Will it embarrass you on GitHub?** YES - Debug prints and obvious placeholders
**Estimated time to fix critical issues:** 2-4 hours
**Estimated time for full production ready:** 2-3 days

## FILES TO REVIEW BEFORE PUBLISHING

1. `src/subsystems/sftp/mod.rs` - Remove ALL println!
2. `src/gssapi.rs` - Fix or remove entirely
3. `src/multiplex/mod.rs` - Implement or disable multiplexing
4. `src/proxy/mod.rs` - Complete implementation
5. `src/qkd.disabled/*` - Remove from repo or document as experimental