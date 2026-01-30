# QSSH-Drista Multi-Repository Integration Map

## Repository Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    INTEGRATION OVERVIEW                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  quantum-harmony-base (Core Substrate Chain)                │
│       ├── pallets/                                          │
│       │   ├── pallet-qssh/  ← NEW PALLET HERE              │
│       │   ├── kirq-entropy/ (existing quantum entropy)      │
│       │   └── qtrust/       (existing quantum trust)        │
│       └── runtime/          (chain runtime)                 │
│                                                              │
│  drista (Application Layer)                                 │
│       ├── cli/              ← CLI INTEGRATION               │
│       ├── node/             ← RPC MODIFICATIONS             │
│       └── client/           ← WALLET INTEGRATION            │
│                                                              │
│  qssh (Transport Layer)                                     │
│       ├── src/drista_integration.rs  ← INTEGRATION MODULE   │
│       └── src/security_tiers.rs      ← TIER SYSTEM          │
│                                                              │
│  polkadot-sdk (Framework)                                   │
│       └── (reference only, no direct changes)               │
│                                                              │
│  parity-scale-codec (Encoding)                              │
│       └── (used for extrinsic encoding)                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Component Placement by Repository

### 1. **quantum-harmony-base** (Core Blockchain)
**Repository**: `QuantumVerseProtocols/quantum-harmony-base`
**Purpose**: Core Substrate runtime with quantum pallets

**New Files**:
```
pallets/
└── pallet-qssh/
    ├── Cargo.toml
    ├── src/
    │   ├── lib.rs           # Pallet logic
    │   ├── benchmarking.rs  # Performance benchmarks
    │   └── tests.rs         # Pallet tests
    └── README.md

runtime/
└── src/lib.rs  # Add pallet to runtime
```

**Why Here**: This is where ALL pallets live, including quantum-related ones

### 2. **drista** (User-Facing Layer)
**Repository**: `QuantumVerseProtocols/drista`
**Purpose**: CLI, RPC, and client applications

**New Files**:
```
cli/
└── src/
    └── commands/
        └── qssh_connect.rs  # CLI command for QSSH

node/
└── src/
    └── rpc/
        └── qssh_transport.rs  # RPC over QSSH

client/
└── src/
    └── transport/
        └── qssh_client.rs  # Client library
```

**Why Here**: User interaction layer

### 3. **qssh** (Transport Protocol)
**Repository**: `Paraxiom/qssh`
**Purpose**: Quantum-resistant SSH implementation

**New Files** (already created):
```
src/
├── drista_integration.rs   # Bridge to Drista
├── security_tiers.rs       # Security tier system
└── substrate_codec.rs      # NEW: SCALE codec support

examples/
└── drista_wallet_ui.rs     # Example integration
```

**Why Here**: Transport protocol implementation

### 4. **polkadot-sdk** (Reference Only)
**Repository**: `paritytech/polkadot-sdk`
**Purpose**: Upstream Substrate framework

**No Changes** - We inherit from this

### 5. **parity-scale-codec** (Utility)
**Repository**: Local fork
**Purpose**: SCALE encoding for extrinsics

**Potential Changes**:
```
src/
└── quantum_types.rs  # NEW: Quantum-specific types
```

## Integration Flow

### Phase 1: Core Pallet (quantum-harmony-base)
```bash
cd ~/quantum-harmony-base
git checkout -b feature/pallet-qssh

# Create pallet
cargo new --lib pallets/pallet-qssh
# Add pallet code
# Update runtime

git commit -m "feat: Add pallet-qssh for quantum-resistant RPC"
git push origin feature/pallet-qssh
```

### Phase 2: Transport Layer (qssh)
```bash
cd ~/qssh
git checkout -b feature/drista-integration

# Add integration modules (already done)
# Add SCALE codec support

git commit -m "feat: Add Drista blockchain integration"
git push origin feature/drista-integration
```

### Phase 3: User Layer (drista)
```bash
cd ~/drista
git checkout -b feature/qssh-transport

# Add CLI commands
# Update RPC handler
# Modify wallet

git commit -m "feat: Integrate QSSH secure transport"
git push origin feature/qssh-transport
```

## Dependency Graph

```
quantum-harmony-base
    ↓ (runtime includes pallet)
    ↓
drista
    ↓ (uses RPC)
    ↓
qssh
    ↓ (provides transport)
    ↓
parity-scale-codec
    ↓ (encodes messages)
    ↓
Network Layer (TCP/IP)
```

## Build Order

1. **qssh** - Transport protocol (independent)
2. **pallet-qssh** - Blockchain logic (depends on Substrate)
3. **quantum-harmony-base** - Runtime integration
4. **drista** - User interface (depends on all above)

## Testing Strategy

### Unit Tests (Per Repo)
- `qssh`: Transport tests
- `pallet-qssh`: Pallet logic tests
- `drista`: CLI/RPC tests

### Integration Tests (Cross-Repo)
```bash
# Start quantum-harmony-base node
cd ~/quantum-harmony-base && cargo run --release

# Start QSSH tunnel
cd ~/qssh && cargo run --bin qsshd

# Test Drista CLI
cd ~/drista && cargo test --features qssh-integration
```

## Coordination Required

### Pull Requests Needed:
1. **qssh** → `Paraxiom/qssh` (your repo)
2. **pallet-qssh** → `quantum-harmony-base` (QuantumVerse)
3. **drista** → `drista` (QuantumVerse)

### Review Order:
1. Review and merge QSSH changes first (standalone)
2. Review pallet-qssh (depends on QSSH)
3. Update quantum-harmony-base runtime
4. Finally update Drista CLI/RPC

## Current Status

✅ **QSSH Repo**: Integration modules created
⏳ **quantum-harmony-base**: Pallet needs to be created
⏳ **drista**: CLI/RPC integration pending
⏳ **parity-scale-codec**: May need quantum types

## Next Action

Should I:
1. **Commit current QSSH changes** (ready now)
2. **Move pallet to quantum-harmony-base** (correct location)
3. **Create Drista CLI integration** (user-facing)

The pallet DEFINITELY belongs in `quantum-harmony-base`, not in QSSH!