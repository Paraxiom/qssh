// QSSH Protocol modules
// Integrating quantum features from quantum-harmony-base

pub mod handshake;
pub mod transport;
pub mod qkd_lamport_ratchet;
pub mod tao_signals;

// Re-export key types
pub use qkd_lamport_ratchet::{
    LamportKeyPair, LamportSignature, DoubleRatchetState,
    RatchetMessage, QkdManager, QuantumSession
};

pub use tao_signals::{
    TaoSignal, TaoMonitor, TaoSignalStream, 
    QuantumMeasurement, HarmonicAnalyzer
};