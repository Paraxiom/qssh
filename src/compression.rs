//! Compression Support for QSSH
//!
//! Implements zlib, zstd, and lz4 compression algorithms for bandwidth optimization

use std::io::{Read, Write};
use flate2::Compression as ZlibLevel;
use flate2::read::{ZlibDecoder, ZlibEncoder};
use flate2::write::{ZlibDecoder as ZlibWriteDecoder, ZlibEncoder as ZlibWriteEncoder};
use crate::{Result, QsshError};

/// Compression algorithms supported by QSSH
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    /// No compression
    None,
    /// Standard zlib compression (SSH compatible)
    Zlib,
    /// Zstandard compression (better ratio)
    Zstd,
    /// LZ4 compression (fastest)
    Lz4,
    /// Delayed compression (after authentication)
    Delayed,
}

impl CompressionAlgorithm {
    /// Parse compression algorithm from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "none" => Self::None,
            "zlib" => Self::Zlib,
            "zlib@openssh.com" => Self::Zlib,
            "zstd" => Self::Zstd,
            "zstd@openssh.com" => Self::Zstd,
            "lz4" => Self::Lz4,
            "lz4@openssh.com" => Self::Lz4,
            "delayed" | "zlib@openssh.com,zlib" => Self::Delayed,
            _ => Self::None,
        }
    }

    /// Get algorithm name for SSH negotiation
    pub fn to_ssh_name(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Zlib => "zlib@openssh.com",
            Self::Zstd => "zstd@openssh.com",
            Self::Lz4 => "lz4@openssh.com",
            Self::Delayed => "zlib@openssh.com,zlib",
        }
    }

    /// Check if compression is enabled
    pub fn is_enabled(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Compression context for a connection
pub struct CompressionContext {
    /// Algorithm in use
    algorithm: CompressionAlgorithm,
    /// Compression level (1-9)
    level: u32,
    /// Whether compression is active
    active: bool,
    /// Compression statistics
    stats: CompressionStats,
}

/// Compression statistics
#[derive(Debug, Default, Clone)]
pub struct CompressionStats {
    /// Total uncompressed bytes sent
    pub bytes_sent_raw: u64,
    /// Total compressed bytes sent
    pub bytes_sent_compressed: u64,
    /// Total uncompressed bytes received
    pub bytes_received_raw: u64,
    /// Total compressed bytes received
    pub bytes_received_compressed: u64,
    /// Number of packets compressed
    pub packets_compressed: u64,
    /// Number of packets decompressed
    pub packets_decompressed: u64,
}

impl CompressionStats {
    /// Calculate compression ratio for sent data
    pub fn sent_ratio(&self) -> f64 {
        if self.bytes_sent_raw == 0 {
            1.0
        } else {
            self.bytes_sent_compressed as f64 / self.bytes_sent_raw as f64
        }
    }

    /// Calculate compression ratio for received data
    pub fn received_ratio(&self) -> f64 {
        if self.bytes_received_raw == 0 {
            1.0
        } else {
            self.bytes_received_compressed as f64 / self.bytes_received_raw as f64
        }
    }

    /// Get total bytes saved
    pub fn bytes_saved(&self) -> i64 {
        let sent_saved = self.bytes_sent_raw as i64 - self.bytes_sent_compressed as i64;
        let received_saved = self.bytes_received_raw as i64 - self.bytes_received_compressed as i64;
        sent_saved + received_saved
    }
}

impl CompressionContext {
    /// Create new compression context
    pub fn new(algorithm: CompressionAlgorithm, level: u32) -> Self {
        Self {
            algorithm,
            level: level.clamp(1, 9),
            active: algorithm.is_enabled(),
            stats: CompressionStats::default(),
        }
    }

    /// Enable compression (for delayed compression)
    pub fn enable(&mut self) {
        if self.algorithm == CompressionAlgorithm::Delayed {
            self.algorithm = CompressionAlgorithm::Zlib;
            self.active = true;
        }
    }

    /// Compress data
    pub fn compress(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.active || self.algorithm == CompressionAlgorithm::None {
            return Ok(data.to_vec());
        }

        let compressed = match self.algorithm {
            CompressionAlgorithm::Zlib => self.compress_zlib(data)?,
            CompressionAlgorithm::Zstd => self.compress_zstd(data)?,
            CompressionAlgorithm::Lz4 => self.compress_lz4(data)?,
            _ => data.to_vec(),
        };

        // Update statistics
        self.stats.bytes_sent_raw += data.len() as u64;
        self.stats.bytes_sent_compressed += compressed.len() as u64;
        self.stats.packets_compressed += 1;

        Ok(compressed)
    }

    /// Decompress data
    pub fn decompress(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.active || self.algorithm == CompressionAlgorithm::None {
            return Ok(data.to_vec());
        }

        let decompressed = match self.algorithm {
            CompressionAlgorithm::Zlib => self.decompress_zlib(data)?,
            CompressionAlgorithm::Zstd => self.decompress_zstd(data)?,
            CompressionAlgorithm::Lz4 => self.decompress_lz4(data)?,
            _ => data.to_vec(),
        };

        // Update statistics
        self.stats.bytes_received_compressed += data.len() as u64;
        self.stats.bytes_received_raw += decompressed.len() as u64;
        self.stats.packets_decompressed += 1;

        Ok(decompressed)
    }

    /// Compress using zlib
    fn compress_zlib(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = ZlibWriteEncoder::new(Vec::new(), ZlibLevel::new(self.level));
        encoder.write_all(data)
            .map_err(|e| QsshError::Protocol(format!("Zlib compression failed: {}", e)))?;
        encoder.finish()
            .map_err(|e| QsshError::Protocol(format!("Zlib compression finish failed: {}", e)))
    }

    /// Decompress using zlib
    fn decompress_zlib(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = ZlibDecoder::new(data);
        let mut result = Vec::new();
        decoder.read_to_end(&mut result)
            .map_err(|e| QsshError::Protocol(format!("Zlib decompression failed: {}", e)))?;
        Ok(result)
    }

    /// Compress using zstd
    fn compress_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        zstd::encode_all(data, self.level as i32)
            .map_err(|e| QsshError::Protocol(format!("Zstd compression failed: {}", e)))
    }

    /// Decompress using zstd
    fn decompress_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        zstd::decode_all(data)
            .map_err(|e| QsshError::Protocol(format!("Zstd decompression failed: {}", e)))
    }

    /// Compress using lz4
    fn compress_lz4(&self, data: &[u8]) -> Result<Vec<u8>> {
        lz4::block::compress(data, Some(lz4::block::CompressionMode::DEFAULT), true)
            .map_err(|e| QsshError::Protocol(format!("LZ4 compression failed: {}", e)))
    }

    /// Decompress using lz4
    fn decompress_lz4(&self, data: &[u8]) -> Result<Vec<u8>> {
        lz4::block::decompress(data, None)
            .map_err(|e| QsshError::Protocol(format!("LZ4 decompression failed: {}", e)))
    }

    /// Get compression statistics
    pub fn stats(&self) -> &CompressionStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = CompressionStats::default();
    }
}

/// Compression negotiation for SSH handshake
pub struct CompressionNegotiator {
    /// Client compression preferences
    client_algorithms: Vec<CompressionAlgorithm>,
    /// Server compression preferences
    server_algorithms: Vec<CompressionAlgorithm>,
}

impl CompressionNegotiator {
    /// Create new negotiator with default preferences
    pub fn new() -> Self {
        Self {
            client_algorithms: vec![
                CompressionAlgorithm::Lz4,    // Fastest
                CompressionAlgorithm::Zstd,   // Best ratio
                CompressionAlgorithm::Zlib,   // Standard
                CompressionAlgorithm::None,   // Fallback
            ],
            server_algorithms: vec![
                CompressionAlgorithm::Lz4,
                CompressionAlgorithm::Zstd,
                CompressionAlgorithm::Zlib,
                CompressionAlgorithm::None,
            ],
        }
    }

    /// Set client preferences
    pub fn set_client_preferences(&mut self, algorithms: Vec<CompressionAlgorithm>) {
        self.client_algorithms = algorithms;
    }

    /// Set server preferences
    pub fn set_server_preferences(&mut self, algorithms: Vec<CompressionAlgorithm>) {
        self.server_algorithms = algorithms;
    }

    /// Negotiate compression algorithm
    pub fn negotiate(&self) -> CompressionAlgorithm {
        // Find first matching algorithm
        for client_algo in &self.client_algorithms {
            for server_algo in &self.server_algorithms {
                if client_algo == server_algo {
                    return *client_algo;
                }
            }
        }

        // Default to no compression if no match
        CompressionAlgorithm::None
    }

    /// Get algorithm list for SSH packet
    pub fn get_algorithm_list(algorithms: &[CompressionAlgorithm]) -> String {
        algorithms
            .iter()
            .map(|a| a.to_ssh_name())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Adaptive compression that adjusts based on network conditions
pub struct AdaptiveCompression {
    /// Current compression context
    context: CompressionContext,
    /// Minimum data size to compress (bytes)
    min_compress_size: usize,
    /// Maximum compression level
    max_level: u32,
    /// Minimum compression level
    min_level: u32,
    /// Target compression ratio
    target_ratio: f64,
    /// Adaptation interval (packets)
    adapt_interval: u64,
    /// Packets since last adaptation
    packets_since_adapt: u64,
}

impl AdaptiveCompression {
    /// Create new adaptive compression
    pub fn new(algorithm: CompressionAlgorithm) -> Self {
        Self {
            context: CompressionContext::new(algorithm, 6),
            min_compress_size: 1024,  // Don't compress small packets
            max_level: 9,
            min_level: 1,
            target_ratio: 0.7,  // Target 30% reduction
            adapt_interval: 100,  // Adapt every 100 packets
            packets_since_adapt: 0,
        }
    }

    /// Compress with adaptation
    pub fn compress(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        // Skip compression for small data
        if data.len() < self.min_compress_size {
            return Ok(data.to_vec());
        }

        let result = self.context.compress(data)?;

        // Check if we should adapt
        self.packets_since_adapt += 1;
        if self.packets_since_adapt >= self.adapt_interval {
            self.adapt();
            self.packets_since_adapt = 0;
        }

        Ok(result)
    }

    /// Decompress data
    pub fn decompress(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.context.decompress(data)
    }

    /// Adapt compression level based on performance
    fn adapt(&mut self) {
        let ratio = self.context.stats().sent_ratio();

        if ratio > self.target_ratio && self.context.level < self.max_level {
            // Compression not effective enough, increase level
            self.context.level += 1;
        } else if ratio < self.target_ratio * 0.8 && self.context.level > self.min_level {
            // Compression too aggressive, decrease level
            self.context.level -= 1;
        }
    }

    /// Get compression statistics
    pub fn stats(&self) -> &CompressionStats {
        self.context.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_algorithms() {
        assert_eq!(CompressionAlgorithm::from_str("zlib"), CompressionAlgorithm::Zlib);
        assert_eq!(CompressionAlgorithm::from_str("none"), CompressionAlgorithm::None);
        assert_eq!(CompressionAlgorithm::from_str("lz4"), CompressionAlgorithm::Lz4);
        assert_eq!(CompressionAlgorithm::from_str("unknown"), CompressionAlgorithm::None);
    }

    #[test]
    fn test_zlib_compression() {
        let mut ctx = CompressionContext::new(CompressionAlgorithm::Zlib, 6);

        let data = b"Hello, this is test data that should compress well because it has repetition repetition repetition!";
        let compressed = ctx.compress(data).unwrap();
        assert!(compressed.len() < data.len());

        let decompressed = ctx.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_stats() {
        let mut ctx = CompressionContext::new(CompressionAlgorithm::Zlib, 6);

        let data = vec![b'A'; 1000];
        let _compressed = ctx.compress(&data).unwrap();

        let stats = ctx.stats();
        assert_eq!(stats.bytes_sent_raw, 1000);
        assert!(stats.bytes_sent_compressed < 1000);
        assert!(stats.sent_ratio() < 1.0);
        assert!(stats.bytes_saved() > 0);
    }

    #[test]
    fn test_compression_negotiation() {
        let mut negotiator = CompressionNegotiator::new();

        negotiator.set_client_preferences(vec![
            CompressionAlgorithm::Zlib,
            CompressionAlgorithm::None,
        ]);

        negotiator.set_server_preferences(vec![
            CompressionAlgorithm::Lz4,
            CompressionAlgorithm::Zlib,
        ]);

        let result = negotiator.negotiate();
        assert_eq!(result, CompressionAlgorithm::Zlib);
    }

    #[test]
    fn test_adaptive_compression() {
        let mut adaptive = AdaptiveCompression::new(CompressionAlgorithm::Zlib);

        // Small data should not be compressed
        let small_data = b"small";
        let result = adaptive.compress(small_data).unwrap();
        assert_eq!(result, small_data);

        // Large repetitive data should be compressed
        let large_data = vec![b'B'; 2000];
        let compressed = adaptive.compress(&large_data).unwrap();
        assert!(compressed.len() < large_data.len());
    }
}