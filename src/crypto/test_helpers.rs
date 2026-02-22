//! Test helpers for PQ crypto operations
//!
//! Now using pure-Rust fn-dsa + slh-dsa — no segfault risk.

#[cfg(test)]
pub mod test_support {
    use crate::Result;
    use super::super::PqKeyExchange;

    /// Create a PqKeyExchange for testing
    ///
    /// NOTE: This function now delegates to PqKeyExchange::new() instead of
    /// using mock data, as the mock approach had type compatibility issues.
    pub fn create_test_kex() -> Result<PqKeyExchange> {
        // Use the real implementation instead of mock data
        // The previous mock approach had type compatibility issues with pqcrypto traits
        PqKeyExchange::new()
    }
}
