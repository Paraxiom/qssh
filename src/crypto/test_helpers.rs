//! Test helpers that avoid segfaults
//!
//! NOTE: This module is currently non-functional due to API changes in pqcrypto.
//! The PqKeyExchange::new() function should be used instead for testing.

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
