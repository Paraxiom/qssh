//! Test helpers that avoid segfaults

#[cfg(test)]
pub mod test_support {
    use crate::Result;
    use super::super::PqKeyExchange;

    /// Create a mock PqKeyExchange for testing without calling keypair()
    /// This avoids the segfault in test environments
    pub fn create_test_kex() -> Result<PqKeyExchange> {
        use pqcrypto_sphincsplus::sphincsharaka128fsimple as sphincs;
        use pqcrypto_falcon::falcon512;

        // Create keys from fixed test vectors instead of generating
        // This avoids the segfault in keypair() functions

        // These are not real keys - just valid-sized data for testing
        let sphincs_pk_bytes = vec![0x01; 32]; // SPHINCS+ public key is 32 bytes
        let sphincs_sk_bytes = vec![0x02; 64]; // SPHINCS+ secret key is 64 bytes

        let falcon_pk_bytes = vec![0x03; 897]; // Falcon-512 public key
        let falcon_sk_bytes = vec![0x04; 1281]; // Falcon-512 secret key

        let sphincs_pk = sphincs::PublicKey::from_bytes(&sphincs_pk_bytes)
            .expect("Failed to create test SPHINCS+ public key");
        let sphincs_sk = sphincs::SecretKey::from_bytes(&sphincs_sk_bytes)
            .expect("Failed to create test SPHINCS+ secret key");

        let falcon_pk = falcon512::PublicKey::from_bytes(&falcon_pk_bytes)
            .expect("Failed to create test Falcon public key");
        let falcon_sk = falcon512::SecretKey::from_bytes(&falcon_sk_bytes)
            .expect("Failed to create test Falcon secret key");

        Ok(PqKeyExchange {
            sphincs_sk,
            sphincs_pk,
            falcon_sk,
            falcon_pk,
        })
    }
}