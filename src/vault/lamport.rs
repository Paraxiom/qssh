//! Lamport One-Time Signatures for QSSH
//! 
//! Quantum-resistant signatures using only hash functions

use sha3::{Sha3_256, Sha3_512, Digest};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroize;

/// Lamport keypair for one-time signatures
#[derive(Clone)]
pub struct LamportKeypair {
    /// Private key (2 * 256 * 32 bytes)
    private_key: Vec<[u8; 32]>,
    /// Public key (2 * 256 * 32 bytes)
    public_key: Vec<[u8; 32]>,
    /// Used flag to prevent reuse
    used: bool,
}

/// Lamport signature
#[derive(Clone, Debug)]
pub struct LamportSignature {
    /// Signature blocks (256 * 32 bytes)
    blocks: Vec<[u8; 32]>,
}

impl LamportKeypair {
    /// Generate a new Lamport keypair from seed
    pub fn generate(seed: &[u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        
        // Generate private key: 2 * 256 random values of 32 bytes each
        let mut private_key = Vec::with_capacity(512);
        let mut public_key = Vec::with_capacity(512);
        
        for _ in 0..512 {
            let mut priv_block = [0u8; 32];
            rng.fill_bytes(&mut priv_block);
            
            // Public key is hash of private key
            let mut hasher = Sha3_256::new();
            hasher.update(&priv_block);
            let mut pub_block = [0u8; 32];
            pub_block.copy_from_slice(&hasher.finalize());
            
            private_key.push(priv_block);
            public_key.push(pub_block);
        }
        
        Self {
            private_key,
            public_key,
            used: false,
        }
    }
    
    /// Sign a message (consumes the keypair - one-time use only!)
    pub fn sign(&mut self, message: &[u8]) -> Result<LamportSignature, &'static str> {
        if self.used {
            return Err("Lamport key already used");
        }
        
        // Hash the message
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        
        // Create signature by revealing private key blocks based on hash bits
        let mut signature_blocks = Vec::with_capacity(256);
        
        for (i, hash_byte) in hash.iter().enumerate() {
            for bit in 0..8 {
                let bit_value = (hash_byte >> (7 - bit)) & 1;
                let index = i * 8 + bit;
                
                // Select private key block based on bit value
                let block_index = index * 2 + bit_value as usize;
                signature_blocks.push(self.private_key[block_index]);
            }
        }
        
        // Mark as used and zeroize private key
        self.used = true;
        for block in &mut self.private_key {
            block.zeroize();
        }
        
        Ok(LamportSignature {
            blocks: signature_blocks,
        })
    }
    
    /// Get public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(512 * 32);
        for block in &self.public_key {
            bytes.extend_from_slice(block);
        }
        bytes
    }
    
    /// Verify a signature
    pub fn verify(public_key: &[u8], message: &[u8], signature: &LamportSignature) -> bool {
        // Check public key length
        if public_key.len() != 512 * 32 {
            return false;
        }
        
        // Hash the message
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        
        // Verify each signature block
        for (i, hash_byte) in hash.iter().enumerate() {
            for bit in 0..8 {
                let bit_value = (hash_byte >> (7 - bit)) & 1;
                let sig_index = i * 8 + bit;
                
                // Hash the signature block
                let mut hasher = Sha3_256::new();
                hasher.update(&signature.blocks[sig_index]);
                let computed_pub = hasher.finalize();
                
                // Compare with public key block
                let pub_index = sig_index * 2 + bit_value as usize;
                let pub_start = pub_index * 32;
                let pub_end = pub_start + 32;
                
                if computed_pub.as_slice() != &public_key[pub_start..pub_end] {
                    return false;
                }
            }
        }
        
        true
    }
}

/// Merkle tree for multiple Lamport signatures
pub struct LamportMerkleTree {
    /// Tree height (2^height leaves)
    height: usize,
    /// Leaf nodes (public key hashes)
    leaves: Vec<[u8; 32]>,
    /// Root hash
    root: [u8; 32],
}

impl LamportMerkleTree {
    /// Build Merkle tree from public keys
    pub fn build(public_keys: &[Vec<u8>]) -> Self {
        let height = (public_keys.len() as f64).log2().ceil() as usize;
        let tree_size = 1 << height;
        
        // Hash all public keys to create leaves
        let mut leaves = Vec::with_capacity(tree_size);
        for pk in public_keys {
            let mut hasher = Sha3_256::new();
            hasher.update(pk);
            let mut leaf = [0u8; 32];
            leaf.copy_from_slice(&hasher.finalize());
            leaves.push(leaf);
        }
        
        // Pad with empty leaves if needed
        while leaves.len() < tree_size {
            leaves.push([0u8; 32]);
        }
        
        // Build tree bottom-up
        let root = Self::compute_root(&leaves);
        
        Self {
            height,
            leaves,
            root,
        }
    }
    
    /// Compute Merkle root
    fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.len() == 1 {
            return leaves[0];
        }
        
        let mut current_level = leaves.to_vec();
        
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for i in (0..current_level.len()).step_by(2) {
                let mut hasher = Sha3_256::new();
                hasher.update(&current_level[i]);
                if i + 1 < current_level.len() {
                    hasher.update(&current_level[i + 1]);
                } else {
                    hasher.update(&current_level[i]); // Duplicate last node if odd
                }
                
                let mut parent = [0u8; 32];
                parent.copy_from_slice(&hasher.finalize());
                next_level.push(parent);
            }
            
            current_level = next_level;
        }
        
        current_level[0]
    }
    
    /// Generate authentication path for a leaf
    pub fn auth_path(&self, index: usize) -> Vec<[u8; 32]> {
        let mut path = Vec::new();
        let mut current_index = index;
        let mut level_nodes = self.leaves.clone();
        
        for _ in 0..self.height {
            // Get sibling node
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            
            if sibling_index < level_nodes.len() {
                path.push(level_nodes[sibling_index]);
            } else {
                path.push([0u8; 32]); // Padding node
            }
            
            // Move to next level
            current_index /= 2;
            
            // Compute next level
            let mut next_level = Vec::new();
            for i in (0..level_nodes.len()).step_by(2) {
                let mut hasher = Sha3_256::new();
                hasher.update(&level_nodes[i]);
                if i + 1 < level_nodes.len() {
                    hasher.update(&level_nodes[i + 1]);
                } else {
                    hasher.update(&level_nodes[i]);
                }
                
                let mut parent = [0u8; 32];
                parent.copy_from_slice(&hasher.finalize());
                next_level.push(parent);
            }
            
            level_nodes = next_level;
        }
        
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lamport_sign_verify() {
        let seed = [42u8; 32];
        let mut keypair = LamportKeypair::generate(&seed);
        let public_key = keypair.public_key_bytes();

        let message = b"Hello, quantum world!";
        let signature = keypair.sign(message).expect("Failed to sign message");

        assert!(LamportKeypair::verify(&public_key, message, &signature));

        // Wrong message should fail
        let wrong_message = b"Hello, classical world!";
        assert!(!LamportKeypair::verify(&public_key, wrong_message, &signature));
    }
    
    #[test]
    fn test_lamport_one_time_only() {
        let seed = [42u8; 32];
        let mut keypair = LamportKeypair::generate(&seed);

        let message = b"First message";
        let _sig1 = keypair.sign(message).expect("Failed to sign first message");

        // Second sign should fail
        let result = keypair.sign(b"Second message");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_merkle_tree() {
        // Generate some keypairs
        let mut public_keys = Vec::new();
        for i in 0..4 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            let keypair = LamportKeypair::generate(&seed);
            public_keys.push(keypair.public_key_bytes());
        }
        
        let tree = LamportMerkleTree::build(&public_keys);
        assert_eq!(tree.height, 2); // log2(4) = 2
        
        // Generate auth paths
        for i in 0..4 {
            let path = tree.auth_path(i);
            assert_eq!(path.len(), 2); // Height of tree
        }
    }
}