//! Standalone binary to test pqcrypto initialization

fn main() {
    println!("Testing pqcrypto keypair generation as standalone binary...\n");

    // Set larger stack size if needed
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024) // 16MB stack
        .spawn(|| {
            test_keypairs();
        })
        .unwrap()
        .join()
        .unwrap();
}

fn test_keypairs() {
    use pqcrypto_sphincsplus::sphincsharaka128fsimple as sphincs;
    use pqcrypto_falcon::falcon512;
    use pqcrypto_traits::sign::{PublicKey, SecretKey};

    println!("Generating SPHINCS+ keypair...");
    match std::panic::catch_unwind(|| {
        sphincs::keypair()
    }) {
        Ok((pk, sk)) => {
            println!("✅ SPHINCS+ keypair generated successfully!");
            println!("   Public key: {} bytes", pk.as_bytes().len());
            println!("   Secret key: {} bytes", sk.as_bytes().len());
        }
        Err(e) => {
            println!("❌ SPHINCS+ keypair generation panicked: {:?}", e);
        }
    }

    println!("\nGenerating Falcon-512 keypair...");
    match std::panic::catch_unwind(|| {
        falcon512::keypair()
    }) {
        Ok((pk, sk)) => {
            println!("✅ Falcon-512 keypair generated successfully!");
            println!("   Public key: {} bytes", pk.as_bytes().len());
            println!("   Secret key: {} bytes", sk.as_bytes().len());
        }
        Err(e) => {
            println!("❌ Falcon-512 keypair generation panicked: {:?}", e);
        }
    }
}