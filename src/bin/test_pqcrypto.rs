//! Standalone binary to test pure-Rust PQC implementations (fn-dsa + slh-dsa)

use fn_dsa::KeyPairGenerator as _;
use signature::Keypair as _;

fn main() {
    println!("Testing pure-Rust post-quantum crypto...\n");

    println!("Generating SLH-DSA (SPHINCS+) keypair...");
    match std::panic::catch_unwind(|| {
        use aes_gcm::aead::OsRng;
        let sk = slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::new(&mut OsRng);
        let pk = sk.verifying_key().clone();
        (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
    }) {
        Ok((sk, pk)) => {
            println!("  SLH-DSA keypair generated successfully!");
            println!("   Public key: {} bytes", pk.len());
            println!("   Secret key: {} bytes", sk.len());
        }
        Err(e) => {
            println!("  SLH-DSA keypair generation panicked: {:?}", e);
        }
    }

    println!("\nGenerating FN-DSA (Falcon-512) keypair...");
    match std::panic::catch_unwind(|| {
        use aes_gcm::aead::OsRng;
        let mut sk = vec![0u8; fn_dsa::sign_key_size(fn_dsa::FN_DSA_LOGN_512)];
        let mut pk = vec![0u8; fn_dsa::vrfy_key_size(fn_dsa::FN_DSA_LOGN_512)];
        fn_dsa::KeyPairGeneratorStandard::default()
            .keygen(fn_dsa::FN_DSA_LOGN_512, &mut OsRng, &mut sk, &mut pk);
        (sk, pk)
    }) {
        Ok((sk, pk)) => {
            println!("  FN-DSA keypair generated successfully!");
            println!("   Public key: {} bytes", pk.len());
            println!("   Secret key: {} bytes", sk.len());
        }
        Err(e) => {
            println!("  FN-DSA keypair generation panicked: {:?}", e);
        }
    }
}
