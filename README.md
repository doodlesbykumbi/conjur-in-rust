# conjur-in-rust

On one Focus Friday I thought to explore Rust in some detail. I learned about the memory safety guarantees of Rust. I thought memory safety would be a good fit for Conjur core. 

My port of entry is symmetric encryption. The initial goal was the ability to decrypt Conjur data.
Conjur uses `AES-GCM`, and there's a nice Rust crate `aes-gcm` with the necessary capabilities to implement this.

While looking into `AES-GCM` I learned about an algorithm with better performance, `ChaCha20-Poly1305`. Some exploratioins revealed that it would be trivial to switch from `AES-GCM` to `ChaCha20-Poly1305` while maintaining the same data key. This is mainly because the packing of encrypted data for storage by Conjur allows specification of an algorithm version, which would allow data encrypted by different algorithms to co-exist.

## What's done

1. POC of decrypting Conjur data
2. POC of encrypting then decrypting Conjur data using `ChaCha20-Poly1305`
