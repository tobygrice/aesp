//! This crate provides an intuitive interface for AES-128, AES-192, and AES-256 encryption and decryption.
//! The following modes of operation are supported:
//! - [Galois/counter mode](crate::aes_lib::cipher::Cipher::encrypt_gcm) (GCM), with optional additional authenticated data (AAD)
//! - [Counter mode](crate::aes_lib::cipher::Cipher::encrypt_ctr) (CTR)
//! - [Electronic codebook mode](crate::aes_lib::cipher::Cipher::encrypt_ecb) (ECB)


mod aes_lib;

pub use aes_lib::{Cipher, Error, Key, Result};
