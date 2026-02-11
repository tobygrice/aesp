mod aes_core;

pub use aes_core::{
    Error, KeySize, Result, decrypt_ctr, decrypt_ecb, decrypt_gcm, encrypt_ctr, encrypt_ecb,
    encrypt_gcm, random_key,
};
