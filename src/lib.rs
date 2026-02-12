mod aes_lib;

pub use aes_lib::{
    Error, KeySize, Result, decrypt_ctr, decrypt_ecb, decrypt_gcm, encrypt_ctr, encrypt_ecb,
    encrypt_gcm, random_key,
};
