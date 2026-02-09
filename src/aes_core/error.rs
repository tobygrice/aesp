use thiserror::Error;
use rand::rand_core;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid key length: {len} bytes (expected 16, 24, or 32)")]
    InvalidKeyLength { len: usize },

    #[error("input size caused counter overflow (maximum input size for 32 bit counter is 16 * 2^32 bytes)")]
    CounterOverflow,

    #[error("invalid nonce length for GCM: {len} bytes (expected 12 bytes)")]
    InvalidNonceLength { len: usize },

    #[error("invalid ciphertext length: {len} bytes ({context})")]
    InvalidCiphertext { len: usize, context: &'static str },

    #[error("OS RNG failed in random key generation")]
    Rng(#[from] rand_core::OsError),

    #[error("GCM authentication failed (invalid tag)")]
    AuthFailed,
}
