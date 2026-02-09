mod aes_core;

pub use aes_core::{decrypt, encrypt, Mode, random_key, KeySize, Result, Error};
