use super::error::{Error, Result};
use super::mode::*;
use super::util::random_iv;

pub fn encrypt(plaintext: &[u8], key: &[u8], mode: Mode) -> Result<Vec<u8>> {
    match mode {
        Mode::ModeECB => encrypt_ecb(plaintext, key),
        Mode::ModeCTR => {
            // generate IV and prepend to ciphertext
            let iv = random_iv()?;
            let mut ciphertext: Vec<u8> = iv.to_vec();
            ciphertext.append(&mut ctr(plaintext, key, &iv, 0)?);
            Ok(ciphertext)
        }
        Mode::ModeGCM => Err(Error::AuthFailed), // not implemented yet
    }
}

pub fn decrypt(ciphertext: &[u8], key: &[u8], mode: Mode) -> Result<Vec<u8>> {
    match mode {
        Mode::ModeECB => decrypt_ecb(ciphertext, key),
        Mode::ModeCTR => {
            // extract and remove IV from ciphertext
            if ciphertext.len() < 12 {
                return Err(Error::InvalidCiphertext {
                    len: ciphertext.len(),
                    context: "CTR: missing 12-byte IV",
                });
            }

            let (iv_bytes, ciphertext) = ciphertext.split_at(12);
            let mut iv = [0u8; 12];
            iv.copy_from_slice(iv_bytes);

            ctr(ciphertext, key, &iv, 0)
        }
        Mode::ModeGCM => Err(Error::AuthFailed), // not implemented yet
    }
}
