use rand::TryRngCore;
use rand::rngs::OsRng;

use crate::aesp::error::*;

pub(crate) fn random_iv() -> Result<[u8; 12]> {
    let mut iv = [0u8; 12];
    OsRng.try_fill_bytes(&mut iv)?;
    Ok(iv)
}

#[inline(always)]
pub(crate) fn xor_words(a: &[u8; 4], b: &[u8; 4]) -> [u8; 4] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

/// PKCS#7 padding for ECB (16-byte blocks)
pub(crate) fn pad(plaintext: &[u8]) -> Vec<u8> {
    let rem = plaintext.len() % 16;
    let pad_len = if rem == 0 { 16 } else { 16 - rem };

    let total_len = plaintext
        .len()
        .checked_add(pad_len)
        .expect("plaintext too large to pad");

    let mut out = vec![0u8; total_len];
    out[..plaintext.len()].copy_from_slice(plaintext);
    out[plaintext.len()..].fill(pad_len as u8);
    out
}

/// Remove and validate PKCS#7 padding
pub(crate) fn unpad(input: &mut Vec<u8>) -> Result<()> {
    if input.is_empty() {
        return Err(Error::InvalidCiphertext {
            len: 0,
            context: "Unpad: attempted to unpad empty input",
        });
    }

    let pad = *input.last().unwrap() as usize;
    if pad == 0 || pad > 16 || pad > input.len() {
        return Err(Error::InvalidCiphertext {
            len: input.len(),
            context: "Unpad: invalid padding length specified by last byte",
        });
    }

    let start = input.len() - pad;
    if !input[start..].iter().all(|&b| b as usize == pad) {
        return Err(Error::InvalidCiphertext {
            len: input.len(),
            context: "Unpad: invalid PKCS#7 padding format",
        });
    }

    input.truncate(start);
    Ok(())
}
