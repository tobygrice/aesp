use rand::TryRngCore;
use rand::rngs::OsRng;

use crate::aesp::error::Result;

pub(crate) fn random_iv() -> Result<[u8; 12]> {
    let mut iv = [0u8; 12];
    OsRng.try_fill_bytes(&mut iv)?;
    Ok(iv)
}

#[inline(always)]
pub(crate) fn xor_words(a: &[u8; 4], b: &[u8; 4]) -> [u8; 4] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}