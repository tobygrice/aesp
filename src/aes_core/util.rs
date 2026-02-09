use rand::TryRngCore;
use rand::rngs::OsRng;

use super::error::{Error, Result};

// adapted from https://crypto.stackexchange.com/a/71206
#[inline(always)]
pub(crate) fn dbl(a: u8) -> u8 {
    (a << 1) ^ (0x1B & (0u8).wrapping_sub((a >> 7) & 1))
}

#[inline]
pub(crate) fn random_iv() -> Result<[u8; 12]> {
    let mut iv = [0u8; 12];
    OsRng.try_fill_bytes(&mut iv)?;
    Ok(iv)
}

pub(crate) fn pad(plaintext: &[u8]) -> Vec<u8> {
    // PKCS#7: pad with number of elems to pad
    let mut res = plaintext.to_vec();
    let pad_value = 16 - (plaintext.len() % 16);

    res.extend(std::iter::repeat(pad_value as u8).take(pad_value));

    res
}

pub(crate) fn unpad(plaintext: &[u8]) -> Vec<u8> {
    // PKCS#7: pad with number of elems to pad
    let mut res = plaintext.to_vec();
    let pad_value: usize = match res.last() {
        Some(v) => *v as usize,
        None => 0,
    };

    res.truncate(res.len() - pad_value);

    res
}

// this function was written with assistance of an LLM
pub(crate) fn blockify(input: Vec<u8>) -> Result<Vec<[[u8; 4]; 4]>> {
    if input.len() % 16 != 0 {
        return Err(Error::InvalidCiphertext {
            len: input.len(),
            context: "ECB: not a multiple of 16 bytes",
        });
    }

    Ok(input
        .chunks_exact(16)
        .map(|c| {
            [
                [c[00], c[01], c[02], c[03]],
                [c[04], c[05], c[06], c[07]],
                [c[08], c[09], c[10], c[11]],
                [c[12], c[13], c[14], c[15]],
            ]
        })
        .collect())
}

#[inline]
pub(crate) fn ctr_block(iv: &[u8; 12], ctr: u32) -> [[u8; 4]; 4] {
    let cb = ctr.to_be_bytes();
    [
        [iv[00], iv[01], iv[02], iv[03]],
        [iv[04], iv[05], iv[06], iv[07]],
        [iv[08], iv[09], iv[10], iv[11]],
        [cb[00], cb[01], cb[02], cb[03]],
    ]
}

#[inline]
pub(crate) fn xor_block(keystream: [[u8; 4]; 4], chunk: &[u8]) -> Vec<u8> {
    keystream
        .iter()
        .flatten()
        .zip(chunk.iter())
        .map(|(k, c)| k ^ c)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding() {
        let plaintext: [u8; 20] = [
            0x6B, 0xC1, 0xBE, 0xE2, //
            0x2E, 0x40, 0x9F, 0x96, //
            0xE9, 0x3D, 0x7E, 0x11, //
            0x73, 0x93, 0x17, 0x2A, //
            0xAE, 0x2D, 0x8A, 0x57, //
        ];

        let padded: Vec<u8> = vec![
            0x6B, 0xC1, 0xBE, 0xE2, //
            0x2E, 0x40, 0x9F, 0x96, //
            0xE9, 0x3D, 0x7E, 0x11, //
            0x73, 0x93, 0x17, 0x2A, //
            0xAE, 0x2D, 0x8A, 0x57, //
            0x0C, 0x0C, 0x0C, 0x0C, //
            0x0C, 0x0C, 0x0C, 0x0C, //
            0x0C, 0x0C, 0x0C, 0x0C, //
        ];

        let actual1 = pad(&plaintext);
        assert_eq!(actual1, padded, "plaintext padded incorrectly");

        let actual2 = unpad(&actual1);
        assert_eq!(actual2, plaintext, "plaintext unpadded incorrectly");
    }

    #[test]
    fn test_blockify() -> Result<()> {
        // 20 bytes -> pads to 32 bytes, so 2 blocks/states.
        let plaintext: [u8; 20] = [
            0x6B, 0xC1, 0xBE, 0xE2, //
            0x2E, 0x40, 0x9F, 0x96, //
            0xE9, 0x3D, 0x7E, 0x11, //
            0x73, 0x93, 0x17, 0x2A, //
            0xAE, 0x2D, 0x8A, 0x57, //
        ];

        let expected1: Vec<[[u8; 4]; 4]> = vec![
            [
                [0x6B, 0xC1, 0xBE, 0xE2],
                [0x2E, 0x40, 0x9F, 0x96],
                [0xE9, 0x3D, 0x7E, 0x11],
                [0x73, 0x93, 0x17, 0x2A],
            ],
            [
                [0xAE, 0x2D, 0x8A, 0x57],
                [0x0C, 0x0C, 0x0C, 0x0C],
                [0x0C, 0x0C, 0x0C, 0x0C],
                [0x0C, 0x0C, 0x0C, 0x0C],
            ],
        ];

        let expected2: Vec<[[u8; 4]; 4]> = vec![[
            [0x6B, 0xC1, 0xBE, 0xE2],
            [0x2E, 0x40, 0x9F, 0x96],
            [0xE9, 0x3D, 0x06, 0x06],
            [0x06, 0x06, 0x06, 0x06],
        ]];

        let padded1 = pad(&plaintext);
        let padded2 = pad(&plaintext[..10]);
        let actual1 = blockify(padded1)?;
        let actual2 = blockify(padded2)?;

        assert_eq!(actual1, expected1);
        assert_eq!(actual2, expected2);

        Ok(())
    }
}
