use rand::TryRngCore;
use rand::rngs::OsRng;

use super::error::{Error, Result};

// adapted from https://crypto.stackexchange.com/a/71206
#[inline(always)]
pub(crate) fn dbl(a: u8) -> u8 {
    (a << 1) ^ (0x1B & (0u8).wrapping_sub((a >> 7) & 1))
}

pub(crate) fn random_iv() -> Result<[u8; 12]> {
    let mut iv = [0u8; 12];
    OsRng.try_fill_bytes(&mut iv)?;
    Ok(iv)
}

pub(crate) fn unpad(input: &mut Vec<u8>) {
    // PKCS#7: pad with number of elems to pad
    let pad_value: usize = match input.last() {
        Some(v) => *v as usize,
        None => 0,
    };
    input.truncate(input.len() - pad_value);
}

// this function was written with assistance of an LLM
pub(crate) fn blockify(input: &[u8]) -> Result<Vec<[[u8; 4]; 4]>> {
    if input.len() % 16 != 0 {
        return Err(Error::InvalidCiphertext {
            len: input.len(),
            context: "blockify: input not a multiple of 16 bytes",
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

// this function was written with assistance of an LLM
pub(crate) fn blockify_pad(input: &[u8], pkcs7: bool) -> Vec<[[u8; 4]; 4]> {
    let pad_len = (16 - (input.len() % 16)) as u8; // 16 if rem == 0
    let total_bytes = input.len() + pad_len as usize;

    let mut out: Vec<[[u8; 4]; 4]> = Vec::with_capacity(total_bytes / 16);

    let mut chunks = input.chunks_exact(16);
    for c in &mut chunks {
        out.push([
            [c[00], c[01], c[02], c[03]],
            [c[04], c[05], c[06], c[07]],
            [c[08], c[09], c[10], c[11]],
            [c[12], c[13], c[14], c[15]],
        ]);
    }

    let r = chunks.remainder(); // len = rem (0..15)
    let mut last = if pkcs7 { [[pad_len; 4]; 4] } else { [[0u8; 4]; 4] };
        // pre-fill with padding bytes

    for (i, &b) in r.iter().enumerate() {
        last[i / 4][i % 4] = b;
    }

    out.push(last);
    out
}

#[inline(always)]
pub(crate) fn ctr_block(iv: &[u8; 12], ctr: u32) -> [[u8; 4]; 4] {
    let cb = ctr.to_be_bytes();
    [
        [iv[00], iv[01], iv[02], iv[03]],
        [iv[04], iv[05], iv[06], iv[07]],
        [iv[08], iv[09], iv[10], iv[11]],
        [cb[00], cb[01], cb[02], cb[03]],
    ]
}


#[inline(always)]
pub(crate) fn xor_chunks(y: &[u8; 16], chunk: &[u8]) -> [u8; 16] {
    let mut out: [u8; 16] = *y;
    for i in 0..chunk.len() {
        out[i] ^= chunk[i];
    }
    out
}

#[inline(always)]
pub(crate) fn flatten_block(b: [[u8; 4]; 4]) -> [u8; 16] {
    [
        b[0][0], b[0][1], b[0][2], b[0][3],
        b[1][0], b[1][1], b[1][2], b[1][3],
        b[2][0], b[2][1], b[2][2], b[2][3],
        b[3][0], b[3][1], b[3][2], b[3][3],
    ]
}

// written by an LLM!
#[inline(always)]
pub(crate) fn gf_mul(tag: [u8; 16], h: [u8; 16]) -> [u8; 16] {
    const R: u128 = 0xE100_0000_0000_0000_0000_0000_0000_0000;

    let x = u128::from_be_bytes(tag);
    let mut v = u128::from_be_bytes(h);
    let mut z: u128 = 0;

    // Process x bits from MSB -> LSB
    for i in 0..128 {
        let bit = (x >> (127 - i)) & 1;
        // If bit == 1, z ^= v (branchless)
        z ^= v & (0u128.wrapping_sub(bit));

        // v = v >> 1; if LSB was 1, v ^= R
        let lsb = v & 1;
        v >>= 1;
        v ^= R & (0u128.wrapping_sub(lsb));
    }

    z.to_be_bytes()
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockify_pad() {
        // 20 bytes -> pads to 32 bytes, so 2 blocks/states.
        let plaintext: [u8; 20] = [
            0x6B, 0xC1, 0xBE, 0xE2, //
            0x2E, 0x40, 0x9F, 0x96, //
            0xE9, 0x3D, 0x7E, 0x11, //
            0x73, 0x93, 0x17, 0x2A, //
            0xAE, 0x2D, 0x8A, 0x57, //
        ];

        let expected: Vec<[[u8; 4]; 4]> = vec![
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

        let actual = blockify_pad(&plaintext, true);

        assert_eq!(actual, expected);
    }
}
