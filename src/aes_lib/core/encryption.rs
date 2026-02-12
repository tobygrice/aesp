use super::constants::SBOX;
use super::core_util::{add_round_key, dbl};

#[inline(always)]
pub fn encrypt_block(plaintext: &[u8; 16], round_keys: &[[u8; 16]]) -> [u8; 16] {
    let mut state = *plaintext;
    let num_rounds = round_keys.len();

    add_round_key(&mut state, &round_keys[0]);

    for round_key in &round_keys[1..num_rounds - 1] {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, round_key);
    }

    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, round_keys.last().unwrap());

    state
}

#[inline(always)]
pub(crate) fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state {
        *byte = SBOX[*byte as usize];
    }
}

#[inline(always)]
pub(crate) fn shift_rows(state: &mut [u8; 16]) {
    let s = *state;
    for row in 0..4 {
        for col in 0..4 {
            let old_idx = ((col + row) & 3) * 4 + row;
            state[col * 4 + row] = s[old_idx];
        }
    }
}

// optimisation by https://crypto.stackexchange.com/a/71206
#[inline(always)]
pub(crate) fn mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let (a, b, c, d) = (state[i], state[i + 1], state[i + 2], state[i + 3]);
        state[i + 0] = dbl(a ^ b) ^ b ^ c ^ d; /* 2a + 3b + c + d */
        state[i + 1] = dbl(b ^ c) ^ c ^ d ^ a; /* 2b + 3c + d + a */
        state[i + 2] = dbl(c ^ d) ^ d ^ a ^ b; /* 2c + 3d + a + b */
        state[i + 3] = dbl(d ^ a) ^ a ^ b ^ c; /* 2d + 3a + b + c */
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes_lib::Key;
    use crate::aes_lib::error::Result;
    use crate::aes_lib::cipher::expand_key;

    #[test]
    fn test_mix_columns() {
        // test cases from https://en.wikipedia.org/wiki/Rijndael_MixColumns
        // Note: these are expressed as 4 columns of 4 bytes; we store column-major in [u8; 16].

        let mut test1: [u8; 16] = [
            // col 0
            0x63, 0x47, 0xa2, 0xf0,
            // col 1
            0xf2, 0x0a, 0x22, 0x5c,
            // col 2
            0x01, 0x01, 0x01, 0x01,
            // col 3
            0xc6, 0xc6, 0xc6, 0xc6,
        ];

        let mut test2: [u8; 16] = [
            // col 0
            0x01, 0x01, 0x01, 0x01,
            // col 1
            0xc6, 0xc6, 0xc6, 0xc6,
            // col 2
            0xd4, 0xd4, 0xd4, 0xd5,
            // col 3
            0x2d, 0x26, 0x31, 0x4c,
        ];

        mix_columns(&mut test1);
        mix_columns(&mut test2);

        assert_eq!(
            test1,
            [
                // col 0
                0x5d, 0xe0, 0x70, 0xbb,
                // col 1
                0x9f, 0xdc, 0x58, 0x9d,
                // col 2
                0x01, 0x01, 0x01, 0x01,
                // col 3
                0xc6, 0xc6, 0xc6, 0xc6,
            ],
            "mix columns test case 1 does not match"
        );

        assert_eq!(
            test2,
            [
                // col 0
                0x01, 0x01, 0x01, 0x01,
                // col 1
                0xc6, 0xc6, 0xc6, 0xc6,
                // col 2
                0xd5, 0xd5, 0xd7, 0xd6,
                // col 3
                0x4d, 0x7e, 0xbd, 0xf8,
            ],
            "mix columns test case 2 does not match"
        );
    }

    #[test]
    fn test_encrypt_block_256() -> Result<()> {
        // test case from:
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core256.pdf
        let key: [u8; 32] = [
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, //
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81, //
            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, //
            0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4, //
        ];

        let plaintext: [u8; 16] = [
            // col 0
            0x6B, 0xC1, 0xBE, 0xE2,
            // col 1
            0x2E, 0x40, 0x9F, 0x96,
            // col 2
            0xE9, 0x3D, 0x7E, 0x11,
            // col 3
            0x73, 0x93, 0x17, 0x2A,
        ];

        let expected: [u8; 16] = [
            // col 0
            0xF3, 0xEE, 0xD1, 0xBD,
            // col 1
            0xB5, 0xD2, 0xA0, 0x3C,
            // col 2
            0x06, 0x4B, 0x5A, 0x7E,
            // col 3
            0x3D, 0xB1, 0x81, 0xF8,
        ];

        let key = Key::try_from_slice(&key)?;
        let round_keys = expand_key(&key);
        let actual = encrypt_block(&plaintext, &round_keys);

        assert_eq!(actual, expected, "incorrect AES-256 encryption of block");
        Ok(())
    }

    #[test]
    fn test_encrypt_block_192() -> Result<()> {
        // test case from:
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core192.pdf
        let key: [u8; 24] = [
            0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, //
            0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5, //
            0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B, //
        ];

        let plaintext: [u8; 16] = [
            // col 0
            0x6B, 0xC1, 0xBE, 0xE2,
            // col 1
            0x2E, 0x40, 0x9F, 0x96,
            // col 2
            0xE9, 0x3D, 0x7E, 0x11,
            // col 3
            0x73, 0x93, 0x17, 0x2A,
        ];

        let expected: [u8; 16] = [
            // col 0
            0xBD, 0x33, 0x4F, 0x1D,
            // col 1
            0x6E, 0x45, 0xF2, 0x5F,
            // col 2
            0xF7, 0x12, 0xA2, 0x14,
            // col 3
            0x57, 0x1F, 0xA5, 0xCC,
        ];

        let key = Key::try_from_slice(&key)?;
        let round_keys = expand_key(&key);
        let actual = encrypt_block(&plaintext, &round_keys);

        assert_eq!(actual, expected, "incorrect AES-192 encryption of block");
        Ok(())
    }

    #[test]
    fn test_encrypt_block_128() -> Result<()> {
        // test case from:
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf
        let key: [u8; 16] = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, //
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C, //
        ];

        let plaintext: [u8; 16] = [
            // col 0
            0x6B, 0xC1, 0xBE, 0xE2,
            // col 1
            0x2E, 0x40, 0x9F, 0x96,
            // col 2
            0xE9, 0x3D, 0x7E, 0x11,
            // col 3
            0x73, 0x93, 0x17, 0x2A,
        ];

        let expected: [u8; 16] = [
            // col 0
            0x3A, 0xD7, 0x7B, 0xB4,
            // col 1
            0x0D, 0x7A, 0x36, 0x60,
            // col 2
            0xA8, 0x9E, 0xCA, 0xF3,
            // col 3
            0x24, 0x66, 0xEF, 0x97,
        ];

        let key = Key::try_from_slice(&key)?;
        let round_keys = expand_key(&key);
        let actual = encrypt_block(&plaintext, &round_keys);

        assert_eq!(actual, expected, "incorrect AES-128 encryption of block");
        Ok(())
    }
}
