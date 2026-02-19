// used for both encryption and decryption
#[inline(always)]
pub(crate) fn add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

// adapted from https://crypto.stackexchange.com/a/71206
#[inline(always)]
pub(crate) fn dbl(a: u8) -> u8 {
    (a << 1) ^ (0x1B & (0u8).wrapping_sub((a >> 7) & 1))
}
