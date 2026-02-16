use crate::aesp::core::encrypt_block;
use crate::aesp::error::*;
use crate::aesp::modes::util::{ctr_block, gf_mul, xor_chunks};

/*
https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
diagram on page 5

H = block of 0s encrypted with key
start with accumulator s = 0
for each 16-byte block b:
    s = (s ^ b) * H (GF128 multiplication)

where blocks are:
    - all AAD blocks (padded)
    - all ciphertext blocks (padded)
    - one block comprised aad.len || ct.len

final tag = s ^ encrypt_block(J0, key)

where J0 is:
    - IV || 1u32 (initial ctr block for ctr = 1)
*/
/// Function to compute GCM cryptographic tag from ciphertext + AAD
pub fn compute_tag(
    ciphertext: &[u8],
    round_keys: &[[u8; 16]],
    iv: &[u8; 12],
    aad: &[u8],
) -> Result<[u8; 16]> {
    // create initial ctr block (xor'd with tag at end)
    let j0 = ctr_block(iv, 1);
    let j0_e = encrypt_block(&j0, round_keys);

    // generate H by encrypting block of 0s
    let h = encrypt_block(&[0u8; 16], round_keys);

    // s = ghash accumulator
    let mut s = [0u8; 16];

    // compute s over AAD
    for aad_chunk in aad.chunks(16) {
        s = gf_mul(xor_chunks(&s, aad_chunk), h);
    }

    // compute s over ciphertext
    for ct_chunk in ciphertext.chunks(16) {
        s = gf_mul(xor_chunks(&s, ct_chunk), h);
    }

    // authenticate message length, build aad_size || ct_size
    let aad_size = (aad.len() as u64) * 8; // size in bits
    let ct_size = (ciphertext.len() as u64) * 8; // size in bits
    let mut len = [0u8; 16];
    len[..8].copy_from_slice(&aad_size.to_be_bytes());
    len[8..].copy_from_slice(&ct_size.to_be_bytes());

    s = gf_mul(xor_chunks(&s, &len), h);

    // tag = E(K, J0) ^ S
    Ok(xor_chunks(&s, &j0_e))
}


// gcm tests written with LLM assistance
#[cfg(test)]
mod test_gcm {
    use super::*;
    use crate::aesp::cipher::Cipher;
    use crate::aesp::key::Key;
    use crate::aesp::modes::util::test_util::{hex_to_bytes, hex_to_arr_12, hex_to_arr_16};

    // all test vectors from
    // https://boringssl.googlesource.com/boringssl.git/%2B/734fca08902889c88e84839134262bdf5c12eebf/crypto/cipher/cipher_test.txt

    #[test]
    fn tag_no_pt_no_aad() -> Result<()> {
        // Vector:
        // key = 00..00 (16 bytes)
        // iv  = 00..00 (12 bytes)
        // aad = empty
        // ct  = empty
        // tag = 58e2fccefa7e3061367f1d57a4e7455a
        let key = hex_to_bytes("00000000000000000000000000000000");
        let iv = hex_to_arr_12("000000000000000000000000");
        let aad: [u8; 0] = [];
        let ciphertext: [u8; 0] = [];

        let key = Key::try_from_slice(&key)?;
        let cipher = Cipher::new(&key);
        let tag = compute_tag(&ciphertext, cipher.get_round_keys(), &iv, &aad).unwrap();
        assert_eq!(tag, hex_to_arr_16("58e2fccefa7e3061367f1d57a4e7455a"));

        Ok(())
    }

    #[test]
    fn tag_no_aad_1() -> Result<()> {
        // Vector:
        // key = 00..00 (16 bytes)
        // iv  = 00..00 (12 bytes)
        // pt  = 00..00 (16 bytes)
        // ct  = 0388dace60b6a392f328c2b971b2fe78
        // aad = empty
        // tag = ab6e47d42cec13bdf53a67b21257bddf
        let key = hex_to_bytes("00000000000000000000000000000000");
        let iv = hex_to_arr_12("000000000000000000000000");
        let aad: [u8; 0] = [];
        let ciphertext = hex_to_bytes("0388dace60b6a392f328c2b971b2fe78");

        let key = Key::try_from_slice(&key)?;
        let cipher = Cipher::new(&key);
        let tag = compute_tag(&ciphertext, cipher.get_round_keys(), &iv, &aad).unwrap();
        assert_eq!(tag, hex_to_arr_16("ab6e47d42cec13bdf53a67b21257bddf"));

        Ok(())
    }

    #[test]
    fn tag_no_aad_2() -> Result<()> {
        // Vector:
        // key = feffe9928665731c6d6a8f9467308308
        // iv  = cafebabefacedbaddecaf888
        // aad = empty
        // ct  = 42831e...3f5985
        // tag = 4d5c2af327cd64a62cf35abd2ba6fab4
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_arr_12("cafebabefacedbaddecaf888");
        let aad: [u8; 0] = [];
        let ciphertext = hex_to_bytes(
            "42831ec2217774244b7221b784d0d49c\
             e3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa05\
             1ba30b396a0aac973d58e091473f5985",
        );

        let key = Key::try_from_slice(&key)?;
        let cipher = Cipher::new(&key);
        let tag = compute_tag(&ciphertext, cipher.get_round_keys(), &iv, &aad).unwrap();
        assert_eq!(tag, hex_to_arr_16("4d5c2af327cd64a62cf35abd2ba6fab4"));

        Ok(())
    }

    #[test]
    fn tag_with_aad() -> Result<()> {
        // Vector:
        // key = feffe9928665731c6d6a8f9467308308
        // iv  = cafebabefacedbaddecaf888
        // aad = feedfacedeadbeeffeedfacedeadbeefabaddad2
        // ct  = 42831e...58e091
        // tag = 5bc94fbc3221a5db94fae95ae7121a47
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_arr_12("cafebabefacedbaddecaf888");
        let aad = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let ciphertext = hex_to_bytes(
            "42831ec2217774244b7221b784d0d49c\
             e3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa05\
             1ba30b396a0aac973d58e091",
        );

        let key = Key::try_from_slice(&key)?;
        let cipher = Cipher::new(&key);
        let tag = compute_tag(&ciphertext, cipher.get_round_keys(), &iv, &aad).unwrap();
        assert_eq!(tag, hex_to_arr_16("5bc94fbc3221a5db94fae95ae7121a47"));

        Ok(())
    }
}
