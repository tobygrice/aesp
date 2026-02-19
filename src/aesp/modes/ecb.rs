use rayon::prelude::*;

use crate::aesp::core::{decrypt_block, encrypt_block};
use crate::aesp::error::*;
use crate::aesp::modes::util::PARALLEL_THRESHOLD;

/// Core ECB encryption/decryption algorithm.
/// Crypts in 16-byte blocks to form output.
/// Input length must be a multiple of 16, InvalidECBInput error if not.
fn ecb_core<F>(input: &[u8], round_keys: &[[u8; 16]], block_fn: F) -> Result<Vec<u8>>
where
    F: Fn(&[u8; 16], &[[u8; 16]]) -> [u8; 16] + Sync + Copy,
{
    if input.len() % 16 != 0 {
        return Err(Error::InvalidECBInput { len: input.len() });
    }

    let mut output = vec![0u8; input.len()];

    // encrypt in parallel if feature enabled and size exceeds threshold
    if input.len() > PARALLEL_THRESHOLD {
        output
            .par_chunks_exact_mut(16)
            .zip(input.par_chunks_exact(16))
            .for_each(|(ct, pt)| {
                // convert pt into [u8; 16] - safe to unwrap, used chunks_exact(16)
                let pt_block: &[u8; 16] = pt.try_into().unwrap();
                let enc = block_fn(pt_block, round_keys);
                ct.copy_from_slice(&enc);
            });
    } else {
        // encrypt serially
        output
            .chunks_exact_mut(16)
            .zip(input.chunks_exact(16))
            .for_each(|(ct, pt)| {
                // convert pt into [u8; 16] - safe to unwrap, used chunks_exact(16)
                let pt_block: &[u8; 16] = pt.try_into().unwrap();
                let enc = block_fn(pt_block, round_keys);
                ct.copy_from_slice(&enc);
            });
    }

    Ok(output)
}

pub fn ecb_core_enc(plaintext: &[u8], round_keys: &[[u8; 16]]) -> Result<Vec<u8>> {
    ecb_core(plaintext, round_keys, encrypt_block)
}

pub fn ecb_core_dec(ciphertext: &[u8], round_keys: &[[u8; 16]]) -> Result<Vec<u8>> {
    ecb_core(ciphertext, round_keys, decrypt_block)
}

#[cfg(test)]
mod test_ecb {
    use super::*;
    use crate::aesp::modes::util::test_util::{KEY_128, KEY_192, KEY_256, PLAINTEXT, hex_to_bytes};
    use crate::{Cipher, Key};

    #[test]
    fn aes_ecb_128_encrypt() -> Result<()> {
        // SP 800-38A ECB example vector (no padding): 4 blocks only
        let expected = hex_to_bytes(
            "
    3ad77bb40d7a3660a89ecaf32466ef97\
    f5d3d58503b9699de785895a96fdbaaf\
    43b1cd7f598ece23881b00e3ed030688\
    7b0c785e27e8ad3f8223207104725dd4",
        );

        let key = Key::try_from_slice(&KEY_128)?;
        let cipher = Cipher::new(&key);

        // ECB core now assumes input is already 16-byte aligned and unpadded
        let encrypted = ecb_core_enc(&PLAINTEXT, cipher.round_keys())?;

        assert_eq!(
            expected, encrypted,
            "encrypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ecb_128_decrypt() -> Result<()> {
        let ciphertext = hex_to_bytes(
            "
    3ad77bb40d7a3660a89ecaf32466ef97\
    f5d3d58503b9699de785895a96fdbaaf\
    43b1cd7f598ece23881b00e3ed030688\
    7b0c785e27e8ad3f8223207104725dd4",
        );

        let key = Key::try_from_slice(&KEY_128)?;
        let cipher = Cipher::new(&key);
        let decrypted = ecb_core_dec(&ciphertext, cipher.round_keys())?;

        assert_eq!(
            PLAINTEXT.to_vec(),
            decrypted,
            "decrypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ecb_192_encrypt() -> Result<()> {
        // SP 800-38A ECB example vector (no padding): 4 blocks only
        let expected = hex_to_bytes(
            "
    bd334f1d6e45f25ff712a214571fa5cc\
    974104846d0ad3ad7734ecb3ecee4eef\
    ef7afd2270e2e60adce0ba2face6444e\
    9a4b41ba738d6c72fb16691603c18e0e",
        );

        let key = Key::try_from_slice(&KEY_192)?;
        let cipher = Cipher::new(&key);
        let encrypted = ecb_core_enc(&PLAINTEXT, cipher.round_keys())?;

        assert_eq!(
            expected, encrypted,
            "encrypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ecb_192_decrypt() -> Result<()> {
        let ciphertext = hex_to_bytes(
            "
    bd334f1d6e45f25ff712a214571fa5cc\
    974104846d0ad3ad7734ecb3ecee4eef\
    ef7afd2270e2e60adce0ba2face6444e\
    9a4b41ba738d6c72fb16691603c18e0e",
        );

        let key = Key::try_from_slice(&KEY_192)?;
        let cipher = Cipher::new(&key);
        let decrypted = ecb_core_dec(&ciphertext, cipher.round_keys())?;

        assert_eq!(
            PLAINTEXT.to_vec(),
            decrypted,
            "decrypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ecb_256_encrypt() -> Result<()> {
        // SP 800-38A ECB example vector (no padding): 4 blocks only
        let expected = hex_to_bytes(
            "
    f3eed1bdb5d2a03c064b5a7e3db181f8\
    591ccb10d410ed26dc5ba74a31362870\
    b6ed21b99ca6f4f9f153e7b1beafed1d\
    23304b7a39f9f3ff067d8d8f9e24ecc7",
        );

        let key = Key::try_from_slice(&KEY_256)?;
        let cipher = Cipher::new(&key);
        let encrypted = ecb_core_enc(&PLAINTEXT, cipher.round_keys())?;

        assert_eq!(
            expected, encrypted,
            "encrypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ecb_256_decrypt() -> Result<()> {
        let ciphertext = hex_to_bytes(
            "
    f3eed1bdb5d2a03c064b5a7e3db181f8\
    591ccb10d410ed26dc5ba74a31362870\
    b6ed21b99ca6f4f9f153e7b1beafed1d\
    23304b7a39f9f3ff067d8d8f9e24ecc7",
        );

        let key = Key::try_from_slice(&KEY_256)?;
        let cipher = Cipher::new(&key);
        let decrypted = ecb_core_dec(&ciphertext, cipher.round_keys())?;

        assert_eq!(
            PLAINTEXT.to_vec(),
            decrypted,
            "decrypted result does not match expected"
        );
        Ok(())
    }
}
