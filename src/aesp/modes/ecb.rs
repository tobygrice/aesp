use rayon::prelude::*;

use crate::aesp::core::{decrypt_block, encrypt_block};
use crate::aesp::error::*;
use crate::aesp::modes::util::PARALLEL_THRESHOLD;

/// Core ECB encryption algorithm.
/// Encrypts `plaintext` in 16-byte blocks to form ciphertext.
/// **Assumes `plaintext.len()` is a multiple of 16** (padding must be done by caller).
pub fn ecb_core_enc(plaintext: &[u8], round_keys: &[[u8; 16]]) -> Result<Vec<u8>> {
    if plaintext.len() % 16 != 0 {
        return Err(Error::InvalidPlaintext {
            len: plaintext.len(),
            context: "ECB plaintext not a multiple of 16 bytes",
        });
    }

    let mut ciphertext = vec![0u8; plaintext.len()];

    // encrypt in parallel if feature enabled and size exceeds threshold
    if plaintext.len() > PARALLEL_THRESHOLD {
        ciphertext
            .par_chunks_exact_mut(16)
            .zip(plaintext.par_chunks_exact(16))
            .for_each(|(ct, pt)| {
                let pt_block: &[u8; 16] = pt.try_into().unwrap(); // exact 16
                let enc = encrypt_block(pt_block, round_keys);
                ct.copy_from_slice(&enc);
            });
    } else {
        // encrypt serially
        for (pt, ct) in plaintext
            .chunks_exact(16)
            .zip(ciphertext.chunks_exact_mut(16))
        {
            let pt_block: &[u8; 16] = pt.try_into().unwrap(); // exact 16
            let enc = encrypt_block(pt_block, round_keys);
            ct.copy_from_slice(&enc);
        }
    }

    Ok(ciphertext)
}

/// Core ECB decryption algorithm. Decrypts ciphertext in 16-byte blocks to form plaintext. Assumes ciphertext was PKCS#7 padded.
pub fn ecb_core_dec(ciphertext: &[u8], round_keys: &[[u8; 16]]) -> Result<Vec<u8>> {
    // ECB ciphertext should (and must) always be a multiple of 16 bytes.
    if ciphertext.len() % 16 != 0 {
        return Err(Error::InvalidCiphertext {
            len: ciphertext.len(),
            context: "ECB ciphertext not a multiple of 16 bytes",
        });
    }

    let mut plaintext = vec![0u8; ciphertext.len()];

    // decrypt in parallel if feature enabled and size exceeds threshold
    if ciphertext.len() > PARALLEL_THRESHOLD {
            // decrypt ciphertext in 16-byte blocks
            ciphertext
                .par_chunks_exact(16)
                .zip(plaintext.par_chunks_exact_mut(16))
                .for_each(|(ct, pt)| {
                    let ct_block: &[u8; 16] = ct.try_into().unwrap(); // guaranteed exact chunks 16
                    let dec = decrypt_block(ct_block, round_keys);
                    pt.copy_from_slice(&dec);
                });
    } else {
        // parallel feature not enabled or input len below threshold
        // decrypt serially
        for (ct, pt) in ciphertext
            .chunks_exact(16)
            .zip(plaintext.chunks_exact_mut(16))
        {
            let ct_block: &[u8; 16] = ct.try_into().unwrap(); // safe unwrap, loop guarantees exact chunks 16
            let dec = decrypt_block(ct_block, round_keys);
            pt.copy_from_slice(&dec);
        }
    }

    Ok(plaintext)
}

#[cfg(test)]
mod test_ecb {
    use super::*;
    use crate::aesp::cipher::Cipher;
    use crate::aesp::key::Key;
    use crate::aesp::modes::util::test_util::{hex_to_bytes, KEY_128, KEY_192, KEY_256, PLAINTEXT};

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
        let encrypted = ecb_core_enc(&PLAINTEXT, cipher.get_round_keys())?;

        assert_eq!(expected, encrypted, "encrypted result does not match expected");
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
        let decrypted = ecb_core_dec(&ciphertext, cipher.get_round_keys())?;

        assert_eq!(PLAINTEXT.to_vec(), decrypted, "decrypted result does not match expected");
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
        let encrypted = ecb_core_enc(&PLAINTEXT, cipher.get_round_keys())?;

        assert_eq!(expected, encrypted, "encrypted result does not match expected");
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
        let decrypted = ecb_core_dec(&ciphertext, cipher.get_round_keys())?;

        assert_eq!(PLAINTEXT.to_vec(), decrypted, "decrypted result does not match expected");
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
        let encrypted = ecb_core_enc(&PLAINTEXT, cipher.get_round_keys())?;

        assert_eq!(expected, encrypted, "encrypted result does not match expected");
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
        let decrypted = ecb_core_dec(&ciphertext, cipher.get_round_keys())?;

        assert_eq!(PLAINTEXT.to_vec(), decrypted, "decrypted result does not match expected");
        Ok(())
    }
}
