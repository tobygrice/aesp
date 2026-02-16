use crate::aes_lib::error::{Error, Result};
use crate::aes_lib::key::{Key, expand_key};
use crate::aes_lib::mode::encrypt_ecb_core;

use crate::aes_lib::mode::*;
use crate::aes_lib::util::random_iv;

/// Holds a set of round keys to be used for encryption and decryption. Supports ECB, CTR, and GCM.
pub struct Cipher {
    round_keys: Vec<[u8; 16]>,
}

impl Cipher {
    /// Generates round keys from provided key and stores in object.
    pub fn new(key: &Key) -> Self {
        Self {
            round_keys: expand_key(key),
        }
    }

    /// Electronic Codebook encryption. Encrypts each 16-byte block entirely independently
    /// and chains them together. This can result in patterns emerging in the ciphertext.
    pub fn encrypt_ecb(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        encrypt_ecb_core(plaintext, &self.round_keys)
    }

    /// Electronic Codebook decryption.
    pub fn decrypt_ecb(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        decrypt_ecb_core(ciphertext, &self.round_keys)
    }

    /// Counter mode encryption. Generates a random 12-byte initialisation vector (IV).
    /// For each 16-byte block of plaintext:
    /// 1. 4-byte counter is incremented (starts at zero).
    /// 2. Counter is appended to 12-byte IV to form a 16-byte block.
    /// 3. The `IV || Counter` block is encrypted using the round keys.
    /// 4. The plaintext block is `XOR`'d with the encrypted counter block.
    /// Important: the same IV must never be reused with the same key. 96 bits is 
    /// sufficiently large to assume uniqueness.
    /// 
    /// Output is `IV || CIPHERTEXT`
    pub fn encrypt_ctr(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // generate IV and prepend to ciphertext
        let iv = random_iv()?;
        let mut ciphertext: Vec<u8> = iv.to_vec();
        ciphertext.append(&mut ctr_core(plaintext, &self.round_keys, &iv, 0)?);
        Ok(ciphertext)
    }

    /// Counter mode decryption. 
    /// Assumes format matches output of encryption: `IV (12 bytes) || Ciphertext`
    pub fn decrypt_ctr(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
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

        ctr_core(ciphertext, &self.round_keys, &iv, 0)
    }

    /// Galois/counter mode encryption. 
    /// Encrypts using counter mode and generates a cryptographic tag to verify the 
    /// message has not been modified.
    /// 
    /// Also accepts additional authenticated data (AAD), which is not encrypted but
    /// is included in the computation of the tag. 
    /// 
    /// Output is `IV (12 bytes) || AAD length (4 bytes) || AAD || Ciphertext || Tag (16 bytes)`
    pub fn encrypt_gcm(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let iv = random_iv()?;
        let mut out: Vec<u8> = iv.to_vec();

        // prepend AAD len and AAD
        let aad_bytes = aad.unwrap_or(&[]);
        out.extend_from_slice(&(aad_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(aad_bytes);

        // compute ciphertext and tag
        let mut ct = ctr_core(plaintext, &self.round_keys, &iv, 2)?;
        let tag = compute_tag(&ct, &self.round_keys, &iv, aad_bytes)?;

        out.append(&mut ct);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Galois/counter mode decryption. 
    /// Assumes input follows the same format as [encryption](crate::aes_lib::cipher::Cipher::encrypt_gcm): 
    /// `IV (12 bytes) || AAD length (4 bytes) || AAD || Ciphertext || Tag (16 bytes)`
    /// 
    pub fn decrypt_gcm(&self, ciphertext: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        // minimum size is 32 bytes -> 12 (iv) + 4 (aad_len) + 16 (tag)
        if ciphertext.len() < 32 {
            return Err(Error::InvalidCiphertext {
                len: ciphertext.len(),
                context: "insufficient bytes for valid GCM",
            });
        }

        // extract IV
        let (iv_bytes, ciphertext) = ciphertext.split_at(12);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(iv_bytes);

        // extract AAD len and validate remaining size
        let (aad_len, ciphertext) = ciphertext.split_at(4);
        let aad_len = u32::from_be_bytes([aad_len[0], aad_len[1], aad_len[2], aad_len[3]]);
        if ciphertext.len() < aad_len as usize + 16 {
            return Err(Error::InvalidCiphertext {
                len: ciphertext.len(),
                context: "insufficient bytes given aad_len",
            });
        }

        // extract aad and save in vector
        let (aad, ciphertext) = ciphertext.split_at(aad_len as usize);
        let aad = aad.to_vec();

        // extract tag and format as [u8; 16]
        let mut received_tag = [0u8; 16];
        let (ct, tag_bytes) = ciphertext.split_at(ciphertext.len() - 16);
        received_tag.copy_from_slice(tag_bytes);

        // compute and compare tag
        let computed_tag = compute_tag(ct, &self.round_keys, &iv, &aad)?;
        if received_tag != computed_tag {
            return Err(Error::AuthFailed);
        }

        // wrap AAD in option
        let aad = if !aad.is_empty() { Some(aad) } else { None };

        // run ctr starting at 2, as per NIST spec
        let plaintext = ctr_core(ct, &self.round_keys, &iv, 2)?;
        Ok((plaintext, aad))
    }
}
