use super::error::{Error, Result};
use super::mode::*;
use super::util::random_iv;

pub fn encrypt(plaintext: &[u8], key: &[u8], mode: Mode) -> Result<Vec<u8>> {
    match mode {
        Mode::ModeECB => encrypt_ecb(plaintext, key),
        Mode::ModeCTR => {
            // generate IV and prepend to ciphertext
            let iv = random_iv()?;
            let mut ciphertext: Vec<u8> = iv.to_vec();
            ciphertext.append(&mut ctr(plaintext, key, &iv, 0)?);
            Ok(ciphertext)
        }
        Mode::ModeGCM => {
            // generate IV and prepend to ciphertext
            let iv = random_iv()?;
            let mut ciphertext: Vec<u8> = iv.to_vec();

            let mut aad_len = vec![0x00, 0x00, 0x00, 0x00];
            ciphertext.append(&mut aad_len);

            let (mut ct, tag) = gcm(&plaintext, key, &iv, &[])?;
            ciphertext.append(&mut ct);
            ciphertext.append(&mut tag.to_vec());
            Ok(ciphertext)
        }
    }
}

pub fn decrypt(ciphertext: &[u8], key: &[u8], mode: Mode) -> Result<Vec<u8>> {
    match mode {
        Mode::ModeECB => decrypt_ecb(ciphertext, key),
        Mode::ModeCTR => {
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

            ctr(ciphertext, key, &iv, 0)
        }
        Mode::ModeGCM => {
            // extract and remove IV from ciphertext
            if ciphertext.len() < 12 + 4 + 16 {
                return Err(Error::InvalidCiphertext {
                    len: ciphertext.len(),
                    context: "insufficient bytes for valid GCM message",
                });
            }

            let (iv_bytes, ciphertext) = ciphertext.split_at(12);
            let mut iv = [0u8; 12];
            iv.copy_from_slice(iv_bytes);

            let (aad_len_bytes, ciphertext) = ciphertext.split_at(4);
            let aad_len = u32::from_be_bytes([
                aad_len_bytes[0],
                aad_len_bytes[1],
                aad_len_bytes[2],
                aad_len_bytes[3],
            ]) as usize;

            // expect minimum aad_len + 16 byte tag left (no ciphertext)
            if ciphertext.len() < aad_len + 16 {
                return Err(Error::InvalidCiphertext {
                    len: ciphertext.len(),
                    context: "insufficient bytes given aad_len",
                });
            }

            let (aad, ciphertext) = ciphertext.split_at(aad_len);
            let (ciphertext, tag_bytes) = ciphertext.split_at(ciphertext.len() - 16);

            let mut tag = [0u8; 16];
            tag.copy_from_slice(tag_bytes);

            let (mut pt, recv_tag) = gcm(&ciphertext, key, &iv, &[])?;

            if tag != recv_tag {
                return Err(Error::AuthFailed);
            }

            let mut output = aad.to_vec();
            output.append(&mut pt);
            Ok(output)
        }
    }
}
