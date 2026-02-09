use std::vec;

use super::decryption::decrypt_block;
use super::encryption::encrypt_block;
use super::error::Result;
use super::key::expand_key;
use super::util::{blockify, ctr_block, pad, unpad, xor_block};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Mode {
    ModeECB,
    ModeCTR,
    ModeGCM,
}

pub fn encrypt(plaintext: &[u8], key: &[u8], mode: Mode) -> Result<Vec<u8>> {
    match mode {
        Mode::ModeECB => encrypt_ecb(plaintext, key),
        Mode::ModeCTR => {
            // generate IV and prepend to ciphertext
            let iv = [0u8; 12];
            let mut res: Vec<u8> = iv.to_vec();
            let mut ciphertext = ctr(plaintext, key, &iv)?;
            res.append(&mut ciphertext);
            Ok(res)
        }
        Mode::ModeGCM => {
            // generate IV and prepend to ciphertext
            let iv = [0u8; 12];
            let mut res: Vec<u8> = iv.to_vec();
            let mut ciphertext = ctr(plaintext, key, &iv)?;
            res.append(&mut ciphertext);
            Ok(res)
        }
    }
}

pub fn decrypt(ciphertext: &[u8], key: &[u8], mode: Mode) -> Result<Vec<u8>> {
    match mode {
        Mode::ModeECB => decrypt_ecb(ciphertext, key),
        Mode::ModeCTR => {
            // extract and remove IV from ciphertext
            let iv = [0u8; 12];
            ctr(ciphertext, key, &iv)
        }
        Mode::ModeGCM => {
            // extract and remove IV from ciphertext
            let iv = [0u8; 12];
            ctr(ciphertext, key, &iv)
        }
    }
}

fn encrypt_ecb(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let round_keys = expand_key(&key)?;
    let plaintext = blockify(pad(plaintext))?;

    let mut ciphertext: Vec<u8> = vec![];
    for block in plaintext {
        let enc_block = encrypt_block(&block, &round_keys);
        ciphertext.append(&mut enc_block.into_iter().flatten().collect());
    }

    Ok(ciphertext)
}

fn decrypt_ecb(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let round_keys = expand_key(&key)?;
    let ciphertext = blockify(ciphertext.to_vec())?;

    let mut plaintext: Vec<u8> = vec![];
    for block in ciphertext {
        let dec_block = decrypt_block(&block, &round_keys);
        plaintext.append(&mut dec_block.into_iter().flatten().collect());
    }

    unpad(&plaintext);
    Ok(plaintext)
}

fn ctr(input: &[u8], key: &[u8], iv: &[u8; 12]) -> Result<Vec<u8>> {
    let round_keys: Vec<[[u8; 4]; 4]> = expand_key(&key)?;
    let mut output: Vec<u8> = vec![0u8; input.len()];
    let mut ctr: u32 = 0;

    for chunk in input.chunks(16) {
        let block = ctr_block(&iv, ctr); // form block from iv + ctr
        // encrypt block
        let keystream = encrypt_block(&block, &round_keys);
        // xor each element of chunk (1-16 bytes) with corresponding elem in keystream
        output.append(&mut xor_block(keystream, chunk));
        ctr += 1; // err on overflow -> can't encrypt more than 64GiB
    }

    Ok(output)
}
