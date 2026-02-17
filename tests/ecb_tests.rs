#![cfg(feature = "test-vectors")]

// this file written by an LLM

// all test vectors from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES

use std::{
    error::Error,
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use aesp::{Cipher, Key};

#[derive(Copy, Clone, Debug)]
enum Dir {
    Encrypt,
    Decrypt,
}

#[test]
fn nist_ecb_kat_rsp() -> Result<(), Box<dyn Error>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors");
    run_ecb_rsp_dir(&dir)?;
    Ok(())
}

fn run_ecb_rsp_dir(dir: &Path) -> Result<(), Box<dyn Error>> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rsp"))
        })
        .collect();

    paths.sort();

    let mut total = 0usize;
    for path in paths {
        total += run_ecb_rsp_file(&path)?;
    }

    eprintln!("ECB KAT: executed {total} cases");
    Ok(())
}

fn run_ecb_rsp_file(path: &Path) -> Result<usize, Box<dyn Error>> {
    let f = std::fs::File::open(path)?;
    let reader = BufReader::new(f);

    let mut dir: Option<Dir> = None;

    // current case under construction
    let mut count: Option<u32> = None;
    let mut key: Option<Vec<u8>> = None;
    let mut pt: Option<Vec<u8>> = None;
    let mut ct: Option<Vec<u8>> = None;

    let mut executed = 0usize;

    for (lineno, line) in reader.lines().enumerate() {
        let line = line?;
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }

        // Section markers
        if s.eq_ignore_ascii_case("[ENCRYPT]") {
            dir = Some(Dir::Encrypt);
            // clear any partial case so we don't mix across sections
            count = None;
            key = None;
            pt = None;
            ct = None;
            continue;
        }
        if s.eq_ignore_ascii_case("[DECRYPT]") {
            dir = Some(Dir::Decrypt);
            count = None;
            key = None;
            pt = None;
            ct = None;
            continue;
        }

        // ECB-only guard: if you accidentally mixed non-ECB data into the file, fail loudly.
        if s.to_ascii_uppercase().starts_with("IV ")
            || s.to_ascii_uppercase().starts_with("IV=")
            || s.to_ascii_uppercase().starts_with("NONCE ")
            || s.to_ascii_uppercase().starts_with("COUNTER ")
        {
            return Err(format!(
                "Found IV/NONCE/COUNTER field in ECB harness. File is not ECB-only: {} (line {})",
                path.display(),
                lineno + 1
            )
            .into());
        }

        // Key-value lines like: KEY = ... / PLAINTEXT = ... / CIPHERTEXT = ...
        if let Some((k, v)) = s.split_once('=') {
            let key_name = k.trim();
            let val = v.trim();

            if key_name.eq_ignore_ascii_case("COUNT") {
                count = Some(val.parse()?);
            } else if key_name.eq_ignore_ascii_case("KEY") {
                key = Some(
                    decode_hex(val).map_err(|e| format_rsp_err(path, lineno, count, dir, &e))?,
                );
            } else if key_name.eq_ignore_ascii_case("PLAINTEXT") {
                pt = Some(
                    decode_hex(val).map_err(|e| format_rsp_err(path, lineno, count, dir, &e))?,
                );
            } else if key_name.eq_ignore_ascii_case("CIPHERTEXT") {
                ct = Some(
                    decode_hex(val).map_err(|e| format_rsp_err(path, lineno, count, dir, &e))?,
                );
            }

            // If we have a full case, execute it immediately (streaming; no huge allocations).
            if let (Some(d), Some(kb), Some(p), Some(c)) =
                (dir, key.as_deref(), pt.as_deref(), ct.as_deref())
            {
                run_one_ecb_case(path, lineno + 1, count, d, kb, p, c)?;
                executed += 1;

                // reset case fields but keep current dir
                count = None;
                key = None;
                pt = None;
                ct = None;
            }
        }
    }

    Ok(executed)
}

fn run_one_ecb_case(
    path: &Path,
    lineno: usize,
    count: Option<u32>,
    dir: Dir,
    key_bytes: &[u8],
    pt: &[u8],
    ct: &[u8],
) -> Result<(), Box<dyn Error>> {
    // ECB KATs are block-aligned; if your ECB implementation pads, you won't match these vectors.
    if pt.len() % 16 != 0 || ct.len() % 16 != 0 || pt.len() != ct.len() {
        return Err(format!(
            "Invalid ECB test lengths at {}:{} COUNT={:?} (pt={}, ct={})",
            path.display(),
            lineno,
            count,
            pt.len(),
            ct.len()
        )
        .into());
    }

    // Whatever you use in normal code to make a Key from raw bytes:
    let key = Key::try_from_slice(key_bytes)?;

    let cipher = Cipher::new(&key);

    match dir {
        Dir::Encrypt => {
            let got = cipher.encrypt_ecb_raw(pt).unwrap();
            if got.as_slice() != ct {
                return Err(format!(
        "ECB ENCRYPT mismatch at {}:{} COUNT={:?}\n  KEY={}\n  PT ={}\n  EXP={}\n  GOT={}",
        path.display(),
        lineno,
        count,
        hex(key_bytes),
        hex(pt),
        hex(ct),
        hex(got.as_slice()),
    ).into());
            }
        }
        Dir::Decrypt => {
            let got = cipher.decrypt_ecb_raw(ct)?;
            if got.as_slice() != pt {
                return Err(format!(
                    "ECB DECRYPT mismatch at {}:{} COUNT={:?} (got != expected)",
                    path.display(),
                    lineno,
                    count
                )
                .into());
            }
        }
    }

    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if s.len() % 2 != 0 {
        return Err(format!("Odd-length hex string: len={}", s.len()));
    }

    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();

    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }

    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("Invalid hex character: {}", b as char)),
    }
}

fn format_rsp_err(
    path: &Path,
    lineno: usize,
    count: Option<u32>,
    dir: Option<Dir>,
    msg: &str,
) -> String {
    format!(
        "Parse error in {}:{} COUNT={:?} DIR={:?}: {}",
        path.display(),
        lineno + 1,
        count,
        dir,
        msg
    )
}
