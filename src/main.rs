mod args;

use args::{Cli, Commands};
use clap::Parser;

use std::fs;
use std::time::Instant;

fn main() {
    if let Err(e) = aes_cli() {
        eprintln!("error: {e}");
        //std::process::exit(1);
    }
}

fn aes_cli() -> aes::Result<()> {
    let args = Cli::parse();

    match args.command {
        Commands::Encrypt(enc) => {
            // common args:
            let input_path = enc.common.input; // move ownership
            let output_path = enc.common.output;
            let key_path = enc.common.key;
            let mode = enc.common.mode;

            // read plaintext from input_path
            let plaintext = fs::read(input_path).expect("Failed to read input");

            // read or generate key
            let key = if enc.gen_key {
                let rand_key = match enc.key_size {
                    args::KeySize::Bits128 => aes::random_key(aes::KeySize::Bits128)?,
                    args::KeySize::Bits192 => aes::random_key(aes::KeySize::Bits192)?,
                    args::KeySize::Bits256 => aes::random_key(aes::KeySize::Bits256)?,
                };
                fs::write(key_path, &rand_key).expect("Failed to write key");
                rand_key
            } else {
                // read key from key_path
                fs::read(key_path).expect("Failed to read key")
            };

            let start = Instant::now();

            // encrypt plaintext and write output
            let ciphertext = match mode {
                args::Mode::ModeECB => aes::encrypt(&plaintext, &key, aes::Mode::ModeECB)?,
                args::Mode::ModeCTR => aes::encrypt(&plaintext, &key, aes::Mode::ModeCTR)?,
                args::Mode::ModeGCM => aes::encrypt(&plaintext, &key, aes::Mode::ModeGCM)?,
            };

            let duration = start.elapsed();

            fs::write(output_path, &ciphertext).expect("Failed to write output");
            println!(
                "Encrypted {} bytes in {} ms",
                plaintext.len(),
                duration.as_millis()
            );
            Ok(())
        }
        Commands::Decrypt(common) => {
            let input_path = common.input; // move ownership
            let output_path = common.output;
            let key_path = common.key;
            let mode = common.mode;

            // read inputs
            let ciphertext = fs::read(input_path).expect("Failed to read input");
            let key = fs::read(key_path).expect("Failed to read key");

            let start = Instant::now();

            // decrypt ciphertext and write output
            let plaintext = match mode {
                args::Mode::ModeECB => aes::decrypt(&ciphertext, &key, aes::Mode::ModeECB)?,
                args::Mode::ModeCTR => aes::decrypt(&ciphertext, &key, aes::Mode::ModeCTR)?,
                args::Mode::ModeGCM => aes::decrypt(&ciphertext, &key, aes::Mode::ModeGCM)?,
            };

            let duration = start.elapsed();

            fs::write(output_path, &plaintext).expect("Failed to write output");

            println!(
                "Decrypted {} bytes in {} ms",
                plaintext.len(),
                duration.as_millis()
            );

            Ok(())
        }
    }
}
