mod args;

use args::{Cli, Commands};
use clap::Parser;

use std::fs;

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

            // encrypt plaintext and write output
            let ciphertext = aes::encrypt(&plaintext, &key)?;
            fs::write(output_path, &ciphertext).expect("Failed to write output");
            Ok(())
        }
        Commands::Decrypt(common) => {
            let input_path = common.input; // move ownership
            let output_path = common.output;
            let key_path = common.key;

            // read inputs
            let ciphertext = fs::read(input_path).expect("Failed to read input");
            let key = fs::read(key_path).expect("Failed to read key");

            // decrypt ciphertext and write output
            let plaintext = aes::decrypt(&ciphertext, &key)?;
            fs::write(output_path, &plaintext).expect("Failed to write output");
            Ok(())
        }
    }
}
