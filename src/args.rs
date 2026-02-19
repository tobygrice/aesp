use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about, author, arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt input to output
    Encrypt(EncryptArgs),

    /// Decrypt input to output
    Decrypt(CommonArgs),
}


#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct CommonArgs {
    /// Mode of operation.
    #[arg(
        short = 'm',
        long = "mode",
        value_enum,
        default_value_t = Mode::ModeGCM,
    )]
    pub mode: Mode,

    /// Input file path.
    #[arg(short = 'i', long = "input")]
    pub input: PathBuf,

    /// Output file path.
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,

    /// Key file path.
    #[arg(short = 'k', long = "key")]
    pub key: PathBuf,

}

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct EncryptArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Generate a random key (written to path specified by key)
    #[arg(long = "gen-key")]
    pub gen_key: bool,

    /// Only valid with --gen-key.
    #[arg(
        long = "key-size",
        value_enum,
        default_value_t = KeySize::Bits256,
        requires = "gen_key"
    )]
    pub key_size: KeySize,

    /// Additional authenticated data, provided as hex string (optional, GCM only)
    #[arg(long = "aad", value_name = "HEX")]
    pub aad: Option<String>,
}

#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
pub enum KeySize {
    #[value(name = "128")]
    Bits128,
    #[value(name = "192")]
    Bits192,
    #[value(name = "256")]
    Bits256,
}

#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
pub enum Mode {
    #[value(name = "ecb")]
    ModeECB,
    #[value(name = "ctr")]
    ModeCTR,
    #[value(name = "gcm")]
    ModeGCM,
}
