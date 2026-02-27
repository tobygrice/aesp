//! Defines the [`Key`] struct, which holds a valid AES key of 128, 192, or 256 bits.
//! Keys can be randomly generated or constructed from an existing byte slice.

use rand::TryRngCore;
use rand::rngs::OsRng;

use crate::aesp::error::{Error, Result};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum KeyBytes {
    K128([u8; 16]),
    K192([u8; 24]),
    K256([u8; 32]),
}

/// Contains a valid AES key. Can be instantiated with a random key, or built from a slice
/// of bytes that is 16, 24, or 32 bytes long.
/// A `key` object is required to instantiate a [Cipher](crate::Cipher).
/// 
/// ## Examples
/// ```
/// # fn main() -> aesp::Result<()> {
/// use aesp::Key;
/// 
/// // Instantiate random keys:
/// let rk_128 = Key::rand_key_128()?;
/// let rk_192 = Key::rand_key_192()?;
/// let rk_256 = Key::rand_key_256()?;
/// 
/// // Instantiate keys from slice:
/// let key_bytes: [u8; 32] = [0xBA, 0x32, 0x82, 0x9A, 0x43, 0x8A, 0x48, 0xED, 
///                            0xC2, 0xEA, 0x10, 0x73, 0x26, 0xF8, 0xA9, 0x62, 
///                            0xDE, 0x82, 0x06, 0xBA, 0x53, 0xC2, 0xC7, 0x55, 
///                            0x2C, 0x72, 0xC5, 0x37, 0xBF, 0xD4, 0xDB, 0x5E];
/// let my_key_128 = Key::try_from_slice(&key_bytes[..16])?;
/// let my_key_192 = Key::try_from_slice(&key_bytes[..24])?;
/// let my_key_256 = Key::try_from_slice(&key_bytes[..32])?;
/// 
/// // Internal bytes of Key objects are accessible and match the original key:
/// assert_eq!(my_key_128.as_bytes(), &key_bytes[..16]);
/// assert_eq!(my_key_192.as_bytes(), &key_bytes[..24]);
/// assert_eq!(my_key_256.as_bytes(), &key_bytes[..32]);
/// 
/// // Attempting to instantiate with an invalid key size (not 16, 24, or 32 bytes)
/// // returns an InvalidKeyLength error:
/// assert!(Key::try_from_slice(&key_bytes[..20]).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Key {
    bytes: KeyBytes,
}

impl Key {
    /// Generate a random 128-bit key. Returns Error if OsRng fails.
    pub fn rand_key_128() -> Result<Self> {
        let mut k = [0u8; 16];
        OsRng.try_fill_bytes(&mut k)?;
        Ok(Self {
            bytes: KeyBytes::K128(k),
        })
    }

    /// Generate a random 192-bit key. Returns Error if OsRng fails.
    pub fn rand_key_192() -> Result<Self> {
        let mut k = [0u8; 24];
        OsRng.try_fill_bytes(&mut k)?;
        Ok(Self {
            bytes: KeyBytes::K192(k),
        })
    }

    /// Generate a random 256-bit key. Returns Error if OsRng fails.
    pub fn rand_key_256() -> Result<Self> {
        let mut k = [0u8; 32];
        OsRng.try_fill_bytes(&mut k)?;
        Ok(Self {
            bytes: KeyBytes::K256(k),
        })
    }

    /// Attempts to build a key from a slice of bytes. Will return an InvalidKeyLength error
    /// if the input slice is anything other than 16, 24, or 32 bytes long.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        Ok(match bytes.len() {
            16 => Self {
                bytes: KeyBytes::K128(bytes.try_into().unwrap()), // match condition guarantees safe unwrap
            },
            24 => Self {
                bytes: KeyBytes::K192(bytes.try_into().unwrap()),
            },
            32 => Self {
                bytes: KeyBytes::K256(bytes.try_into().unwrap()),
            },
            _ => return Err(Error::InvalidKeyLength { len: bytes.len() }),
        })
    }

    /// Returns a reference to the internal key as an array of bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.bytes {
            KeyBytes::K128(k) => k,
            KeyBytes::K192(k) => k,
            KeyBytes::K256(k) => k,
        }
    }
}
