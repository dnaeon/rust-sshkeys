use std::io::Read;
use std::fs::File;
use std::path::Path;

use super::keytype::{KeyType, KeyTypeKind};
use super::cursor::Cursor;
use super::error::{Error, Kind, Result};

use base64;

// The different kinds of public keys.
#[derive(Debug, PartialEq)]
pub enum PublicKeyKind {
    Rsa(RsaPublicKey),
}

// TODO: Implement methods on `PublicKeyKind` for displaying key fingerprint

// RSA public key format is described in RFC 4253, section 6.6
#[derive(Debug, PartialEq)]
pub struct RsaPublicKey {
    pub e: Vec<u8>,
    pub n: Vec<u8>,
}

// Represents a public key in OpenSSH format
#[derive(Debug)]
pub struct PublicKey {
    pub key_type: KeyType,
    pub kind: PublicKeyKind,
    pub comment: Option<String>,
}

impl PublicKey {
    // TODO: Implement method for displaying the key bits
    // TODO: Implement method for displaying the key fingerprint

    // Reads an OpenSSH public key from a given path.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<PublicKey> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        PublicKey::from_string(&contents)
    }

    // Reads an OpenSSH public key from the given string.
    pub fn from_string(contents: &str) -> Result<PublicKey> {
        let mut iter = contents.split_whitespace();

        let kt_name = iter.next().ok_or(Error::with_kind(Kind::InvalidFormat))?;
        let data = iter.next().ok_or(Error::with_kind(Kind::InvalidFormat))?;
        let comment = iter.next().map(|v| String::from(v));

        let kt = KeyType::from_name(&kt_name)?;
        let decoded = base64::decode(&data)?;
        let mut cursor = Cursor::new(&decoded);

        // Validate key type before reading rest of the data
        let kt_from_cursor = cursor.read_string()?;
        if kt_name != kt_from_cursor {
            return Err(Error::with_kind(Kind::KeyTypeMismatch))
        }

        // Construct a new `PublicKey` value and preserve the `comment` value.
        let k = PublicKey::from_cursor(&kt_name, &mut cursor)?;
        let key = PublicKey {
            key_type: kt,
            kind: k.kind,
            comment: comment,
        };

        Ok(key)
    }

    // Reads a public key from the given byte sequence, e.g. a public key extracted
    // from an OpenSSH certificate.
    // The byte sequence is expected to be the base64 decoded body of the public key.
    pub fn from_bytes<T: ?Sized + AsRef<[u8]>>(data: &T) -> Result<PublicKey> {
        let mut cursor = Cursor::new(&data);
        let kt_name = cursor.read_string()?;

        PublicKey::from_cursor(&kt_name, &mut cursor)
    }

    // This function is used for extracting a public key from an existing cursor, e.g.
    // we already have a cursor for reading an OpenSSH certificate key and
    // we want to extract the public key information from it.
    pub(crate) fn from_cursor(kt_name: &str, cursor: &mut Cursor) -> Result<PublicKey> {
        let kt = KeyType::from_name(&kt_name)?;

        let kind = match kt.kind {
            KeyTypeKind::KeyRsa |
            KeyTypeKind::KeyRsaCert => {
                let k = RsaPublicKey {
                    e: cursor.read_mpint()?,
                    n: cursor.read_mpint()?,
                };

                PublicKeyKind::Rsa(k)
            },
            // TODO: Implement the rest of the key kinds
            _ => unimplemented!(),
        };

        let key = PublicKey {
            key_type: kt,
            kind: kind,
            comment: None,
        };

        Ok(key)
    }

    // Returns the number of bits of the public key
    pub fn bits(&self) -> usize {
        match self.kind {
            // For RSA public key the size of the key is the number of bits of the modulus
            PublicKeyKind::Rsa(ref k) => {
                k.n.len() * 8
            }
        }
    }
}
