use std::io::Read;
use std::fs::File;
use std::path::Path;

use super::keytype::{KeyType, KeyTypeKind};
use super::reader::Reader;
use super::writer::Writer;
use super::error::{Error, ErrorKind, Result};

use base64;

use sha2::{Sha256, Digest};

// The different kinds of public keys.
#[derive(Debug, PartialEq)]
pub enum PublicKeyKind {
    Rsa(RsaPublicKey),
    Dsa(DsaPublicKey),
}

// TODO: Implement methods on `PublicKeyKind` for displaying key fingerprint

// RSA public key format is described in RFC 4253, section 6.6
#[derive(Debug, PartialEq)]
pub struct RsaPublicKey {
    pub e: Vec<u8>,
    pub n: Vec<u8>,
}

// DSA public key format is described in RFC 4253, section 6.6
#[derive(Debug, PartialEq)]
pub struct DsaPublicKey {
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub g: Vec<u8>,
    pub y: Vec<u8>,
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

        let kt_name = iter.next().ok_or(Error::with_kind(ErrorKind::InvalidFormat))?;
        let data = iter.next().ok_or(Error::with_kind(ErrorKind::InvalidFormat))?;
        let comment = iter.next().map(|v| String::from(v));

        let kt = KeyType::from_name(&kt_name)?;
        let decoded = base64::decode(&data)?;
        let mut reader = Reader::new(&decoded);

        // Validate key type before reading rest of the data
        let kt_from_reader = reader.read_string()?;
        if kt_name != kt_from_reader {
            return Err(Error::with_kind(ErrorKind::KeyTypeMismatch))
        }

        // Construct a new `PublicKey` value and preserve the `comment` value.
        let k = PublicKey::from_reader(&kt_name, &mut reader)?;
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
        let mut reader = Reader::new(&data);
        let kt_name = reader.read_string()?;

        PublicKey::from_reader(&kt_name, &mut reader)
    }

    // This function is used for extracting a public key from an existing reader, e.g.
    // we already have a reader for reading an OpenSSH certificate key and
    // we want to extract the public key information from it.
    pub(crate) fn from_reader(kt_name: &str, reader: &mut Reader) -> Result<PublicKey> {
        let kt = KeyType::from_name(&kt_name)?;

        let kind = match kt.kind {
            KeyTypeKind::KeyRsa     |
            KeyTypeKind::KeyRsaCert => {
                let k = RsaPublicKey {
                    e: reader.read_mpint()?,
                    n: reader.read_mpint()?,
                };

                PublicKeyKind::Rsa(k)
            },
            KeyTypeKind::KeyDsa     |
            KeyTypeKind::KeyDsaCert => {
                let k = DsaPublicKey {
                    p: reader.read_mpint()?,
                    q: reader.read_mpint()?,
                    g: reader.read_mpint()?,
                    y: reader.read_mpint()?,
                };

                PublicKeyKind::Dsa(k)
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
            },
            // For DSA public keys the size of the key is the number of bits of the `p` parameter
            PublicKeyKind::Dsa(ref k) => {
                k.p.len() * 8
            }
        }
    }

    // Encodes the public key in an OpenSSH compatible format
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();

        w.write_string(self.key_type.name)?;
        match self.kind {
            PublicKeyKind::Rsa(ref k) => {
                w.write_mpint(&k.e)?;
                w.write_mpint(&k.n)?;
            },
            PublicKeyKind::Dsa(ref k) => {
                w.write_mpint(&k.p)?;
                w.write_mpint(&k.q)?;
                w.write_mpint(&k.g)?;
                w.write_mpint(&k.y)?;
            },
        }

        Ok(w.into_bytes())
    }

    // Calculates the fingerprint of the public key using the
    // default OpenSSH fingerprint representation with Sha256.
    pub fn fingerprint(&self) -> Result<String> {
        let data = self.encode()?;
        let digest = Sha256::digest(&data);
        let mut encoded = base64::encode(&digest);

        // Trim padding characters from end
        let fingerprint = match encoded.find('=') {
            Some(offset) => encoded.drain(..offset).collect(),
            None         => encoded,
        };

        Ok(fingerprint)
    }
}
