use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::io::Read;

use super::keytype::KeyType;
use super::pubkey::PublicKey;
use super::cursor::Cursor;
use super::error::{Error, Kind, Result};

use base64;

// `CertType` represents the valid types a certificate can be.
pub enum CertType {
    User,
    Host
}

pub struct Certificate {
    pub key_type: KeyType,
    pub nonce: Vec<u8>,
    pub key: PublicKey,
    pub serial: u64,
    pub cert_type: CertType,
    pub key_id: String,
    pub valid_principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    pub critical_options: HashMap<String, String>,
    pub extensions: HashMap<String, String>,
    pub reserved: Vec<u8>,
    pub signature_key: Vec<u8>,
    pub signature: PublicKey,
}

impl Certificate {
    // Reads an OpenSSH certificate key from a given path.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Certificate> {
        let mut file = File::open(path)?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        Certificate::from_string(&contents)
    }

    // Reads an OpenSSH certificate key from the given string.
    pub fn from_string(s: &str) -> Result<Certificate> {
        let mut iter = s.split_whitespace();

        let kt_name = iter.next().ok_or(Error::with_kind(Kind::InvalidFormat))?;
        let kt = KeyType::from_name(&kt_name)?;

        if !kt.is_cert {
            return Err(Error::with_kind(Kind::NotCertificate));
        }

        let data = iter.next().ok_or(Error::with_kind(Kind::InvalidFormat))?;

        let decoded = base64::decode(&data)?;
        let mut cursor = Cursor::new(&decoded);

        // Validate key types before reading the rest of the data
        let kt_from_cursor = cursor.read_string()?;
        if kt_name != kt_from_cursor {
            return Err(Error::with_kind(Kind::KeyTypeMismatch));
        }

        let nonce = cursor.read_bytes()?;
        let key = PublicKey::from_cursor(&kt_name, &mut cursor)?;
        let serial = cursor.read_u64()?;

        let cert_type = match cursor.read_u32()? {
            1 => CertType::User,
            2 => CertType::Host,
            n => return Err(Error::with_kind(Kind::InvalidCertType(n))),
        };

        let key_id = cursor.read_string()?;

        // Valid principals is a list of strings, so we must use a new
        // cursor and read all strings from it.
        let valid_principals = match cursor.read_bytes() {
            Ok(buf) => Cursor::new(&buf).read_strings_until_eof()?,
            Err(e)  => return Err(e),
        };

        let valid_after = cursor.read_u64()?;
        let valid_before = cursor.read_u64()?;

        // Critical options is a HashMap
        let critical_options = match cursor.read_bytes() {
            Ok(buf) => Cursor::new(&buf).read_strings_to_map()?,
            Err(e)  => return Err(e),
        };

        // Extensions is a HashMap, where each key value is the empty string.
        let extensions = match cursor.read_bytes() {
            Ok(buf) => Cursor::new(&buf).read_strings_to_map()?,
            Err(e)  => return Err(e),
        };

        let signature_key = cursor.read_bytes()?;
        let signature_buf = cursor.read_bytes()?;
        let signature = PublicKey::from_bytes(&signature_buf)?;

        let cert = Certificate {
            key_type: kt,
            nonce: nonce,
            key: key,
            serial: serial,
            cert_type: cert_type,
            key_id: key_id,
            valid_principals: valid_principals,
            valid_after: valid_after,
            valid_before: valid_before,
            critical_options: critical_options,
            extensions: extensions,
            reserved: Vec::new(),
            signature_key: signature_key,
            signature: signature,
        };

        Ok(cert)
    }

    // TODO: Add method for validating a certificate, e.g. whether or not it has already expired
}
