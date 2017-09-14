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
#[derive(Debug, PartialEq)]
pub enum CertType {
    User,
    Host
}

#[derive(Debug)]
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
            Ok(buf) => Cursor::new(&buf).read_strings()?,
            Err(e)  => return Err(e),
        };

        let valid_after = cursor.read_u64()?;
        let valid_before = cursor.read_u64()?;

        // Critical options
        let co_buf = cursor.read_bytes()?;
        let critical_options = read_options(&co_buf)?;

        // Extensions
        let extensions_buf = cursor.read_bytes()?;
        let extensions = read_options(&extensions_buf)?;

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

// Reads `option` values from a byte sequence.
// The `option` values are used to represent the `critical options` and
// `extensions` in an OpenSSH certificate key, which are represented as tuples
// containing the `name` and `data` values of type `string`.
// Some `options` are `flags` only (e.g. the certificate extensions) and the
// associated value with them is the empty string (""), while others are `string`
// options and have an associated value, which is a `string`.
// The `critical options` of a certificate are always `string` options, since they
// have an associated `string` value, which is embedded in a separate buffer, so
// in order to extract the associated value we need to read the buffer first and then
// read the `string` value itself.
fn read_options(buf: &[u8]) -> Result<HashMap<String, String>> {
    let mut reader = Cursor::new(&buf);
    let mut options = HashMap::new();

    // Use a `Reader` and loop until EOF is reached, so that we can
    // read all options from the provided byte slice.
    loop {
        let name = match reader.read_string() {
            Ok(v)  => v,
            Err(e) => {
                match e.kind {
                    Kind::UnexpectedEof => break,
                    _ => return Err(e),
                }
            },
        };

        // If we have a `string` option extract the value from the buffer,
        // otherwise we have a `flag` option which is the `empty` string.
        let value_buf = reader.read_bytes()?;
        let value = if value_buf.len() > 0 {
            Cursor::new(&value_buf).read_string()?
        } else {
            "".to_string()
        };

        // TODO: Check if the options are in lexical order
        // TODO: Check if options are specified only once
        options.insert(name, value);
    }

    Ok(options)
}
