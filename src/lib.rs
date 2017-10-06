#![deny(warnings)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

//! The `sshkeys` crate provides types and methods for parsing
//! OpenSSH public keys and certificates.
//!
//! The following public key types are supported.
//!
//! - RSA
//! - DSA
//! - ECDSA
//! - ED25519
//!
//! The following OpenSSH certificate types are supported as well.
//!
//! - ssh-rsa-cert-v01@openssh.com
//! - ssh-dss-cert-v01@openssh.com
//! - ecdsa-sha2-nistp256-cert-v01@openssh.com
//! - ecdsa-sha2-nistp384-cert-v01@openssh.com
//! - ecdsa-sha2-nistp512-cert-v01@openssh.com
//! - ssh-ed25519-cert-v01@openssh.com
//!
//! # Examples
//!
//! ```rust
//! # use sshkeys;
//! # fn run() -> sshkeys::Result<()> {
//! let key = sshkeys::PublicKey::from_path("/path/to/my-public-key.pub")?;
//! println!("Key bits: {}", key.bits());
//! # Ok(())
//! # }
//! ```
//!
//! TODO: Add more examples

extern crate base64;
extern crate byteorder;
extern crate sha2;

pub mod cert;
pub mod curve;
pub mod error;
pub mod keytype;
pub mod pubkey;
pub mod reader;
pub mod writer;

pub use self::curve::{Curve, CurveKind};
pub use self::cert::{CertType, Certificate};
pub use self::error::{Error, ErrorKind, Result};
pub use self::keytype::{KeyType, KeyTypeKind};
pub use self::pubkey::{PublicKey, PublicKeyKind, RsaPublicKey, DsaPublicKey, EcdsaPublicKey, Ed25519PublicKey, Fingerprint, FingerprintKind};
pub use self::reader::Reader;
pub use self::writer::Writer;


