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
//! In order to view examples of this crate in use, please refer to the
//! `examples` directory.

extern crate base64;
extern crate byteorder;
extern crate sha2;

mod cert;
mod error;
mod keytype;
mod pubkey;
mod reader;
mod writer;

pub use self::cert::{CertType, Certificate};
pub use self::error::{Error, Result};
pub use self::keytype::{KeyType, KeyTypeKind};
pub use self::pubkey::{Curve, CurveKind, DsaPublicKey, EcdsaPublicKey, Ed25519PublicKey,
                       Fingerprint, FingerprintKind, PublicKey, PublicKeyKind, RsaPublicKey};
pub use self::reader::Reader;
pub use self::writer::Writer;
