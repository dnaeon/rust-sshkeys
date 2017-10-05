#![deny(warnings)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

extern crate base64;
extern crate byteorder;
extern crate sha2;

// TODO: Should all be public?
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


