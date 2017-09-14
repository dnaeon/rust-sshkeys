use std::{io, string, fmt, result};
use std::error::Error as StdError;

use base64;

// The `Error` type represents the possible errors that may occur when
// dealing with OpenSSH keys.
#[derive(Debug)]
pub struct Error {
    pub(crate) kind: Kind,
}

impl Error {
    // TODO: Make this associated function only public to the crate?
    pub fn with_kind(kind: Kind) -> Error {
        Error { kind: kind }
    }
}

#[derive(Debug)]
pub enum Kind {
    Io(io::Error),
    Decode(base64::DecodeError),
    Utf8Error(string::FromUtf8Error),
    InvalidCertType(u32),
    InvalidFormat,
    UnexpectedEof,
    NotCertificate,
    KeyTypeMismatch,
    UnknownKeyType(String),
}

// A `Result` type alias where the `Err` variant is `Error`
pub type Result<T> = result::Result<T, Error>;

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error { kind: Kind::Io(error) }
    }
}

impl From<base64::DecodeError> for Error {
    fn from(error: base64::DecodeError) -> Error {
        Error { kind: Kind::Decode(error) }
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(error: string::FromUtf8Error) -> Error {
        Error { kind: Kind::Utf8Error(error) }
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match self.kind {
            Kind::Io(ref e)          => e.description(),
            Kind::Decode(ref e)      => e.description(),
            Kind::Utf8Error(ref e)   => e.description(),
            Kind::InvalidCertType(_) => "Invalid certificate type",
            Kind::InvalidFormat      => "Invalid format",
            Kind::UnexpectedEof      => "Unexpected EOF reached while reading data",
            Kind::UnknownKeyType(_)  => "Unknown key type",
            Kind::NotCertificate     => "Not a certificate",
            Kind::KeyTypeMismatch    => "Key type mismatch",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match self.kind {
            Kind::Io(ref e)          => e.cause(),
            Kind::Decode(ref e)      => e.cause(),
            Kind::Utf8Error(ref e)   => e.cause(),
            Kind::InvalidCertType(_) |
            Kind::InvalidFormat      |
            Kind::UnexpectedEof      |
            Kind::NotCertificate     |
            Kind::KeyTypeMismatch    |
            Kind::UnknownKeyType(_)  => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            Kind::Io(ref err)           => err.fmt(f),
            Kind::Decode(ref err)       => err.fmt(f),
            Kind::Utf8Error(ref err)    => err.fmt(f),
            Kind::InvalidFormat         => write!(f, "Invalid format"),
            Kind::InvalidCertType(v)    => write!(f, "Invalid certificate type with value {}", v),
            Kind::UnexpectedEof         => write!(f, "Unexpected EOF reached while reading data"),
            Kind::UnknownKeyType(ref v) => write!(f, "Unknown key type {}", v),
            Kind::NotCertificate        => write!(f, "Not a certificate"),
            Kind::KeyTypeMismatch       => write!(f, "Key type mismatch"),
        }
    }
}
