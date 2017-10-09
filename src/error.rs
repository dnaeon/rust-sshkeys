use std::{io, string, fmt, result};
use std::error::Error as StdError;

use base64;

/// The `Error` type represents the possible errors that may occur when
/// dealing with OpenSSH keys.
#[derive(Debug)]
pub struct Error {
    pub(crate) kind: ErrorKind,
}

impl Error {
    pub(crate) fn with_kind(kind: ErrorKind) -> Error {
        Error { kind: kind }
    }
}

/// A type to represent the different kinds of errors.
#[derive(Debug)]
pub enum ErrorKind {
    Io(io::Error),
    Decode(base64::DecodeError),
    Utf8Error(string::FromUtf8Error),
    InvalidCertType(u32),
    InvalidFormat,
    UnexpectedEof,
    NotCertificate,
    KeyTypeMismatch,
    UnknownKeyType(String),
    UnknownCurve(String),
}

/// A `Result` type alias where the `Err` variant is `Error`
pub type Result<T> = result::Result<T, Error>;

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error { kind: ErrorKind::Io(error) }
    }
}

impl From<base64::DecodeError> for Error {
    fn from(error: base64::DecodeError) -> Error {
        Error { kind: ErrorKind::Decode(error) }
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(error: string::FromUtf8Error) -> Error {
        Error { kind: ErrorKind::Utf8Error(error) }
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match self.kind {
            ErrorKind::Io(ref e)          => e.description(),
            ErrorKind::Decode(ref e)      => e.description(),
            ErrorKind::Utf8Error(ref e)   => e.description(),
            ErrorKind::InvalidCertType(_) => "Invalid certificate type",
            ErrorKind::InvalidFormat      => "Invalid format",
            ErrorKind::UnexpectedEof      => "Unexpected EOF reached while reading data",
            ErrorKind::UnknownKeyType(_)  => "Unknown key type",
            ErrorKind::NotCertificate     => "Not a certificate",
            ErrorKind::KeyTypeMismatch    => "Key type mismatch",
            ErrorKind::UnknownCurve(_)    => "Unknown curve",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match self.kind {
            ErrorKind::Io(ref e)          => e.cause(),
            ErrorKind::Decode(ref e)      => e.cause(),
            ErrorKind::Utf8Error(ref e)   => e.cause(),
            ErrorKind::InvalidCertType(_) |
            ErrorKind::InvalidFormat      |
            ErrorKind::UnexpectedEof      |
            ErrorKind::NotCertificate     |
            ErrorKind::KeyTypeMismatch    |
            ErrorKind::UnknownCurve(_)    |
            ErrorKind::UnknownKeyType(_)  => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            ErrorKind::Io(ref err)           => err.fmt(f),
            ErrorKind::Decode(ref err)       => err.fmt(f),
            ErrorKind::Utf8Error(ref err)    => err.fmt(f),
            ErrorKind::InvalidFormat         => write!(f, "Invalid format"),
            ErrorKind::InvalidCertType(v)    => write!(f, "Invalid certificate type with value {}", v),
            ErrorKind::UnexpectedEof         => write!(f, "Unexpected EOF reached while reading data"),
            ErrorKind::UnknownKeyType(ref v) => write!(f, "Unknown key type {}", v),
            ErrorKind::NotCertificate        => write!(f, "Not a certificate"),
            ErrorKind::KeyTypeMismatch       => write!(f, "Key type mismatch"),
            ErrorKind::UnknownCurve(ref v)   => write!(f, "Unknown curve {}", v),
        }
    }
}
