use super::error::{Error, ErrorKind, Result};

use base64;
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};

pub struct Writer {
    inner: Vec<u8>,
}

impl Writer {
    pub fn new() -> Writer {
        Writer { inner: Vec::new() }
    }

    // Writes a byte sequence to the underlying vector.
    // The value is represented as a the byte sequence length,
    // followed by the actual byte sequence.
    pub fn write_bytes(&mut self, val: &[u8]) -> Result<()> {
        let mut bytes = val.to_vec();
        let size = bytes.len() as u32;
        self.inner.write_u32::<BigEndian>(size)?;
        self.inner.append(&mut bytes);

        Ok(())
    }

    // Writes a `string` value to the underlying byte sequence.
    pub fn write_string(&mut self, val: &str) -> Result<()> {
        self.write_bytes(val.as_bytes())
    }

    // Writes an `mpint` value to the underlying byte sequence.
    // If the MSB bit of the first byte is set then the number is
    // negative, otherwise it is positive.
    // Positive numbers must be preceeded by a leading zero byte according to RFC 4251, section 5.
    pub fn write_mpint(&mut self, val: &[u8]) -> Result<()> {
        let mut bytes = val.to_vec();
        let msb = match val.get(0) {
            Some(x) => x,
            None => return Err(Error::with_kind(ErrorKind::InvalidFormat)),
        };

        // Positive mpints must be preceeded by a leading zero byte
        if msb & 0x80 == 0 {
            bytes.insert(0, 0);
        }

        self.write_bytes(&bytes)
    }

    // Converts the `Writer` into a byte sequence.
    // This consumes the underlying byte sequence used by the `Writer`.
    pub fn into_bytes(self) -> Vec<u8> {
        self.inner
    }
}
