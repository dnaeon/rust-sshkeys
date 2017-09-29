use super::error::{Error, ErrorKind, Result};

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};

// A `Writer` is used by encoding a key in OpenSSH compatible format.
pub struct Writer {
    inner: Vec<u8>,
}

impl Writer {
    // Creates a new `Writer` instance.
    pub fn new() -> Writer {
        Writer { inner: Vec::new() }
    }

    // Writes a byte sequence to the underlying vector.
    // The value is represented as a the byte sequence length,
    // followed by the actual byte sequence.
    pub fn write_bytes(&mut self, val: &[u8]) {
        let mut bytes = val.to_vec();
        let size = bytes.len() as u32;
        self.inner.write_u32::<BigEndian>(size);
        self.inner.append(&mut bytes);
    }

    // Writes a `string` value to the underlying byte sequence.
    pub fn write_string(&mut self, val: &str) {
        self.write_bytes(val.as_bytes())
    }

    // Writes an `mpint` value to the underlying byte sequence.
    // If the MSB bit of the first byte is set then the number is
    // negative, otherwise it is positive.
    // Positive numbers must be preceeded by a leading zero byte according to RFC 4251, section 5.
    pub fn write_mpint(&mut self, val: &[u8]) {
        let mut bytes = val.to_vec();

        // If most significant bit is set then prepend a zero byte to
        // avoid interpretation as a negative number.
        if val.get(0).unwrap_or(&0) & 0x80 != 0 {
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
