use super::error::{Error, ErrorKind, Result};

use byteorder::{BigEndian, ByteOrder};

// A `Reader` is used for reading and iterating over a
// byte sequence representing an OpenSSH certificate key.
// The data types used in an OpenSSH certificate key are
// described in RFC4251 section 5.
pub struct Reader<'a> {
    inner: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    // Creates a new `Reader` instance from the given slice.
    pub fn new<T: ?Sized + AsRef<[u8]>>(inner: &T) -> Reader {
        Reader { inner: inner.as_ref(), offset: 0, }
    }

    // Sets the `Reader` offset to a given position.
    pub fn set_offset(&mut self, offset: usize) -> Result<()> {
        self.offset = offset;

        Ok(())
    }

    // Reads a `string` value from the wrapped byte sequence and
    // returns it as a `Vec<u8>`.
    // A `string` is represented by it's length as `u32` value
    // followed by the bytes to read.
    pub fn read_bytes(&mut self) -> Result<Vec<u8>> {
        if self.offset >= self.inner.len() {
            return Err(Error::with_kind(ErrorKind::UnexpectedEof));
        }

        let slice = &self.inner[self.offset..];

        if slice.len() < 4 {
            return Err(Error::with_kind(ErrorKind::InvalidFormat));
        }

        let size = BigEndian::read_u32(&slice[..4]) as usize;

        if slice.len() < size + 4 {
            return Err(Error::with_kind(ErrorKind::InvalidFormat));
        }

        self.offset += size + 4;
        let result = slice[4..size + 4].to_vec();

        Ok(result)
    }

    // Reads an `mpint` value from the wrapped byte sequence.
    // Drops the leading byte if it's value is zero.
    pub fn read_mpint(&mut self) -> Result<Vec<u8>> {
        let bytes = self.read_bytes()?;

        if bytes[0] == 0 {
            return Ok(bytes[1..].to_vec());
        }

        Ok(bytes)
    }

    // Reads a `string` value from the wrapped byte sequence and
    // returns it as a `String`.
    // The value that we read should be a valid UTF-8.
    // If the value is not a valid UTF-8 consider using `read_string_unchecked` method.
    pub fn read_string(&mut self) -> Result<String> {
        let bytes = self.read_bytes()?;
        let result = String::from_utf8(bytes)?;

        Ok(result)
    }

    // Reads an `u32` value from the wrapped byte sequence and returns it.
    pub fn read_u32(&mut self) -> Result<u32> {
        if self.offset >= self.inner.len() {
            return Err(Error::with_kind(ErrorKind::UnexpectedEof));
        }

        let slice = &self.inner[self.offset..];
        if slice.len() < 4 {
            return Err(Error::with_kind(ErrorKind::InvalidFormat));
        }

        self.offset += 4;
        let value = BigEndian::read_u32(&slice[..4]);

        Ok(value)
    }

    // Reads an `u64` value from the wrapped byte sequence and returns it.
    pub fn read_u64(&mut self) -> Result<u64> {
        if self.offset >= self.inner.len() {
            return Err(Error::with_kind(ErrorKind::UnexpectedEof));
        }

        let slice = &self.inner[self.offset..];
        if slice.len() < 8 {
            return Err(Error::with_kind(ErrorKind::InvalidFormat));
        }

        self.offset += 8;
        let value = BigEndian::read_u64(&slice[..8]);

        Ok(value)
    }
}
