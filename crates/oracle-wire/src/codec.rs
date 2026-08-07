//! Big-endian primitives for the canonical encodings.
//!
//! Writing is infallible and panics on a buffer mismatch, because a fixed-layout
//! encoder that overruns its buffer is a bug in this crate, not a runtime
//! condition. Reading is fallible throughout: its input arrives from the network.

use crate::WireError;

/// A destination for canonical bytes.
pub(crate) trait Sink {
    /// Appends raw bytes.
    fn put_bytes(&mut self, bytes: &[u8]);

    fn put_u8(&mut self, value: u8) {
        self.put_bytes(&[value]);
    }

    fn put_u16(&mut self, value: u16) {
        self.put_bytes(&value.to_be_bytes());
    }

    fn put_u32(&mut self, value: u32) {
        self.put_bytes(&value.to_be_bytes());
    }

    fn put_u64(&mut self, value: u64) {
        self.put_bytes(&value.to_be_bytes());
    }

    fn put_i32(&mut self, value: i32) {
        self.put_bytes(&value.to_be_bytes());
    }

    fn put_i64(&mut self, value: i64) {
        self.put_bytes(&value.to_be_bytes());
    }

    /// Appends a `u16`-length-prefixed string, enforcing a cap.
    ///
    /// The cap is what keeps canonical re-encoding of an untrusted registry from
    /// becoming unbounded work, so this is fallible where the rest is not.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::FieldTooLong`] if the string exceeds `limit` bytes.
    fn try_put_str(
        &mut self,
        field: &'static str,
        value: &str,
        limit: usize,
    ) -> Result<(), WireError> {
        let bytes = value.as_bytes();
        if bytes.len() > limit {
            return Err(WireError::FieldTooLong {
                field,
                actual: bytes.len(),
                limit,
            });
        }
        let len = u16::try_from(bytes.len()).map_err(|_| WireError::FieldTooLong {
            field,
            actual: bytes.len(),
            limit,
        })?;
        self.put_u16(len);
        self.put_bytes(bytes);
        Ok(())
    }
}

impl Sink for Vec<u8> {
    fn put_bytes(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// A stack buffer of exactly `N` bytes, for fixed-layout payloads.
pub(crate) struct FixedBuf<const N: usize> {
    buf: [u8; N],
    pos: usize,
}

impl<const N: usize> FixedBuf<N> {
    pub(crate) const fn new() -> Self {
        Self {
            buf: [0_u8; N],
            pos: 0,
        }
    }

    /// Returns the completed buffer.
    ///
    /// # Panics
    ///
    /// Panics if fewer than `N` bytes were written, which means the encoder and
    /// the declared payload size have drifted apart.
    pub(crate) fn finish(self) -> [u8; N] {
        assert_eq!(
            self.pos, N,
            "encoder wrote {} bytes into a {N}-byte payload",
            self.pos
        );
        self.buf
    }
}

impl<const N: usize> Sink for FixedBuf<N> {
    /// # Panics
    ///
    /// Panics if the write would overrun the buffer. See the module docs.
    fn put_bytes(&mut self, bytes: &[u8]) {
        let end = self.pos + bytes.len();
        self.buf[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
    }
}

/// A cursor over untrusted bytes.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(len).ok_or(WireError::Truncated {
            expected: len,
            actual: self.remaining(),
        })?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated {
            expected: len,
            actual: self.remaining(),
        })?;
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let slice = self.take(N)?;
        let mut out = [0_u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, WireError> {
        Ok(u8::from_be_bytes(self.array::<1>()?))
    }

    pub(crate) fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    pub(crate) fn i32(&mut self) -> Result<i32, WireError> {
        Ok(i32::from_be_bytes(self.array::<4>()?))
    }

    pub(crate) fn i64(&mut self) -> Result<i64, WireError> {
        Ok(i64::from_be_bytes(self.array::<8>()?))
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Asserts the input was consumed exactly.
    ///
    /// Trailing bytes are an error rather than an ignorable suffix: a decoder
    /// that tolerates them lets two distinct byte strings decode to the same
    /// update, which breaks signature-keyed deduplication.
    pub(crate) fn finish(self) -> Result<(), WireError> {
        match self.remaining() {
            0 => Ok(()),
            n => Err(WireError::TrailingBytes(n)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_buffer_round_trips() {
        let mut buf = FixedBuf::<15>::new();
        buf.put_u8(0x01);
        buf.put_u16(0x0203);
        buf.put_u32(0x0405_0607);
        buf.put_i64(-1);
        let bytes = buf.finish();
        assert_eq!(&bytes[..7], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);

        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.u8().expect("read"), 0x01);
        assert_eq!(reader.u16().expect("read"), 0x0203);
        assert_eq!(reader.u32().expect("read"), 0x0405_0607);
        assert_eq!(reader.i64().expect("read"), -1);
        assert!(reader.finish().is_ok());
    }

    #[test]
    #[should_panic(expected = "encoder wrote")]
    fn fixed_buffer_rejects_short_writes() {
        let mut buf = FixedBuf::<8>::new();
        buf.put_u32(1);
        let _ = buf.finish();
    }

    #[test]
    fn reader_reports_truncation() {
        let mut reader = Reader::new(&[1, 2]);
        assert!(matches!(reader.u32(), Err(WireError::Truncated { .. })));
    }

    #[test]
    fn reader_rejects_trailing_bytes() {
        let mut reader = Reader::new(&[1, 2, 3]);
        assert_eq!(reader.u8().expect("read"), 1);
        assert_eq!(reader.finish(), Err(WireError::TrailingBytes(2)));
    }

    #[test]
    fn string_cap_is_enforced() {
        let mut out = Vec::new();
        assert!(out.try_put_str("node_id", "oracle-eu-1", 64).is_ok());
        assert!(matches!(
            out.try_put_str("node_id", &"x".repeat(65), 64),
            Err(WireError::FieldTooLong {
                limit: 64,
                actual: 65,
                ..
            })
        ));
    }
}
