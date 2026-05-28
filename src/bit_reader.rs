//! Shared MSB-first bit reader with `u(n)` / `ue(v)` / `se(v)`
//! primitives. These are the basic building blocks every codec module
//! needs.
//!
//! # Conventions
//!
//! - `u(n)` reads `n` bits (0 ≤ n ≤ 32), MSB first inside each byte.
//! - `ue(v)` is the unsigned Exp-Golomb code from H.264 9.1 / H.265 9.2.
//! - `se(v)` is the signed Exp-Golomb code from H.264 9.1.1 /
//!   H.265 9.2.2.
//! - Past-the-end reads silently yield zero bits. Callers wanting
//!   strict EOF behaviour should compare [`BitReader::bit_pos`]
//!   against `bytes.len() * 8` themselves.

use crate::BitstreamError;

/// MSB-first bit reader over a borrowed byte slice.
pub struct BitReader<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) bit_pos: usize,
}

impl<'a> BitReader<'a> {
    /// Create a fresh reader positioned at bit 0 of `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bit_pos: 0 }
    }

    /// Total number of payload bits in the reader.
    pub fn total_bits(&self) -> usize {
        self.bytes.len() * 8
    }

    /// Current absolute bit offset.
    pub fn bit_pos(&self) -> usize {
        self.bit_pos
    }

    /// Number of unread bits (saturating at zero).
    pub fn bits_remaining(&self) -> usize {
        self.total_bits().saturating_sub(self.bit_pos)
    }

    /// True if the next read would fall past the end of the buffer.
    pub fn at_end(&self) -> bool {
        self.bit_pos >= self.total_bits()
    }

    /// True if the reader is currently byte-aligned.
    pub fn byte_aligned(&self) -> bool {
        self.bit_pos % 8 == 0
    }

    /// Skip forward by `n` bits.
    pub fn skip(&mut self, n: usize) {
        self.bit_pos = self.bit_pos.saturating_add(n);
    }

    /// Skip forward to the next byte boundary if not already aligned.
    pub fn align_to_byte(&mut self) {
        let rem = self.bit_pos % 8;
        if rem != 0 {
            self.bit_pos += 8 - rem;
        }
    }

    /// Read one bit. Returns 0 past the end.
    pub fn read_bit(&mut self) -> u32 {
        let byte_idx = self.bit_pos / 8;
        let shift = 7 - (self.bit_pos % 8) as u32;
        let bit = if byte_idx < self.bytes.len() {
            ((self.bytes[byte_idx] >> shift) & 1) as u32
        } else {
            0
        };
        self.bit_pos += 1;
        bit
    }

    /// Read `n` bits MSB first into a `u32`. Past-the-end bits are 0.
    /// `n` must be ≤ 32 (the upper limit covers every fixed-width
    /// field used by H.264 / HEVC / AV1 OBU headers).
    pub fn u(&mut self, n: u32) -> u32 {
        debug_assert!(n <= 32, "BitReader::u({n}) > 32 bits");
        let mut value: u32 = 0;
        for _ in 0..n {
            value = (value << 1) | self.read_bit();
        }
        value
    }

    /// Read `n` bits MSB first into a `u64` (for AV1's 64-bit
    /// `reference_frame_id`-class fields).
    pub fn u64(&mut self, n: u32) -> u64 {
        debug_assert!(n <= 64, "BitReader::u64({n}) > 64 bits");
        let mut value: u64 = 0;
        for _ in 0..n {
            value = (value << 1) | (self.read_bit() as u64);
        }
        value
    }

    /// Peek the next `n` bits MSB-first without advancing `bit_pos`.
    /// `n` must be ≤ 32. Past-the-end bits are zero, identical to
    /// [`BitReader::u`]'s contract. Useful for codec parsers that need
    /// to inspect a marker bit before deciding whether to commit to a
    /// branch.
    pub fn peek_bits(&self, n: u32) -> u32 {
        debug_assert!(n <= 32, "BitReader::peek_bits({n}) > 32 bits");
        let mut value: u32 = 0;
        let total = self.total_bits();
        for offset in 0..n as usize {
            let pos = self.bit_pos + offset;
            let bit = if pos < total {
                let byte_idx = pos / 8;
                let shift = 7 - (pos % 8) as u32;
                ((self.bytes[byte_idx] >> shift) & 1) as u32
            } else {
                0
            };
            value = (value << 1) | bit;
        }
        value
    }

    /// H.264 §7.2 / H.265 §7.2 / H.266 §7.2 `more_rbsp_data()`.
    ///
    /// Returns `true` if there is at least one more RBSP data bit
    /// before the `rbsp_trailing_bits()` marker. The marker is a `1`
    /// bit (the `rbsp_stop_one_bit`) followed by zero or more `0`
    /// bits up to the next byte boundary, sitting at the end of the
    /// RBSP. The algorithm: search forward from the current position
    /// for any `1` bit after the *next* `1` — if we find one, the
    /// next `1` was not the stop marker and there is more data.
    ///
    /// Returns `false` once positioned at or past the stop bit, and
    /// at end-of-stream.
    pub fn more_rbsp_data(&self) -> bool {
        let total = self.total_bits();
        if self.bit_pos >= total {
            return false;
        }
        let mut saw_one = false;
        for p in self.bit_pos..total {
            let b = (self.bytes[p / 8] >> (7 - (p % 8))) & 1;
            if !saw_one {
                if b == 1 {
                    saw_one = true;
                }
            } else if b == 1 {
                return true;
            }
        }
        false
    }

    /// H.264 §7.3.2.11 / H.265 §7.3.2.11 / H.266 §7.3.10
    /// `rbsp_trailing_bits()`. Consumes a `1` (`rbsp_stop_one_bit`)
    /// followed by zero or more `0` bits up to the next byte
    /// boundary. Returns `Err(InvalidData)` if the next bit is not
    /// `1`, if any of the padding bits before the boundary is not
    /// `0`, or if the stream ends before the marker is found.
    pub fn read_rbsp_trailing_bits(&mut self) -> Result<(), BitstreamError> {
        if self.at_end() {
            return Err(BitstreamError::UnexpectedEnd(
                "rbsp_trailing_bits: no bits left for stop bit".into(),
            ));
        }
        if self.read_bit() != 1 {
            return Err(BitstreamError::InvalidData(
                "rbsp_trailing_bits: rbsp_stop_one_bit was 0".into(),
            ));
        }
        while !self.byte_aligned() {
            if self.at_end() {
                return Err(BitstreamError::UnexpectedEnd(
                    "rbsp_trailing_bits: stream ended before byte alignment".into(),
                ));
            }
            if self.read_bit() != 0 {
                return Err(BitstreamError::InvalidData(
                    "rbsp_trailing_bits: alignment_zero_bit was 1".into(),
                ));
            }
        }
        Ok(())
    }

    /// Unsigned Exp-Golomb (`ue(v)`). H.264 9.1 / H.265 9.2.
    /// Returns an error if 32 or more leading zeros are seen: the
    /// largest representable `ue(v)` value is `u32::MAX - 1` (31 leading
    /// zeros), so 32 leading zeros has no valid `u32` value and the
    /// `1 << leadingZeros` term would overflow.
    pub fn ue(&mut self) -> Result<u32, BitstreamError> {
        let mut leading_zeros = 0u32;
        while !self.at_end() && self.read_bit() == 0 {
            leading_zeros += 1;
            if leading_zeros >= 32 {
                return Err(BitstreamError::InvalidData(
                    "ue(v): 32 or more leading zero bits".into(),
                ));
            }
        }
        // The loop can also exit by hitting end-of-stream after a run of
        // zeros (every remaining bit was 0). Guard that path too so a
        // 32-bit all-zero buffer can never reach the shift below with
        // `leading_zeros == 32`.
        if leading_zeros >= 32 {
            return Err(BitstreamError::InvalidData(
                "ue(v): 32 or more leading zero bits".into(),
            ));
        }
        if leading_zeros == 0 {
            Ok(0)
        } else {
            let suffix = self.u(leading_zeros);
            Ok((1u32 << leading_zeros) - 1 + suffix)
        }
    }

    /// Signed Exp-Golomb (`se(v)`). H.264 9.1.1 / H.265 9.2.2.
    pub fn se(&mut self) -> Result<i32, BitstreamError> {
        let code = self.ue()?;
        if code == 0 {
            Ok(0)
        } else if code & 1 == 1 {
            Ok(code.div_ceil(2) as i32)
        } else {
            Ok(-((code / 2) as i32))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u_reads_known_pattern() {
        // 0b1010_1100 0b1111_0000
        let bytes = [0b1010_1100, 0b1111_0000];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.u(4), 0b1010);
        assert_eq!(r.u(4), 0b1100);
        assert_eq!(r.u(8), 0b1111_0000);
    }

    #[test]
    fn ue_decodes_known_values() {
        // 1 010 011 00100 → ue codes 0,1,2,3 (13 bits)
        // Packed MSB-first: 10100110 01000000
        let bytes = [0b1010_0110, 0b0100_0000];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.ue().unwrap(), 0);
        assert_eq!(r.ue().unwrap(), 1);
        assert_eq!(r.ue().unwrap(), 2);
        assert_eq!(r.ue().unwrap(), 3);
    }

    #[test]
    fn se_decodes_zero_pos_neg() {
        // ue codes: 0, 1, 2 → se: 0, +1, -1
        let bytes = [0b1010_0110, 0b0000_0000];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.se().unwrap(), 0);
        assert_eq!(r.se().unwrap(), 1);
        assert_eq!(r.se().unwrap(), -1);
    }

    #[test]
    fn align_to_byte_no_op_when_aligned() {
        let bytes = [0xff, 0x00];
        let mut r = BitReader::new(&bytes);
        r.u(8);
        assert!(r.byte_aligned());
        r.align_to_byte();
        assert_eq!(r.bit_pos, 8);
    }

    #[test]
    fn align_to_byte_advances_to_next_byte() {
        let bytes = [0xff, 0x00];
        let mut r = BitReader::new(&bytes);
        r.u(3);
        r.align_to_byte();
        assert_eq!(r.bit_pos, 8);
    }

    #[test]
    fn past_end_reads_zero() {
        let bytes = [0xff];
        let mut r = BitReader::new(&bytes);
        r.u(8);
        assert_eq!(r.u(8), 0);
        assert!(r.at_end());
    }

    #[test]
    fn peek_bits_does_not_advance() {
        let bytes = [0b1010_1100, 0b1111_0000];
        let r0 = BitReader::new(&bytes);
        assert_eq!(r0.peek_bits(4), 0b1010);
        // Re-borrow as mutable to compare against a real read.
        let mut r = BitReader::new(&bytes);
        let peeked = r.peek_bits(8);
        assert_eq!(peeked, 0b1010_1100);
        assert_eq!(r.bit_pos(), 0);
        assert_eq!(r.u(8), 0b1010_1100);
    }

    #[test]
    fn peek_bits_past_end_is_zero_padded() {
        let bytes = [0b1111_0000];
        let mut r = BitReader::new(&bytes);
        // Advance to bit 4; the next 4 payload bits are 0.
        r.u(4);
        assert_eq!(r.peek_bits(8), 0b0000_0000);
        // Past the end entirely.
        r.u(4);
        assert_eq!(r.peek_bits(16), 0);
    }

    #[test]
    fn more_rbsp_data_after_payload() {
        // Three payload bits `101`, then `rbsp_stop_one_bit=1`, then
        // 4 zero alignment bits = byte 0b1011_0000 = 0xB0.
        let bytes = [0xB0];
        let mut r = BitReader::new(&bytes);
        assert!(r.more_rbsp_data(), "before payload there's more data");
        r.u(1); // 1 (payload bit 0)
        assert!(r.more_rbsp_data());
        r.u(1); // 0 (payload bit 1)
        assert!(r.more_rbsp_data());
        r.u(1); // 1 (payload bit 2) — positioned at stop bit now
        assert!(!r.more_rbsp_data());
    }

    #[test]
    fn more_rbsp_data_minimal_stop_byte() {
        // Just the stop byte (no payload): 0b1000_0000.
        let bytes = [0x80];
        let r = BitReader::new(&bytes);
        assert!(
            !r.more_rbsp_data(),
            "stop-bit-only buffer has no further RBSP data"
        );
    }

    #[test]
    fn more_rbsp_data_at_end_is_false() {
        let bytes = [0xff];
        let mut r = BitReader::new(&bytes);
        r.u(8);
        assert!(!r.more_rbsp_data());
    }

    #[test]
    fn read_rbsp_trailing_bits_accepts_minimal_marker() {
        // 0b1000_0000: stop_one_bit + 7 zero alignment bits.
        let bytes = [0x80];
        let mut r = BitReader::new(&bytes);
        r.read_rbsp_trailing_bits().unwrap();
        assert!(r.byte_aligned());
        assert!(r.at_end());
    }

    #[test]
    fn read_rbsp_trailing_bits_after_payload() {
        // 5 payload bits `10110`, stop bit, 2 zero pad → 0b1011_0100 = 0xB4.
        let bytes = [0xB4];
        let mut r = BitReader::new(&bytes);
        // Consume the payload.
        assert_eq!(r.u(5), 0b10110);
        r.read_rbsp_trailing_bits().unwrap();
        assert!(r.byte_aligned());
        assert!(r.at_end());
    }

    #[test]
    fn read_rbsp_trailing_bits_rejects_zero_stop_bit() {
        let bytes = [0x00];
        let mut r = BitReader::new(&bytes);
        match r.read_rbsp_trailing_bits() {
            Err(BitstreamError::InvalidData(msg)) => assert!(msg.contains("stop")),
            other => panic!("expected InvalidData, got {other:?}"),
        }
    }

    #[test]
    fn read_rbsp_trailing_bits_rejects_nonzero_alignment_bit() {
        // stop bit + 0001 alignment (bit 4 from MSB is 1).
        let bytes = [0b1000_1000];
        let mut r = BitReader::new(&bytes);
        match r.read_rbsp_trailing_bits() {
            Err(BitstreamError::InvalidData(msg)) => assert!(msg.contains("alignment")),
            other => panic!("expected InvalidData, got {other:?}"),
        }
    }

    #[test]
    fn read_rbsp_trailing_bits_rejects_empty_reader() {
        let bytes: [u8; 0] = [];
        let mut r = BitReader::new(&bytes);
        match r.read_rbsp_trailing_bits() {
            Err(BitstreamError::UnexpectedEnd(_)) => {}
            other => panic!("expected UnexpectedEnd, got {other:?}"),
        }
    }
}
