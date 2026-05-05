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

    /// Unsigned Exp-Golomb (`ue(v)`). H.264 9.1 / H.265 9.2.
    /// Returns an error if more than 32 leading zeros are seen
    /// (would overflow a `u32`).
    pub fn ue(&mut self) -> Result<u32, BitstreamError> {
        let mut leading_zeros = 0u32;
        while !self.at_end() && self.read_bit() == 0 {
            leading_zeros += 1;
            if leading_zeros > 32 {
                return Err(BitstreamError::InvalidData(
                    "ue(v): more than 32 leading zero bits".into(),
                ));
            }
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
}
