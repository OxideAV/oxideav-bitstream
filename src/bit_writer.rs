//! Shared MSB-first bit writer — the inverse of [`BitReader`].
//!
//! [`BitWriter`] accumulates bits MSB-first into an internal byte
//! buffer so that a value written with [`BitWriter::write_bits`] and
//! then read back with [`crate::bit_reader::BitReader::u`] at the same
//! bit offset round-trips exactly. The Exp-Golomb writers
//! ([`BitWriter::write_ue`] / [`BitWriter::write_se`]) are the inverses
//! of [`crate::bit_reader::BitReader::ue`] /
//! [`crate::bit_reader::BitReader::se`].
//!
//! # Conventions
//!
//! - Bits are packed MSB-first inside each byte, matching
//!   [`BitReader`](crate::bit_reader::BitReader).
//! - The buffer grows one byte at a time; partial trailing bits are
//!   left-aligned (the unused low bits of the final byte are zero).
//! - [`BitWriter::finish`] returns the accumulated bytes. Trailing
//!   zero-padding is implicit: if you wrote 11 bits you get 2 bytes
//!   with the low 5 bits of the second byte zero.
//!
//! # Clean-room
//!
//! This is an original primitive. No external bit-IO source was
//! consulted; it is defined purely as the algebraic inverse of the
//! in-crate [`BitReader`].

use crate::BitstreamError;

/// MSB-first bit writer accumulating into an owned `Vec<u8>`.
#[derive(Debug, Default, Clone)]
pub struct BitWriter {
    bytes: Vec<u8>,
    /// Number of valid bits in the buffer (≤ `bytes.len() * 8`).
    bit_pos: usize,
}

impl BitWriter {
    /// Create an empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of bits written so far.
    pub fn bit_pos(&self) -> usize {
        self.bit_pos
    }

    /// True if the next write would start on a byte boundary.
    pub fn byte_aligned(&self) -> bool {
        self.bit_pos % 8 == 0
    }

    /// Append a single bit (only bit 0 of `bit` is used).
    pub fn write_bit(&mut self, bit: u32) {
        let byte_idx = self.bit_pos / 8;
        if byte_idx >= self.bytes.len() {
            self.bytes.push(0);
        }
        if bit & 1 != 0 {
            let shift = 7 - (self.bit_pos % 8) as u32;
            self.bytes[byte_idx] |= 1u8 << shift;
        }
        self.bit_pos += 1;
    }

    /// Write the low `n` bits of `value` MSB-first. `n` must be ≤ 32;
    /// bits above bit `n-1` of `value` are ignored.
    pub fn write_bits(&mut self, value: u32, n: u32) {
        debug_assert!(n <= 32, "BitWriter::write_bits n={n} > 32");
        for i in (0..n).rev() {
            self.write_bit((value >> i) & 1);
        }
    }

    /// Write the low `n` bits of a `u64` MSB-first. `n` must be ≤ 64.
    pub fn write_bits_u64(&mut self, value: u64, n: u32) {
        debug_assert!(n <= 64, "BitWriter::write_bits_u64 n={n} > 64");
        for i in (0..n).rev() {
            self.write_bit(((value >> i) & 1) as u32);
        }
    }

    /// Write an unsigned Exp-Golomb (`ue(v)`) code — the inverse of
    /// [`BitReader::ue`](crate::bit_reader::BitReader::ue). Refuses
    /// `u32::MAX` because `code_num = value + 1` would overflow.
    pub fn write_ue(&mut self, value: u32) -> Result<(), BitstreamError> {
        if value == u32::MAX {
            return Err(BitstreamError::invalid(
                "write_ue: value u32::MAX has no representable ue(v) code",
            ));
        }
        let code_num = value + 1; // ≥ 1, so it has a defined MSB.
        let bits = 32 - code_num.leading_zeros(); // number of significant bits
        let leading_zeros = bits - 1;
        for _ in 0..leading_zeros {
            self.write_bit(0);
        }
        // `code_num` written in `bits` bits is `1` then the suffix;
        // this matches the reader's `(1 << lz) - 1 + suffix` decode.
        self.write_bits(code_num, bits);
        Ok(())
    }

    /// Write a signed Exp-Golomb (`se(v)`) code — the inverse of
    /// [`BitReader::se`](crate::bit_reader::BitReader::se).
    pub fn write_se(&mut self, value: i32) -> Result<(), BitstreamError> {
        // Mapping (H.264 9.1.1): 0→0, +k→2k-1, -k→2k for k>0.
        let code_num: u32 = if value == 0 {
            0
        } else if value > 0 {
            // 2*value - 1, computed without i32 overflow for i32::MAX.
            (value as u32)
                .checked_mul(2)
                .and_then(|x| x.checked_sub(1))
                .ok_or_else(|| BitstreamError::invalid("write_se: value too large for se(v)"))?
        } else {
            // value < 0: 2*|value|. `-(value as i64)` avoids i32::MIN
            // negation UB; result fits u32 for all valid magnitudes.
            let mag = -(value as i64) as u64;
            mag.checked_mul(2)
                .filter(|&x| x <= u32::MAX as u64)
                .map(|x| x as u32)
                .ok_or_else(|| BitstreamError::invalid("write_se: value too large for se(v)"))?
        };
        self.write_ue(code_num)
    }

    /// Pad with zero bits up to the next byte boundary.
    pub fn align_to_byte(&mut self) {
        while !self.byte_aligned() {
            self.write_bit(0);
        }
    }

    /// Consume the writer and return the accumulated bytes. The final
    /// byte's unused low bits (if the bit count is not a multiple of 8)
    /// are zero.
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    /// Borrow the accumulated bytes without consuming the writer.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bit_reader::BitReader;

    #[test]
    fn write_bits_matches_known_pattern() {
        let mut w = BitWriter::new();
        w.write_bits(0b1010, 4);
        w.write_bits(0b1100, 4);
        w.write_bits(0b1111_0000, 8);
        assert_eq!(w.finish(), vec![0b1010_1100, 0b1111_0000]);
    }

    #[test]
    fn ue_roundtrips_small_values() {
        let mut w = BitWriter::new();
        for v in 0..=10u32 {
            w.write_ue(v).unwrap();
        }
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        for v in 0..=10u32 {
            assert_eq!(r.ue().unwrap(), v);
        }
    }

    #[test]
    fn se_roundtrips_signed_values() {
        let mut w = BitWriter::new();
        let vals = [0, 1, -1, 2, -2, 100, -100];
        for &v in &vals {
            w.write_se(v).unwrap();
        }
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        for &v in &vals {
            assert_eq!(r.se().unwrap(), v);
        }
    }

    #[test]
    fn ue_rejects_u32_max() {
        let mut w = BitWriter::new();
        assert!(w.write_ue(u32::MAX).is_err());
    }
}
