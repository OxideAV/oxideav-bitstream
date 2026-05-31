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

    /// Write a signed `n`-bit two's complement integer — the inverse
    /// of [`BitReader::i`](crate::bit_reader::BitReader::i). `n` must
    /// be in `1..=32`; `value` must fit inside the representable range
    /// `-(2^(n-1)) .. 2^(n-1)`, otherwise `InvalidData` is returned.
    /// `n == 32` accepts every `i32`.
    pub fn write_i(&mut self, value: i32, n: u32) -> Result<(), BitstreamError> {
        if n == 0 || n > 32 {
            return Err(BitstreamError::invalid(format!(
                "write_i: n={n} outside 1..=32"
            )));
        }
        if n < 32 {
            let min = -(1i64 << (n - 1));
            let max = (1i64 << (n - 1)) - 1;
            let v = value as i64;
            if v < min || v > max {
                return Err(BitstreamError::invalid(format!(
                    "write_i: value {value} outside representable {n}-bit range"
                )));
            }
        }
        // Mask to `n` bits — this is the same encoding the reader
        // interprets as two's complement.
        let mask = if n == 32 { u32::MAX } else { (1u32 << n) - 1 };
        let raw = (value as u32) & mask;
        self.write_bits(raw, n);
        Ok(())
    }

    /// Write a signed value as `n` magnitude bits followed by a 1-bit
    /// sign (`1` = negative) — the inverse of
    /// [`BitReader::signed_magnitude`](crate::bit_reader::BitReader::signed_magnitude).
    /// `n` must be in `1..=31`; the magnitude must fit in `n` unsigned
    /// bits (i.e. `|value| < 2^n`).
    ///
    /// `value == 0` always writes sign=0 to keep the round-trip
    /// canonical (a `-0` symbol decodes back as `0`, so re-encoding it
    /// here as positive zero closes the loop with no fixed-point drift).
    pub fn write_signed_magnitude(&mut self, value: i32, n: u32) -> Result<(), BitstreamError> {
        if n == 0 || n > 31 {
            return Err(BitstreamError::invalid(format!(
                "write_signed_magnitude: n={n} outside 1..=31"
            )));
        }
        let max_mag = 1u64 << n;
        let magnitude = value.unsigned_abs() as u64;
        if magnitude >= max_mag {
            return Err(BitstreamError::invalid(format!(
                "write_signed_magnitude: |{value}| does not fit in {n} bits"
            )));
        }
        self.write_bits(magnitude as u32, n);
        let sign = if value < 0 { 1 } else { 0 };
        self.write_bit(sign);
        Ok(())
    }

    /// Write a truncated Exp-Golomb code — the inverse of
    /// [`BitReader::te`](crate::bit_reader::BitReader::te). H.264 §9.1.2.
    ///
    /// For `x_max == 1` the value must be 0 or 1 and is emitted as a
    /// single bit equal to `1 - value`. For `x_max > 1` the writer
    /// delegates to [`BitWriter::write_ue`] and additionally enforces
    /// `value <= x_max` (the spec only defines `te(v)` over that range).
    /// `x_max == 0` has no defined code and is rejected.
    pub fn write_te(&mut self, value: u32, x_max: u32) -> Result<(), BitstreamError> {
        if x_max == 0 {
            return Err(BitstreamError::invalid(
                "write_te: x_max == 0 has no defined code",
            ));
        }
        if value > x_max {
            return Err(BitstreamError::invalid(format!(
                "write_te: value {value} exceeds x_max {x_max}"
            )));
        }
        if x_max == 1 {
            self.write_bit(1 - value);
            Ok(())
        } else {
            self.write_ue(value)
        }
    }

    /// Append a byte slice. The writer must be byte-aligned; otherwise
    /// returns `InvalidData`. The matching reader is
    /// [`BitReader::read_bytes`](crate::bit_reader::BitReader::read_bytes).
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), BitstreamError> {
        if !self.byte_aligned() {
            return Err(BitstreamError::invalid(
                "write_bytes: writer is not byte-aligned",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        self.bit_pos += bytes.len() * 8;
        Ok(())
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

    #[test]
    fn write_i_roundtrips_full_eight_bit_range() {
        // Walk every legal i8 value through write_i(_, 8) and verify
        // BitReader::i(8) returns it.
        for v in i8::MIN..=i8::MAX {
            let mut w = BitWriter::new();
            w.write_i(v as i32, 8).unwrap();
            let bytes = w.finish();
            let mut r = BitReader::new(&bytes);
            assert_eq!(r.i(8).unwrap(), v as i32);
        }
    }

    #[test]
    fn write_i_rejects_out_of_range_values() {
        let mut w = BitWriter::new();
        // 4-bit range is [-8, 7]; 8 should be rejected.
        assert!(w.write_i(8, 4).is_err());
        assert!(w.write_i(-9, 4).is_err());
    }

    #[test]
    fn write_i_accepts_full_i32_range_at_width_32() {
        for &v in &[i32::MIN, -1, 0, 1, i32::MAX] {
            let mut w = BitWriter::new();
            w.write_i(v, 32).unwrap();
            let bytes = w.finish();
            let mut r = BitReader::new(&bytes);
            assert_eq!(r.i(32).unwrap(), v);
        }
    }

    #[test]
    fn write_signed_magnitude_roundtrips_positive_and_negative() {
        for v in [-31i32, -1, 0, 1, 31] {
            let mut w = BitWriter::new();
            w.write_signed_magnitude(v, 5).unwrap();
            let bytes = w.finish();
            let mut r = BitReader::new(&bytes);
            assert_eq!(r.signed_magnitude(5).unwrap(), v);
        }
    }

    #[test]
    fn write_signed_magnitude_rejects_overflow() {
        let mut w = BitWriter::new();
        // 6-bit magnitude → |value| < 64; 64 should be rejected.
        assert!(w.write_signed_magnitude(64, 6).is_err());
        assert!(w.write_signed_magnitude(-64, 6).is_err());
    }

    #[test]
    fn write_te_x_max_one_inverts_single_bit() {
        // value=0 → bit 1; value=1 → bit 0.
        let mut w = BitWriter::new();
        w.write_te(0, 1).unwrap();
        w.write_te(1, 1).unwrap();
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.te(1).unwrap(), 0);
        assert_eq!(r.te(1).unwrap(), 1);
    }

    #[test]
    fn write_te_x_max_above_one_matches_ue() {
        // Same round-trip but x_max > 1: delegates to ue/se path.
        let mut w = BitWriter::new();
        for v in 0..=10u32 {
            w.write_te(v, 100).unwrap();
        }
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        for v in 0..=10u32 {
            assert_eq!(r.te(100).unwrap(), v);
        }
    }

    #[test]
    fn write_te_rejects_value_above_x_max() {
        let mut w = BitWriter::new();
        assert!(w.write_te(11, 10).is_err());
        assert!(w.write_te(2, 1).is_err());
    }

    #[test]
    fn write_bytes_roundtrips_with_read_bytes() {
        let mut w = BitWriter::new();
        w.write_bits(0xA5, 8);
        w.write_bytes(&[0x11, 0x22, 0x33]).unwrap();
        let bytes = w.finish();
        assert_eq!(bytes, vec![0xA5, 0x11, 0x22, 0x33]);

        let mut r = BitReader::new(&bytes);
        assert_eq!(r.u(8), 0xA5);
        assert_eq!(r.read_bytes(3).unwrap(), &[0x11, 0x22, 0x33]);
    }

    #[test]
    fn write_bytes_rejects_unaligned_writer() {
        let mut w = BitWriter::new();
        w.write_bits(0b101, 3);
        assert!(w.write_bytes(&[0xff]).is_err());
    }
}
