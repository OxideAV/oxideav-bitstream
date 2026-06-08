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

    /// Peek the next `n` bits MSB-first into a `u64` without advancing
    /// `bit_pos`. The 64-bit counterpart of [`BitReader::peek_bits`],
    /// symmetric with [`BitReader::u64`]. `n` must be ≤ 64.
    ///
    /// Past-the-end bits are zero, identical to [`BitReader::u64`]'s
    /// contract. Useful for codec parsers that need to inspect a wide
    /// marker (e.g. AV1's `reference_frame_id` u(v) class fields up to
    /// 16 bits or longer leb128-aware look-aheads on a 64-bit horizon)
    /// before deciding whether to commit to a branch.
    ///
    /// `peek_bits_u64(n)` is observationally equivalent to a `u64(n)`
    /// followed by rewinding `bit_pos` by `n`, but the reader stays
    /// borrowed `&self` rather than `&mut self` so callers can peek
    /// without losing other borrows.
    pub fn peek_bits_u64(&self, n: u32) -> u64 {
        debug_assert!(n <= 64, "BitReader::peek_bits_u64({n}) > 64 bits");
        let mut value: u64 = 0;
        let total = self.total_bits();
        for offset in 0..n as usize {
            let pos = self.bit_pos + offset;
            let bit = if pos < total {
                let byte_idx = pos / 8;
                let shift = 7 - (pos % 8) as u32;
                ((self.bytes[byte_idx] >> shift) & 1) as u64
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

    /// `i(n)` — read `n` bits MSB-first and interpret as a two's
    /// complement signed integer. H.264 §7.2, H.265 §7.2, H.266 §7.2.
    ///
    /// `n` must be in `1..=32`. `n == 0` is rejected because two's
    /// complement requires at least one sign bit; bypass with `u(0)`
    /// for the no-op read.
    ///
    /// Past-the-end bits are zero per [`BitReader::u`]'s contract, so
    /// over-reads degrade to zero rather than panicking.
    pub fn i(&mut self, n: u32) -> Result<i32, BitstreamError> {
        if n == 0 || n > 32 {
            return Err(BitstreamError::InvalidData(format!(
                "i(n): n={n} outside 1..=32"
            )));
        }
        let raw = if n == 32 { self.u(32) } else { self.u(n) };
        if n == 32 {
            // `raw as i32` is already the two's-complement value.
            Ok(raw as i32)
        } else {
            let sign_mask = 1u32 << (n - 1);
            if raw & sign_mask != 0 {
                // Sign-extend by subtracting 2^n.
                let extended = raw as i64 - (1i64 << n);
                Ok(extended as i32)
            } else {
                Ok(raw as i32)
            }
        }
    }

    /// Read a signed integer encoded as `n` magnitude bits followed by a
    /// 1-bit sign (`1` = negative). This is the VP9 §6.2.7
    /// `s(n)`-equivalent layout used in `loop_filter_ref_deltas` and
    /// friends, and it also appears in JPEG/MJPEG quantisation-table
    /// extensions and several legacy codec headers.
    ///
    /// `n` must be in `1..=31` — the value would otherwise be unable to
    /// fit in an `i32` without ambiguity (32-bit magnitude + sign bit
    /// has more than 32 bits of dynamic range).
    ///
    /// Layout matches VP9: magnitude bits first (MSB-first), sign bit
    /// last. A zero magnitude with sign bit set decodes to `0` (a
    /// negative zero collapses to positive zero); the inverse writer
    /// always emits sign=0 for `value == 0` to keep the round-trip
    /// canonical.
    pub fn signed_magnitude(&mut self, n: u32) -> Result<i32, BitstreamError> {
        if n == 0 || n > 31 {
            return Err(BitstreamError::InvalidData(format!(
                "signed_magnitude(n): n={n} outside 1..=31"
            )));
        }
        let magnitude = self.u(n) as i32;
        let sign = self.read_bit();
        if sign == 1 {
            Ok(-magnitude)
        } else {
            Ok(magnitude)
        }
    }

    /// `te(v)` — truncated Exp-Golomb (H.264 §9.1.2). When `x_max == 1`
    /// the code is a single bit interpreted as `1 - bit` (so a `0` bit
    /// decodes to `1`, a `1` bit decodes to `0`). For `x_max > 1` the
    /// decoder behaves like [`BitReader::ue`].
    ///
    /// `x_max == 0` has no valid `te(v)` code and is rejected; the
    /// H.264 spec only defines `te(v)` for `x_max >= 1`.
    pub fn te(&mut self, x_max: u32) -> Result<u32, BitstreamError> {
        if x_max == 0 {
            return Err(BitstreamError::InvalidData(
                "te(v): x_max == 0 has no defined code".into(),
            ));
        }
        if x_max == 1 {
            Ok(1 - self.read_bit())
        } else {
            self.ue()
        }
    }

    /// `ns(n)` — non-symmetric encoded integer with maximum number of
    /// values `n` (output in range `0..n`). AV1 spec §4.10.7.
    ///
    /// Reduces wastage when encoding a range whose size is not a power
    /// of two by emitting `FloorLog2(n)` bits for the lower part of
    /// the range and `FloorLog2(n) + 1` bits for the upper part.
    ///
    /// Algorithm (verbatim from §4.10.7, restated in Rust):
    ///
    /// ```text
    /// w = FloorLog2(n) + 1
    /// m = (1 << w) - n
    /// v = f(w - 1)
    /// if v < m { return v }
    /// extra_bit = f(1)
    /// return (v << 1) - m + extra_bit
    /// ```
    ///
    /// `n == 0` is rejected — the spec only defines `ns(n)` for
    /// `n >= 1`. `n == 1` yields the trivial code (a zero-bit read
    /// that always returns 0) which we serve directly without
    /// touching `bit_pos`.
    ///
    /// `n` is capped at `1 << 30` so that `w` never exceeds 31 and the
    /// arithmetic always fits in `u32`. Realistic AV1 callers stay far
    /// below that bound (the largest envelope is the tile-size
    /// `width_in_sbs_minus_1 ns(maxWidth)`, where `maxWidth <= 64`).
    pub fn ns(&mut self, n: u32) -> Result<u32, BitstreamError> {
        if n == 0 {
            return Err(BitstreamError::InvalidData(
                "ns(n): n == 0 has no defined code".into(),
            ));
        }
        if n > (1u32 << 30) {
            return Err(BitstreamError::InvalidData(format!(
                "ns(n): n={n} exceeds the supported 1<<30 envelope"
            )));
        }
        if n == 1 {
            return Ok(0);
        }
        // w = FloorLog2(n) + 1 == number of bits needed to address n
        // when n is not a power of two, i.e. the bit width of (n-1) + 1
        // when n is a power of two. For n >= 2, w >= 2.
        let w = 32 - (n - 1).leading_zeros();
        // For n == 2 the AV1 spec gives w = FloorLog2(2) + 1 = 2 but
        // our (32 - leading_zeros) formula yields w = 1. The two
        // definitions agree everywhere except at exact powers of two,
        // where the spec leaves a redundant high bit (m would be 0 and
        // every value would be coded with w-1 bits). Patch w upward
        // when n is exactly a power of two so we match §4.10.7 byte-
        // for-byte.
        let w = if n.is_power_of_two() { w + 1 } else { w };
        let m = (1u32 << w) - n;
        let v = self.u(w - 1);
        if v < m {
            Ok(v)
        } else {
            let extra_bit = self.read_bit();
            Ok((v << 1) - m + extra_bit)
        }
    }

    /// Read `n` aligned bytes into a borrowed slice. The reader must be
    /// byte-aligned at entry; otherwise an `InvalidData` is returned
    /// (callers should `align_to_byte()` first or use the bit-level
    /// `u()` path). Returns `UnexpectedEnd` if fewer than `n` bytes are
    /// available.
    ///
    /// On success the reader's bit position advances by `n * 8`.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], BitstreamError> {
        if !self.byte_aligned() {
            return Err(BitstreamError::InvalidData(
                "read_bytes: reader is not byte-aligned".into(),
            ));
        }
        let start = self.bit_pos / 8;
        let end = start
            .checked_add(n)
            .ok_or_else(|| BitstreamError::InvalidData("read_bytes: byte count overflow".into()))?;
        if end > self.bytes.len() {
            return Err(BitstreamError::UnexpectedEnd(format!(
                "read_bytes: need {n} bytes, only {} available",
                self.bytes.len() - start
            )));
        }
        self.bit_pos = end * 8;
        Ok(&self.bytes[start..end])
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
    fn peek_bits_u64_matches_u64_at_bit_zero() {
        // Width 64 covers every byte completely; verify the value
        // matches a `u64(64)` read on a fresh reader.
        let bytes = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22];
        let r0 = BitReader::new(&bytes);
        let peeked = r0.peek_bits_u64(64);
        assert_eq!(peeked, 0x1234_5678_9abc_def0);
        // Reader's bit_pos must be unchanged after a peek.
        assert_eq!(r0.bit_pos(), 0);
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.u64(64), peeked);
        assert_eq!(r.bit_pos(), 64);
    }

    #[test]
    fn peek_bits_u64_at_unaligned_offset_matches_subsequent_u64() {
        // Drive across every bit offset 0..16 and every width 0..=64 on
        // a fixed buffer; peek then read must agree.
        let bytes: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        for start in 0..16usize {
            for n in 0u32..=64 {
                let mut r_peek = BitReader::new(&bytes);
                r_peek.skip(start);
                let peeked = r_peek.peek_bits_u64(n);
                assert_eq!(r_peek.bit_pos(), start, "peek must not advance");
                let mut r_read = BitReader::new(&bytes);
                r_read.skip(start);
                let read = r_read.u64(n);
                assert_eq!(
                    read, peeked,
                    "peek_bits_u64 / u64 mismatch start={start} n={n}"
                );
            }
        }
    }

    #[test]
    fn peek_bits_u64_past_end_is_zero_padded() {
        let bytes = [0xff_u8; 4];
        let mut r = BitReader::new(&bytes);
        // Consume the buffer; subsequent peeks must return zeros.
        r.u64(32);
        assert!(r.at_end());
        assert_eq!(r.peek_bits_u64(64), 0);
        // Partial overlap: at bit 24, the next 16 bits straddle the end.
        // Bits 24..32 = 0xff; bits 32.. = past end = 0.
        let mut r = BitReader::new(&bytes);
        r.u64(24);
        assert_eq!(r.peek_bits_u64(16), 0xff00);
    }

    #[test]
    fn peek_bits_u64_agrees_with_peek_bits_for_widths_up_to_32() {
        // For n ≤ 32 the 64-bit peek and the 32-bit peek must produce
        // identical values (the high 32 bits of the u64 are zero).
        let bytes: [u8; 5] = [0xa5, 0x5a, 0xc3, 0x3c, 0xf0];
        for start in 0..(bytes.len() * 8) {
            for n in 0u32..=32 {
                let mut r1 = BitReader::new(&bytes);
                r1.skip(start);
                let v32 = r1.peek_bits(n);
                let r2 = BitReader::new(&bytes);
                let mut r2m = r2;
                r2m.skip(start);
                let v64 = r2m.peek_bits_u64(n);
                assert_eq!(v64, v32 as u64, "start={start} n={n}");
            }
        }
    }

    #[test]
    fn peek_bits_u64_width_zero_returns_zero() {
        let bytes = [0xff_u8; 2];
        let r = BitReader::new(&bytes);
        assert_eq!(r.peek_bits_u64(0), 0);
        assert_eq!(r.bit_pos(), 0);
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

    #[test]
    fn i_decodes_two_s_complement_for_every_width() {
        // For n in 1..=8 verify the full value enumeration matches a
        // direct interpretation of `u(n)` as a signed n-bit integer.
        for n in 1u32..=8 {
            let count = 1u32 << n;
            let half = 1u32 << (n - 1);
            for raw in 0..count {
                let mut bytes = [0u8; 4];
                // Place raw left-justified into the buffer.
                let shifted = (raw as u64) << (32 - n);
                bytes[0] = (shifted >> 24) as u8;
                bytes[1] = (shifted >> 16) as u8;
                bytes[2] = (shifted >> 8) as u8;
                bytes[3] = shifted as u8;
                let mut r = BitReader::new(&bytes);
                let got = r.i(n).unwrap();
                let expected: i32 = if raw < half {
                    raw as i32
                } else {
                    raw as i32 - count as i32
                };
                assert_eq!(got, expected, "i({n}) over raw {raw}");
                assert_eq!(r.bit_pos(), n as usize);
            }
        }
    }

    #[test]
    fn i_rejects_zero_and_oversize_widths() {
        let bytes = [0xff; 4];
        let mut r = BitReader::new(&bytes);
        assert!(matches!(r.i(0), Err(BitstreamError::InvalidData(_))));
        assert!(matches!(r.i(33), Err(BitstreamError::InvalidData(_))));
    }

    #[test]
    fn i_reads_full_width_thirty_two() {
        // 0x8000_0000 → -2^31 (i32::MIN).
        let bytes = [0x80, 0x00, 0x00, 0x00];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.i(32).unwrap(), i32::MIN);
        let bytes = [0x7f, 0xff, 0xff, 0xff];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.i(32).unwrap(), i32::MAX);
    }

    #[test]
    fn signed_magnitude_decodes_canonical_layout() {
        // 6 value bits + sign bit. value=5, sign=1 → -5.
        // Pattern: 000101 | 1 = 0b0001011_0 padded → 0b0001_0110 = 0x16
        let bytes = [0x16];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.signed_magnitude(6).unwrap(), -5);

        // value=0, sign=0 → 0.
        let bytes = [0x00];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.signed_magnitude(6).unwrap(), 0);

        // value=0, sign=1 → -0 collapses to 0.
        let bytes = [0b0000_0010];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.signed_magnitude(6).unwrap(), 0);
    }

    #[test]
    fn signed_magnitude_rejects_out_of_range_widths() {
        let bytes = [0xff; 4];
        let mut r = BitReader::new(&bytes);
        assert!(matches!(
            r.signed_magnitude(0),
            Err(BitstreamError::InvalidData(_))
        ));
        assert!(matches!(
            r.signed_magnitude(32),
            Err(BitstreamError::InvalidData(_))
        ));
    }

    #[test]
    fn te_with_x_max_one_inverts_single_bit() {
        // Bit 0 → te value 1; bit 1 → te value 0.
        let bytes = [0b0100_0000];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.te(1).unwrap(), 1);
        assert_eq!(r.te(1).unwrap(), 0);
    }

    #[test]
    fn te_with_x_max_above_one_matches_ue() {
        // ue codes 0,1,2 → bytes 0b1010_0110.
        let bytes = [0b1010_0110];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.te(5).unwrap(), 0);
        assert_eq!(r.te(5).unwrap(), 1);
        assert_eq!(r.te(5).unwrap(), 2);
    }

    #[test]
    fn te_rejects_x_max_zero() {
        let bytes = [0xff];
        let mut r = BitReader::new(&bytes);
        assert!(matches!(r.te(0), Err(BitstreamError::InvalidData(_))));
    }

    #[test]
    fn read_bytes_returns_aligned_slice() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut r = BitReader::new(&bytes);
        let slice = r.read_bytes(3).unwrap();
        assert_eq!(slice, &[0x01, 0x02, 0x03]);
        assert_eq!(r.bit_pos(), 24);
        let slice = r.read_bytes(2).unwrap();
        assert_eq!(slice, &[0x04, 0x05]);
        assert!(r.at_end());
    }

    #[test]
    fn read_bytes_rejects_unaligned_reader() {
        let bytes = [0xff, 0xff];
        let mut r = BitReader::new(&bytes);
        r.u(3);
        assert!(matches!(
            r.read_bytes(1),
            Err(BitstreamError::InvalidData(_))
        ));
    }

    #[test]
    fn read_bytes_rejects_short_buffer() {
        let bytes = [0xaa, 0xbb];
        let mut r = BitReader::new(&bytes);
        assert!(matches!(
            r.read_bytes(3),
            Err(BitstreamError::UnexpectedEnd(_))
        ));
        // Position must be unchanged on the failure path.
        assert_eq!(r.bit_pos(), 0);
    }

    #[test]
    fn ns_matches_av1_spec_table_for_n_five() {
        // AV1 §4.10.7 table: n=5 → codes 00, 01, 10, 110, 111.
        // Pack the five codes back-to-back: 00 01 10 110 111 =
        // 0001_1011 0111 -> 12 bits -> 0x1B 0x70 (last 4 bits unused).
        let bytes = [0b0001_1011, 0b0111_0000];
        let mut r = BitReader::new(&bytes);
        for expected in 0u32..=4 {
            assert_eq!(r.ns(5).unwrap(), expected, "value {expected}");
        }
    }

    #[test]
    fn ns_with_n_one_returns_zero_without_reading() {
        let bytes = [0xff_u8; 2];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.ns(1).unwrap(), 0);
        // Trivial single-value alphabet must not consume bits.
        assert_eq!(r.bit_pos(), 0);
    }

    #[test]
    fn ns_with_power_of_two_n_is_plain_f_log2_n() {
        // n=4 → w=3, m=4, so every value in 0..4 is coded as plain
        // u(2). Encode codes 00, 01, 10, 11 -> 0b0001_1011 = 0x1B.
        let bytes = [0b0001_1011];
        let mut r = BitReader::new(&bytes);
        for expected in 0u32..=3 {
            assert_eq!(r.ns(4).unwrap(), expected);
        }
    }

    #[test]
    fn ns_with_n_three_uses_one_bit_for_zero_two_bits_for_others() {
        // n=3 → w=2, m=1. Codes: 0 → `0`, 1 → `10`, 2 → `11`.
        // Pack: 0 10 11 = 0_10_11 padded -> 0b0101_1000 = 0x58
        let bytes = [0b0101_1000];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.ns(3).unwrap(), 0);
        assert_eq!(r.ns(3).unwrap(), 1);
        assert_eq!(r.ns(3).unwrap(), 2);
    }

    #[test]
    fn ns_rejects_n_zero() {
        let bytes = [0xff_u8; 2];
        let mut r = BitReader::new(&bytes);
        assert!(matches!(r.ns(0), Err(BitstreamError::InvalidData(_))));
    }

    #[test]
    fn ns_rejects_n_above_envelope() {
        let bytes = [0xff_u8; 8];
        let mut r = BitReader::new(&bytes);
        assert!(matches!(
            r.ns((1u32 << 30) + 1),
            Err(BitstreamError::InvalidData(_))
        ));
    }
}
