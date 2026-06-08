//! Property / invariant suite for the foundational bit-IO primitives.
//!
//! `oxideav-bitstream` is the shared bit reader/writer every codec
//! parser leans on, so its round-trip and bounds behaviour is worth
//! pinning down hard. These tests are deliberately dependency-free:
//! rather than pulling in a property-testing framework, they drive a
//! small deterministic LCG over a large fixed iteration count. The
//! seed is constant, so a failure is exactly reproducible.
//!
//! Invariants asserted:
//!
//! * `write_bits(v, n)` then `u(n)` returns `v & mask(n)` for every
//!   width `1..=32`, and the `u64` path for `1..=64`.
//! * `write_ue` / `ue` and `write_se` / `se` are exact inverses.
//! * concatenated fields read back in order (no inter-field bleed).
//! * byte alignment on writer and reader stay in lock-step.
//! * over-reading past the end never panics (the reader's documented
//!   "zero past the end" contract) and `ue` over a malformed run
//!   returns a clean error rather than panicking.
//! * `read_leb128` round-trips against a local LEB128 encoder.

use oxideav_bitstream::av1::{
    read_leb128, read_obu, write_leb128, write_obu, ObuHeader, LEB128_MAX, OBU_FRAME,
    OBU_FRAME_HEADER, OBU_METADATA, OBU_PADDING, OBU_SEQUENCE_HEADER, OBU_SPATIAL_ID_MAX,
    OBU_TEMPORAL_DELIMITER, OBU_TEMPORAL_ID_MAX, OBU_TILE_GROUP, OBU_TYPE_MAX,
};
use oxideav_bitstream::bit_reader::BitReader;
use oxideav_bitstream::bit_writer::BitWriter;
use oxideav_bitstream::h264::{
    parse_aud_nal as h264_parse_aud_nal, write_aud_nal as h264_write_aud_nal,
    H264AccessUnitDelimiter, H264_PRIMARY_PIC_TYPE_MAX,
};
use oxideav_bitstream::h266::{
    parse_aud, parse_picture_header, parse_picture_header_with_sps, write_aud,
    VvcAccessUnitDelimiter, VvcSps, AUD_PIC_TYPE_MAX, NAL_TYPE_PH, PH_PIC_PARAMETER_SET_ID_MAX,
    SPS_LOG2_MAX_PIC_ORDER_CNT_LSB_MINUS4_MAX,
};
use oxideav_bitstream::hevc::{
    parse_aud_nal as hevc_parse_aud_nal, write_aud_nal as hevc_write_aud_nal,
    HevcAccessUnitDelimiter, HEVC_PIC_TYPE_MAX,
};
use oxideav_bitstream::ivf::{
    parse_all, parse_frame, parse_header, write_all, write_frame, write_header, IvfHeader,
    IVF_FOURCC_VP80, IVF_FOURCC_VP90, IVF_FRAME_HEADER_LEN, IVF_HEADER_LEN,
};
use oxideav_bitstream::nal::{ebsp_to_rbsp, rbsp_to_ebsp};
use oxideav_bitstream::BitstreamError;

/// Deterministic 64-bit linear-congruential generator (Numerical
/// Recipes constants). Clean-room: a textbook LCG, not copied IO code.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        // Return the high-quality upper bits.
        self.0
    }
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
    /// Uniform in `lo..=hi`.
    fn range(&mut self, lo: u32, hi: u32) -> u32 {
        lo + (self.next_u32() % (hi - lo + 1))
    }
}

/// Mask keeping the low `n` bits (`n` in `0..=32`).
fn mask32(n: u32) -> u32 {
    if n >= 32 {
        u32::MAX
    } else {
        (1u32 << n) - 1
    }
}

fn mask64(n: u32) -> u64 {
    if n >= 64 {
        u64::MAX
    } else {
        (1u64 << n) - 1
    }
}

#[test]
fn u_roundtrips_every_width_1_to_32() {
    let mut rng = Lcg::new(0x1234_5678_9abc_def0);
    for n in 1..=32u32 {
        for _ in 0..2000 {
            let raw = rng.next_u32();
            let expected = raw & mask32(n);
            let mut w = BitWriter::new();
            w.write_bits(raw, n);
            assert_eq!(w.bit_pos(), n as usize);
            let bytes = w.finish();
            let mut r = BitReader::new(&bytes);
            let got = r.u(n);
            assert_eq!(got, expected, "u({n}) round-trip of {raw:#x}");
            assert_eq!(r.bit_pos(), n as usize);
        }
    }
}

#[test]
fn u64_roundtrips_every_width_1_to_64() {
    let mut rng = Lcg::new(0x0fed_cba9_8765_4321);
    for n in 1..=64u32 {
        for _ in 0..1000 {
            let raw = rng.next_u64();
            let expected = raw & mask64(n);
            let mut w = BitWriter::new();
            w.write_bits_u64(raw, n);
            let bytes = w.finish();
            let mut r = BitReader::new(&bytes);
            let got = r.u64(n);
            assert_eq!(got, expected, "u64({n}) round-trip of {raw:#x}");
            assert_eq!(r.bit_pos(), n as usize);
        }
    }
}

#[test]
fn u_zero_width_reads_nothing() {
    let bytes = [0xff, 0x00];
    let mut r = BitReader::new(&bytes);
    assert_eq!(r.u(0), 0);
    assert_eq!(r.bit_pos(), 0);
    let mut w = BitWriter::new();
    w.write_bits(0xdead_beef, 0);
    assert!(w.finish().is_empty());
}

#[test]
fn ue_roundtrips_across_range() {
    let mut rng = Lcg::new(0xdead_beef_cafe_babe);
    // u32::MAX has no ue(v) code (code_num overflow); everything below
    // it must round-trip.
    let mut values: Vec<u32> = (0..=64u32).collect();
    values.extend([1000, 65535, 65536, 1 << 20, (1 << 30) - 1, u32::MAX - 1]);
    for _ in 0..5000 {
        let v = rng.next_u32();
        if v == u32::MAX {
            continue;
        }
        values.push(v);
    }
    for &v in &values {
        let mut w = BitWriter::new();
        w.write_ue(v).unwrap();
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.ue().unwrap(), v, "ue round-trip of {v}");
    }
}

#[test]
fn se_roundtrips_across_range() {
    let mut rng = Lcg::new(0xfeed_face_0000_1111);
    let mut values: Vec<i32> = vec![0];
    for k in 1..=64i32 {
        values.push(k);
        values.push(-k);
    }
    values.extend([1000, -1000, 1 << 20, -(1 << 20), (1 << 29), -(1 << 29)]);
    for _ in 0..5000 {
        // Keep magnitudes inside the se(v) representable band
        // (2*|v|-1 / 2*|v| must fit a u32, hence v in roughly
        // ±2^30; we conservatively cap at ±2^30).
        let v = (rng.next_u32() % (1 << 30)) as i32 - (1 << 29);
        values.push(v);
    }
    for &v in &values {
        let mut w = BitWriter::new();
        w.write_se(v).unwrap();
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.se().unwrap(), v, "se round-trip of {v}");
    }
}

#[test]
fn mixed_fields_read_back_in_order() {
    // Interleave fixed-width, ue and se fields and confirm there is no
    // bleed between adjacent fields. Reproduce a slice-header-shaped
    // mix many times with random payloads.
    let mut rng = Lcg::new(0xa5a5_5a5a_1234_9876);
    for _ in 0..3000 {
        let a = rng.range(1, 32);
        let av = rng.next_u32() & mask32(a);
        let b = rng.next_u32() % 1000; // ue
        let c = (rng.next_u32() % 2000) as i32 - 1000; // se
        let d = rng.range(1, 24);
        let dv = rng.next_u32() & mask32(d);

        let mut w = BitWriter::new();
        w.write_bits(av, a);
        w.write_ue(b).unwrap();
        w.write_se(c).unwrap();
        w.write_bits(dv, d);
        let bytes = w.finish();

        let mut r = BitReader::new(&bytes);
        assert_eq!(r.u(a), av);
        assert_eq!(r.ue().unwrap(), b);
        assert_eq!(r.se().unwrap(), c);
        assert_eq!(r.u(d), dv);
    }
}

#[test]
fn byte_alignment_is_symmetric() {
    let mut rng = Lcg::new(0x0102_0304_0506_0708);
    for _ in 0..2000 {
        let pre = rng.range(1, 7); // not aligned
        let pv = rng.next_u32() & mask32(pre);
        let mut w = BitWriter::new();
        w.write_bits(pv, pre);
        assert!(!w.byte_aligned());
        w.align_to_byte();
        assert!(w.byte_aligned());
        let after_align = w.bit_pos();
        assert_eq!(after_align % 8, 0);
        // Write a full byte after alignment.
        let byte = rng.next_u32() & 0xff;
        w.write_bits(byte, 8);
        let bytes = w.finish();

        let mut r = BitReader::new(&bytes);
        assert_eq!(r.u(pre), pv);
        assert!(!r.byte_aligned());
        r.align_to_byte();
        assert!(r.byte_aligned());
        assert_eq!(r.bit_pos(), after_align);
        assert_eq!(r.u(8), byte);
    }
}

#[test]
fn over_read_never_panics_and_zeros() {
    // Reader contract: reads past the end yield zero and never panic.
    let mut rng = Lcg::new(0xbeef_0bad_f00d_1357);
    for _ in 0..3000 {
        let len = (rng.next_u32() % 6) as usize;
        let mut bytes = Vec::new();
        for _ in 0..len {
            bytes.push((rng.next_u32() & 0xff) as u8);
        }
        let mut r = BitReader::new(&bytes);
        // Drain well past the end with assorted widths.
        for _ in 0..40 {
            let n = rng.range(0, 32);
            let _ = r.u(n);
        }
        assert!(r.at_end() || r.bits_remaining() == 0 || r.bit_pos() <= r.total_bits() + 32 * 40);
        // u64 path past the end.
        let _ = r.u64(rng.range(0, 64));
        // The next single bit past end is zero.
        let pos = r.bit_pos();
        assert!(pos >= r.total_bits());
        assert_eq!(r.read_bit(), 0);
    }
}

#[test]
fn ue_on_all_zero_run_returns_clean_error_or_zero() {
    // An all-zero buffer: every bit is 0, so `ue` keeps seeing leading
    // zeros until at_end(); it must terminate with either a clean Err
    // (too many leading zeros) or a value, never a panic.
    for len in 0..=8usize {
        let bytes = vec![0u8; len];
        let mut r = BitReader::new(&bytes);
        match r.ue() {
            Ok(_) => {}
            Err(BitstreamError::InvalidData(_)) => {}
            Err(other) => panic!("unexpected ue error variant: {other:?}"),
        }
        // se delegates to ue and must likewise not panic.
        let mut r2 = BitReader::new(&bytes);
        let _ = r2.se();
    }
}

#[test]
fn empty_reader_is_safe() {
    let mut r = BitReader::new(&[]);
    assert!(r.at_end());
    assert_eq!(r.bits_remaining(), 0);
    assert_eq!(r.u(0), 0);
    assert_eq!(r.u(32), 0);
    assert_eq!(r.u64(64), 0);
    assert_eq!(r.read_bit(), 0);
    // ue on an empty reader: no bits → leading_zeros == 0 → Ok(0).
    assert_eq!(r.ue().unwrap(), 0);
}

/// Minimal LEB128 encoder used only to drive the round-trip test
/// against the crate's `read_leb128`. Clean-room: the unsigned-LEB128
/// algorithm is the canonical 7-bits-per-byte continuation form.
fn encode_leb128(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
    out
}

#[test]
fn leb128_roundtrips_against_local_encoder() {
    let mut rng = Lcg::new(0x9999_8888_7777_6666);
    let mut values: Vec<u64> = vec![0, 1, 127, 128, 255, 256, 16383, 16384];
    for _ in 0..5000 {
        // read_leb128 caps at 8 bytes → 56 bits of payload. Stay inside
        // that band so a well-formed code is always decodable.
        values.push(rng.next_u64() & ((1u64 << 56) - 1));
    }
    for &v in &values {
        let bytes = encode_leb128(v);
        // read_leb128 caps at 8 bytes; values < 2^56 encode in ≤ 8.
        assert!(
            bytes.len() <= 8,
            "value {v} encoded to {} bytes",
            bytes.len()
        );
        let (decoded, consumed) = read_leb128(&bytes, 0).unwrap();
        assert_eq!(decoded, v, "leb128 round-trip of {v}");
        assert_eq!(consumed, bytes.len());
    }
}

#[test]
fn peek_bits_equals_subsequent_u_for_every_width_and_offset() {
    // Invariant: peek_bits(n) at offset p returns the same value as
    // u(n) at offset p, but leaves the reader unmoved. Drive the
    // assertion across many random buffers, every starting offset
    // within the buffer, and every width 0..=32.
    let mut rng = Lcg::new(0x1357_9bdf_2468_ace0);
    for _ in 0..200 {
        let len = (rng.next_u32() % 12) as usize + 4;
        let bytes: Vec<u8> = (0..len).map(|_| (rng.next_u32() & 0xff) as u8).collect();
        for start in 0..(len * 8) {
            for n in 0..=32u32 {
                let mut r_peek = BitReader::new(&bytes);
                r_peek.skip(start);
                let peeked = r_peek.peek_bits(n);
                assert_eq!(r_peek.bit_pos(), start, "peek must not advance");

                let mut r_read = BitReader::new(&bytes);
                r_read.skip(start);
                let read = r_read.u(n);
                assert_eq!(read, peeked, "peek/read mismatch start={start} n={n}");
            }
        }
    }
}

#[test]
fn peek_bits_u64_equals_subsequent_u64_for_every_width_and_offset() {
    // 64-bit analogue of the peek_bits property: peek_bits_u64(n) at
    // offset p returns the same value as u64(n) at offset p, but leaves
    // the reader unmoved. Drive across random buffers, every starting
    // offset within the buffer, and every width 0..=64.
    let mut rng = Lcg::new(0x6789_abcd_0123_4567);
    for _ in 0..120 {
        // Buffer needs to be large enough that the widest peek (64
        // bits) at the deepest in-buffer offset still has bits to read.
        // 14..=20 bytes gives 112..=160 bits.
        let len = (rng.next_u32() % 7) as usize + 14;
        let bytes: Vec<u8> = (0..len).map(|_| (rng.next_u32() & 0xff) as u8).collect();
        for start in 0..(len * 8) {
            for n in 0..=64u32 {
                let mut r_peek = BitReader::new(&bytes);
                r_peek.skip(start);
                let peeked = r_peek.peek_bits_u64(n);
                assert_eq!(r_peek.bit_pos(), start, "peek_u64 must not advance");

                let mut r_read = BitReader::new(&bytes);
                r_read.skip(start);
                let read = r_read.u64(n);
                assert_eq!(read, peeked, "peek_u64/read mismatch start={start} n={n}");

                // For n ≤ 32 the value must also match peek_bits.
                if n <= 32 {
                    let r32 = BitReader::new(&bytes);
                    let mut r32m = r32;
                    r32m.skip(start);
                    let p32 = r32m.peek_bits(n);
                    assert_eq!(peeked, p32 as u64, "peek_bits_u64 != peek_bits for n={n}");
                }

                // Past-the-end contract: bits beyond the buffer read
                // as zero. Past-end bits land in the LOW positions of
                // the result because the loop shifts left and ORs in
                // each successive bit. For any (start, n) with
                // n > bits_remaining, the low `n - rem` bits of `peeked`
                // must therefore be zero.
                let rem = (len * 8).saturating_sub(start) as u32;
                if n > rem {
                    let low_zero_bits = n - rem;
                    let low_mask = mask64(low_zero_bits);
                    assert_eq!(
                        peeked & low_mask,
                        0,
                        "past-end bits must be zero start={start} n={n} rem={rem}"
                    );
                }
            }
        }
    }
}

#[test]
fn peek_bits_u64_does_not_panic_on_empty_reader() {
    let r = BitReader::new(&[]);
    for n in 0u32..=64 {
        assert_eq!(r.peek_bits_u64(n), 0);
    }
    assert_eq!(r.bit_pos(), 0);
}

#[test]
fn peek_bits_u64_full_width_round_trips_against_writer() {
    // Write a sequence of random u64 fields with widths drawn from
    // 1..=64; for each, peek_bits_u64 at the reader's current position
    // must return the same value u64(n) will subsequently return.
    let mut rng = Lcg::new(0xfedc_ba98_7654_3210);
    for _ in 0..400 {
        let mut w = BitWriter::new();
        let mut fields: Vec<(u64, u32)> = Vec::new();
        let nfields = (rng.next_u32() % 8) as usize + 1;
        for _ in 0..nfields {
            let n = rng.range(1, 64);
            let raw = rng.next_u64();
            let masked = raw & mask64(n);
            w.write_bits_u64(masked, n);
            fields.push((masked, n));
        }
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        for (expected, n) in fields {
            let peeked = r.peek_bits_u64(n);
            assert_eq!(peeked, expected, "peek_bits_u64 mismatch n={n}");
            let read = r.u64(n);
            assert_eq!(read, expected, "u64 mismatch n={n}");
        }
    }
}

#[test]
fn rbsp_trailing_bits_roundtrips_at_every_bit_offset() {
    // For each payload-bit count 0..=23 and each random payload value,
    // build a buffer containing `payload || rbsp_stop_one_bit ||
    // zero_alignment_bits` and check the reader: it consumes the
    // payload via u(), then read_rbsp_trailing_bits() must succeed and
    // leave the reader byte-aligned at end-of-stream.
    let mut rng = Lcg::new(0x2222_3333_4444_5555);
    for payload_bits in 0u32..=23 {
        for _ in 0..200 {
            let payload = rng.next_u32() & mask32(payload_bits);
            let mut w = BitWriter::new();
            if payload_bits > 0 {
                w.write_bits(payload, payload_bits);
            }
            // rbsp_stop_one_bit followed by trailing alignment zeros.
            w.write_bit(1);
            w.align_to_byte();
            let bytes = w.finish();

            let mut r = BitReader::new(&bytes);
            if payload_bits > 0 {
                assert_eq!(r.u(payload_bits), payload);
            }
            r.read_rbsp_trailing_bits().unwrap();
            assert!(r.byte_aligned());
            assert!(r.at_end());
        }
    }
}

#[test]
fn more_rbsp_data_tracks_payload_consumption() {
    // For each payload-bit count `p` in 1..=15, build `payload ||
    // stop_bit || zero_align` and verify: while strictly fewer than `p`
    // payload bits have been read, more_rbsp_data() is true; once
    // exactly `p` bits have been read (positioned at the stop bit),
    // more_rbsp_data() is false.
    let mut rng = Lcg::new(0x9999_aaaa_bbbb_cccc);
    for p in 1u32..=15 {
        for _ in 0..50 {
            // Pick a payload whose final bit is `1` so the next `1`
            // after the cursor (during payload) isn't ambiguously the
            // stop bit — the more_rbsp_data scan handles both, but
            // mixing the two would muddy this invariant. Force the LSB.
            let payload = (rng.next_u32() & mask32(p)) | 1;
            let mut w = BitWriter::new();
            w.write_bits(payload, p);
            w.write_bit(1);
            w.align_to_byte();
            let bytes = w.finish();

            for consumed in 0..p {
                let mut r = BitReader::new(&bytes);
                if consumed > 0 {
                    r.u(consumed);
                }
                assert!(
                    r.more_rbsp_data(),
                    "p={p} consumed={consumed} should still have more data"
                );
            }
            // Consume exactly the payload; the next bit is the stop bit.
            let mut r = BitReader::new(&bytes);
            r.u(p);
            assert!(
                !r.more_rbsp_data(),
                "after consuming {p} payload bits, no more data should remain"
            );
        }
    }
}

#[test]
fn write_leb128_is_exact_inverse_of_read_leb128() {
    // Invariant: write_leb128(v) emits bytes such that read_leb128
    // returns (v, n) where n is the same length the writer reported.
    // Quantify over every size class plus a swath of random values
    // inside the 56-bit envelope.
    let edges: [u64; 17] = [
        0,
        1,
        127,
        128,
        16_383,
        16_384,
        2_097_151,
        2_097_152,
        268_435_455,
        268_435_456,
        34_359_738_367,
        34_359_738_368,
        4_398_046_511_103,
        4_398_046_511_104,
        562_949_953_421_311,
        562_949_953_421_312,
        LEB128_MAX,
    ];
    for &v in &edges {
        let mut buf = Vec::new();
        let n = write_leb128(&mut buf, v).unwrap();
        assert_eq!(buf.len(), n, "writer length matches returned size");
        let (got, consumed) = read_leb128(&buf, 0).unwrap();
        assert_eq!(got, v, "round-trip value for {v}");
        assert_eq!(consumed, n, "round-trip byte count for {v}");
    }

    let mut rng = Lcg::new(0xfeed_face_dead_beef);
    for _ in 0..5000 {
        let v = rng.next_u64() & LEB128_MAX;
        let mut buf = Vec::new();
        let n = write_leb128(&mut buf, v).unwrap();
        let (got, consumed) = read_leb128(&buf, 0).unwrap();
        assert_eq!(got, v);
        assert_eq!(consumed, n);
        // Encoded length must agree with the canonical 7-bits-per-byte
        // rule: ceil(bits_needed/7), with a one-byte floor for v == 0.
        let bits_needed = if v == 0 { 1 } else { 64 - v.leading_zeros() };
        let expected_len = bits_needed.div_ceil(7) as usize;
        assert_eq!(n, expected_len, "minimal-length encoding for {v}");
    }
}

#[test]
fn write_leb128_rejects_values_outside_56_bit_envelope() {
    // The reader caps a code at 8 bytes (56 bits of payload). The writer
    // must refuse anything above LEB128_MAX so the round-trip contract
    // is never silently violated.
    let mut buf = Vec::new();
    assert!(write_leb128(&mut buf, LEB128_MAX + 1).is_err());
    assert!(write_leb128(&mut buf, u64::MAX).is_err());
    assert!(buf.is_empty(), "rejected writes must not append");
}

#[test]
fn write_leb128_appends_to_existing_buffer() {
    // The writer must extend an existing buffer in place; downstream
    // callers prepend an OBU header byte (and optional extension byte)
    // before serialising the size field.
    let mut buf = vec![0x12, 0xff, 0xfe]; // arbitrary prefix.
    let n = write_leb128(&mut buf, 12_345).unwrap();
    assert_eq!(&buf[0..3], &[0x12, 0xff, 0xfe], "prefix preserved");
    let (val, consumed) = read_leb128(&buf, 3).unwrap();
    assert_eq!(val, 12_345);
    assert_eq!(consumed, n);
    assert_eq!(buf.len(), 3 + n);
}

#[test]
fn i_roundtrips_every_width_1_to_32() {
    // For each width n in 1..=32 pick random i32 values inside the
    // representable [-(2^(n-1)), 2^(n-1) - 1] range, round-trip them
    // through write_i / i, and assert the value plus the post-read
    // bit position both come back unchanged.
    let mut rng = Lcg::new(0xabcd_1234_5678_9999);
    for n in 1..=32u32 {
        for _ in 0..1500 {
            let raw = rng.next_u32();
            let v: i32 = if n == 32 {
                raw as i32
            } else {
                // n in 1..=31. Use i64 arithmetic to avoid edge cases at n==31.
                let modulus = 1i64 << n;
                let half = 1i64 << (n - 1);
                let bounded = (raw as i64) % modulus;
                if bounded < half {
                    bounded as i32
                } else {
                    (bounded - modulus) as i32
                }
            };
            let mut w = BitWriter::new();
            w.write_i(v, n).unwrap();
            assert_eq!(w.bit_pos(), n as usize);
            let bytes = w.finish();
            let mut r = BitReader::new(&bytes);
            assert_eq!(r.i(n).unwrap(), v, "i({n}) round-trip of {v}");
            assert_eq!(r.bit_pos(), n as usize);
        }
    }
}

#[test]
fn i_rejects_out_of_range_writes_for_every_width() {
    // For each n in 1..=31 verify the writer refuses the first
    // out-of-range value on either side (no silent truncation).
    for n in 1..=31u32 {
        let min = -(1i64 << (n - 1));
        let max = (1i64 << (n - 1)) - 1;
        let mut w = BitWriter::new();
        assert!(
            w.write_i((min - 1) as i32, n).is_err(),
            "n={n} should reject below-min {} ",
            min - 1
        );
        assert!(
            w.write_i((max + 1) as i32, n).is_err(),
            "n={n} should reject above-max {}",
            max + 1
        );
    }
}

#[test]
fn signed_magnitude_roundtrips_every_width_1_to_31() {
    // n bits of magnitude + 1 sign bit. For each width sweep random
    // values inside [-(2^n - 1), 2^n - 1] and round-trip them.
    let mut rng = Lcg::new(0xdead_d00d_0bad_caf0);
    for n in 1..=31u32 {
        for _ in 0..1500 {
            let modulus = if n == 31 { 1u32 << 31 } else { 1u32 << n };
            let mag = rng.next_u32() % modulus;
            let sign_neg = (rng.next_u32() & 1) == 1;
            // Re-canonicalise zero to positive (writer does the same).
            let v: i32 = if mag == 0 {
                0
            } else if sign_neg {
                -(mag as i32)
            } else {
                mag as i32
            };
            let mut w = BitWriter::new();
            w.write_signed_magnitude(v, n).unwrap();
            assert_eq!(w.bit_pos(), (n + 1) as usize);
            let bytes = w.finish();
            let mut r = BitReader::new(&bytes);
            assert_eq!(
                r.signed_magnitude(n).unwrap(),
                v,
                "signed_magnitude({n}) round-trip of {v}"
            );
            assert_eq!(r.bit_pos(), (n + 1) as usize);
        }
    }
}

#[test]
fn signed_magnitude_negative_zero_normalises_to_positive() {
    // The reader collapses (magnitude=0, sign=1) to value 0, matching
    // the writer's canonical (sign=0 for zero) emission. A hand-crafted
    // -0 input must therefore decode as +0 and re-encode to a different
    // byte string — confirming the canonicalisation is observable.
    let bytes = [0b0000_0010]; // 6 zero magnitude bits then sign=1.
    let mut r = BitReader::new(&bytes);
    let decoded = r.signed_magnitude(6).unwrap();
    assert_eq!(decoded, 0);
    let mut w = BitWriter::new();
    w.write_signed_magnitude(decoded, 6).unwrap();
    let re_encoded = w.finish();
    assert_eq!(re_encoded, vec![0x00], "writer always picks sign=0 for 0");
}

#[test]
fn te_roundtrips_for_every_x_max() {
    // x_max == 1: the only legal values are 0 and 1.
    let mut w = BitWriter::new();
    w.write_te(0, 1).unwrap();
    w.write_te(1, 1).unwrap();
    w.write_te(0, 1).unwrap();
    w.write_te(1, 1).unwrap();
    let bytes = w.finish();
    let mut r = BitReader::new(&bytes);
    assert_eq!(r.te(1).unwrap(), 0);
    assert_eq!(r.te(1).unwrap(), 1);
    assert_eq!(r.te(1).unwrap(), 0);
    assert_eq!(r.te(1).unwrap(), 1);

    // x_max >= 2: behaves like ue(v); sweep multiple values.
    let mut rng = Lcg::new(0x1010_2020_3030_4040);
    for x_max in [2u32, 3, 7, 15, 100, 1000] {
        let mut w = BitWriter::new();
        let mut written = Vec::new();
        for _ in 0..200 {
            let v = rng.next_u32() % (x_max + 1);
            w.write_te(v, x_max).unwrap();
            written.push(v);
        }
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        for &v in &written {
            assert_eq!(
                r.te(x_max).unwrap(),
                v,
                "te round-trip x_max={x_max} value={v}"
            );
        }
    }
}

#[test]
fn te_rejects_value_above_x_max() {
    let mut w = BitWriter::new();
    assert!(w.write_te(2, 1).is_err());
    assert!(w.write_te(11, 10).is_err());
    assert!(w.write_te(0, 0).is_err());
}

#[test]
fn read_bytes_roundtrips_aligned_payload() {
    // Interleave a few bit fields with a byte-aligned payload and make
    // sure the slice the reader hands back is byte-identical to the
    // bytes the writer pushed in.
    let mut rng = Lcg::new(0x5555_6666_7777_8888);
    for _ in 0..500 {
        let header = rng.next_u32() & 0xff;
        let len = (rng.next_u32() % 16) as usize + 1;
        let payload: Vec<u8> = (0..len).map(|_| (rng.next_u32() & 0xff) as u8).collect();

        let mut w = BitWriter::new();
        w.write_bits(header, 8);
        w.write_bytes(&payload).unwrap();
        let trailer = rng.next_u32() & 0xff;
        w.write_bits(trailer, 8);
        let bytes = w.finish();

        let mut r = BitReader::new(&bytes);
        assert_eq!(r.u(8), header);
        let got = r.read_bytes(len).unwrap();
        assert_eq!(got, payload.as_slice());
        assert_eq!(r.u(8), trailer);
        assert!(r.at_end());
    }
}

#[test]
fn read_bytes_rejects_unaligned_position() {
    let bytes = [0xaa, 0xbb];
    let mut r = BitReader::new(&bytes);
    r.u(1);
    let err = r.read_bytes(1).unwrap_err();
    matches_invalid_data(&err);
    // Reader cursor is unchanged after the error.
    assert_eq!(r.bit_pos(), 1);
}

#[test]
fn read_bytes_rejects_overlong_request() {
    let bytes = [0xaa];
    let mut r = BitReader::new(&bytes);
    let err = r.read_bytes(2).unwrap_err();
    matches!(err, BitstreamError::UnexpectedEnd(_));
    assert_eq!(r.bit_pos(), 0);
}

fn matches_invalid_data(err: &BitstreamError) {
    assert!(
        matches!(err, BitstreamError::InvalidData(_)),
        "expected InvalidData, got {err:?}"
    );
}

#[test]
fn write_obu_round_trips_against_read_obu_over_random_payloads() {
    // Invariant: for every (header, payload) the writer accepts, read_obu
    // recovers the same header, the payload byte range matches, and the
    // computed next_offset lands exactly at the end of the framed OBU.
    let mut rng = Lcg::new(0xc0de_cafe_1234_5678);
    let obu_types: [u8; 7] = [
        OBU_SEQUENCE_HEADER,
        OBU_TEMPORAL_DELIMITER,
        OBU_FRAME_HEADER,
        OBU_TILE_GROUP,
        OBU_METADATA,
        OBU_FRAME,
        OBU_PADDING,
    ];
    for _ in 0..400 {
        let obu_type = obu_types[(rng.next_u32() as usize) % obu_types.len()];
        let extension_flag = rng.next_u32() & 1 != 0;
        let (temporal_id, spatial_id) = if extension_flag {
            (
                (rng.next_u32() as u8) & OBU_TEMPORAL_ID_MAX,
                (rng.next_u32() as u8) & OBU_SPATIAL_ID_MAX,
            )
        } else {
            (0, 0)
        };
        let header = ObuHeader {
            obu_type,
            extension_flag,
            has_size_field: true,
            temporal_id,
            spatial_id,
        };
        // Bounded payload length — sweep across single-byte, multi-byte,
        // and 7-bit-boundary-crossing size-field encodings.
        let len = (rng.next_u32() % 600) as usize;
        let payload: Vec<u8> = (0..len).map(|_| (rng.next_u32() & 0xff) as u8).collect();

        let mut out = Vec::new();
        let (start, end) = write_obu(&mut out, header, &payload).unwrap();
        let (got, p_start, p_end, next) = read_obu(&out, start).unwrap();
        assert_eq!(got, header, "header round-trip");
        assert_eq!(p_end - p_start, payload.len(), "payload size matches");
        assert_eq!(&out[p_start..p_end], payload.as_slice(), "payload bytes");
        assert_eq!(next, end, "next_offset matches reported end");
    }
}

#[test]
fn write_obu_validates_field_widths() {
    // Every field has a precise bit width per §5.3.2 / §5.3.3; values
    // above the cap must be rejected with an InvalidData error and the
    // output buffer left untouched.
    let h_ok = ObuHeader {
        obu_type: OBU_TEMPORAL_DELIMITER,
        extension_flag: false,
        has_size_field: true,
        temporal_id: 0,
        spatial_id: 0,
    };

    // obu_type > 15.
    let mut h = h_ok;
    h.obu_type = OBU_TYPE_MAX + 1;
    let mut buf = Vec::new();
    assert!(write_obu(&mut buf, h, &[]).is_err());
    assert!(buf.is_empty());

    // has_size_field=false (LOBF requires =1).
    let mut h = h_ok;
    h.has_size_field = false;
    let mut buf = Vec::new();
    assert!(write_obu(&mut buf, h, &[]).is_err());
    assert!(buf.is_empty());

    // temporal_id > 7 with extension_flag=true.
    let h = ObuHeader {
        obu_type: OBU_FRAME,
        extension_flag: true,
        has_size_field: true,
        temporal_id: OBU_TEMPORAL_ID_MAX + 1,
        spatial_id: 0,
    };
    let mut buf = Vec::new();
    assert!(write_obu(&mut buf, h, &[]).is_err());
    assert!(buf.is_empty());

    // spatial_id > 3 with extension_flag=true.
    let h = ObuHeader {
        obu_type: OBU_FRAME,
        extension_flag: true,
        has_size_field: true,
        temporal_id: 0,
        spatial_id: OBU_SPATIAL_ID_MAX + 1,
    };
    let mut buf = Vec::new();
    assert!(write_obu(&mut buf, h, &[]).is_err());
    assert!(buf.is_empty());

    // Non-zero IDs with extension_flag=false silently lose info in the
    // reader; the writer rejects them.
    let h = ObuHeader {
        obu_type: OBU_FRAME,
        extension_flag: false,
        has_size_field: true,
        temporal_id: 1,
        spatial_id: 0,
    };
    let mut buf = Vec::new();
    assert!(write_obu(&mut buf, h, &[]).is_err());
    assert!(buf.is_empty());
}

#[test]
fn write_obu_concatenated_stream_is_walkable_by_read_obu() {
    // Build a synthetic temporal unit out of several OBUs and walk it
    // back end-to-end. This exercises the `next_offset` chain that
    // `parse_obu_stream` itself depends on.
    let mut rng = Lcg::new(0x4242_4242_8888_8888);
    let mut out = Vec::new();
    let mut expectations: Vec<(ObuHeader, Vec<u8>)> = Vec::new();
    for _ in 0..32 {
        let obu_type = ((rng.next_u32() as u8) & 0x7).min(OBU_TYPE_MAX); // type in 0..=7
        let extension_flag = rng.next_u32() & 1 != 0;
        let (temporal_id, spatial_id) = if extension_flag {
            (
                (rng.next_u32() as u8) & OBU_TEMPORAL_ID_MAX,
                (rng.next_u32() as u8) & OBU_SPATIAL_ID_MAX,
            )
        } else {
            (0, 0)
        };
        let header = ObuHeader {
            obu_type,
            extension_flag,
            has_size_field: true,
            temporal_id,
            spatial_id,
        };
        let len = (rng.next_u32() % 50) as usize;
        let payload: Vec<u8> = (0..len).map(|_| (rng.next_u32() & 0xff) as u8).collect();
        write_obu(&mut out, header, &payload).unwrap();
        expectations.push((header, payload));
    }

    let mut offset = 0;
    for (expected_header, expected_payload) in &expectations {
        let (h, ps, pe, next) = read_obu(&out, offset).unwrap();
        assert_eq!(&h, expected_header);
        assert_eq!(&out[ps..pe], expected_payload.as_slice());
        offset = next;
    }
    assert_eq!(offset, out.len(), "walked exactly to end-of-stream");
}

#[test]
fn leb128_truncated_is_clean_error() {
    // A continuation-bit-set byte with nothing after it must error, not
    // panic or index out of bounds.
    let bytes = [0x80u8];
    assert!(read_leb128(&bytes, 0).is_err());
    // Offset past the end.
    assert!(read_leb128(&[0x01], 5).is_err());
    // Empty.
    assert!(read_leb128(&[], 0).is_err());
}

/// Build a 2-byte VVC PH NAL header (layer 0, temporal_id 0) followed
/// by the supplied RBSP. Mirrors the `build_ph_nal` helper inside
/// `h266::tests` so the property suite can exercise the parser without
/// touching test-only internals.
fn build_ph_nal(rbsp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + rbsp.len());
    out.push(0u8);
    out.push((NAL_TYPE_PH << 3) | 1);
    out.extend_from_slice(rbsp);
    out
}

/// Pack the H.266 picture-header structural prefix (7.3.2.8 prefix
/// through `ph_pic_parameter_set_id`) into an RBSP using the public
/// `BitWriter`. Returns the canonical RBSP bytes.
fn build_ph_rbsp(
    gdr_or_irap: u8,
    non_ref: u8,
    gdr_pic: u8,
    inter_allowed: u8,
    intra_allowed: u8,
    pps_id: u32,
) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.write_bits(gdr_or_irap as u32, 1);
    w.write_bits(non_ref as u32, 1);
    if gdr_or_irap != 0 {
        w.write_bits(gdr_pic as u32, 1);
    }
    w.write_bits(inter_allowed as u32, 1);
    if inter_allowed != 0 {
        w.write_bits(intra_allowed as u32, 1);
    }
    w.write_ue(pps_id).expect("pps_id within ue range");
    w.finish()
}

#[test]
fn h266_picture_header_round_trips_full_flag_grid_and_pps_id_range() {
    // Exhaustively sweep the 2x2x{1,2}x2x{1,2} flag-combination tree
    // (28 paths) crossed with every legal `ph_pic_parameter_set_id`
    // (0..=63). For each combination, build the PH structural-prefix
    // RBSP with the public `BitWriter`, wrap it as an Annex-B NAL, and
    // confirm `parse_picture_header` recovers every signalled field.
    //
    // This pins down two contracts simultaneously: that the parser
    // walks the optional `ph_gdr_pic_flag` / `ph_intra_slice_allowed_flag`
    // gates correctly (an off-by-one bit would shift `ph_pic_parameter_set_id`
    // by 1 and cascade through the assert), and that every encoded
    // `pps_id` value in the spec range survives ue(v) round-trip.
    let mut paths = 0u32;
    for gdr_or_irap in 0u8..=1 {
        for non_ref in 0u8..=1 {
            for inter in 0u8..=1 {
                let gdr_pics: &[u8] = if gdr_or_irap != 0 { &[0, 1] } else { &[0] };
                let intras: &[u8] = if inter != 0 { &[0, 1] } else { &[0] };
                for &gdr_pic in gdr_pics {
                    for &intra in intras {
                        for pps_id in 0u32..=PH_PIC_PARAMETER_SET_ID_MAX as u32 {
                            let rbsp =
                                build_ph_rbsp(gdr_or_irap, non_ref, gdr_pic, inter, intra, pps_id);
                            let nal = build_ph_nal(&rbsp);
                            let ph = parse_picture_header(&nal).unwrap_or_else(|e| {
                                panic!(
                                    "PH should parse for ({gdr_or_irap},{non_ref},{gdr_pic},{inter},{intra},pps_id={pps_id}): {e:?}"
                                )
                            });
                            assert_eq!(ph.ph_gdr_or_irap_pic_flag, gdr_or_irap);
                            assert_eq!(ph.ph_non_ref_pic_flag, non_ref);
                            assert_eq!(
                                ph.ph_gdr_pic_flag,
                                if gdr_or_irap != 0 {
                                    Some(gdr_pic)
                                } else {
                                    None
                                }
                            );
                            assert_eq!(ph.ph_inter_slice_allowed_flag, inter);
                            assert_eq!(
                                ph.ph_intra_slice_allowed_flag,
                                if inter != 0 { Some(intra) } else { None }
                            );
                            assert_eq!(ph.ph_pic_parameter_set_id, pps_id as u8);
                            paths += 1;
                        }
                    }
                }
            }
        }
    }
    // Sanity-check the path count: 2 (gdr_or_irap) * 2 (non_ref) *
    // {1 with gdr_or_irap=0 or 2 with gdr_or_irap=1}{gdr_pic}
    //   * 2 (inter) * {1 with inter=0 or 2 with inter=1}{intra}
    //   * 64 (pps_id).
    // ≡ (1+2) * (1+2) * 2 * 64 = 1152 paths.
    assert_eq!(
        paths, 1152,
        "expected 1152 unique (flag-combo, pps_id) paths"
    );
}

#[test]
fn h266_picture_header_rejects_every_oversized_pps_id() {
    // Confirm `parse_picture_header` refuses every value of
    // `ph_pic_parameter_set_id` above the spec maximum (>63). The check
    // sweeps a window past the boundary so a forgotten `<` vs `<=` would
    // leak at least one accepted value into the assertion.
    for pps_id in
        (PH_PIC_PARAMETER_SET_ID_MAX as u32 + 1)..=(PH_PIC_PARAMETER_SET_ID_MAX as u32 + 16)
    {
        let rbsp = build_ph_rbsp(0, 0, /*ignored*/ 0, 0, /*ignored*/ 0, pps_id);
        let nal = build_ph_nal(&rbsp);
        let err = parse_picture_header(&nal).unwrap_err_or_else_panic(pps_id);
        matches_invalid_data(&err);
    }
}

trait UnwrapErrOrElsePanic<T> {
    fn unwrap_err_or_else_panic(self, ctx: u32) -> BitstreamError;
}

impl<T: core::fmt::Debug> UnwrapErrOrElsePanic<T> for Result<T, BitstreamError> {
    fn unwrap_err_or_else_panic(self, ctx: u32) -> BitstreamError {
        match self {
            Ok(v) => panic!("expected rejection for ctx={ctx}, got Ok({v:?})"),
            Err(e) => e,
        }
    }
}

/// Build a [`VvcSps`] stub that only varies the field
/// [`parse_picture_header_with_sps`] actually reads
/// (`sps_log2_max_pic_order_cnt_lsb_minus4`). Other fields are filled
/// with canonical defaults the PH parser does not touch.
fn sps_for_poc_width(log2_max_poc_lsb_minus4: u8) -> VvcSps {
    VvcSps {
        sps_seq_parameter_set_id: 0,
        sps_video_parameter_set_id: 0,
        sps_max_sublayers_minus1: 0,
        sps_chroma_format_idc: 1,
        sps_log2_ctu_size_minus5: 2,
        sps_ptl_dpb_hrd_params_present_flag: 0,
        profile_tier_level: None,
        sps_pic_width_max_in_luma_samples: 1920,
        sps_pic_height_max_in_luma_samples: 1080,
        sps_subpic_info_present_flag: 0,
        sps_bitdepth_minus8: 2,
        sps_entropy_coding_sync_enabled_flag: 0,
        sps_entry_point_offsets_present_flag: 0,
        sps_log2_max_pic_order_cnt_lsb_minus4: log2_max_poc_lsb_minus4,
    }
}

/// Pack a PH RBSP carrying the structural prefix, the `ph_pic_order_cnt_lsb`
/// `u(v)` field at `poc_width` bits, and — when `gdr_pic == 1` — the
/// `ph_recovery_poc_cnt` ue(v). The PH parser's spec-driven inverse.
#[allow(clippy::too_many_arguments)]
fn build_ph_rbsp_with_poc(
    gdr_or_irap: u8,
    non_ref: u8,
    gdr_pic: u8,
    inter_allowed: u8,
    intra_allowed: u8,
    pps_id: u32,
    poc_lsb: u32,
    poc_width: u32,
    recovery_poc_cnt: Option<u32>,
) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.write_bits(gdr_or_irap as u32, 1);
    w.write_bits(non_ref as u32, 1);
    if gdr_or_irap != 0 {
        w.write_bits(gdr_pic as u32, 1);
    }
    w.write_bits(inter_allowed as u32, 1);
    if inter_allowed != 0 {
        w.write_bits(intra_allowed as u32, 1);
    }
    w.write_ue(pps_id).expect("pps_id within ue range");
    w.write_bits(poc_lsb, poc_width);
    if let Some(rpc) = recovery_poc_cnt {
        w.write_ue(rpc).expect("recovery_poc_cnt within ue range");
    }
    w.finish()
}

#[test]
fn h266_picture_header_with_sps_round_trips_every_poc_width_and_value() {
    // Sweep every legal `sps_log2_max_pic_order_cnt_lsb_minus4`
    // (0..=12 → POC LSB widths 4..=16). For each width, drive a
    // representative slice of the POC LSB value space — the two
    // endpoints (0 and `2^width - 1`) plus a randomised tail — through
    // an IRAP picture (no recovery_poc_cnt) and a GDR picture (with
    // recovery_poc_cnt), and confirm the parser recovers both fields
    // exactly. Off-by-one width bugs would shift later bits and
    // corrupt the recovery_poc_cnt ue(v), so the GDR path is the
    // sharpest end-to-end check.
    let mut rng = Lcg::new(0xfeed_face_dead_c0de);
    let mut paths = 0u32;
    for log2_max in 0u8..=SPS_LOG2_MAX_PIC_ORDER_CNT_LSB_MINUS4_MAX {
        let sps = sps_for_poc_width(log2_max);
        let width = sps.poc_lsb_width();
        let max_lsb = if width == 32 {
            u32::MAX
        } else {
            (1u32 << width) - 1
        };
        // Endpoint + ~40 randomised mid-range values.
        let mut sample_values: Vec<u32> = vec![0, max_lsb];
        for _ in 0..40 {
            sample_values.push(rng.next_u32() & max_lsb);
        }
        for &poc_lsb in &sample_values {
            // IRAP picture (gdr_or_irap=1, gdr_pic=0): no recovery_poc_cnt.
            let rbsp = build_ph_rbsp_with_poc(1, 0, 0, 1, 1, 0, poc_lsb, width, None);
            let nal = build_ph_nal(&rbsp);
            let ph = parse_picture_header_with_sps(&nal, &sps).unwrap_or_else(|e| {
                panic!("IRAP PH should parse for log2_max={log2_max}, poc_lsb={poc_lsb}: {e:?}")
            });
            assert_eq!(ph.ph_pic_order_cnt_lsb, Some(poc_lsb));
            assert_eq!(ph.ph_recovery_poc_cnt, None);
            assert!(ph.is_irap());
            paths += 1;

            // GDR picture (gdr_or_irap=1, gdr_pic=1): recovery_poc_cnt
            // present. Use the same value as poc_lsb (modulo a small
            // cap so the ue(v) stays a reasonable size) — the parser
            // doesn't care, but the round-trip must be exact.
            let rpc = poc_lsb & 0xff;
            let rbsp = build_ph_rbsp_with_poc(1, 0, 1, 1, 1, 0, poc_lsb, width, Some(rpc));
            let nal = build_ph_nal(&rbsp);
            let ph = parse_picture_header_with_sps(&nal, &sps).unwrap_or_else(|e| {
                panic!("GDR PH should parse for log2_max={log2_max}, poc_lsb={poc_lsb}: {e:?}")
            });
            assert_eq!(ph.ph_pic_order_cnt_lsb, Some(poc_lsb));
            assert_eq!(ph.ph_recovery_poc_cnt, Some(rpc));
            assert!(!ph.is_irap());
            assert!(ph.is_gdr());
            paths += 1;
        }
    }
    // Sanity: 13 widths × 42 values × 2 picture types = 1092 paths.
    assert_eq!(paths, 13 * 42 * 2, "expected 1092 IRAP+GDR PH paths");
}

// ─── nal::rbsp_to_ebsp ↔ nal::ebsp_to_rbsp invariants ────────────────────────

/// Helper: emit a known-conformant EBSP that round-trips through both
/// directions cleanly. We construct it from a freely-chosen RBSP via
/// `rbsp_to_ebsp` so the trailing-zero-guard branch is automatically
/// handled (the inverse pair is total over the RBSP side; the EBSP side
/// is only total over conformant inputs).
fn rng_rbsp(rng: &mut Lcg, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push((rng.next_u32() & 0xff) as u8);
    }
    out
}

#[test]
fn nal_rbsp_roundtrips_through_ebsp() {
    // Random RBSPs of varying lengths must round-trip exactly through
    // the inverse pair. Includes the empty buffer and the boundary
    // cases of trailing zeros / leading zeros / triple-zero clusters.
    let mut rng = Lcg::new(0x1357_9bdf_2468_ace0);

    // Hand-constructed edge cases first.
    let edge_cases: &[&[u8]] = &[
        &[],
        &[0x00],
        &[0x00, 0x00],
        &[0x00, 0x00, 0x00],
        &[0x00, 0x00, 0x01],
        &[0x00, 0x00, 0x02],
        &[0x00, 0x00, 0x03],
        &[0x00, 0x00, 0x04],
        &[0xff, 0x00, 0x00],
        &[0xff, 0x00, 0x00, 0x00],
        &[0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02],
        // A sequence of all-zero bytes — every interior `00 00 X≤3`
        // window must get an escape.
        &[0x00; 8],
        &[0x00; 9],
        &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
    ];
    for &rbsp in edge_cases {
        let ebsp = rbsp_to_ebsp(rbsp);
        let recovered = ebsp_to_rbsp(&ebsp);
        assert_eq!(recovered, rbsp, "edge round-trip for {rbsp:?} via {ebsp:?}");
    }

    // Random sweep across a range of lengths. The seed is fixed so a
    // failure is reproducible.
    for &len in &[1usize, 2, 3, 4, 8, 16, 32, 64, 128, 256, 1024] {
        for _ in 0..200 {
            let rbsp = rng_rbsp(&mut rng, len);
            let ebsp = rbsp_to_ebsp(&rbsp);
            let recovered = ebsp_to_rbsp(&ebsp);
            assert_eq!(
                recovered, rbsp,
                "random round-trip failed at len {len}: ebsp={ebsp:x?}"
            );
        }
    }
}

#[test]
fn nal_ebsp_never_contains_internal_start_code_prefix() {
    // After framing, no three-byte window `00 00 X` with X in 0..=1 is
    // permitted inside the EBSP — that is exactly what the escape rule
    // guarantees (and a start-code scanner relies on). We assert it on
    // both edge cases and random RBSPs.
    let mut rng = Lcg::new(0xc0ff_ee15_b00b_face);

    // Property holds for arbitrary RBSPs because the writer escapes
    // every `00 00 (00..=03)` triple.
    for len in [3usize, 4, 8, 32, 128, 1024] {
        for _ in 0..200 {
            let rbsp = rng_rbsp(&mut rng, len);
            let ebsp = rbsp_to_ebsp(&rbsp);
            // Scan: no two consecutive zeros may be followed by 0x00 or
            // 0x01 (that would be the start of an Annex-B prefix or
            // its prefix-of-prefix special case).
            for i in 0..ebsp.len().saturating_sub(2) {
                if ebsp[i] == 0 && ebsp[i + 1] == 0 {
                    let third = ebsp[i + 2];
                    assert!(
                        third != 0x00 && third != 0x01,
                        "EBSP contains forbidden window at {i}: {:x?}",
                        &ebsp[i..i + 3.min(ebsp.len() - i)]
                    );
                }
            }
        }
    }
}

#[test]
fn nal_codec_module_reexports_share_identity() {
    // The three codec modules export `ebsp_to_rbsp` as a re-export of
    // the shared `nal::ebsp_to_rbsp`. Pinning that down here means a
    // later accidental fork of the per-codec helper (e.g. someone
    // restoring the private copy) shows up as a behavioural drift on
    // the same fixture.
    let ebsp = [0x67, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x03, 0x02];
    let want = ebsp_to_rbsp(&ebsp);
    assert_eq!(oxideav_bitstream::h264::ebsp_to_rbsp(&ebsp), want);
    assert_eq!(oxideav_bitstream::hevc::ebsp_to_rbsp(&ebsp), want);
    assert_eq!(oxideav_bitstream::h266::ebsp_to_rbsp(&ebsp), want);
}

/// IVF `write_header` is an exact inverse of `parse_header` across a
/// randomised sweep of legal `IvfHeader` field values. We seed the LCG
/// once, then drive 5000 iterations covering every u16 / u32 width on
/// the fields, plus a four-element FourCC enumeration that includes
/// the two project-exported constants and two synthetic FourCCs.
#[test]
fn ivf_write_header_round_trips_through_parse_header_randomised() {
    let mut rng = Lcg::new(0xc0ffee_deadbeefu64);
    let fourccs = [IVF_FOURCC_VP80, IVF_FOURCC_VP90, *b"AV01", *b"XYZW"];
    for i in 0..5000 {
        let header = IvfHeader {
            fourcc: fourccs[i % fourccs.len()],
            width: rng.next_u32() as u16,
            height: rng.next_u32() as u16,
            framerate_num: rng.next_u32(),
            framerate_den: rng.next_u32(),
            frame_count: rng.next_u32(),
        };
        let mut out = Vec::new();
        let (start, end) = write_header(&mut out, header);
        assert_eq!(start, 0);
        assert_eq!(end, IVF_HEADER_LEN);
        let (got, rest) = parse_header(&out).expect("write_header output parses");
        assert_eq!(got, header, "header round-trip mismatch on iter {i}");
        assert!(
            rest.is_empty(),
            "lone-header output has no per-frame remainder"
        );
    }
}

/// `write_frame` and `parse_frame` are exact inverses on a randomised
/// sweep of payload sizes from 0 up to 4096 bytes (covers every byte
/// length the per-frame `size` decoder is likely to see on a typical
/// VP8 / VP9 / AV1 fixture).
#[test]
fn ivf_write_frame_round_trips_through_parse_frame_randomised() {
    let mut rng = Lcg::new(0x1234_5678_9abc_def0u64);
    for i in 0..2000 {
        // Payload size in 0..=4096 with a small bias to the short end.
        let size = (rng.next_u32() % 4097) as usize;
        let mut payload = vec![0u8; size];
        for byte in payload.iter_mut() {
            *byte = rng.next_u32() as u8;
        }
        let timestamp = rng.next_u64();

        let mut out = Vec::new();
        let (start, end) = write_frame(&mut out, timestamp, &payload).expect("legal payload size");
        assert_eq!(start, 0);
        assert_eq!(end, IVF_FRAME_HEADER_LEN + payload.len());

        let (frame, rest) = parse_frame(&out)
            .expect("write_frame output parses")
            .unwrap();
        assert_eq!(
            frame.timestamp, timestamp,
            "frame timestamp round-trip on iter {i}"
        );
        assert_eq!(
            frame.payload, payload,
            "frame payload round-trip on iter {i}"
        );
        assert!(rest.is_empty(), "no remainder after a single frame");
    }
}

/// `write_all` ↔ `parse_all` is total on a multi-frame stream with a
/// mix of legal frame sizes. The asserted invariant: the parsed
/// (timestamp, payload) tuples line up byte-for-byte with the inputs,
/// and the buffer length is exactly the documented sum.
#[test]
fn ivf_write_all_round_trips_through_parse_all_multi_frame() {
    let mut rng = Lcg::new(0xfeed_face_0000_0001u64);
    for stream_i in 0..200 {
        let header = IvfHeader {
            fourcc: IVF_FOURCC_VP90,
            width: rng.next_u32() as u16,
            height: rng.next_u32() as u16,
            framerate_num: rng.next_u32(),
            framerate_den: rng.next_u32(),
            frame_count: rng.next_u32(),
        };
        let n_frames = (rng.next_u32() % 17) as usize; // 0..=16
        let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(n_frames);
        let mut timestamps: Vec<u64> = Vec::with_capacity(n_frames);
        for _ in 0..n_frames {
            let len = (rng.next_u32() % 256) as usize;
            let mut p = vec![0u8; len];
            for b in p.iter_mut() {
                *b = rng.next_u32() as u8;
            }
            payloads.push(p);
            timestamps.push(rng.next_u64());
        }
        let frames: Vec<(u64, &[u8])> = timestamps
            .iter()
            .zip(payloads.iter())
            .map(|(t, p)| (*t, p.as_slice()))
            .collect();

        let buf = write_all(header, &frames).expect("legal frame sizes");
        let expected_len: usize = IVF_HEADER_LEN
            + frames
                .iter()
                .map(|(_, p)| IVF_FRAME_HEADER_LEN + p.len())
                .sum::<usize>();
        assert_eq!(
            buf.len(),
            expected_len,
            "byte-length matches the header + per-frame sum"
        );

        let (parsed_h, parsed_frames) = parse_all(&buf).expect("write_all output parses");
        assert_eq!(parsed_h, header, "header round-trip on stream {stream_i}");
        assert_eq!(
            parsed_frames.len(),
            frames.len(),
            "frame count on stream {stream_i}"
        );
        for (i, (got, want)) in parsed_frames.iter().zip(frames.iter()).enumerate() {
            assert_eq!(
                got.timestamp, want.0,
                "frame {i} timestamp on stream {stream_i}"
            );
            assert_eq!(
                got.payload, want.1,
                "frame {i} payload on stream {stream_i}"
            );
        }
    }
}

/// Mixing a hand-written prefix and `write_header` / `write_frame` calls
/// preserves byte ranges so downstream consumers can locate every
/// header / frame inside a larger byte vector. The `(start, end)` tuple
/// the writer returns is the byte range covering the appended block.
#[test]
fn ivf_writer_returned_ranges_locate_appended_blocks() {
    let mut rng = Lcg::new(0xabad_cafe_1337_4242u64);
    for _ in 0..200 {
        let prefix_len = (rng.next_u32() % 16) as usize;
        let mut buf: Vec<u8> = (0..prefix_len).map(|i| (i & 0xff) as u8).collect();
        let prefix_snapshot = buf.clone();
        let header = IvfHeader {
            fourcc: IVF_FOURCC_VP80,
            width: 320,
            height: 240,
            framerate_num: 1,
            framerate_den: 1,
            frame_count: 0,
        };
        let (hstart, hend) = write_header(&mut buf, header);
        assert_eq!(hstart, prefix_len);
        assert_eq!(hend, prefix_len + IVF_HEADER_LEN);
        assert_eq!(&buf[..prefix_len], prefix_snapshot.as_slice());

        // Append a frame; check the returned range too.
        let payload: Vec<u8> = (0..rng.next_u32() % 64).map(|i| (i & 0xff) as u8).collect();
        let ts = rng.next_u64();
        let (fstart, fend) = write_frame(&mut buf, ts, &payload).unwrap();
        assert_eq!(fstart, hend);
        assert_eq!(fend, hend + IVF_FRAME_HEADER_LEN + payload.len());

        // Parsing back at hstart yields the original (header, frames).
        let (parsed_h, frames) = parse_all(&buf[hstart..]).unwrap();
        assert_eq!(parsed_h, header);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].timestamp, ts);
        assert_eq!(frames[0].payload, payload.as_slice());
    }
}

/// Ensure the writer's fixed bytes (DKIF magic, version=0, header_len=32,
/// reserved tail) match the reader's strict checks. A drift on any of
/// these would cause `parse_header` to reject `write_header`'s output —
/// the exact-inverse property already covered above is the operational
/// check, but pinning the magic-byte layout to the bytes the reader
/// hard-codes catches a one-sided edit before the round-trip would.
#[test]
fn ivf_write_header_emits_fixed_bytes_reader_demands() {
    let header = IvfHeader {
        fourcc: *b"FOUR",
        width: 1,
        height: 2,
        framerate_num: 3,
        framerate_den: 4,
        frame_count: 5,
    };
    let mut out = Vec::new();
    write_header(&mut out, header);
    assert_eq!(&out[0..4], b"DKIF", "DKIF magic");
    assert_eq!(
        u16::from_le_bytes([out[4], out[5]]),
        0,
        "version field is zero"
    );
    assert_eq!(
        u16::from_le_bytes([out[6], out[7]]),
        IVF_HEADER_LEN as u16,
        "header_len field equals the documented constant"
    );
    assert_eq!(
        &out[28..32],
        &[0u8; 4],
        "reserved tail is zeroed (documented unused bytes)"
    );
}

// ─────────────────────────── AUD round-trip invariants ──────────────────────

/// H.264 AUD: every legal `primary_pic_type` value (0..=7) round-trips
/// through `write_aud_nal` -> `parse_aud_nal` byte-identically. The
/// emitted bytes are a known 2-byte sequence (header byte 0x09 + one
/// payload byte) so we also pin the encoded byte count.
#[test]
fn h264_aud_roundtrips_every_pic_type() {
    for pt in 0u8..=H264_PRIMARY_PIC_TYPE_MAX {
        let in_ = H264AccessUnitDelimiter {
            primary_pic_type: pt,
        };
        let bytes = h264_write_aud_nal(&in_).expect("h264 AUD writes");
        assert_eq!(bytes.len(), 2, "h264 AUD is 2 bytes");
        assert_eq!(bytes[0], 0x09, "header byte is nal_unit_type=9");
        let parsed = h264_parse_aud_nal(&bytes).expect("h264 AUD parses");
        assert_eq!(parsed, in_, "h264 AUD round-trip pic_type={pt}");
    }
}

/// H.264 AUD: out-of-range `primary_pic_type` values (8..=255) are
/// rejected as `InvalidData` rather than silently truncated to the
/// low three bits — a silent-truncation bug would round-trip as a
/// different conforming value and never get caught.
#[test]
fn h264_aud_rejects_oversized_pic_type() {
    for pt in (H264_PRIMARY_PIC_TYPE_MAX + 1)..=255 {
        let err = h264_write_aud_nal(&H264AccessUnitDelimiter {
            primary_pic_type: pt,
        })
        .expect_err("oversized pic_type rejected");
        assert!(matches!(
            err,
            oxideav_bitstream::BitstreamError::InvalidData(_)
        ));
    }
}

/// HEVC AUD: every value across the full u(3) range (including
/// reserved 3..=7 which decoders MUST accept) round-trips
/// byte-identically through `write_aud_nal` -> `parse_aud_nal`. The
/// encoded form is a known 3-byte sequence (two-byte NAL header
/// 0x46 0x01 plus one payload byte) so we also pin the byte count.
#[test]
fn hevc_aud_roundtrips_every_pic_type() {
    for pt in 0u8..=HEVC_PIC_TYPE_MAX {
        let in_ = HevcAccessUnitDelimiter { pic_type: pt };
        let bytes = hevc_write_aud_nal(&in_).expect("hevc AUD writes");
        assert_eq!(bytes.len(), 3, "hevc AUD is 3 bytes");
        assert_eq!(bytes[0], 0x46, "header byte0: nal_unit_type=35");
        assert_eq!(bytes[1], 0x01, "header byte1: layer=0 / tid_plus1=1");
        let parsed = hevc_parse_aud_nal(&bytes).expect("hevc AUD parses");
        assert_eq!(parsed, in_, "hevc AUD round-trip pic_type={pt}");
    }
}

#[test]
fn hevc_aud_rejects_oversized_pic_type() {
    for pt in (HEVC_PIC_TYPE_MAX + 1)..=255 {
        let err = hevc_write_aud_nal(&HevcAccessUnitDelimiter { pic_type: pt })
            .expect_err("oversized pic_type rejected");
        assert!(matches!(
            err,
            oxideav_bitstream::BitstreamError::InvalidData(_)
        ));
    }
}

/// H.266 AUD: every (`aud_irap_or_gdr_flag`, `aud_pic_type`)
/// combination across `{0,1} × 0..=7` round-trips byte-identically.
/// The full u(3) range is covered (including reserved values that
/// decoders MUST accept). The encoded form is a known 3-byte
/// sequence: NAL header 0x00 0xA1 plus a one-byte payload.
#[test]
fn h266_aud_roundtrips_every_combination() {
    for irap in 0u8..=1 {
        for pt in 0u8..=AUD_PIC_TYPE_MAX {
            let in_ = VvcAccessUnitDelimiter {
                aud_irap_or_gdr_flag: irap,
                aud_pic_type: pt,
            };
            let bytes = write_aud(&in_).expect("h266 AUD writes");
            assert_eq!(bytes.len(), 3, "h266 AUD is 3 bytes");
            assert_eq!(bytes[0], 0x00, "header byte0: forbidden+reserved+layer=0");
            assert_eq!(bytes[1], 0xA1, "header byte1: type=20 / tid_plus1=1");
            let parsed = parse_aud(&bytes).expect("h266 AUD parses");
            assert_eq!(parsed, in_, "h266 AUD round-trip irap={irap} pt={pt}");
        }
    }
}

#[test]
fn h266_aud_rejects_oversized_fields() {
    // Out-of-range irap flag.
    for bad_irap in 2u8..=255 {
        let err = write_aud(&VvcAccessUnitDelimiter {
            aud_irap_or_gdr_flag: bad_irap,
            aud_pic_type: 0,
        })
        .expect_err("oversized irap flag rejected");
        assert!(matches!(
            err,
            oxideav_bitstream::BitstreamError::InvalidData(_)
        ));
    }
    // Out-of-range pic_type.
    for bad_pt in (AUD_PIC_TYPE_MAX + 1)..=255 {
        let err = write_aud(&VvcAccessUnitDelimiter {
            aud_irap_or_gdr_flag: 0,
            aud_pic_type: bad_pt,
        })
        .expect_err("oversized aud_pic_type rejected");
        assert!(matches!(
            err,
            oxideav_bitstream::BitstreamError::InvalidData(_)
        ));
    }
}

/// Pinning the writer's byte layout independently of the parser
/// catches one-sided drift. For each codec, the emitted bytes are
/// fully determined by the input fields, so we hard-code the expected
/// sequence for two representative inputs.
#[test]
fn aud_writers_emit_documented_byte_layout() {
    // H.264, primary_pic_type=3 (011) + stop(1) + alignment 0000 ->
    // 0b0111_0000 = 0x70.
    assert_eq!(
        h264_write_aud_nal(&H264AccessUnitDelimiter {
            primary_pic_type: 3
        })
        .unwrap(),
        vec![0x09, 0x70]
    );
    // HEVC, pic_type=1 (001) + stop(1) + alignment 0000 -> 0b0011_0000
    // = 0x30.
    assert_eq!(
        hevc_write_aud_nal(&HevcAccessUnitDelimiter { pic_type: 1 }).unwrap(),
        vec![0x46, 0x01, 0x30]
    );
    // H.266, irap=1, pic_type=1 (001) -> 1 001 1 000 = 0b1001_1000 =
    // 0x98.
    assert_eq!(
        write_aud(&VvcAccessUnitDelimiter {
            aud_irap_or_gdr_flag: 1,
            aud_pic_type: 1
        })
        .unwrap(),
        vec![0x00, 0xA1, 0x98]
    );
}
