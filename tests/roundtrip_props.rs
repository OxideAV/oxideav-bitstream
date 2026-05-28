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

use oxideav_bitstream::av1::read_leb128;
use oxideav_bitstream::bit_reader::BitReader;
use oxideav_bitstream::bit_writer::BitWriter;
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
