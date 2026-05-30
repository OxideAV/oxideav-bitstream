#![no_main]

//! Panic-hardening fuzz harness for the `oxideav-bitstream` primitives.
//!
//! `oxideav-bitstream` is the foundational bit-IO crate every codec
//! parser builds on, so its reader must be panic-free on *any* byte
//! sequence read in *any* width pattern. This target treats the input
//! `data` as both a payload buffer and an opcode tape that drives the
//! reader through an arbitrary mix of `u(n)` / `u64(n)` / `ue` / `se` /
//! `read_bit` / `align_to_byte` / `skip` operations, deliberately
//! reading far past the end of the buffer. None of these may panic,
//! overflow, or index out of bounds — past-the-end reads must follow
//! the documented "zero bits" contract.
//!
//! Surfaces exercised on every input:
//!
//! * [`BitReader`] — the core reader, driven by an opcode tape.
//! * [`read_leb128`] — the AV1 LEB128 reader, at every byte offset.
//! * [`parse_obu_stream`] — the OBU walker, over raw attacker bytes.
//!
//! Round-trip invariant fuzzed on structured inputs:
//!
//! * a sequence of `(value, width)` fields written via [`BitWriter`]
//!   and read back via [`BitReader`] reproduces each field exactly —
//!   the writer/reader inverse-pair contract.

use libfuzzer_sys::fuzz_target;
use oxideav_bitstream::av1::{
    parse_obu_stream, read_leb128, read_obu, write_leb128, write_obu, ObuHeader, LEB128_MAX,
    OBU_SPATIAL_ID_MAX, OBU_TEMPORAL_ID_MAX, OBU_TYPE_MAX,
};
use oxideav_bitstream::bit_reader::BitReader;
use oxideav_bitstream::bit_writer::BitWriter;

fuzz_target!(|data: &[u8]| {
    // 1. Drive the reader through an opcode tape. The first half of the
    //    input is the opcode stream; the whole input is the payload the
    //    reader reads from. We intentionally let the reader run past
    //    the end of the payload — that must yield zeros, never panic.
    drive_reader(data);

    // 2. read_leb128 at every byte offset (including past the end) must
    //    return Ok/Err but never panic or index out of bounds.
    for off in 0..=data.len() {
        let _ = read_leb128(data, off);
    }
    // An offset strictly past the end is also valid input.
    let _ = read_leb128(data, data.len().wrapping_add(1));

    // 3. The OBU walker over arbitrary bytes must never panic.
    let _ = parse_obu_stream(data);

    // 4. Writer -> reader round-trip on a structured view of the input.
    roundtrip_fields(data);

    // 5. write_leb128 round-trip: pull u64 values out of `data` and assert
    //    that write_leb128 followed by read_leb128 reproduces them. The
    //    writer refuses anything above LEB128_MAX, so mask the candidate
    //    value into the legal envelope.
    leb128_writer_roundtrip(data);

    // 6. write_obu round-trip: synthesise OBU headers + payload slices
    //    from the attacker bytes, frame them with write_obu, and assert
    //    read_obu reproduces the same header + payload range — or that
    //    rejected headers leave the buffer untouched.
    obu_writer_roundtrip(data);
});

/// Treat `data` as an opcode tape and a payload simultaneously, running
/// the reader through a varied operation mix that reads well past EOF.
fn drive_reader(data: &[u8]) {
    let mut r = BitReader::new(data);
    // Bound the op count so the harness stays fast; long inputs still
    // get plenty of operations.
    let ops = data.len().saturating_mul(2).min(4096) + 64;
    for i in 0..ops {
        // Derive the opcode from the input bytes (wrapping) so the tape
        // is input-controlled, plus the loop index for variety.
        let op = data.get(i % data.len().max(1)).copied().unwrap_or(i as u8);
        match op % 8 {
            0 => {
                let _ = r.read_bit();
            }
            1 => {
                let n = (op as u32 >> 3) % 33; // 0..=32
                let _ = r.u(n);
            }
            2 => {
                let n = (op as u32 >> 1) % 65; // 0..=64
                let _ = r.u64(n);
            }
            3 => {
                // ue must never panic; it returns Err on malformed runs.
                let _ = r.ue();
            }
            4 => {
                let _ = r.se();
            }
            5 => {
                r.align_to_byte();
            }
            6 => {
                let n = (op as usize) % 17;
                r.skip(n);
            }
            _ => {
                // Query methods must agree with each other and not panic.
                let _ = r.bit_pos();
                let _ = r.bits_remaining();
                let _ = r.at_end();
                let _ = r.byte_aligned();
                // peek_bits / more_rbsp_data / read_rbsp_trailing_bits
                // are part of the foundational surface; they must never
                // panic on attacker bytes either.
                let pn = (op as u32 >> 2) % 33;
                let _ = r.peek_bits(pn);
                let _ = r.more_rbsp_data();
                // read_rbsp_trailing_bits mutates position; only call it
                // occasionally so the tape keeps making progress.
                if op & 0b1100_0000 == 0b1100_0000 {
                    let _ = r.read_rbsp_trailing_bits();
                }
            }
        }
    }
}

/// Carve `data` into `(value, width)` field descriptors, write them with
/// `BitWriter`, then read them back and assert each field round-trips.
fn roundtrip_fields(data: &[u8]) {
    // Each field needs 5 bytes: 4 for a u32 value LE + 1 for the width.
    let mut w = BitWriter::new();
    let mut fields: Vec<(u32, u32)> = Vec::new();
    for chunk in data.chunks_exact(5) {
        let value = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        // Width 1..=32 (avoid 0 so there is always a bit to compare).
        let width = (chunk[4] % 32) as u32 + 1;
        let masked = if width >= 32 {
            value
        } else {
            value & ((1u32 << width) - 1)
        };
        w.write_bits(value, width);
        fields.push((masked, width));
        // Keep the buffer bounded.
        if fields.len() >= 512 {
            break;
        }
    }
    if fields.is_empty() {
        return;
    }
    let bytes = w.finish();
    let mut r = BitReader::new(&bytes);
    for (expected, width) in fields {
        let got = r.u(width);
        assert_eq!(
            got, expected,
            "writer/reader round-trip mismatch for width {width}"
        );
    }
}

/// Carve `data` into header-descriptor + payload chunks and exercise
/// `write_obu`. Each iteration synthesises:
///
/// * 1 byte of "shape" bits that pick `obu_type`, `extension_flag`,
///   `temporal_id`, `spatial_id`, and a payload-length scaler;
/// * `payload_len` payload bytes from the rest of `data`.
///
/// The invariant: when `write_obu` returns Ok, feeding the framed bytes
/// back through `read_obu` reproduces the header and payload exactly. On
/// any Err (e.g. validation rejects oversized IDs), the output buffer
/// must be untouched.
fn obu_writer_roundtrip(data: &[u8]) {
    let mut cursor = 0usize;
    let mut rounds = 0usize;
    while cursor < data.len() && rounds < 64 {
        rounds += 1;
        // Pull 1 shape byte from `data` (cycle if exhausted).
        let shape = data[cursor % data.len()];
        cursor = cursor.saturating_add(1);

        // Derive header fields from the shape byte.
        let obu_type = (shape & 0x0f).min(OBU_TYPE_MAX);
        let extension_flag = shape & 0x10 != 0;
        let (temporal_id, spatial_id) = if extension_flag {
            (
                (shape >> 5) & OBU_TEMPORAL_ID_MAX,
                ((shape >> 4) & 0b11) & OBU_SPATIAL_ID_MAX,
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
        // Cap payload at 32 bytes for fuzz performance; longer payloads
        // are well-exercised by the property test.
        let payload_len = (shape >> 6) as usize * 8 + 1; // 1, 9, 17, 25
        let payload_len = payload_len.min(data.len().saturating_sub(cursor));
        let payload = &data[cursor..cursor.saturating_add(payload_len)];
        cursor = cursor.saturating_add(payload_len);

        let mut out = Vec::new();
        match write_obu(&mut out, header, payload) {
            Ok((start, end)) => {
                assert_eq!(start, 0);
                assert_eq!(end, out.len());
                let (got, ps, pe, next) =
                    read_obu(&out, start).expect("framed OBU must decode");
                assert_eq!(got, header, "header round-trip");
                assert_eq!(pe - ps, payload.len(), "payload size");
                assert_eq!(&out[ps..pe], payload, "payload bytes");
                assert_eq!(next, end, "next_offset matches end");
            }
            Err(_) => {
                assert!(out.is_empty(), "rejected write_obu must not append");
            }
        }
    }
}

/// Carve `data` into 8-byte chunks, decode each as a u64, mask into the
/// 56-bit leb128 envelope, and assert write_leb128 / read_leb128 form an
/// exact inverse pair. The writer is the only surface here so we also
/// confirm it never panics on rejection paths.
fn leb128_writer_roundtrip(data: &[u8]) {
    let mut emitted = 0;
    for chunk in data.chunks_exact(8) {
        if emitted >= 256 {
            break;
        }
        let raw = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        // Half the time, take the raw value (which may exceed LEB128_MAX
        // and must be rejected with a clean error). Half the time, mask
        // into the legal envelope and assert a successful round-trip.
        if raw & 1 == 0 {
            let v = raw & LEB128_MAX;
            let mut out = Vec::new();
            let n = write_leb128(&mut out, v).expect("masked value is in range");
            assert_eq!(out.len(), n);
            let (decoded, consumed) = read_leb128(&out, 0).expect("encoded code decodes");
            assert_eq!(decoded, v);
            assert_eq!(consumed, n);
        } else {
            let mut out = Vec::new();
            match write_leb128(&mut out, raw) {
                Ok(_) => {
                    // raw was already in range — same contract applies.
                    let (decoded, _) = read_leb128(&out, 0).expect("encoded code decodes");
                    assert_eq!(decoded, raw);
                }
                Err(_) => {
                    // Out-of-range values must leave the buffer unchanged.
                    assert!(out.is_empty(), "rejected write must not append");
                }
            }
        }
        emitted += 1;
    }
}
