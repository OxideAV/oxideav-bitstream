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
use oxideav_bitstream::av1::{parse_obu_stream, read_leb128};
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
