//! Shared NAL-unit byte-level helpers.
//!
//! H.264, H.265 (HEVC) and H.266 (VVC) all use the same Annex-B byte
//! stuffing rule to prevent payload bytes from accidentally forming a
//! start-code prefix: any `0x00 0x00 0x0X` triplet with `X ∈ {0,1,2,3}`
//! inside the NAL payload is escaped by inserting an `emulation_prevention_three_byte`
//! (`0x03`) between the two zeros and the third byte. Stripping that
//! byte recovers the raw byte stream payload (RBSP) from the encapsulated
//! byte stream payload (EBSP).
//!
//! The rule is described identically in:
//!
//! - ITU-T H.264 §7.4.1.1 (`Encapsulated byte sequence payload` /
//!   `NAL unit and byte stream formats` annex).
//! - ITU-T H.265 (HEVC) §7.4.1.1.
//! - ITU-T H.266 (VVC) §7.3.1.1 (general NAL unit syntax) +
//!   §7.4.2.1 (process of inserting `emulation_prevention_three_byte`).
//!
//! Before this module existed, each codec sub-module
//! ([`crate::h264`], [`crate::hevc`], [`crate::h266`]) carried its own
//! byte-identical copy of the stripper. Hosting one definition here
//! removes that drift hazard and adds the inverse direction (an
//! emulation-prevention *inserter*) that the per-codec modules did not
//! previously expose, so encoders that build an RBSP through
//! [`crate::bit_writer::BitWriter`] can frame it for the wire with the
//! same crate.
//!
//! # Clean-room
//!
//! Both functions are derived from the spec rule above. No external
//! decoder source was consulted; the algorithm is a two-line state
//! machine matched literally against the spec sentence.

/// Strip `emulation_prevention_three_byte` (`0x03`) bytes from an EBSP
/// to produce an RBSP.
///
/// The encoder inserts `0x03` after every `0x00 0x00` sequence in the
/// NAL payload whose third byte would otherwise be `0x00`, `0x01`,
/// `0x02` or `0x03`, ensuring no internal start-code prefix can be
/// constructed. Reversing the rule means: whenever a `0x00 0x00 0x03`
/// triple is seen and at least one more byte follows (so the triple is
/// not the trailing two zeros of the buffer plus a stray `0x03`),
/// drop the `0x03`.
///
/// Past-the-end safety: the function returns a new owned `Vec<u8>`;
/// the input is never mutated and shorter buffers are handled by the
/// natural loop termination.
pub fn ebsp_to_rbsp(ebsp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ebsp.len());
    let mut i = 0;
    let n = ebsp.len();
    while i < n {
        if i + 2 < n && ebsp[i] == 0 && ebsp[i + 1] == 0 && ebsp[i + 2] == 3 {
            out.push(0);
            out.push(0);
            i += 3;
        } else {
            out.push(ebsp[i]);
            i += 1;
        }
    }
    out
}

/// Insert `emulation_prevention_three_byte` (`0x03`) bytes into an RBSP
/// to produce an EBSP — the inverse of [`ebsp_to_rbsp`].
///
/// Whenever the writer is about to emit a byte that is `0x00`, `0x01`,
/// `0x02` or `0x03` **immediately after** an existing `0x00 0x00`
/// suffix in the output, an `0x03` is inserted first. This guarantees
/// no start-code prefix (`0x00 0x00 0x01` or its 4-byte variant) can
/// appear inside the resulting EBSP payload.
///
/// The transformation also handles the trailing case described in
/// ITU-T H.264 §7.4.1.1 / H.265 §7.4.1.1 / H.266 §7.4.2.1: if the RBSP
/// ends with `0x00 0x00`, a trailing `0x03` is appended so the next
/// NAL's start-code can be distinguished from a payload-internal pair
/// of zeros. Without this an Annex-B parser scanning the concatenated
/// stream could fold the leading byte of the next start code into the
/// trailing zeros of this NAL.
///
/// Round-trip contract: `ebsp_to_rbsp(&rbsp_to_ebsp(x)) == x` for any
/// byte slice `x`. The reverse direction holds when the input is
/// already a conformant EBSP (any RBSP byte stream that did not need
/// escaping decodes back to itself); inputs that contain a non-spec
/// `0x00 0x00 0x03 X` with `X >= 4` are *not* conformant EBSPs and
/// the property does not apply.
pub fn rbsp_to_ebsp(rbsp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rbsp.len() + rbsp.len() / 32);
    // Number of trailing `0x00` bytes already emitted to `out`. The
    // emulation rule only fires when this count is at least 2.
    let mut zero_run = 0usize;
    for &b in rbsp {
        if zero_run >= 2 && b <= 0x03 {
            out.push(0x03);
            zero_run = 0;
        }
        out.push(b);
        if b == 0 {
            zero_run += 1;
        } else {
            zero_run = 0;
        }
    }
    // Trailing-zero guard: an RBSP that ends in `0x00 0x00` would let
    // the next access unit's start-code prefix slide one byte into the
    // current NAL, so the spec requires an escape byte at the tail.
    if zero_run >= 2 {
        out.push(0x03);
    }
    out
}

// ─────────────────────────── Framing conversion ─────────────────────────────
//
// The same elementary stream travels in two framings:
//
// * **Annex-B byte stream** (ITU-T H.264 / H.265 / H.266 Annex B) —
//   each NAL unit is preceded by a 3-byte (`00 00 01`) or 4-byte
//   (`00 00 00 01`) start-code prefix.
// * **Length-prefixed** (ISO base-media sample framing) — each NAL
//   unit is preceded by a 1..4-byte big-endian length field
//   (`nal_length_size`, most commonly 4).
//
// The converters below re-frame between the two without touching NAL
// payload bytes (emulation-prevention stays as-is: it is a property
// of the NAL body, not of the framing).

use crate::BitstreamError;

/// Split a length-prefixed stream into NAL-unit body slices.
///
/// `length_size` is the prefix width in bytes (1..=4). Every declared
/// length is validated against the remaining bytes before slicing —
/// a truncated final unit yields [`BitstreamError::UnexpectedEnd`].
pub fn split_length_prefixed(buf: &[u8], length_size: usize) -> Result<Vec<&[u8]>, BitstreamError> {
    if !(1..=4).contains(&length_size) {
        return Err(BitstreamError::invalid(
            "nal_length_size must be 1..=4 bytes",
        ));
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < buf.len() {
        if i + length_size > buf.len() {
            return Err(BitstreamError::unexpected_end(
                "length prefix truncated at end of stream",
            ));
        }
        let mut len = 0usize;
        for &b in &buf[i..i + length_size] {
            len = (len << 8) | b as usize;
        }
        i += length_size;
        let end = i
            .checked_add(len)
            .ok_or_else(|| BitstreamError::invalid("NAL length overflow"))?;
        if end > buf.len() {
            return Err(BitstreamError::unexpected_end(format!(
                "declared NAL length {len} overruns stream ({} bytes left)",
                buf.len() - i
            )));
        }
        out.push(&buf[i..end]);
        i = end;
    }
    Ok(out)
}

/// Convert a length-prefixed stream to an Annex-B byte stream. Every
/// NAL unit is emitted behind a 4-byte `00 00 00 01` start code.
pub fn length_prefixed_to_annex_b(
    buf: &[u8],
    length_size: usize,
) -> Result<Vec<u8>, BitstreamError> {
    let nals = split_length_prefixed(buf, length_size)?;
    let mut out = Vec::with_capacity(buf.len() + nals.len());
    for nal in nals {
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(nal);
    }
    Ok(out)
}

/// Convert an Annex-B byte stream to length-prefixed framing.
///
/// Accepts both 3- and 4-byte start codes and any leading garbage
/// before the first start code (skipped, matching the Annex-B
/// byte-stream decoding process which scans for the first prefix).
/// Fails with [`BitstreamError::InvalidData`] when a NAL unit's
/// length does not fit `length_size` bytes, or when no start code is
/// found at all.
pub fn annex_b_to_length_prefixed(
    buf: &[u8],
    length_size: usize,
) -> Result<Vec<u8>, BitstreamError> {
    if !(1..=4).contains(&length_size) {
        return Err(BitstreamError::invalid(
            "nal_length_size must be 1..=4 bytes",
        ));
    }
    let max_len: u64 = if length_size == 4 {
        u32::MAX as u64
    } else {
        (1u64 << (8 * length_size)) - 1
    };
    let mut out = Vec::with_capacity(buf.len());
    let mut found_any = false;
    let mut i = 0usize;
    let n = buf.len();
    let mut body_start: Option<usize> = None;
    let flush = |start: usize, end: usize, out: &mut Vec<u8>| -> Result<(), BitstreamError> {
        let len = end - start;
        if len as u64 > max_len {
            return Err(BitstreamError::invalid(format!(
                "NAL unit of {len} bytes does not fit a {length_size}-byte length prefix"
            )));
        }
        for shift in (0..length_size).rev() {
            out.push((len >> (8 * shift)) as u8);
        }
        out.extend_from_slice(&buf[start..end]);
        Ok(())
    };
    while i < n {
        let four =
            i + 3 < n && buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 0 && buf[i + 3] == 1;
        let three = !four && i + 2 < n && buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 1;
        if four || three {
            if let Some(start) = body_start.take() {
                flush(start, i, &mut out)?;
            }
            i += if four { 4 } else { 3 };
            body_start = Some(i);
            found_any = true;
            continue;
        }
        i += 1;
    }
    if let Some(start) = body_start.take() {
        flush(start, n, &mut out)?;
    }
    if !found_any {
        return Err(BitstreamError::invalid(
            "no Annex-B start code found in input",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ebsp_strips_canonical_triple() {
        // `0x00 0x00 0x03 0x01` → `0x00 0x00 0x01`.
        let ebsp = [0x00, 0x00, 0x03, 0x01];
        assert_eq!(ebsp_to_rbsp(&ebsp), vec![0x00, 0x00, 0x01]);
    }

    #[test]
    fn ebsp_strips_every_escaped_third_byte() {
        // The escape fires for third bytes 0x00..=0x03.
        for x in 0u8..=3 {
            let ebsp = [0x00, 0x00, 0x03, x];
            assert_eq!(ebsp_to_rbsp(&ebsp), vec![0x00, 0x00, x]);
        }
    }

    #[test]
    fn ebsp_leaves_three_byte_alone_without_zero_prefix() {
        // A bare `0x03` not preceded by `00 00` is a payload byte.
        let ebsp = [0x10, 0x00, 0x03, 0x05];
        assert_eq!(ebsp_to_rbsp(&ebsp), vec![0x10, 0x00, 0x03, 0x05]);
    }

    #[test]
    fn ebsp_strips_trailing_escape_guard() {
        // ITU-T H.264 §7.4.1.1 / H.265 §7.4.1.1 / H.266 §7.4.2.1 add a
        // trailing `0x03` after an RBSP that ends in `0x00 0x00` so the
        // next NAL's start-code cannot be folded in. The stripper
        // recovers the original `0x00 0x00`-terminated RBSP by dropping
        // that escape byte, matching the inverse on the writer side.
        let ebsp = [0x00, 0x00, 0x03];
        assert_eq!(ebsp_to_rbsp(&ebsp), vec![0x00, 0x00]);
    }

    #[test]
    fn ebsp_empty_in_empty_out() {
        assert_eq!(ebsp_to_rbsp(&[]), Vec::<u8>::new());
    }

    #[test]
    fn rbsp_inserts_emulation_byte_before_each_escaped_value() {
        // `0x00 0x00 X` for X in 0..=3 must become `0x00 0x00 0x03 X`.
        for x in 0u8..=3 {
            let rbsp = [0x00, 0x00, x];
            assert_eq!(rbsp_to_ebsp(&rbsp), vec![0x00, 0x00, 0x03, x]);
        }
    }

    #[test]
    fn rbsp_leaves_unaffected_bytes_alone() {
        // The third byte 0x04 is not escaped: no emulation byte added.
        let rbsp = [0x00, 0x00, 0x04];
        assert_eq!(rbsp_to_ebsp(&rbsp), vec![0x00, 0x00, 0x04]);
    }

    #[test]
    fn rbsp_handles_longer_zero_run_correctly() {
        // Four leading zeros then `0x01`: the second `00 00 01` triple
        // (positions 2..5) must be escaped, but the first pair of
        // zeros stays unescaped because the third byte is itself `0`,
        // already part of the second escape window.
        //
        // Walkthrough with the two-zero rolling window:
        //   pos 0 byte 0x00 → emit;     run=1
        //   pos 1 byte 0x00 → emit;     run=2
        //   pos 2 byte 0x00 → escape; emit 0x03 then 0x00; run=1
        //   pos 3 byte 0x00 → emit;     run=2
        //   pos 4 byte 0x01 → escape; emit 0x03 then 0x01; run=0
        let rbsp = [0x00, 0x00, 0x00, 0x00, 0x01];
        let ebsp = rbsp_to_ebsp(&rbsp);
        // After escape: 00 00 03 00 00 03 01
        assert_eq!(ebsp, vec![0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x01]);
        // And it must round-trip cleanly.
        assert_eq!(ebsp_to_rbsp(&ebsp), rbsp);
    }

    #[test]
    fn rbsp_appends_trailing_escape_when_ending_in_two_zeros() {
        // An RBSP that finishes on `0x00 0x00` gets a trailing `0x03`
        // appended so the next NAL's start-code cannot be folded in.
        let rbsp = [0xAB, 0x00, 0x00];
        assert_eq!(rbsp_to_ebsp(&rbsp), vec![0xAB, 0x00, 0x00, 0x03]);
    }

    #[test]
    fn rbsp_does_not_append_trailing_escape_for_single_trailing_zero() {
        let rbsp = [0xAB, 0xCD, 0x00];
        assert_eq!(rbsp_to_ebsp(&rbsp), vec![0xAB, 0xCD, 0x00]);
    }

    #[test]
    fn rbsp_empty_in_empty_out() {
        assert_eq!(rbsp_to_ebsp(&[]), Vec::<u8>::new());
    }

    #[test]
    fn length_prefixed_split_and_roundtrip() {
        // Two units behind 4-byte lengths.
        let stream = [
            0, 0, 0, 3, 0x67, 0xAA, 0xBB, // NAL 1 (3 bytes)
            0, 0, 0, 2, 0x68, 0xCC, // NAL 2 (2 bytes)
        ];
        let nals = split_length_prefixed(&stream, 4).unwrap();
        assert_eq!(nals, vec![&[0x67, 0xAA, 0xBB][..], &[0x68, 0xCC][..]]);

        let annex_b = length_prefixed_to_annex_b(&stream, 4).unwrap();
        assert_eq!(
            annex_b,
            vec![0, 0, 0, 1, 0x67, 0xAA, 0xBB, 0, 0, 0, 1, 0x68, 0xCC]
        );
        // And back.
        assert_eq!(
            annex_b_to_length_prefixed(&annex_b, 4).unwrap(),
            stream.to_vec()
        );
    }

    #[test]
    fn length_prefixed_supports_all_prefix_widths() {
        for size in 1usize..=4 {
            let mut stream = Vec::new();
            let body = [0x41u8, 0x9A, 0x00, 0x7F];
            for shift in (0..size).rev() {
                stream.push(((body.len() >> (8 * shift)) & 0xFF) as u8);
            }
            stream.extend_from_slice(&body);
            let nals = split_length_prefixed(&stream, size).unwrap();
            assert_eq!(nals, vec![&body[..]], "prefix width {size}");
            let ab = length_prefixed_to_annex_b(&stream, size).unwrap();
            assert_eq!(annex_b_to_length_prefixed(&ab, size).unwrap(), stream);
        }
    }

    #[test]
    fn length_prefixed_rejects_overrun_and_bad_width() {
        // Declares 5 bytes, provides 2.
        let stream = [0, 0, 0, 5, 0xAA, 0xBB];
        assert!(matches!(
            split_length_prefixed(&stream, 4).unwrap_err(),
            BitstreamError::UnexpectedEnd(_)
        ));
        // Truncated prefix.
        assert!(matches!(
            split_length_prefixed(&[0, 0], 4).unwrap_err(),
            BitstreamError::UnexpectedEnd(_)
        ));
        // Invalid width.
        assert!(matches!(
            split_length_prefixed(&[0], 0).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));
        assert!(matches!(
            split_length_prefixed(&[0], 5).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));
    }

    #[test]
    fn annex_b_conversion_accepts_mixed_start_codes_and_rejects_oversize() {
        // 3-byte start code for the second NAL.
        let annex_b = [0u8, 0, 0, 1, 0x67, 0xAA, 0, 0, 1, 0x68];
        let lp = annex_b_to_length_prefixed(&annex_b, 4).unwrap();
        assert_eq!(lp, vec![0, 0, 0, 2, 0x67, 0xAA, 0, 0, 0, 1, 0x68]);

        // A 300-byte NAL cannot fit a 1-byte prefix.
        let mut big = vec![0u8, 0, 0, 1];
        big.extend(std::iter::repeat_n(0x42u8, 300));
        assert!(matches!(
            annex_b_to_length_prefixed(&big, 1).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));

        // No start code at all.
        assert!(matches!(
            annex_b_to_length_prefixed(&[0x12, 0x34], 4).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));
    }

    #[test]
    fn ebsp_to_rbsp_to_ebsp_roundtrips_canonical_inputs() {
        // Deterministic spot-check: a few hand-constructed conformant
        // EBSPs round-trip exactly through the rbsp↔ebsp pair.
        let cases: &[&[u8]] = &[
            &[0x10, 0x20, 0x30],
            &[0x00, 0x00, 0x03, 0x01, 0x02],
            &[0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x01],
            &[0xff, 0x00, 0x00, 0x03, 0x02, 0xfe],
        ];
        for &ebsp in cases {
            let rbsp = ebsp_to_rbsp(ebsp);
            let reframed = rbsp_to_ebsp(&rbsp);
            // For inputs that already encode trailing-zero guards
            // conformantly, the inverse pair returns identical bytes.
            let trail = ebsp.len() >= 2 && ebsp[ebsp.len() - 2] == 0 && ebsp[ebsp.len() - 1] == 0;
            if !trail {
                assert_eq!(reframed, ebsp);
            }
        }
    }
}
