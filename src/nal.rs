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
