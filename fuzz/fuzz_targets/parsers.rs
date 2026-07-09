#![no_main]

//! Panic-hardening fuzz harness for the codec *header parsers*.
//!
//! The `reader` fuzz target hammers the foundational `BitReader` /
//! `BitWriter` primitives and the AV1 OBU / IVF walkers. This target
//! covers the layer above them: the per-codec `parse_*` entry points
//! that the HW-accel bridge crates call on attacker-controlled
//! bitstream bytes to populate GPU parameter buffers
//! (`VAPictureParameterBufferH264` and friends).
//!
//! Every one of these parsers takes a raw byte slice and must return
//! `Ok` / `Err(BitstreamError)` — never panic, overflow, slice out of
//! bounds, or loop unboundedly — on *any* input. A malformed NAL,
//! a truncated OBU-free header, an Exp-Golomb run with 32+ leading
//! zeros, a reserved field value, an empty buffer: all must be handled
//! gracefully so a hostile fixture cannot crash the host application.
//!
//! Surfaces exercised on every input (each at multiple byte offsets so
//! the parser sees a fresh alignment / framing each time):
//!
//! * H.264   — `parse_sps_nal`, `parse_pps_nal`, `parse_aud_nal`,
//!   `parse_idr_only`, and `parse_slice_header_minimal` driven with an
//!   SPS / PPS context recovered from a prefix of the same input.
//! * HEVC    — `parse_vps_nal`, `parse_sps_nal`, `parse_pps_nal`,
//!   `parse_aud_nal`, `parse_idr_only`, and the slice-header parser
//!   with a recovered SPS / PPS context.
//! * H.266   — `parse_nal_header`, `parse_vps`, `parse_sps`,
//!   `parse_pps`, `parse_picture_header`, `parse_aud`, and
//!   `parse_picture_header_with_sps` with a recovered SPS context.
//! * MPEG-2  — `parse_sequence_header`, `parse_sequence_extension`,
//!   `parse_picture_header`, `parse_picture_coding_extension`.
//! * VC-1    — `parse_sequence_header_advanced`, `parse_first_picture`,
//!   and the entry-point / picture-header parsers with a recovered
//!   sequence-header context.
//! * VP8     — `parse_frame_header`, `parse_keyframe`.
//! * VP9     — `parse_uncompressed_header`.
//!
//! No round-trip assertions live here — the entry points are one-way
//! parsers. The invariant under test is purely: *no panic on any
//! byte sequence*.

use libfuzzer_sys::fuzz_target;

use oxideav_bitstream::{av1, h264, h266, hevc, mpeg2, nal, vc1, vp8, vp9};

fuzz_target!(|data: &[u8]| {
    // Run every single-arg parser at a handful of byte offsets so a
    // parser that is robust at offset 0 but not at a shifted alignment
    // still gets caught. The offsets are cheap and keep coverage broad
    // without exploding the per-input cost.
    let offsets = pick_offsets(data);

    for &off in &offsets {
        let slice = &data[off..];
        drive_single_arg_parsers(slice);
    }

    // Context-dependent parsers: recover a real SPS / PPS / sequence
    // header from a prefix of the input, then feed the remainder to the
    // slice / picture / entry-point parser that needs that context.
    // This reaches code paths a context-free fuzz never can (the parser
    // branches on SPS-derived field widths).
    drive_h264_with_context(data);
    drive_hevc_with_context(data);
    drive_h266_with_context(data);
    drive_vc1_with_context(data);

    // Parse→write→parse fixed-point invariants: whenever a parse
    // succeeds, the writer must accept the parsed struct and the
    // re-parse must reproduce it exactly.
    drive_h264_writer_roundtrips(data);
    drive_av1_metadata_roundtrip(data);
    drive_framing_roundtrips(data);
});

/// Choose up to four offsets into `data` to re-run the context-free
/// parsers from. Always includes 0; the rest are derived from the input
/// so the fuzzer can steer them, clamped into range.
fn pick_offsets(data: &[u8]) -> Vec<usize> {
    let len = data.len();
    if len == 0 {
        return vec![0];
    }
    let mut offs = vec![0usize];
    // Derive a couple of extra offsets from the first bytes.
    let a = (data[0] as usize) % len;
    let b = (*data.last().unwrap() as usize) % len;
    let mid = len / 2;
    for o in [a, b, mid] {
        if !offs.contains(&o) {
            offs.push(o);
        }
    }
    offs
}

/// Drive every parser that takes only a byte slice. None may panic on
/// `slice`, including the empty slice.
fn drive_single_arg_parsers(slice: &[u8]) {
    // H.264 NAL-level parsers consume the RBSP / NAL body directly.
    let _ = h264::parse_sps(slice);
    let _ = h264::parse_sps_nal(slice);
    let _ = h264::parse_pps(slice);
    let _ = h264::parse_pps_nal(slice);
    let _ = h264::parse_aud_nal(slice);
    // Full Annex-B walker over arbitrary bytes.
    let _ = h264::parse_idr_only(slice);
    // SEI framing + typed decoders (SPS-independent families; the
    // SPS-coupled ones run in drive_h264_with_context).
    if let Ok(msgs) = h264::sei::parse_sei_rbsp(slice) {
        for m in &msgs {
            let _ = h264::sei::decode_sei_message(m, None);
        }
    }
    let _ = h264::sei::parse_sei_nal(slice);

    // AV1 metadata OBU payload parser.
    let _ = av1::parse_metadata_obu(slice);
    let _ = av1::parse_sequence_header(slice);

    // NAL framing converters at every legal prefix width.
    for size in 1..=4usize {
        let _ = nal::split_length_prefixed(slice, size);
        let _ = nal::length_prefixed_to_annex_b(slice, size);
        let _ = nal::annex_b_to_length_prefixed(slice, size);
    }

    // HEVC NAL-level parsers.
    let _ = hevc::parse_vps_nal(slice);
    let _ = hevc::parse_sps_nal(slice);
    let _ = hevc::parse_pps_nal(slice);
    let _ = hevc::parse_aud_nal(slice);
    let _ = hevc::parse_idr_only(slice);
    // HEVC SEI framing + typed decoders (all SPS-independent), plus
    // the framing writer fixed point.
    if let Ok(msgs) = hevc::sei::parse_sei_rbsp(slice) {
        for m in &msgs {
            let _ = hevc::sei::decode_sei_message(m);
        }
        if let Ok(rbsp) = hevc::sei::write_sei_rbsp(&msgs) {
            let re = hevc::sei::parse_sei_rbsp(&rbsp).expect("written HEVC SEI re-parses");
            assert_eq!(re, msgs, "HEVC SEI framing fixed point");
        }
    }
    let _ = hevc::sei::parse_sei_nal(slice);

    // H.266 parsers take the NAL body (2-byte header + payload).
    let _ = h266::parse_nal_header(slice);
    let _ = h266::parse_vps(slice);
    let _ = h266::parse_sps(slice);
    let _ = h266::parse_pps(slice);
    let _ = h266::parse_picture_header(slice);
    let _ = h266::parse_aud(slice);

    // MPEG-2 start-code-payload parsers.
    let _ = mpeg2::parse_sequence_header(slice);
    let _ = mpeg2::parse_sequence_extension(slice);
    let _ = mpeg2::parse_picture_header(slice);
    let _ = mpeg2::parse_picture_coding_extension(slice);

    // VC-1 sequence header + the Annex-B-ish first-picture walker.
    let _ = vc1::parse_sequence_header_advanced(slice);
    let _ = vc1::parse_first_picture(slice);

    // VP8 frame / keyframe header.
    let _ = vp8::parse_frame_header(slice);
    let _ = vp8::parse_keyframe(slice);

    // VP9 uncompressed header.
    let _ = vp9::parse_uncompressed_header(slice);
}

/// Split `data` into a prefix that feeds the SPS / PPS parsers and a
/// suffix that feeds `parse_slice_header_minimal`. The split point is
/// input-derived so the fuzzer can move it. The NAL unit type is also
/// pulled from the input so both the IDR and non-IDR slice paths are
/// reachable.
fn drive_h264_with_context(data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    let split = 1 + (data[0] as usize % data.len().max(1)).min(data.len() - 1);
    let (head, tail) = data.split_at(split.min(data.len()));
    let nal_unit_type = data[1] & 0x1f;

    // Try to parse an SPS and PPS from the head; only proceed to the
    // slice parser when both succeed — that is the only configuration
    // the slice parser is contracted to accept.
    if let (Ok(sps), Ok(pps)) = (h264::parse_sps(head), parse_h264_pps_from(head)) {
        let _ = h264::parse_slice_header_minimal(tail, nal_unit_type, &sps, &pps);
        // SPS-coupled SEI decoders (buffering_period / pic_timing read
        // u(v) fields whose widths come from the recovered SPS's HRD).
        if let Ok(msgs) = h264::sei::parse_sei_rbsp(tail) {
            for m in &msgs {
                let _ = h264::sei::decode_sei_message(m, Some(&sps));
            }
        }
    }
}

/// Parse an H.264 PPS from somewhere in `head`: try the front half as a
/// PPS RBSP so the recovered context is independent of the SPS bytes.
fn parse_h264_pps_from(head: &[u8]) -> Result<h264::H264Pps, oxideav_bitstream::BitstreamError> {
    let mid = head.len() / 2;
    h264::parse_pps(&head[mid..])
}

/// HEVC analogue of [`drive_h264_with_context`].
fn drive_hevc_with_context(data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    let split = 1 + (data[0] as usize % data.len().max(1)).min(data.len() - 1);
    let (head, tail) = data.split_at(split.min(data.len()));
    let mid = head.len() / 2;

    if let (Ok(sps), Ok(pps)) = (hevc::parse_sps_nal(head), hevc::parse_pps_nal(&head[mid..])) {
        let _ = hevc::parse_slice_header_minimal(tail, &sps, &pps);
    }
}

/// H.266 picture-header-with-SPS path: recover an SPS from a prefix and
/// feed the rest to `parse_picture_header_with_sps`.
fn drive_h266_with_context(data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    let split = 2 + (data[0] as usize % data.len().max(1)).min(data.len().saturating_sub(2));
    let (head, tail) = data.split_at(split.min(data.len()));

    if let Ok(sps) = h266::parse_sps(head) {
        let _ = h266::parse_picture_header_with_sps(tail, &sps);
    }
}

/// H.264 parse→write→parse fixed points: SPS, PPS (both context
/// modes) and SEI framing. A successful parse means the writer must
/// accept the struct and re-parsing the written bytes must reproduce
/// it exactly.
fn drive_h264_writer_roundtrips(data: &[u8]) {
    if let Ok(sps) = h264::parse_sps(data) {
        let rbsp = h264::write_sps(&sps).expect("writer accepts every parsed SPS");
        let re = h264::parse_sps(&rbsp).expect("written SPS re-parses");
        assert_eq!(re, sps, "SPS parse→write→parse fixed point");

        // PPS with the recovered SPS as context.
        let mid = data.len() / 2;
        if let Ok(pps) = h264::parse_pps_with_sps(&data[mid..], &sps) {
            let rbsp = h264::write_pps(&pps).expect("writer accepts every parsed PPS");
            let re = h264::parse_pps_with_sps(&rbsp, &sps).expect("written PPS re-parses");
            assert_eq!(re, pps, "PPS parse→write→parse fixed point");
        }
    }
    if let Ok(pps) = h264::parse_pps(data) {
        let rbsp = h264::write_pps(&pps).expect("writer accepts every parsed context-free PPS");
        let re = h264::parse_pps(&rbsp).expect("written PPS re-parses");
        assert_eq!(re, pps);
    }
    if let Ok(msgs) = h264::sei::parse_sei_rbsp(data) {
        if let Ok(rbsp) = h264::sei::write_sei_rbsp(&msgs) {
            let re = h264::sei::parse_sei_rbsp(&rbsp).expect("written SEI re-parses");
            assert_eq!(re, msgs, "SEI framing fixed point");
        }
    }
}

/// AV1 metadata parse→write→parse fixed point.
fn drive_av1_metadata_roundtrip(data: &[u8]) {
    if let Ok(meta) = av1::parse_metadata_obu(data) {
        // Parsed payloads never end in 0x00 (the parser strips the
        // trailing padding), so the writer must accept them.
        let payload = av1::write_metadata_obu(&meta).expect("writer accepts parsed metadata");
        let re = av1::parse_metadata_obu(&payload).expect("written metadata re-parses");
        assert_eq!(re, meta, "metadata parse→write→parse fixed point");
    }
}

/// Framing-converter invariants: a length-prefixed stream that splits
/// cleanly must re-frame to Annex-B and back byte-identically.
fn drive_framing_roundtrips(data: &[u8]) {
    for size in 1..=4usize {
        let Ok(bodies) = nal::split_length_prefixed(data, size) else {
            continue;
        };
        let ab = nal::length_prefixed_to_annex_b(data, size)
            .expect("splittable stream converts to Annex-B");
        // The byte-identical fixed point only holds when the framing
        // is unambiguous under Annex-B: every body non-empty (two
        // consecutive start codes collapse an empty unit) and no body
        // containing a raw start-code pattern (real NAL bodies carry
        // emulation prevention; arbitrary fuzz bytes need not).
        let clean = !ab.is_empty()
            && bodies.iter().all(|n| {
                !n.is_empty() && !n.windows(3).any(|w| w[0] == 0 && w[1] == 0 && w[2] == 1)
            });
        if clean {
            let lp =
                nal::annex_b_to_length_prefixed(&ab, size).expect("converted stream converts back");
            assert_eq!(lp, data, "length-prefixed→Annex-B→length-prefixed");
        }
    }
}

/// VC-1 entry-point + picture parsers both need a sequence-header
/// context; recover one from a prefix, then drive both with the suffix.
fn drive_vc1_with_context(data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    let split = 1 + (data[0] as usize % data.len().max(1)).min(data.len() - 1);
    let (head, tail) = data.split_at(split.min(data.len()));

    if let Ok(seq) = vc1::parse_sequence_header_advanced(head) {
        let _ = vc1::parse_entry_point_header(tail, &seq);
        let _ = vc1::parse_picture_header(tail, &seq);
    }
}
