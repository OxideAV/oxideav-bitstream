#![no_main]

//! Panic-hardening fuzz harness for the per-codec parser entry points.
//!
//! `oxideav-bitstream` exposes a parser surface per codec (H.264 / HEVC
//! / H.266 / AV1 / MPEG-2 / VC-1 / VP8 / VP9 / IVF). Every one of those
//! parsers consumes attacker bytes — Annex-B NAL bodies, OBU payloads,
//! MPEG-2 start-code payloads, IVF container chunks — and must not
//! panic, overflow, or index out of bounds on any input the network or
//! the muxer could deliver.
//!
//! The `reader` fuzz target already covers the foundational primitives
//! (`BitReader`, `BitWriter`, `read_leb128`, `read_obu`,
//! `parse_obu_stream`). This target widens coverage to the **per-codec
//! parsers** that compose those primitives — every entry point exposed
//! on `h264::`, `hevc::`, `h266::`, `mpeg2::`, `vc1::`, `vp8::`,
//! `vp9::`, `ivf::` and `av1::parse_sequence_header` /
//! `av1::parse_frame_header`.
//!
//! Each call site is wrapped in the standard "input → maybe-Ok,
//! maybe-Err, never panic" contract.

use libfuzzer_sys::fuzz_target;
use oxideav_bitstream::{av1, h264, h266, hevc, ivf, mpeg2, vc1, vp8, vp9};

fuzz_target!(|data: &[u8]| {
    drive_h264(data);
    drive_hevc(data);
    drive_h266(data);
    drive_mpeg2(data);
    drive_vc1(data);
    drive_vp8(data);
    drive_vp9(data);
    drive_av1(data);
    drive_ivf(data);
});

// ─────────────────────────── H.264 ─────────────────────────────────────────

fn drive_h264(data: &[u8]) {
    // Annex-B walking + EBSP→RBSP unescape on arbitrary bytes.
    let nals = h264::split_annex_b(data);
    let _ = h264::ebsp_to_rbsp(data);
    if let Some(&b) = data.first() {
        let _ = h264::nal_header(b);
    }
    // Every NAL body the walker returned: drive every per-NAL parser
    // entry point. The walker can never produce more NAL bodies than
    // the input has bytes, but we still cap the iteration to bound
    // worst-case fuzz throughput on pathological all-start-code input.
    for nal in nals.iter().take(32) {
        let _ = h264::parse_sps_nal(nal);
        let _ = h264::parse_pps_nal(nal);
    }
    // RBSP-direct parser variants over raw bytes.
    let _ = h264::parse_sps(data);
    let _ = h264::parse_pps(data);
    // parse_slice_header_minimal needs a decoded SPS + PPS. Feed it
    // the (possibly default / synthesised) values from the parsers
    // above when they succeed — but only on small inputs to keep
    // throughput up.
    if data.len() < 4096 {
        if let (Ok(sps), Ok(pps)) = (h264::parse_sps(data), h264::parse_pps(data)) {
            // nal_unit_type derived from the input so coverage spans
            // both the IDR and non-IDR slice-header branches.
            let nal_type = data.first().copied().unwrap_or(0) & 0x1F;
            let _ = h264::parse_slice_header_minimal(data, nal_type, &sps, &pps);
        }
    }
    // End-to-end IDR-only walker.
    let _ = h264::parse_idr_only(data);
}

// ─────────────────────────── HEVC ──────────────────────────────────────────

fn drive_hevc(data: &[u8]) {
    let nals = hevc::split_annex_b(data);
    let _ = hevc::ebsp_to_rbsp(data);
    if data.len() >= 2 {
        let _ = hevc::nal_header(data[0], data[1]);
        let _ = hevc::is_irap(data[0]);
    }
    for nal in nals.iter().take(32) {
        let _ = hevc::parse_vps_nal(nal);
        let _ = hevc::parse_sps_nal(nal);
        let _ = hevc::parse_pps_nal(nal);
    }
    // parse_slice_header_minimal takes a NAL + decoded SPS + PPS.
    if data.len() < 4096 {
        if let (Ok(sps), Ok(pps)) = (hevc::parse_sps_nal(data), hevc::parse_pps_nal(data)) {
            let _ = hevc::parse_slice_header_minimal(data, &sps, &pps);
        }
    }
    let _ = hevc::parse_idr_only(data);
}

// ─────────────────────────── H.266 (VVC) ──────────────────────────────────

fn drive_h266(data: &[u8]) {
    let nals = h266::split_annex_b(data);
    let _ = h266::ebsp_to_rbsp(data);
    let _ = h266::parse_nal_header(data);
    if let Some(&b) = data.first() {
        let _ = h266::is_vcl(b);
        let _ = h266::is_irap(b);
        let _ = h266::is_parameter_set(b);
    }
    for nal in nals.iter().take(32) {
        let _ = h266::parse_vps(nal);
        let _ = h266::parse_sps(nal);
        let _ = h266::parse_pps(nal);
    }
    // Direct parse over raw bytes covers the "called with non-Annex-B
    // input" failure paths too.
    let _ = h266::parse_vps(data);
    let _ = h266::parse_sps(data);
    let _ = h266::parse_pps(data);
}

// ─────────────────────────── MPEG-2 ────────────────────────────────────────

fn drive_mpeg2(data: &[u8]) {
    let _ = mpeg2::find_start_codes(data);
    let _ = mpeg2::find_first_slice(data);
    let _ = mpeg2::parse_sequence_header(data);
    let _ = mpeg2::parse_picture_header(data);
    let _ = mpeg2::parse_picture_coding_extension(data);
    let _ = mpeg2::parse_sequence_extension(data);
    // Slice fixture starts at variable offsets — exercise a handful so
    // the parsers see "non-zero starting offset" inputs too.
    for off in [1, 2, 4, 8, 16, 32].iter().copied() {
        if off < data.len() {
            let suffix = &data[off..];
            let _ = mpeg2::parse_sequence_header(suffix);
            let _ = mpeg2::parse_picture_header(suffix);
            let _ = mpeg2::parse_picture_coding_extension(suffix);
            let _ = mpeg2::parse_sequence_extension(suffix);
        }
    }
}

// ─────────────────────────── VC-1 ──────────────────────────────────────────

fn drive_vc1(data: &[u8]) {
    let bdus = vc1::split_bdus(data);
    let seq_result = vc1::parse_sequence_header_advanced(data);
    // parse_entry_point_header and parse_picture_header consume both a
    // payload + a decoded sequence header (for HRD-dependent skipping
    // and FCM gating). Provide one from the input when available; on
    // failure, skip — there is no spec-defined "default" Vc1
    // sequence header to fall back to without consulting external
    // material.
    if let Ok(seq) = &seq_result {
        let _ = vc1::parse_entry_point_header(data, seq);
        let _ = vc1::parse_picture_header(data, seq);
        // Also feed every BDU body through both downstream parsers so
        // the typical "BDU walker → per-BDU parse" path is fuzzed.
        for b in bdus.iter().take(16) {
            let _ = vc1::parse_entry_point_header(b.payload, seq);
            let _ = vc1::parse_picture_header(b.payload, seq);
        }
    }
    let _ = vc1::parse_first_picture(data);
}

// ─────────────────────────── VP8 ───────────────────────────────────────────

fn drive_vp8(data: &[u8]) {
    let _ = vp8::parse_frame_header(data);
    let _ = vp8::parse_keyframe(data);
}

// ─────────────────────────── VP9 ───────────────────────────────────────────

fn drive_vp9(data: &[u8]) {
    let _ = vp9::parse_uncompressed_header(data);
}

// ─────────────────────────── AV1 ───────────────────────────────────────────

fn drive_av1(data: &[u8]) {
    let _ = av1::parse_sequence_header(data);
    // parse_frame_header needs a decoded sequence header — feed it the
    // one we just parsed when it succeeded.
    if let Ok(seq) = av1::parse_sequence_header(data) {
        let _ = av1::parse_frame_header(data, &seq);
    }
    // parse_obu_stream is also covered by the `reader` target; calling
    // it here too keeps the per-codec coverage self-contained.
    let _ = av1::parse_obu_stream(data);
}

// ─────────────────────────── IVF ───────────────────────────────────────────

fn drive_ivf(data: &[u8]) {
    let _ = ivf::parse_header(data);
    // parse_frame is iterative — drive it across a few hops to also
    // exercise the "advance past frame N" path.
    let mut cursor = data;
    for _ in 0..16 {
        match ivf::parse_frame(cursor) {
            Ok(Some((_, rest))) => cursor = rest,
            _ => break,
        }
    }
    let _ = ivf::parse_all(data);
}
