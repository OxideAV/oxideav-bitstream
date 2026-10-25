//! VP9 full-stream headers: every frame type (key, inter, intra-only,
//! show_existing_frame, hidden alt-refs in superframes, resized and
//! scaled-reference inter frames) checked against
//! `ffmpeg -bsf:v trace_headers`, and the state in force (loop filter
//! deltas, segmentation features, frame sizes, quantizer index) against
//! the instrumented decode traces staged in `docs/video/vp9/fixtures/`.
//!
//! `*.frames`: one line per frame, syntax elements as `trace_headers`
//! names them, then `bytes=` (uncompressed header incl. trailing bits).
//! `*.state`: the FRAME / LOOPFILTER / SEGMENT / SEGMENT_FEAT records of
//! the fixture's `trace.txt`.

use std::collections::HashMap;

use oxideav_bitstream::ivf;
use oxideav_bitstream::vp9::frame::{
    SEG_LVL_ALT_L, SEG_LVL_ALT_Q, SEG_LVL_REF_FRAME, SEG_LVL_SKIP, Vp9FrameHeader, Vp9FrameType,
    Vp9State, split_superframe,
};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/vp9/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn kv(line: &str) -> HashMap<String, String> {
    line.split_whitespace()
        .filter_map(|t| t.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Our view of a header, under `trace_headers` names.
fn ours(h: &Vp9FrameHeader) -> Vec<(String, i64)> {
    let mut v: Vec<(String, i64)> = Vec::new();
    let mut p = |k: &str, x: i64| v.push((k.to_string(), x));
    p("show_existing_frame", h.show_existing_frame.into());
    p("bytes", h.uncompressed_header_size as i64);
    if h.show_existing_frame {
        p("frame_to_show_map_idx", h.frame_to_show_map_idx.into());
        return v;
    }
    p("frame_type", (h.frame_type == Vp9FrameType::NonKey).into());
    p("show_frame", h.show_frame.into());
    p("error_resilient_mode", h.error_resilient_mode.into());
    if h.frame_type == Vp9FrameType::NonKey {
        if !h.show_frame {
            p("intra_only", h.intra_only.into());
        }
        if !h.error_resilient_mode {
            p("reset_frame_context", h.reset_frame_context.into());
        }
        p("refresh_frame_flags", h.refresh_frame_flags.into());
    }
    if h.is_intra() || h.found_ref.is_none() {
        p("frame_width_minus_1", i64::from(h.frame_width) - 1);
        p("frame_height_minus_1", i64::from(h.frame_height) - 1);
    }
    if !h.is_intra() {
        for i in 0..3 {
            p(&format!("ref_frame_idx[{i}]"), h.ref_frame_idx[i].into());
            p(
                &format!("ref_frame_sign_bias[{}]", i + 1),
                h.coded_ref_frame_sign_bias[i].into(),
            );
        }
        p("allow_high_precision_mv", h.allow_high_precision_mv.into());
    }
    p(
        "render_and_frame_size_different",
        h.render_and_frame_size_different.into(),
    );
    if !h.error_resilient_mode {
        p("refresh_frame_context", h.refresh_frame_context.into());
        p(
            "frame_parallel_decoding_mode",
            h.frame_parallel_decoding_mode.into(),
        );
    }
    p("frame_context_idx", h.coded_frame_context_idx.into());
    let lf = &h.loop_filter;
    p("loop_filter_level", lf.level.into());
    p("loop_filter_sharpness", lf.sharpness.into());
    p("loop_filter_delta_enabled", lf.delta_enabled.into());
    if lf.delta_enabled {
        p("loop_filter_delta_update", lf.delta_update.into());
        if lf.delta_update {
            for i in 0..4 {
                p(
                    &format!("update_ref_delta[{i}]"),
                    lf.coded_ref_deltas[i].is_some().into(),
                );
                if let Some(d) = lf.coded_ref_deltas[i] {
                    p(&format!("loop_filter_ref_deltas[{i}]"), d.into());
                }
            }
            for i in 0..2 {
                p(
                    &format!("update_mode_delta[{i}]"),
                    lf.coded_mode_deltas[i].is_some().into(),
                );
                if let Some(d) = lf.coded_mode_deltas[i] {
                    p(&format!("loop_filter_mode_deltas[{i}]"), d.into());
                }
            }
        }
    }
    p("base_q_idx", h.quantization.base_q_idx.into());
    p("segmentation_enabled", h.segmentation.enabled.into());
    let s = &h.segmentation;
    if s.enabled {
        p("segmentation_update_map", s.update_map.into());
        if s.update_map {
            p("segmentation_temporal_update", s.temporal_update.into());
        }
        p("segmentation_update_data", s.update_data.into());
        if s.update_data {
            p(
                "segmentation_abs_or_delta_update",
                s.abs_or_delta_update.into(),
            );
            for i in 0..8 {
                for j in 0..4 {
                    p(
                        &format!("feature_enabled[{i}][{j}]"),
                        s.feature_enabled[i][j].into(),
                    );
                }
            }
        }
    }
    p("tile_cols_log2", h.tile_info.tile_cols_log2.into());
    p("tile_rows_log2", h.tile_info.tile_rows_log2.into());
    p("header_size_in_bytes", h.header_size_in_bytes.into());
    v
}

fn headers(name: &str) -> Vec<Vp9FrameHeader> {
    let data = fixture(&format!("{name}.ivf"));
    let (_, frames) = ivf::parse_all(&data).unwrap();
    let mut st = Vp9State::new();
    let mut out = Vec::new();
    for f in frames {
        for frame in split_superframe(f.payload) {
            out.push(
                st.decode_frame_header(frame)
                    .unwrap_or_else(|e| panic!("{name}: {e}")),
            );
        }
    }
    out
}

fn check(name: &str) -> Vec<Vp9FrameHeader> {
    let hs = headers(name);
    let golden = String::from_utf8(fixture(&format!("{name}.frames"))).unwrap();
    let golden: Vec<&str> = golden.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(hs.len(), golden.len(), "{name}: frame count");
    for (i, (h, g)) in hs.iter().zip(&golden).enumerate() {
        let g = kv(g);
        let mine = ours(h);
        for (k, v) in &mine {
            let theirs = g
                .get(k)
                .unwrap_or_else(|| panic!("{name} frame {i}: {k} missing from trace"));
            assert_eq!(theirs, &v.to_string(), "{name} frame {i}: {k}");
        }
        assert!(
            h.show_existing_frame || mine.len() >= 12,
            "{name} frame {i}: too few checked fields"
        );
    }
    hs
}

/// Compare the in-force state against the instrumented decode trace.
fn check_state(name: &str, hs: &[Vp9FrameHeader]) {
    let text = String::from_utf8(fixture(&format!("{name}.state"))).unwrap();
    let mut frame_idx = None;
    let mut checked = 0;
    for line in text.lines() {
        let tag = line.split('\t').next().unwrap();
        let m = kv(&line.replace('\t', " "));
        let idx: usize = m["idx"].parse().unwrap();
        let h = &hs[idx];
        match tag {
            "FRAME" => {
                frame_idx = Some(idx);
                assert_eq!(
                    m["show_existing_frame"],
                    u8::from(h.show_existing_frame).to_string()
                );
                if h.show_existing_frame {
                    assert_eq!(m["ref_idx"], h.frame_to_show_map_idx.to_string());
                    continue;
                }
                assert_eq!(m["w"], h.frame_width.to_string(), "{name} {idx} width");
                assert_eq!(m["h"], h.frame_height.to_string(), "{name} {idx} height");
                assert_eq!(m["bpp"], h.color.bit_depth.to_string());
                assert_eq!(
                    m["keyframe"],
                    u8::from(h.frame_type == Vp9FrameType::Key).to_string()
                );
                assert_eq!(m["intraonly"], u8::from(h.intra_only).to_string());
                assert_eq!(m["yac_qi"], h.quantization.base_q_idx.to_string());
                assert_eq!(m["lossless"], u8::from(h.quantization.lossless).to_string());
                assert_eq!(
                    m["refresh_mask"],
                    format!("0x{:02x}", h.refresh_frame_flags),
                    "{name} {idx}"
                );
                assert_eq!(
                    m["uncompressed_hdr_size"],
                    h.uncompressed_header_size.to_string()
                );
                assert_eq!(m["compressed_hdr_size"], h.header_size_in_bytes.to_string());
                checked += 1;
            }
            "LOOPFILTER" => {
                assert_eq!(frame_idx, Some(idx));
                let lf = &h.loop_filter;
                assert_eq!(m["level"], lf.level.to_string());
                assert_eq!(m["sharpness"], lf.sharpness.to_string());
                let fmt = |d: &[i8]| {
                    format!(
                        "[{}]",
                        d.iter().map(i8::to_string).collect::<Vec<_>>().join(",")
                    )
                };
                assert_eq!(
                    m["ref_delta"],
                    fmt(&lf.ref_deltas),
                    "{name} {idx} ref deltas in force"
                );
                assert_eq!(m["mode_delta"], fmt(&lf.mode_deltas), "{name} {idx}");
            }
            "SEGMENT" => {
                let s = &h.segmentation;
                assert_eq!(
                    m["enabled"],
                    u8::from(s.enabled).to_string(),
                    "{name} {idx}"
                );
                if s.enabled {
                    assert_eq!(m["update_map"], u8::from(s.update_map).to_string());
                    assert_eq!(m["absolute"], u8::from(s.abs_or_delta_update).to_string());
                }
            }
            "SEGMENT_FEAT" => {
                let s = &h.segmentation;
                let seg: usize = m["seg"].parse().unwrap();
                let pairs = [
                    ("q_en", "q", SEG_LVL_ALT_Q),
                    ("lf_en", "lf", SEG_LVL_ALT_L),
                    ("ref_en", "ref", SEG_LVL_REF_FRAME),
                ];
                for (en, val, f) in pairs {
                    assert_eq!(
                        m[en],
                        u8::from(s.feature_enabled[seg][f]).to_string(),
                        "{name} {idx}"
                    );
                    assert_eq!(
                        m[val],
                        s.feature_data[seg][f].to_string(),
                        "{name} {idx} seg {seg}"
                    );
                }
                assert_eq!(
                    m["skip"],
                    u8::from(s.feature_enabled[seg][SEG_LVL_SKIP]).to_string()
                );
            }
            _ => {}
        }
    }
    assert!(checked > 0);
}

#[test]
fn key_inter_and_hidden_frames() {
    check("altref_pyramid_gop");
    let hs = check("superframe_2");
    check_state("superframe_2", &hs);
    assert!(hs.iter().any(|h| !h.show_frame), "hidden alt-ref frames");
}

#[test]
fn show_existing_frame_reports_the_slot() {
    let hs = check("show_existing_frame");
    check_state("show_existing_frame", &hs);
    let shown = hs
        .iter()
        .find(|h| h.show_existing_frame)
        .expect("a show_existing_frame");
    assert_eq!((shown.frame_width, shown.frame_height), (64, 64));
}

#[test]
fn intra_only_frames() {
    for name in ["intra_only", "intra_only_emitted_gop"] {
        let hs = check(name);
        let io = hs
            .iter()
            .find(|h| h.intra_only)
            .unwrap_or_else(|| panic!("{name}"));
        assert!(io.is_intra());
        assert_ne!(io.refresh_frame_flags, 0xFF);
    }
}

#[test]
fn resized_and_scaled_references() {
    for name in ["scaled_reference", "resized_encoded_gop"] {
        let hs = check(name);
        let sizes: std::collections::BTreeSet<(u32, u32)> =
            hs.iter().map(|h| (h.frame_width, h.frame_height)).collect();
        assert!(sizes.len() > 1, "{name}: frame size changes mid-stream");
    }
}

#[test]
fn segmentation_and_loop_filter_persistence() {
    check("seg_features_skip_ref_altl");
    check("temporal_seg_predicted");
    check("lossy_lf_deltas_gop");
    let hs = check("segments_aq_mode");
    check_state("segments_aq_mode", &hs);
    let hs = check("frame_parallel_mode");
    check_state("frame_parallel_mode", &hs);
}

#[test]
fn profiles_and_lossless() {
    let hs = check("profile_2_yuv420_10bit");
    assert_eq!(hs[0].color.bit_depth, 10);
    let hs = check("profile_1_yuv444_8bit");
    assert!(!hs[0].color.subsampling_x);
    let hs = check("lossless_inter");
    assert!(hs.iter().all(|h| h.quantization.lossless));
}

#[test]
fn quantizers_follow_8_6_1() {
    let hs = headers("segments_aq_mode");
    let h = &hs[0];
    // base_q_idx 33, segment 0 has ALT_Q −24 (delta mode): qindex 9.
    assert_eq!(h.qindex(0), 9);
    assert_eq!(h.qindex(3), 33);
    // dc_qlookup[0][9] = 14, ac_qlookup[0][9] = 16; [33]: 35 / 40.
    assert_eq!(h.dc_quant(0, 0), 14);
    assert_eq!(h.ac_quant(0, 0), 16);
    assert_eq!(h.dc_quant(0, 3), 35);
    assert_eq!(h.ac_quant(1, 3), 40);
    // §8.8.1 with deltas [1, 0, −1, −1] at level 8 (shift 0).
    let lvl = h.loop_filter_levels();
    assert_eq!(lvl[0][0][0], 9);
    assert_eq!(lvl[0][1], [8, 8]);
    assert_eq!(lvl[0][2], [7, 7]);
}
