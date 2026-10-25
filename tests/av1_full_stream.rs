//! AV1 full-stream frame headers: every frame type (key, inter,
//! intra-only, switch, show_existing_frame) through `Av1RefState`,
//! checked field by field against `ffmpeg -bsf:v trace_headers` over
//! streams with short reference signaling, error resilience, frame
//! ids, global motion, film grain, superres, tiles, segmentation,
//! delta q / lf, loop restoration, CDEF, skip mode, temporal and
//! spatial layers, high bit depth, monochrome and 4:4:4.
//!
//! `*.frames`: one line per frame header, syntax elements as
//! `trace_headers` names them, then `end=` (bit after the last header
//! element, counted from the start of the OBU).

use std::collections::HashMap;

use oxideav_bitstream::av1::frame::{
    Av1Frame, Av1FrameType, Av1InterpolationFilter, Av1RefState, Av1WarpModel, parse_tile_group,
};
use oxideav_bitstream::av1::sequence::{SELECT, SequenceHeader, parse_sequence_header_obu};
use oxideav_bitstream::av1::{
    OBU_FRAME, OBU_FRAME_HEADER, OBU_SEQUENCE_HEADER, OBU_TILE_GROUP, read_obu,
};
use oxideav_bitstream::ivf;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/av1/{name}",
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

/// Our header under `trace_headers` names (the elements actually coded).
fn ours(
    seq: &SequenceHeader,
    h: &Av1Frame,
    state: &Av1RefState,
    obu_header_bits: usize,
) -> Vec<(String, i64)> {
    let mut v: Vec<(String, i64)> = Vec::new();
    let mut p = |k: &str, x: i64| v.push((k.to_string(), x));
    p("end", (obu_header_bits + h.header_bits) as i64);
    if seq.reduced_still_picture_header {
        return v;
    }
    p("show_existing_frame", h.show_existing_frame.into());
    if h.show_existing_frame {
        p("frame_to_show_map_idx", h.frame_to_show_map_idx.into());
        return v;
    }
    p("frame_type", h.frame_type.code().into());
    p("show_frame", h.show_frame.into());
    if !h.show_frame {
        p("showable_frame", h.showable_frame.into());
    }
    if !(h.frame_type == Av1FrameType::Switch || h.frame_type == Av1FrameType::Key && h.show_frame)
    {
        p("error_resilient_mode", h.error_resilient_mode.into());
    }
    p("disable_cdf_update", h.disable_cdf_update.into());
    if seq.seq_force_screen_content_tools == SELECT {
        p(
            "allow_screen_content_tools",
            h.allow_screen_content_tools.into(),
        );
    }
    if h.allow_screen_content_tools && seq.seq_force_integer_mv == SELECT && !h.frame_is_intra {
        p("force_integer_mv", h.force_integer_mv.into());
    }
    if seq.frame_id_numbers_present_flag {
        p("current_frame_id", h.current_frame_id.into());
    }
    if h.frame_type != Av1FrameType::Switch {
        p(
            "frame_size_override_flag",
            h.frame_size_override_flag.into(),
        );
    }
    if seq.order_hint_bits > 0 {
        p("order_hint", h.order_hint.into());
    }
    if !(h.frame_is_intra || h.error_resilient_mode) {
        p("primary_ref_frame", h.primary_ref_frame.into());
    }
    if !(h.frame_type == Av1FrameType::Switch || h.frame_type == Av1FrameType::Key && h.show_frame)
    {
        p("refresh_frame_flags", h.refresh_frame_flags.into());
    }
    if let Some(hints) = h.ref_order_hint {
        for (i, x) in hints.iter().enumerate() {
            p(&format!("ref_order_hint[{i}]"), (*x).into());
        }
    }
    if !h.frame_is_intra {
        if seq.enable_order_hint {
            p(
                "frame_refs_short_signaling",
                h.frame_refs_short_signaling.into(),
            );
        }
        if h.frame_refs_short_signaling {
            p("last_frame_idx", h.last_frame_idx.into());
            p("golden_frame_idx", h.gold_frame_idx.into());
        } else {
            for i in 0..7 {
                p(&format!("ref_frame_idx[{i}]"), h.ref_frame_idx[i].into());
            }
        }
        if seq.frame_id_numbers_present_flag {
            for i in 0..7 {
                p(
                    &format!("delta_frame_id_minus1[{i}]"),
                    h.delta_frame_id_minus_1[i].into(),
                );
            }
        }
        if let Some(i) = h.size.found_ref {
            p(&format!("found_ref[{i}]"), 1);
        }
    }
    if h.frame_size_override_flag && h.size.found_ref.is_none() {
        p("frame_width_minus_1", i64::from(h.size.upscaled_width) - 1);
        p("frame_height_minus_1", i64::from(h.size.frame_height) - 1);
    }
    if seq.enable_superres {
        p("use_superres", h.size.use_superres.into());
        if h.size.use_superres {
            p("coded_denom", i64::from(h.size.superres_denom) - 9);
        }
    }
    if h.size.found_ref.is_none() {
        p(
            "render_and_frame_size_different",
            h.size.render_and_frame_size_different.into(),
        );
        if h.size.render_and_frame_size_different {
            p("render_width_minus_1", i64::from(h.size.render_width) - 1);
            p("render_height_minus_1", i64::from(h.size.render_height) - 1);
        }
    }
    if h.frame_is_intra
        && h.allow_screen_content_tools
        && h.size.upscaled_width == h.size.frame_width
    {
        p("allow_intrabc", h.allow_intrabc.into());
    }
    if !h.frame_is_intra {
        if !h.force_integer_mv {
            p("allow_high_precision_mv", h.allow_high_precision_mv.into());
        }
        let sw = h.interpolation_filter == Av1InterpolationFilter::Switchable;
        p("is_filter_switchable", sw.into());
        if !sw {
            p("interpolation_filter", h.interpolation_filter.code().into());
        }
        p(
            "is_motion_mode_switchable",
            h.is_motion_mode_switchable.into(),
        );
        if !(h.error_resilient_mode || !seq.enable_ref_frame_mvs) {
            p("use_ref_frame_mvs", h.use_ref_frame_mvs.into());
        }
    }
    if !(seq.reduced_still_picture_header || h.disable_cdf_update) {
        p(
            "disable_frame_end_update_cdf",
            h.disable_frame_end_update_cdf.into(),
        );
    }
    let t = &h.tile_info;
    p(
        "uniform_tile_spacing_flag",
        t.uniform_tile_spacing_flag.into(),
    );
    if t.uniform_tile_spacing_flag {
        p("tile_cols_log2", t.tile_cols_log2.into());
        p("tile_rows_log2", t.tile_rows_log2.into());
    } else {
        let sb = Av1Frame::sb_shift(seq);
        for (i, w) in t.col_widths_sb(sb).iter().enumerate() {
            p(&format!("width_in_sbs_minus_1[{i}]"), i64::from(*w) - 1);
        }
        for (i, w) in t.row_heights_sb(sb).iter().enumerate() {
            p(&format!("height_in_sbs_minus_1[{i}]"), i64::from(*w) - 1);
        }
    }
    if t.tile_cols_log2 > 0 || t.tile_rows_log2 > 0 {
        p("context_update_tile_id", t.context_update_tile_id.into());
        p("tile_size_bytes_minus1", i64::from(t.tile_size_bytes) - 1);
    }
    let q = &h.quantization;
    p("base_q_idx", q.base_q_idx.into());
    p("delta_q_y_dc.delta_coded", (q.delta_q_y_dc != 0).into());
    p("using_qmatrix", q.using_qmatrix.into());
    if q.using_qmatrix {
        p("qm_y", q.qm_y.into());
        p("qm_u", q.qm_u.into());
    }
    let s = &h.segmentation;
    p("segmentation_enabled", s.enabled.into());
    if s.enabled && h.primary_ref_frame != 7 {
        p("segmentation_update_map", s.update_map.into());
        if s.update_map {
            p("segmentation_temporal_update", s.temporal_update.into());
        }
        p("segmentation_update_data", s.update_data.into());
    }
    if s.enabled && s.update_data {
        for i in 0..8 {
            for j in 0..8 {
                p(
                    &format!("feature_enabled[{i}][{j}]"),
                    s.feature_enabled[i][j].into(),
                );
            }
        }
    }
    if q.base_q_idx > 0 {
        p("delta_q_present", h.delta.delta_q_present.into());
    }
    if h.delta.delta_q_present {
        p("delta_q_res", h.delta.delta_q_res.into());
        if !h.allow_intrabc {
            p("delta_lf_present", h.delta.delta_lf_present.into());
        }
    }
    if !(h.coded_lossless || h.allow_intrabc) {
        let lf = &h.loop_filter;
        p("loop_filter_level[0]", lf.level[0].into());
        p("loop_filter_level[1]", lf.level[1].into());
        if seq.num_planes() > 1 && (lf.level[0] != 0 || lf.level[1] != 0) {
            p("loop_filter_level[2]", lf.level[2].into());
            p("loop_filter_level[3]", lf.level[3].into());
        }
        p("loop_filter_sharpness", lf.sharpness.into());
        p("loop_filter_delta_enabled", lf.delta_enabled.into());
        if lf.delta_enabled {
            p("loop_filter_delta_update", lf.delta_update.into());
        }
    }
    if !(h.coded_lossless || h.allow_intrabc || !seq.enable_cdef) {
        let c = &h.cdef;
        p("cdef_damping_minus_3", i64::from(c.damping) - 3);
        p("cdef_bits", c.bits.into());
        let coded = |x: u8| if x == 4 { 3 } else { x };
        for i in 0..(1usize << c.bits) {
            p(
                &format!("cdef_y_pri_strength[{i}]"),
                c.y_pri_strength[i].into(),
            );
            p(
                &format!("cdef_y_sec_strength[{i}]"),
                coded(c.y_sec_strength[i]).into(),
            );
            if seq.num_planes() > 1 {
                p(
                    &format!("cdef_uv_pri_strength[{i}]"),
                    c.uv_pri_strength[i].into(),
                );
                p(
                    &format!("cdef_uv_sec_strength[{i}]"),
                    coded(c.uv_sec_strength[i]).into(),
                );
            }
        }
    }
    if !(h.all_lossless || h.allow_intrabc || !seq.enable_restoration) {
        let remap = |t: u8| match t {
            0 => 0,
            3 => 1,
            1 => 2,
            _ => 3,
        };
        for i in 0..seq.num_planes() {
            p(
                &format!("lr_type[{i}]"),
                remap(h.lr.frame_restoration_type[i].code()).into(),
            );
        }
    }
    if !h.coded_lossless {
        let tx = match h.tx_mode {
            oxideav_bitstream::av1::frame::Av1TxMode::Select => 2,
            _ => 1,
        };
        p("tx_mode", tx);
    }
    if !h.frame_is_intra {
        p("reference_select", h.reference_select.into());
    }
    if h.skip_mode_frame.is_some() {
        p("skip_mode_present", h.skip_mode_present.into());
    }
    if !(h.frame_is_intra || h.error_resilient_mode || !seq.enable_warped_motion) {
        p("allow_warped_motion", h.allow_warped_motion.into());
    }
    p("reduced_tx_set", h.reduced_tx_set.into());
    if !h.frame_is_intra {
        let g = &h.global_motion;
        for r in 1..8 {
            let ty = g.gm_type[r];
            p(
                &format!("is_global[{r}]"),
                (ty != Av1WarpModel::Identity).into(),
            );
            if ty != Av1WarpModel::Identity {
                p(
                    &format!("is_rot_zoom[{r}]"),
                    (ty == Av1WarpModel::RotZoom).into(),
                );
                if ty != Av1WarpModel::RotZoom {
                    p(
                        &format!("is_translation[{r}]"),
                        (ty == Av1WarpModel::Translation).into(),
                    );
                }
                // trace_headers prints the raw subexp symbols for
                // gm_params; the bit count (`end`) pins the decode.
            }
        }
    }
    if seq.film_grain_params_present && (h.show_frame || h.showable_frame) {
        let g = &h.film_grain;
        p("apply_grain", g.apply_grain.into());
        if g.apply_grain {
            p("grain_seed", g.grain_seed.into());
            if h.frame_type == Av1FrameType::Inter {
                p("update_grain", g.update_grain.into());
            }
            if g.update_grain || h.frame_type != Av1FrameType::Inter {
                p("num_y_points", g.num_y_points.into());
                for i in 0..usize::from(g.num_y_points) {
                    p(&format!("point_y_value[{i}]"), g.point_y_value[i].into());
                    p(
                        &format!("point_y_scaling[{i}]"),
                        g.point_y_scaling[i].into(),
                    );
                }
                p("ar_coeff_lag", g.ar_coeff_lag.into());
                p("grain_scaling_minus_8", g.grain_scaling_minus_8.into());
                p("overlap_flag", g.overlap_flag.into());
                p(
                    "clip_to_restricted_range",
                    g.clip_to_restricted_range.into(),
                );
                if g.num_cb_points > 0 {
                    p("cb_mult", g.cb_mult.into());
                    p("cb_offset", g.cb_offset.into());
                }
            }
        }
    }
    let _ = state;
    v
}

struct Parsed {
    headers: Vec<(Av1Frame, Vec<(String, i64)>)>,
}

fn parse(name: &str) -> Parsed {
    let data = fixture(&format!("{name}.ivf"));
    let (_, frames) = ivf::parse_all(&data).unwrap();
    let mut seq: Option<SequenceHeader> = None;
    let mut state = Av1RefState::new();
    let mut headers = Vec::new();
    for f in frames {
        let tu = f.payload;
        let mut at = 0;
        let mut pending: Option<Av1Frame> = None;
        let mut next_tile = 0u32;
        while at < tu.len() {
            let (oh, start, end, next) = read_obu(tu, at).unwrap();
            let payload = &tu[start..end];
            let obu_header_bits = (start - at) * 8;
            at = next;
            match oh.obu_type {
                OBU_SEQUENCE_HEADER => seq = Some(parse_sequence_header_obu(payload).unwrap()),
                OBU_FRAME_HEADER | OBU_FRAME => {
                    let s = seq.as_ref().unwrap();
                    let h = state
                        .parse_frame_header(s, payload, oh.temporal_id, oh.spatial_id)
                        .unwrap_or_else(|e| panic!("{name}: frame header {}: {e}", headers.len()));
                    headers.push((h.clone(), ours(s, &h, &state, obu_header_bits)));
                    if h.show_existing_frame {
                        state.update(s, &h);
                        continue;
                    }
                    if oh.obu_type == OBU_FRAME {
                        let body = &payload[h.header_bits.div_ceil(8)..];
                        let g = parse_tile_group(&h.tile_info, body).unwrap();
                        next_tile = g.tg_end + 1;
                    } else {
                        next_tile = 0;
                    }
                    pending = Some(h);
                }
                OBU_TILE_GROUP => {
                    let h = pending.as_ref().unwrap();
                    let g = parse_tile_group(&h.tile_info, payload).unwrap();
                    assert_eq!(g.tg_start, next_tile, "{name}: tile groups in order");
                    next_tile = g.tg_end + 1;
                }
                _ => {}
            }
            if let Some(h) = pending.as_ref()
                && next_tile == h.tile_info.tile_cols * h.tile_info.tile_rows
            {
                state.update(seq.as_ref().unwrap(), h);
                pending = None;
                next_tile = 0;
            }
        }
        assert!(
            pending.is_none(),
            "{name}: temporal unit ends inside a frame"
        );
    }
    Parsed { headers }
}

fn check(name: &str) -> Parsed {
    let p = parse(name);
    let golden = String::from_utf8(fixture(&format!("{name}.frames"))).unwrap();
    let golden: Vec<&str> = golden.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(p.headers.len(), golden.len(), "{name}: header count");
    for (i, ((_, mine), g)) in p.headers.iter().zip(&golden).enumerate() {
        let g = kv(g);
        for (k, v) in mine {
            let theirs = g
                .get(k)
                .unwrap_or_else(|| panic!("{name} header {i}: {k} missing from trace"));
            assert_eq!(theirs, &v.to_string(), "{name} header {i}: {k}");
        }
    }
    p
}

#[test]
fn key_and_inter_frames() {
    check("i_frame_then_p_64x64");
    check("superblocks_128");
    check("self_pyr_64x64_q60_len17_deep");
}

#[test]
fn short_reference_signaling_derives_the_refs() {
    for name in [
        "self_gop_96x64_q80_shortrefs",
        "self_pyr_96x80_q60_shortrefs",
    ] {
        let p = check(name);
        assert!(p.headers.iter().any(|(h, _)| h.frame_refs_short_signaling));
    }
}

#[test]
fn switch_frames_and_error_resilience() {
    let p = check("self_gop_96x64_q80_sframes");
    assert!(
        p.headers
            .iter()
            .any(|(h, _)| h.frame_type == Av1FrameType::Switch)
    );
    check("self_splice_96x64_q60_q140_sframe");
    check("self_gop_96x80_q72_erm");
    let p = check("ext_erm");
    assert!(p.headers.iter().any(|(h, _)| h.ref_order_hint.is_some()));
}

#[test]
fn show_existing_frames() {
    for name in [
        "ext_resize_ss",
        "ext_grain_resize",
        "self_pyr_96x80_q40_film_grain",
    ] {
        let p = check(name);
        assert!(
            p.headers.iter().any(|(h, _)| h.show_existing_frame),
            "{name}"
        );
    }
}

#[test]
fn global_motion_against_prev_gm_params() {
    // Local warped motion (no global models) parses too.
    check("self_gop_64x64_q100_shear_obmc");
    for name in [
        "self_gop_64x64_q60_gm_rotation",
        "self_gop_64x64_q60_gm_zoom_warp",
    ] {
        let p = check(name);
        assert!(
            p.headers.iter().any(|(h, _)| h
                .global_motion
                .gm_type
                .iter()
                .any(|&t| t != Av1WarpModel::Identity)),
            "{name}"
        );
    }
}

#[test]
fn film_grain() {
    for name in [
        "film_grain_on",
        "self_gop_128x96_q60_film_grain_ar",
        "self_gop_128x96_q60_film_grain_csfl",
        "self_gop_192x160_q60_film_grain_lag3",
    ] {
        let p = check(name);
        assert!(
            p.headers.iter().any(|(h, _)| h.film_grain.apply_grain),
            "{name}"
        );
    }
}

#[test]
fn superres_tiles_and_groups() {
    check("self_gop_320x96_q180_superres_explicit_tiles");
    check("self_gop_128x96_q180_superres_inter");
    check("self_gop_192x128_q72_tiles2x2_groups2");
    check("self_gop_192x128_q72_tiles_nonuniform_1p2");
}

#[test]
fn segmentation_quantization_and_filters() {
    check("self_gop_128x128_q120_seg_delta_q");
    check("self_gop_128x64_q72_seg_temporal_moving");
    check("self_gop_128x96_q120_seg_qm");
    check("self_gop_128x128_q100_deltaq");
    check("self_gop_192x128_q140_lr");
    check("self_gop_256x128_q140_cdef_units");
    check("self_gop_64x64_q60_skipmode_tmvs");
    let p = check("self_gop_128x128_q100_dq_lossless_seg");
    assert!(
        p.headers
            .iter()
            .any(|(h, _)| h.lossless_array.iter().any(|&l| l))
    );
    let p = check("self_kf_64x64_lossless");
    assert!(p.headers[0].0.coded_lossless);
}

#[test]
fn layers_and_formats() {
    check("self_gop_64x64_q72_temporal_layers");
    check("self_svc_64_128_q72_spatial_layers");
    check("obu_with_extension_headers");
    check("self_gop_64x64_q60_12bit_420");
    check("self_gop_64x64_q60_10bit_mono");
    check("self_gop_64x64_q60_8bit_444");
    check("self_kf_192x192_q60_screen");
}

#[test]
fn svt_random_access_with_overlays_and_predicted_grain() {
    let p = check("svt_random_access");
    assert!(
        p.headers
            .iter()
            .filter(|(h, _)| h.show_existing_frame)
            .count()
            > 4
    );
    assert!(
        p.headers
            .iter()
            .any(|(h, _)| h.film_grain.apply_grain && !h.film_grain.update_grain)
    );
    // Predicted grain carries the referenced slot's parameters.
    let (h, _) = p
        .headers
        .iter()
        .find(|(h, _)| h.film_grain.apply_grain && !h.film_grain.update_grain)
        .unwrap();
    assert!(h.film_grain.num_y_points > 0);
}
