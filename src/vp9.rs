//! VP9 uncompressed-header parser + writer.
//!
//! VDPAU / VAAPI / NVDEC's VP9 picture-info structs are
//! **uncompressed-header-driven** — the GPU does the compressed
//! frame-header decode and everything downstream. This module
//! extracts the fields the HW APIs consume and stops at the start
//! of the compressed header.
//!
//! Lifted from `oxideav-vdpau::vp9` (Round 4) under the workspace
//! clean-room policy: same author, same workspace, same policy —
//! moving the canonical home from the VDPAU glue crate into the
//! shared bitstream crate so the other backends can re-use it.
//!
//! # Scope
//!
//! - Profile 0..3 keyframes.
//! - `show_existing_frame` is detected but rejected (not in scope
//!   for the IDR-only HW path the workspace targets).
//! - Inter frames are not decoded — we don't carry the frame-context
//!   state that an inter-frame decode requires. The parser still
//!   reads all of the bits a HW backend needs to populate the
//!   picture-info struct for an intra-only / forced-keyframe path.
//!
//! [`write_uncompressed_header`] is the parse's inverse over the
//! keyframe envelope, byte-exact on the crate's fixture; emission is
//! canonical (update flags are coded exactly for non-sentinel
//! values).
//!
//! # Spec reference
//!
//! VP9 Bitstream and Decoding Process Specification, sections 6.2
//! (uncompressed_header), 6.2.1 (frame_size), 6.2.2 (render_size),
//! 6.2.3 (frame_size_with_refs), 6.2.4 (loop_filter_params), 6.2.5
//! (quantization_params), 6.2.6 (segmentation_params), 6.2.7
//! (tile_info).

use crate::bit_reader::BitReader;
use crate::BitstreamError;

const KEY_FRAME: u8 = 0;
const VP9_SYNC_CODE: u32 = 0x49_8342;

const SEG_LVL_MAX: usize = 4;
const SEGMENT_FEATURE_BITS: [u32; SEG_LVL_MAX] = [8, 6, 2, 0];
const SEGMENT_FEATURE_SIGNED: [bool; SEG_LVL_MAX] = [true, true, false, false];

/// Parsed VP9 uncompressed header. Carries every field the slice-data
/// HW APIs consume.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vp9UncompressedHeader {
    pub profile: u8,
    pub show_existing_frame: bool,
    /// 0 = KEY_FRAME, 1 = NON_KEY_FRAME.
    pub frame_type: u8,
    pub show_frame: bool,
    pub error_resilient_mode: bool,
    /// 8 / 10 / 12.
    pub bit_depth: u8,
    /// 0..7 (per spec, 7 = sRGB).
    pub color_space: u8,
    /// Studio (false) / Full (true). Also called `full_range` in the
    /// spec.
    pub color_range: bool,
    pub subsampling_x: bool,
    pub subsampling_y: bool,
    pub frame_width: u32,
    pub frame_height: u32,
    pub render_size_present: bool,
    pub render_width: u32,
    pub render_height: u32,
    pub intra_only: bool,
    pub reset_frame_context: u8,
    pub refresh_frame_flags: u8,
    pub allow_high_precision_mv: bool,
    pub interpolation_filter: u8,
    pub refresh_frame_context: bool,
    pub frame_parallel_decoding_mode: bool,
    /// Derived `frame_context_idx` after the §6.2 intra/error-resilient
    /// reset — always 0 for the keyframes this parser accepts.
    pub frame_context_idx: u8,
    /// The raw coded `frame_context_idx` f(2) bits (§6.2), retained so
    /// [`write_uncompressed_header`] can re-emit the header
    /// byte-exactly even though the derived value resets to 0.
    pub coded_frame_context_idx: u8,
    pub loop_filter_level: u8,
    pub loop_filter_sharpness: u8,
    pub loop_filter_mode_ref_delta_enabled: bool,
    pub loop_filter_ref_deltas: [i32; 4],
    pub loop_filter_mode_deltas: [i32; 2],
    pub base_q_idx: i32,
    pub delta_q_y_dc: i32,
    pub delta_q_uv_dc: i32,
    pub delta_q_uv_ac: i32,
    pub segmentation_enabled: bool,
    pub segmentation_update_map: bool,
    pub segmentation_temporal_update: bool,
    pub segmentation_update_data: bool,
    pub segmentation_abs_or_delta_update: bool,
    pub segment_feature_enable: [[u8; SEG_LVL_MAX]; 8],
    pub segment_feature_data: [[i16; SEG_LVL_MAX]; 8],
    pub mb_segment_tree_probs: [u8; 7],
    pub segment_pred_probs: [u8; 3],
    pub log2_tile_cols: u8,
    pub log2_tile_rows: u8,
    /// Length in bytes of the uncompressed header (including any
    /// byte-alignment padding bits at the end).
    pub uncompressed_header_size: u32,
    /// Length of the bool-coded "compressed header" partition that
    /// follows. (VP9 spec calls this `first_partition_size`.)
    pub compressed_header_size: u32,
    pub ref_frame_idx: [u8; 3],
    pub ref_frame_sign_bias: [u8; 4],
}

fn read_color_config(
    r: &mut BitReader<'_>,
    h: &mut Vp9UncompressedHeader,
) -> Result<(), BitstreamError> {
    if h.profile >= 2 {
        let ten_or_twelve_bit_depth = r.u(1);
        h.bit_depth = if ten_or_twelve_bit_depth != 0 { 12 } else { 10 };
    } else {
        h.bit_depth = 8;
    }
    h.color_space = r.u(3) as u8;
    if h.color_space != 7 {
        // 7 = SRGB — color_range is forced to 1, sub_sampling is 0.
        h.color_range = r.u(1) != 0;
        if h.profile == 1 || h.profile == 3 {
            h.subsampling_x = r.u(1) != 0;
            h.subsampling_y = r.u(1) != 0;
            let _reserved = r.u(1);
        } else {
            h.subsampling_x = true;
            h.subsampling_y = true;
        }
    } else {
        h.color_range = true;
        if h.profile == 1 || h.profile == 3 {
            let _reserved = r.u(1);
        }
        h.subsampling_x = false;
        h.subsampling_y = false;
    }
    Ok(())
}

fn read_frame_size(r: &mut BitReader<'_>, h: &mut Vp9UncompressedHeader) {
    h.frame_width = r.u(16) + 1;
    h.frame_height = r.u(16) + 1;
    h.render_size_present = r.u(1) != 0;
    if h.render_size_present {
        h.render_width = r.u(16) + 1;
        h.render_height = r.u(16) + 1;
    } else {
        h.render_width = h.frame_width;
        h.render_height = h.frame_height;
    }
}

fn read_loop_filter_params(r: &mut BitReader<'_>, h: &mut Vp9UncompressedHeader) {
    h.loop_filter_level = r.u(6) as u8;
    h.loop_filter_sharpness = r.u(3) as u8;
    let mode_ref_delta_enabled = r.u(1) != 0;
    h.loop_filter_mode_ref_delta_enabled = mode_ref_delta_enabled;
    if mode_ref_delta_enabled {
        let mode_ref_delta_update = r.u(1);
        if mode_ref_delta_update != 0 {
            for slot in h.loop_filter_ref_deltas.iter_mut() {
                let update_ref_delta = r.u(1);
                if update_ref_delta != 0 {
                    *slot = read_signed_6bit(r);
                }
            }
            for slot in h.loop_filter_mode_deltas.iter_mut() {
                let update_mode_delta = r.u(1);
                if update_mode_delta != 0 {
                    *slot = read_signed_6bit(r);
                }
            }
        }
    }
}

fn read_signed_6bit(r: &mut BitReader<'_>) -> i32 {
    let value = r.u(6) as i32;
    let sign = r.u(1);
    if sign == 1 {
        -value
    } else {
        value
    }
}

fn read_signed_4bit(r: &mut BitReader<'_>) -> i32 {
    let value = r.u(4) as i32;
    let sign = r.u(1);
    if sign == 1 {
        -value
    } else {
        value
    }
}

fn read_delta_q(r: &mut BitReader<'_>) -> i32 {
    let delta_coded = r.u(1);
    if delta_coded != 0 {
        read_signed_4bit(r)
    } else {
        0
    }
}

fn read_quantization_params(r: &mut BitReader<'_>, h: &mut Vp9UncompressedHeader) {
    h.base_q_idx = r.u(8) as i32;
    h.delta_q_y_dc = read_delta_q(r);
    h.delta_q_uv_dc = read_delta_q(r);
    h.delta_q_uv_ac = read_delta_q(r);
}

fn read_segmentation_params(r: &mut BitReader<'_>, h: &mut Vp9UncompressedHeader) {
    h.segmentation_enabled = r.u(1) != 0;
    if h.segmentation_enabled {
        let update_map = r.u(1) != 0;
        h.segmentation_update_map = update_map;
        if update_map {
            for i in 0..7 {
                let prob_coded = r.u(1);
                h.mb_segment_tree_probs[i] = if prob_coded != 0 { r.u(8) as u8 } else { 255 };
            }
            let temporal_update = r.u(1) != 0;
            h.segmentation_temporal_update = temporal_update;
            for i in 0..3 {
                let prob_coded = if temporal_update { r.u(1) } else { 0 };
                h.segment_pred_probs[i] = if prob_coded != 0 { r.u(8) as u8 } else { 255 };
            }
        }
        let update_data = r.u(1) != 0;
        h.segmentation_update_data = update_data;
        if update_data {
            h.segmentation_abs_or_delta_update = r.u(1) != 0;
            for i in 0..8 {
                for j in 0..SEG_LVL_MAX {
                    let feature_enabled = r.u(1);
                    h.segment_feature_enable[i][j] = feature_enabled as u8;
                    if feature_enabled != 0 {
                        let bits = SEGMENT_FEATURE_BITS[j];
                        let signed = SEGMENT_FEATURE_SIGNED[j];
                        let raw = r.u(bits) as i32;
                        let val = if signed {
                            let sign = r.u(1);
                            if sign != 0 {
                                -raw
                            } else {
                                raw
                            }
                        } else {
                            raw
                        };
                        h.segment_feature_data[i][j] = val as i16;
                    }
                }
            }
        }
    }
}

fn calc_min_log2_tile_cols(sb64_cols: u32) -> u32 {
    let mut min = 0u32;
    while (64 << min) < sb64_cols {
        min += 1;
    }
    min
}

fn calc_max_log2_tile_cols(sb64_cols: u32) -> u32 {
    let mut max = 0u32;
    while (sb64_cols >> (max + 1)) >= 4 {
        max += 1;
    }
    max
}

fn read_tile_info(r: &mut BitReader<'_>, h: &mut Vp9UncompressedHeader) {
    let mi_cols = h.frame_width.div_ceil(8);
    let sb64_cols = mi_cols.div_ceil(8);
    let min_log2 = calc_min_log2_tile_cols(sb64_cols);
    let max_log2 = calc_max_log2_tile_cols(sb64_cols);
    let mut log2_cols = min_log2;
    while log2_cols < max_log2 {
        let increment = r.u(1);
        if increment == 0 {
            break;
        }
        log2_cols += 1;
    }
    h.log2_tile_cols = log2_cols as u8;
    let log2_rows = r.u(1);
    h.log2_tile_rows = if log2_rows != 0 {
        let r2 = r.u(1);
        if r2 != 0 {
            2
        } else {
            1
        }
    } else {
        0
    };
}

/// Parse the uncompressed VP9 header. Currently restricted to
/// keyframes — `show_existing_frame=1` and inter frames are
/// rejected. The parser surfaces the bytes the HW backend later
/// hands to its picture-info population step.
pub fn parse_uncompressed_header(payload: &[u8]) -> Result<Vp9UncompressedHeader, BitstreamError> {
    if payload.len() < 8 {
        return Err(BitstreamError::unexpected_end(
            "VP9 frame shorter than 8 bytes",
        ));
    }
    let mut r = BitReader::new(payload);
    let mut h = Vp9UncompressedHeader::default();
    let frame_marker = r.u(2);
    if frame_marker != 2 {
        return Err(BitstreamError::invalid(format!(
            "VP9 frame_marker {frame_marker} != 2"
        )));
    }
    let profile_low = r.u(1);
    let profile_high = r.u(1);
    h.profile = ((profile_high << 1) | profile_low) as u8;
    if h.profile == 3 {
        let _reserved = r.u(1);
    }
    h.show_existing_frame = r.u(1) != 0;
    if h.show_existing_frame {
        return Err(BitstreamError::unsupported(
            "VP9: show_existing_frame=1 not supported by minimal parser",
        ));
    }
    h.frame_type = r.u(1) as u8;
    h.show_frame = r.u(1) != 0;
    h.error_resilient_mode = r.u(1) != 0;

    if h.frame_type == KEY_FRAME {
        let sync = r.u(24);
        if sync != VP9_SYNC_CODE {
            return Err(BitstreamError::invalid(format!(
                "VP9 frame_sync_code mismatch: 0x{sync:06x} != 0x498342"
            )));
        }
        read_color_config(&mut r, &mut h)?;
        read_frame_size(&mut r, &mut h);
        h.refresh_frame_flags = 0xff;
        h.intra_only = false;
    } else {
        return Err(BitstreamError::unsupported(
            "VP9: only KEY_FRAME supported by minimal parser",
        ));
    }

    // §6.2 — coded for every non-show-existing frame: the entropy
    // refresh pair (absent under error resilience) and the raw
    // frame_context_idx f(2).
    if !h.error_resilient_mode {
        h.refresh_frame_context = r.u(1) != 0;
        h.frame_parallel_decoding_mode = r.u(1) != 0;
    } else {
        h.refresh_frame_context = false;
        h.frame_parallel_decoding_mode = true;
    }
    h.coded_frame_context_idx = r.u(2) as u8;
    // FrameIsIntra (keyframe) → setup_past_independence resets the
    // effective index to 0 (§6.2).
    h.frame_context_idx = 0;

    read_loop_filter_params(&mut r, &mut h);
    read_quantization_params(&mut r, &mut h);
    read_segmentation_params(&mut r, &mut h);
    read_tile_info(&mut r, &mut h);

    // first_partition_size = 16 bits.
    let first_partition_size = r.u(16);

    // Round up to next byte for the uncompressed-header size (the
    // remaining bits of the current byte are byte-alignment padding).
    let uncompressed_size = r.bit_pos().div_ceil(8);
    h.uncompressed_header_size = uncompressed_size as u32;
    h.compressed_header_size = first_partition_size;

    Ok(h)
}

// ─────────────────────────── Writer ──────────────────────────────────────────

fn write_signed(
    w: &mut crate::bit_writer::BitWriter,
    value: i32,
    bits: u32,
    name: &str,
) -> Result<(), BitstreamError> {
    let mag = value.unsigned_abs();
    if bits < 32 && mag >= (1 << bits) {
        return Err(BitstreamError::invalid(format!(
            "{name} = {value} does not fit su({bits}+1)"
        )));
    }
    w.write_bits(mag, bits);
    w.write_bit(u32::from(value < 0));
    Ok(())
}

/// Emit a keyframe `uncompressed_header()` (§6.2, zero-padded to the
/// byte boundary per §6.1 `trailing_bits()`) — the inverse of
/// [`parse_uncompressed_header`] over its keyframe envelope:
/// `parse_uncompressed_header(&write_uncompressed_header(h)?)`
/// reproduces `h`. Emission is canonical — "update" flags whose
/// stored value equals the not-coded sentinel (probability 255, zero
/// deltas) are written as absent, so byte-exactness against foreign
/// bytes holds for canonically-coded streams.
pub fn write_uncompressed_header(h: &Vp9UncompressedHeader) -> Result<Vec<u8>, BitstreamError> {
    if h.show_existing_frame {
        return Err(BitstreamError::unsupported(
            "VP9: show_existing_frame=1 not supported by minimal writer",
        ));
    }
    if h.frame_type != KEY_FRAME {
        return Err(BitstreamError::unsupported(
            "VP9: only KEY_FRAME supported by minimal writer",
        ));
    }
    if h.profile > 3 {
        return Err(BitstreamError::invalid("VP9 profile must be 0..=3"));
    }
    let mut w = crate::bit_writer::BitWriter::new();
    w.write_bits(2, 2); // frame_marker
    w.write_bit(h.profile as u32 & 1); // profile_low_bit
    w.write_bit((h.profile as u32 >> 1) & 1); // profile_high_bit
    if h.profile == 3 {
        w.write_bit(0); // reserved_zero
    }
    w.write_bit(0); // show_existing_frame
    w.write_bit(h.frame_type as u32); // frame_type = KEY_FRAME
    w.write_bit(u32::from(h.show_frame));
    w.write_bit(u32::from(h.error_resilient_mode));
    w.write_bits(VP9_SYNC_CODE, 24);
    write_color_config(&mut w, h)?;
    // frame_size() + render_size().
    if h.frame_width == 0
        || h.frame_height == 0
        || h.frame_width > 1 << 16
        || h.frame_height > 1 << 16
    {
        return Err(BitstreamError::invalid(
            "VP9 frame dimensions must be 1..=65536 (f(16) minus-1 coding)",
        ));
    }
    w.write_bits(h.frame_width - 1, 16);
    w.write_bits(h.frame_height - 1, 16);
    w.write_bit(u32::from(h.render_size_present));
    if h.render_size_present {
        if h.render_width == 0
            || h.render_height == 0
            || h.render_width > 1 << 16
            || h.render_height > 1 << 16
        {
            return Err(BitstreamError::invalid(
                "VP9 render dimensions must be 1..=65536",
            ));
        }
        w.write_bits(h.render_width - 1, 16);
        w.write_bits(h.render_height - 1, 16);
    } else if h.render_width != h.frame_width || h.render_height != h.frame_height {
        return Err(BitstreamError::invalid(
            "render size differs from frame size but render_size_present is unset (6.2.2)",
        ));
    }
    if h.refresh_frame_flags != 0xff || h.intra_only || h.frame_context_idx != 0 {
        return Err(BitstreamError::invalid(
            "keyframes fix refresh_frame_flags = 0xFF, intra_only = 0 and a reset \
             frame_context_idx (6.2)",
        ));
    }
    if !h.error_resilient_mode {
        w.write_bit(u32::from(h.refresh_frame_context));
        w.write_bit(u32::from(h.frame_parallel_decoding_mode));
    } else if h.refresh_frame_context || !h.frame_parallel_decoding_mode {
        return Err(BitstreamError::invalid(
            "error_resilient_mode fixes refresh_frame_context = 0 and \
             frame_parallel_decoding_mode = 1 (6.2)",
        ));
    }
    if h.coded_frame_context_idx > 3 {
        return Err(BitstreamError::invalid(
            "coded_frame_context_idx does not fit f(2)",
        ));
    }
    w.write_bits(h.coded_frame_context_idx as u32, 2);
    // loop_filter_params() — canonical: per-slot update flags are set
    // for nonzero deltas.
    if h.loop_filter_level > 63 || h.loop_filter_sharpness > 7 {
        return Err(BitstreamError::invalid(
            "loop_filter_level f(6) / sharpness f(3) out of range",
        ));
    }
    w.write_bits(h.loop_filter_level as u32, 6);
    w.write_bits(h.loop_filter_sharpness as u32, 3);
    w.write_bit(u32::from(h.loop_filter_mode_ref_delta_enabled));
    if h.loop_filter_mode_ref_delta_enabled {
        let any = h.loop_filter_ref_deltas.iter().any(|&d| d != 0)
            || h.loop_filter_mode_deltas.iter().any(|&d| d != 0);
        w.write_bit(u32::from(any)); // loop_filter_delta_update
        if any {
            for &d in &h.loop_filter_ref_deltas {
                w.write_bit(u32::from(d != 0));
                if d != 0 {
                    write_signed(&mut w, d, 6, "loop_filter_ref_delta")?;
                }
            }
            for &d in &h.loop_filter_mode_deltas {
                w.write_bit(u32::from(d != 0));
                if d != 0 {
                    write_signed(&mut w, d, 6, "loop_filter_mode_delta")?;
                }
            }
        }
    } else if h.loop_filter_ref_deltas.iter().any(|&d| d != 0)
        || h.loop_filter_mode_deltas.iter().any(|&d| d != 0)
    {
        return Err(BitstreamError::invalid(
            "loop-filter deltas require loop_filter_delta_enabled (6.2.4)",
        ));
    }
    // quantization_params().
    if !(0..=255).contains(&h.base_q_idx) {
        return Err(BitstreamError::invalid("base_q_idx must fit f(8)"));
    }
    w.write_bits(h.base_q_idx as u32, 8);
    for (d, name) in [
        (h.delta_q_y_dc, "delta_q_y_dc"),
        (h.delta_q_uv_dc, "delta_q_uv_dc"),
        (h.delta_q_uv_ac, "delta_q_uv_ac"),
    ] {
        w.write_bit(u32::from(d != 0));
        if d != 0 {
            write_signed(&mut w, d, 4, name)?;
        }
    }
    // segmentation_params().
    w.write_bit(u32::from(h.segmentation_enabled));
    if h.segmentation_enabled {
        w.write_bit(u32::from(h.segmentation_update_map));
        if h.segmentation_update_map {
            for &p in &h.mb_segment_tree_probs {
                w.write_bit(u32::from(p != 255));
                if p != 255 {
                    w.write_bits(p as u32, 8);
                }
            }
            w.write_bit(u32::from(h.segmentation_temporal_update));
            for &p in &h.segment_pred_probs {
                if h.segmentation_temporal_update {
                    w.write_bit(u32::from(p != 255));
                    if p != 255 {
                        w.write_bits(p as u32, 8);
                    }
                } else if p != 255 {
                    return Err(BitstreamError::invalid(
                        "segment_pred_probs must be 255 without temporal update (6.2.6)",
                    ));
                }
            }
        }
        w.write_bit(u32::from(h.segmentation_update_data));
        if h.segmentation_update_data {
            w.write_bit(u32::from(h.segmentation_abs_or_delta_update));
            for i in 0..8 {
                for j in 0..SEG_LVL_MAX {
                    let enabled = h.segment_feature_enable[i][j] != 0;
                    w.write_bit(u32::from(enabled));
                    let data = h.segment_feature_data[i][j] as i32;
                    if enabled {
                        let bits = SEGMENT_FEATURE_BITS[j];
                        if SEGMENT_FEATURE_SIGNED[j] {
                            write_signed(&mut w, data, bits, "segment_feature_data")?;
                        } else {
                            if bits < 32 && data as u32 >= (1u32 << bits).max(1) {
                                return Err(BitstreamError::invalid(
                                    "segment_feature_data does not fit its feature width",
                                ));
                            }
                            w.write_bits(data as u32, bits);
                        }
                    } else if data != 0 {
                        return Err(BitstreamError::invalid(
                            "segment_feature_data requires the feature-enabled bit (6.2.6)",
                        ));
                    }
                }
            }
        }
    }
    // tile_info().
    let mi_cols = h.frame_width.div_ceil(8);
    let sb64_cols = mi_cols.div_ceil(8);
    let min_log2 = calc_min_log2_tile_cols(sb64_cols);
    let max_log2 = calc_max_log2_tile_cols(sb64_cols);
    let log2_cols = h.log2_tile_cols as u32;
    if log2_cols < min_log2 || log2_cols > max_log2 {
        return Err(BitstreamError::invalid(format!(
            "log2_tile_cols = {log2_cols} outside {min_log2}..={max_log2} for this width (6.2.7)"
        )));
    }
    for _ in min_log2..log2_cols {
        w.write_bit(1); // increment_tile_cols_log2
    }
    if log2_cols < max_log2 {
        w.write_bit(0);
    }
    match h.log2_tile_rows {
        0 => w.write_bit(0),
        1 => {
            w.write_bit(1);
            w.write_bit(0);
        }
        2 => {
            w.write_bit(1);
            w.write_bit(1);
        }
        _ => {
            return Err(BitstreamError::invalid(
                "log2_tile_rows must be 0..=2 (6.2.7)",
            ));
        }
    }
    // header_size_in_bytes f(16).
    if h.compressed_header_size > 0xffff {
        return Err(BitstreamError::invalid(
            "compressed_header_size does not fit f(16)",
        ));
    }
    w.write_bits(h.compressed_header_size, 16);
    // §6.1 trailing_bits(): zero-pad to the byte boundary.
    while !w.byte_aligned() {
        w.write_bit(0);
    }
    Ok(w.finish())
}

/// §6.2.-side `color_config()` emission for
/// [`write_uncompressed_header`].
fn write_color_config(
    w: &mut crate::bit_writer::BitWriter,
    h: &Vp9UncompressedHeader,
) -> Result<(), BitstreamError> {
    match (h.profile, h.bit_depth) {
        (0 | 1, 8) => {}
        (2 | 3, 10) => w.write_bit(0),
        (2 | 3, 12) => w.write_bit(1),
        _ => {
            return Err(BitstreamError::invalid(format!(
                "bit_depth {} not expressible for VP9 profile {} (6.2)",
                h.bit_depth, h.profile
            )));
        }
    }
    if h.color_space > 7 {
        return Err(BitstreamError::invalid("color_space must fit f(3)"));
    }
    w.write_bits(h.color_space as u32, 3);
    if h.color_space != 7 {
        w.write_bit(u32::from(h.color_range));
        if h.profile == 1 || h.profile == 3 {
            w.write_bit(u32::from(h.subsampling_x));
            w.write_bit(u32::from(h.subsampling_y));
            w.write_bit(0); // reserved_zero
        } else if !h.subsampling_x || !h.subsampling_y {
            return Err(BitstreamError::invalid(
                "VP9 profiles 0/2 fix 4:2:0 sampling (6.2)",
            ));
        }
    } else {
        // CS_RGB: full range, 4:4:4 only, profiles 1/3 only.
        if !h.color_range || h.subsampling_x || h.subsampling_y {
            return Err(BitstreamError::invalid(
                "CS_RGB implies full range and 4:4:4 sampling (6.2)",
            ));
        }
        if h.profile == 1 || h.profile == 3 {
            w.write_bit(0); // reserved_zero
        } else {
            return Err(BitstreamError::invalid(
                "CS_RGB requires VP9 profile 1 or 3 (6.2)",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_max_log2_tile_cols_match_spec() {
        // For sb64_cols = 5: min should be 0, max should be 0 (5>>1=2 < 4).
        assert_eq!(calc_min_log2_tile_cols(5), 0);
        assert_eq!(calc_max_log2_tile_cols(5), 0);
        // For sb64_cols = 16: min=0, max=2 (16>>1=8>=4, 16>>2=4>=4, 16>>3=2<4).
        assert_eq!(calc_min_log2_tile_cols(16), 0);
        assert_eq!(calc_max_log2_tile_cols(16), 2);
    }

    fn base_header() -> Vp9UncompressedHeader {
        Vp9UncompressedHeader {
            profile: 0,
            frame_type: KEY_FRAME,
            show_frame: true,
            bit_depth: 8,
            color_space: 2,
            subsampling_x: true,
            subsampling_y: true,
            frame_width: 320,
            frame_height: 240,
            render_width: 320,
            render_height: 240,
            refresh_frame_flags: 0xff,
            refresh_frame_context: true,
            frame_parallel_decoding_mode: true,
            base_q_idx: 37,
            ..Default::default()
        }
    }

    fn assert_roundtrip(h: &Vp9UncompressedHeader) {
        let mut bytes = write_uncompressed_header(h).expect("writes");
        let expected_size = bytes.len() as u32;
        // Feed enough tail bytes to cover the declared compressed
        // header so the parse's size accounting is exercised.
        bytes.extend(std::iter::repeat_n(0u8, h.compressed_header_size as usize));
        let back = parse_uncompressed_header(&bytes).expect("re-parses");
        let mut expect = h.clone();
        expect.uncompressed_header_size = expected_size;
        assert_eq!(back, expect);
    }

    #[test]
    fn writer_roundtrips_minimal_keyframe() {
        let mut h = base_header();
        h.compressed_header_size = 5;
        assert_roundtrip(&h);
    }

    #[test]
    fn writer_roundtrips_loop_filter_quant_segmentation() {
        let mut h = base_header();
        h.error_resilient_mode = false;
        h.coded_frame_context_idx = 3;
        h.loop_filter_level = 17;
        h.loop_filter_sharpness = 5;
        h.loop_filter_mode_ref_delta_enabled = true;
        h.loop_filter_ref_deltas = [1, 0, -1, -1];
        h.loop_filter_mode_deltas = [2, -2];
        h.delta_q_y_dc = -7;
        h.delta_q_uv_dc = 3;
        h.delta_q_uv_ac = -15;
        h.segmentation_enabled = true;
        h.segmentation_update_map = true;
        h.mb_segment_tree_probs = [12, 255, 200, 255, 255, 1, 255];
        h.segmentation_temporal_update = true;
        h.segment_pred_probs = [255, 128, 255];
        h.segmentation_update_data = true;
        h.segmentation_abs_or_delta_update = true;
        h.segment_feature_enable[0][0] = 1;
        h.segment_feature_data[0][0] = -100; // alt-Q, su(8+1)
        h.segment_feature_enable[3][2] = 1;
        h.segment_feature_data[3][2] = 2; // ref-frame feature, f(2)
        h.segment_feature_enable[7][3] = 1; // skip feature, 0 bits
        h.compressed_header_size = 100;
        assert_roundtrip(&h);
    }

    #[test]
    fn writer_roundtrips_error_resilient_and_tiles() {
        let mut h = base_header();
        h.error_resilient_mode = true;
        h.refresh_frame_context = false;
        h.frame_parallel_decoding_mode = true;
        h.frame_width = 1920; // sb64_cols 30 → max_log2 2
        h.frame_height = 1080;
        h.render_width = 1280;
        h.render_height = 720;
        h.render_size_present = true;
        h.log2_tile_cols = 2;
        h.log2_tile_rows = 1;
        h.compressed_header_size = 9;
        assert_roundtrip(&h);
    }

    #[test]
    fn writer_roundtrips_profiles_and_srgb() {
        // Profile 2, 12-bit 4:2:0.
        let mut h = base_header();
        h.profile = 2;
        h.bit_depth = 12;
        h.compressed_header_size = 1;
        assert_roundtrip(&h);
        // Profile 1, sRGB 4:4:4 full-range.
        let mut h = base_header();
        h.profile = 1;
        h.color_space = 7;
        h.color_range = true;
        h.subsampling_x = false;
        h.subsampling_y = false;
        h.compressed_header_size = 1;
        assert_roundtrip(&h);
        // Profile 3, 10-bit 4:2:2.
        let mut h = base_header();
        h.profile = 3;
        h.bit_depth = 10;
        h.subsampling_x = true;
        h.subsampling_y = false;
        h.compressed_header_size = 1;
        assert_roundtrip(&h);
    }

    #[test]
    fn writer_rejects_inconsistent_headers() {
        // Inter frame.
        let mut h = base_header();
        h.frame_type = 1;
        assert!(write_uncompressed_header(&h).is_err());
        // sRGB on profile 0.
        let mut h = base_header();
        h.color_space = 7;
        h.color_range = true;
        h.subsampling_x = false;
        h.subsampling_y = false;
        assert!(write_uncompressed_header(&h).is_err());
        // log2_tile_cols beyond the width's envelope (320 → max 0).
        let mut h = base_header();
        h.log2_tile_cols = 2;
        assert!(write_uncompressed_header(&h).is_err());
        // error-resilient with refresh_frame_context set.
        let mut h = base_header();
        h.error_resilient_mode = true;
        h.refresh_frame_context = true;
        assert!(write_uncompressed_header(&h).is_err());
    }

    #[test]
    fn parse_rejects_short_input() {
        assert!(matches!(
            parse_uncompressed_header(&[0u8; 4]),
            Err(BitstreamError::UnexpectedEnd(_))
        ));
    }
}
