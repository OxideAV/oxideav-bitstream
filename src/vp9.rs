//! VP9 uncompressed-header parser.
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
    pub frame_context_idx: u8,
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
        return Err(BitstreamError::unexpected_end("VP9 frame shorter than 8 bytes"));
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
        h.frame_context_idx = 0;
        // Keyframes always reset entropy.
        h.refresh_frame_context = true;
    } else {
        return Err(BitstreamError::unsupported(
            "VP9: only KEY_FRAME supported by minimal parser",
        ));
    }

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

    #[test]
    fn parse_rejects_short_input() {
        assert!(matches!(
            parse_uncompressed_header(&[0u8; 4]),
            Err(BitstreamError::UnexpectedEnd(_))
        ));
    }
}
