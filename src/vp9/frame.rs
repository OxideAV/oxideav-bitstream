//! VP9 uncompressed header for every frame type (§6.2) with the state
//! it reads from and leaves to later frames, the §8.6.1 quantizer
//! functions, the §8.8.1 loop filter level table and superframe
//! splitting (Annex B).
//!
//! [`Vp9State::parse_frame`] parses key frames, intra-only frames,
//! inter frames (`frame_size_with_refs()` against the reference slot
//! sizes) and `show_existing_frame` headers, and reports every value
//! *in force* for the frame: colour configuration inherited by inter
//! frames, loop filter deltas and segmentation features carried over
//! from earlier frames unless updated, the §7.2 `setup_past_independence()`
//! resets. [`Vp9State::commit`] then records what the frame leaves
//! behind (reference slot sizes and bit depth for `refresh_frame_flags`,
//! the deltas and features). A hardware bridge needs nothing else to
//! fill its picture and segment parameters; the compressed header and
//! tiles are the hardware's.

use super::tables::{AC_QLOOKUP, DC_QLOOKUP};
use crate::BitstreamError;
use crate::bit_reader::BitReader;

/// `MAX_SEGMENTS`.
pub const MAX_SEGMENTS: usize = 8;
/// `SEG_LVL_MAX`.
pub const SEG_LVL_MAX: usize = 4;
/// Segment feature indices (§7.4.12 / Table in §6.2.11).
pub const SEG_LVL_ALT_Q: usize = 0;
pub const SEG_LVL_ALT_L: usize = 1;
pub const SEG_LVL_REF_FRAME: usize = 2;
pub const SEG_LVL_SKIP: usize = 3;
/// `MAX_LOOP_FILTER`.
pub const MAX_LOOP_FILTER: i32 = 63;
/// Loop filter deltas after `setup_past_independence()` (§7.2).
pub const LOOP_FILTER_REF_DELTAS_DEFAULT: [i8; 4] = [1, 0, -1, -1];

const SEGMENTATION_FEATURE_BITS: [u32; SEG_LVL_MAX] = [8, 6, 2, 0];
const SEGMENTATION_FEATURE_SIGNED: [bool; SEG_LVL_MAX] = [true, true, false, false];
const CS_RGB: u8 = 7;
const MIN_TILE_WIDTH_B64: u32 = 4;
const MAX_TILE_WIDTH_B64: u32 = 64;

/// `frame_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Vp9FrameType {
    #[default]
    Key,
    NonKey,
}

/// `interpolation_filter` (§7.2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Vp9InterpolationFilter {
    #[default]
    EightTap,
    EightTapSmooth,
    EightTapSharp,
    Bilinear,
    Switchable,
}

impl Vp9InterpolationFilter {
    /// The spec's numeric `interpolation_filter` value (§7.2.7: EIGHTTAP 0,
    /// EIGHTTAP_SMOOTH 1, EIGHTTAP_SHARP 2, BILINEAR 3, SWITCHABLE 4) — the
    /// type after the `literal_to_type` mapping, not the coded literal.
    pub fn type_code(self) -> u8 {
        match self {
            Vp9InterpolationFilter::EightTap => 0,
            Vp9InterpolationFilter::EightTapSmooth => 1,
            Vp9InterpolationFilter::EightTapSharp => 2,
            Vp9InterpolationFilter::Bilinear => 3,
            Vp9InterpolationFilter::Switchable => 4,
        }
    }
}

/// `color_config()` (§6.2.2) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Vp9ColorConfig {
    pub bit_depth: u8,
    pub color_space: u8,
    pub color_range: bool,
    pub subsampling_x: bool,
    pub subsampling_y: bool,
}

impl Default for Vp9ColorConfig {
    /// The profile 0 intra-only inference (BT.601, 4:2:0, 8 bits).
    fn default() -> Self {
        Vp9ColorConfig {
            bit_depth: 8,
            color_space: 2,
            color_range: false,
            subsampling_x: true,
            subsampling_y: true,
        }
    }
}

/// `loop_filter_params()` (§6.2.8) with the deltas in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Vp9LoopFilter {
    pub level: u8,
    pub sharpness: u8,
    pub delta_enabled: bool,
    pub delta_update: bool,
    /// Coded `update_ref_delta` values (`None` when not updated).
    pub coded_ref_deltas: [Option<i8>; 4],
    pub coded_mode_deltas: [Option<i8>; 2],
    /// `loop_filter_ref_deltas[]` in force for the frame.
    pub ref_deltas: [i8; 4],
    /// `loop_filter_mode_deltas[]` in force for the frame.
    pub mode_deltas: [i8; 2],
}

/// `quantization_params()` (§6.2.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Vp9Quantization {
    pub base_q_idx: u8,
    pub delta_q_y_dc: i8,
    pub delta_q_uv_dc: i8,
    pub delta_q_uv_ac: i8,
    /// `Lossless`.
    pub lossless: bool,
}

/// `segmentation_params()` (§6.2.11) with the features in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Vp9Segmentation {
    pub enabled: bool,
    pub update_map: bool,
    /// `segmentation_tree_probs` (255 when not coded).
    pub tree_probs: [u8; 7],
    pub temporal_update: bool,
    /// `segmentation_pred_prob` (255 when not coded).
    pub pred_probs: [u8; 3],
    pub update_data: bool,
    /// `segmentation_abs_or_delta_update` in force.
    pub abs_or_delta_update: bool,
    /// `FeatureEnabled[][]` in force.
    pub feature_enabled: [[bool; SEG_LVL_MAX]; MAX_SEGMENTS],
    /// `FeatureData[][]` in force.
    pub feature_data: [[i16; SEG_LVL_MAX]; MAX_SEGMENTS],
}

impl Vp9Segmentation {
    /// `seg_feature_active()` for `segment_id`.
    pub fn feature_active(&self, segment_id: usize, feature: usize) -> bool {
        self.enabled && self.feature_enabled[segment_id][feature]
    }
}

/// `tile_info()` (§6.2.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Vp9TileInfo {
    pub tile_cols_log2: u8,
    pub tile_rows_log2: u8,
}

/// A parsed uncompressed header with every value in force.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Vp9FrameHeader {
    pub profile: u8,
    pub show_existing_frame: bool,
    pub frame_to_show_map_idx: u8,
    pub frame_type: Vp9FrameType,
    pub show_frame: bool,
    pub error_resilient_mode: bool,
    pub intra_only: bool,
    pub reset_frame_context: u8,
    /// The colour configuration in force (coded or inherited).
    pub color: Vp9ColorConfig,
    pub frame_width: u32,
    pub frame_height: u32,
    pub render_and_frame_size_different: bool,
    pub render_width: u32,
    pub render_height: u32,
    /// 0xFF for key frames.
    pub refresh_frame_flags: u8,
    pub ref_frame_idx: [u8; 3],
    /// `ref_frame_sign_bias[ LAST_FRAME..=ALTREF_FRAME ]` in force
    /// (cleared by `setup_past_independence()` in error-resilient frames).
    pub ref_frame_sign_bias: [bool; 3],
    /// The coded `ref_frame_sign_bias` bits.
    pub coded_ref_frame_sign_bias: [bool; 3],
    /// `frame_size_with_refs()`: the reference whose size was copied.
    pub found_ref: Option<u8>,
    pub allow_high_precision_mv: bool,
    pub interpolation_filter: Vp9InterpolationFilter,
    pub refresh_frame_context: bool,
    pub frame_parallel_decoding_mode: bool,
    /// The coded `frame_context_idx`.
    pub coded_frame_context_idx: u8,
    /// `frame_context_idx` after the intra / error-resilient reset.
    pub frame_context_idx: u8,
    pub loop_filter: Vp9LoopFilter,
    pub quantization: Vp9Quantization,
    pub segmentation: Vp9Segmentation,
    pub tile_info: Vp9TileInfo,
    /// `header_size_in_bytes` (the compressed header).
    pub header_size_in_bytes: u16,
    /// Bytes of the uncompressed header incl. `trailing_bits()`.
    pub uncompressed_header_size: usize,
}

impl Vp9FrameHeader {
    /// `FrameIsIntra`.
    pub fn is_intra(&self) -> bool {
        self.frame_type == Vp9FrameType::Key || self.intra_only
    }

    /// `get_qindex()` for `segment_id` (§8.6.1).
    pub fn qindex(&self, segment_id: usize) -> u8 {
        let s = &self.segmentation;
        let base = i32::from(self.quantization.base_q_idx);
        if s.feature_active(segment_id, SEG_LVL_ALT_Q) {
            let data = i32::from(s.feature_data[segment_id][SEG_LVL_ALT_Q]);
            let v = if s.abs_or_delta_update {
                data
            } else {
                base + data
            };
            v.clamp(0, 255) as u8
        } else {
            base as u8
        }
    }

    /// `get_dc_quant( plane )` for `segment_id`.
    pub fn dc_quant(&self, plane: usize, segment_id: usize) -> u16 {
        let q = &self.quantization;
        let delta = if plane == 0 {
            q.delta_q_y_dc
        } else {
            q.delta_q_uv_dc
        };
        dc_q(
            self.color.bit_depth,
            i32::from(self.qindex(segment_id)) + i32::from(delta),
        )
    }

    /// `get_ac_quant( plane )` for `segment_id`.
    pub fn ac_quant(&self, plane: usize, segment_id: usize) -> u16 {
        let q = &self.quantization;
        let delta = if plane == 0 { 0 } else { q.delta_q_uv_ac };
        ac_q(
            self.color.bit_depth,
            i32::from(self.qindex(segment_id)) + i32::from(delta),
        )
    }

    /// `LvlLookup[ segment_id ][ ref ][ mode ]` (§8.8.1); `ref` 0 is
    /// INTRA_FRAME (only mode 0 is meaningful there), 1..=3 LAST /
    /// GOLDEN / ALTREF.
    pub fn loop_filter_levels(&self) -> [[[u8; 2]; 4]; MAX_SEGMENTS] {
        let lf = &self.loop_filter;
        let s = &self.segmentation;
        let shift = lf.level >> 5;
        let mut out = [[[0u8; 2]; 4]; MAX_SEGMENTS];
        for (seg, table) in out.iter_mut().enumerate() {
            let mut lvl = i32::from(lf.level);
            if s.feature_active(seg, SEG_LVL_ALT_L) {
                let d = i32::from(s.feature_data[seg][SEG_LVL_ALT_L]);
                lvl = if s.abs_or_delta_update { d } else { d + lvl };
                lvl = lvl.clamp(0, MAX_LOOP_FILTER);
            }
            if !lf.delta_enabled {
                *table = [[lvl as u8; 2]; 4];
                continue;
            }
            let intra = lvl + (i32::from(lf.ref_deltas[0]) << shift);
            table[0] = [intra.clamp(0, MAX_LOOP_FILTER) as u8; 2];
            for (r, row) in table.iter_mut().enumerate().skip(1) {
                for (m, v) in row.iter_mut().enumerate() {
                    let l = lvl
                        + (i32::from(lf.ref_deltas[r]) << shift)
                        + (i32::from(lf.mode_deltas[m]) << shift);
                    *v = l.clamp(0, MAX_LOOP_FILTER) as u8;
                }
            }
        }
        out
    }
}

/// `dc_q( b )` (§8.6.1).
pub fn dc_q(bit_depth: u8, b: i32) -> u16 {
    DC_QLOOKUP[usize::from(bit_depth.saturating_sub(8) >> 1).min(2)][b.clamp(0, 255) as usize]
}

/// `ac_q( b )` (§8.6.1).
pub fn ac_q(bit_depth: u8, b: i32) -> u16 {
    AC_QLOOKUP[usize::from(bit_depth.saturating_sub(8) >> 1).min(2)][b.clamp(0, 255) as usize]
}

/// Split a chunk into its frames (Annex B superframe index), or return
/// the whole chunk when it carries no index.
pub fn split_superframe(chunk: &[u8]) -> Vec<&[u8]> {
    let Some(&last) = chunk.last() else {
        return Vec::new();
    };
    if last & 0xE0 != 0xC0 {
        return vec![chunk];
    }
    let sz_bytes = usize::from((last >> 3) & 3) + 1;
    let frames = usize::from(last & 7) + 1;
    let index = 2 + frames * sz_bytes;
    if chunk.len() < index || chunk[chunk.len() - index] != last {
        return vec![chunk];
    }
    let mut out = Vec::with_capacity(frames);
    let mut at = 0usize;
    let mut p = chunk.len() - index + 1;
    for _ in 0..frames {
        let mut size = 0usize;
        for k in 0..sz_bytes {
            size |= usize::from(chunk[p + k]) << (8 * k);
        }
        p += sz_bytes;
        let end = at.saturating_add(size);
        if end > chunk.len() - index {
            break;
        }
        if size > 0 {
            out.push(&chunk[at..end]);
        }
        at = end;
    }
    out
}

/// State a VP9 stream carries from frame to frame for header parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Vp9State {
    /// `RefFrameWidth[]` / `RefFrameHeight[]` (0 when empty).
    pub ref_size: [(u32, u32); 8],
    /// Bit depth / subsampling of each reference slot.
    pub ref_color: [Option<Vp9ColorConfig>; 8],
    /// The colour configuration later inter frames inherit.
    pub color: Option<Vp9ColorConfig>,
    pub loop_filter_ref_deltas: [i8; 4],
    pub loop_filter_mode_deltas: [i8; 2],
    pub segmentation_abs_or_delta_update: bool,
    pub feature_enabled: [[bool; SEG_LVL_MAX]; MAX_SEGMENTS],
    pub feature_data: [[i16; SEG_LVL_MAX]; MAX_SEGMENTS],
    /// `segmentation_tree_probs` / `segmentation_pred_prob` of the last
    /// frame that coded them.
    pub tree_probs: [u8; 7],
    pub pred_probs: [u8; 3],
}

impl Default for Vp9State {
    fn default() -> Self {
        Vp9State {
            ref_size: [(0, 0); 8],
            ref_color: [None; 8],
            color: None,
            loop_filter_ref_deltas: LOOP_FILTER_REF_DELTAS_DEFAULT,
            loop_filter_mode_deltas: [0; 2],
            segmentation_abs_or_delta_update: false,
            feature_enabled: [[false; SEG_LVL_MAX]; MAX_SEGMENTS],
            feature_data: [[0; SEG_LVL_MAX]; MAX_SEGMENTS],
            tree_probs: [255; 7],
            pred_probs: [255; 3],
        }
    }
}

impl Vp9State {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse one frame's uncompressed header (`frame` is one frame of a
    /// chunk, see [`split_superframe`]).
    pub fn parse_frame(&self, frame: &[u8]) -> Result<Vp9FrameHeader, BitstreamError> {
        let mut r = BitReader::new(frame);
        let mut h = Vp9FrameHeader::default();
        if r.u(2) != 2 {
            return Err(BitstreamError::invalid("VP9 frame_marker != 2"));
        }
        let low = r.u(1);
        let high = r.u(1);
        h.profile = ((high << 1) | low) as u8;
        if h.profile == 3 && r.u(1) != 0 {
            return Err(BitstreamError::invalid("VP9 profile 3 reserved_zero set"));
        }
        h.show_existing_frame = r.u(1) != 0;
        if h.show_existing_frame {
            h.frame_to_show_map_idx = r.u(3) as u8;
            let i = usize::from(h.frame_to_show_map_idx);
            (h.frame_width, h.frame_height) = self.ref_size[i];
            (h.render_width, h.render_height) = self.ref_size[i];
            h.color = self.ref_color[i].or(self.color).unwrap_or_default();
            h.show_frame = true;
            h.uncompressed_header_size = r.bit_pos().div_ceil(8);
            if h.uncompressed_header_size > frame.len() {
                return Err(BitstreamError::unexpected_end(
                    "VP9 show_existing_frame header",
                ));
            }
            return Ok(h);
        }
        h.frame_type = if r.u(1) == 0 {
            Vp9FrameType::Key
        } else {
            Vp9FrameType::NonKey
        };
        h.show_frame = r.u(1) != 0;
        h.error_resilient_mode = r.u(1) != 0;
        let mut sign_bias = [false; 3];
        if h.frame_type == Vp9FrameType::Key {
            sync_code(&mut r)?;
            h.color = color_config(&mut r, h.profile)?;
            frame_size(&mut r, &mut h);
            render_size(&mut r, &mut h);
            h.refresh_frame_flags = 0xFF;
        } else {
            h.intra_only = if h.show_frame { false } else { r.u(1) != 0 };
            h.reset_frame_context = if h.error_resilient_mode {
                0
            } else {
                r.u(2) as u8
            };
            if h.intra_only {
                sync_code(&mut r)?;
                h.color = if h.profile > 0 {
                    color_config(&mut r, h.profile)?
                } else {
                    Vp9ColorConfig::default()
                };
                h.refresh_frame_flags = r.u(8) as u8;
                frame_size(&mut r, &mut h);
                render_size(&mut r, &mut h);
            } else {
                h.color = self.color.ok_or_else(|| {
                    BitstreamError::invalid("VP9 inter frame before any key frame")
                })?;
                h.refresh_frame_flags = r.u(8) as u8;
                for (idx, bias) in h.ref_frame_idx.iter_mut().zip(sign_bias.iter_mut()) {
                    *idx = r.u(3) as u8;
                    *bias = r.u(1) != 0;
                }
                h.coded_ref_frame_sign_bias = sign_bias;
                // frame_size_with_refs()
                for i in 0..3 {
                    if r.u(1) == 1 {
                        let (w, hh) = self.ref_size[usize::from(h.ref_frame_idx[i])];
                        if w == 0 || hh == 0 {
                            return Err(BitstreamError::invalid(
                                "VP9 frame size taken from an empty reference slot",
                            ));
                        }
                        h.frame_width = w;
                        h.frame_height = hh;
                        h.found_ref = Some(i as u8);
                        break;
                    }
                }
                if h.found_ref.is_none() {
                    frame_size(&mut r, &mut h);
                }
                render_size(&mut r, &mut h);
                h.allow_high_precision_mv = r.u(1) != 0;
                h.interpolation_filter = if r.u(1) == 1 {
                    Vp9InterpolationFilter::Switchable
                } else {
                    [
                        Vp9InterpolationFilter::EightTapSmooth,
                        Vp9InterpolationFilter::EightTap,
                        Vp9InterpolationFilter::EightTapSharp,
                        Vp9InterpolationFilter::Bilinear,
                    ][r.u(2) as usize]
                };
            }
        }
        if !h.error_resilient_mode {
            h.refresh_frame_context = r.u(1) != 0;
            h.frame_parallel_decoding_mode = r.u(1) != 0;
        } else {
            h.frame_parallel_decoding_mode = true;
        }
        h.coded_frame_context_idx = r.u(2) as u8;
        h.frame_context_idx = h.coded_frame_context_idx;
        let past_independence = h.is_intra() || h.error_resilient_mode;
        let (mut ref_deltas, mut mode_deltas) =
            (self.loop_filter_ref_deltas, self.loop_filter_mode_deltas);
        let mut seg = Vp9Segmentation {
            abs_or_delta_update: self.segmentation_abs_or_delta_update,
            feature_enabled: self.feature_enabled,
            feature_data: self.feature_data,
            tree_probs: [255; 7],
            pred_probs: [255; 3],
            ..Vp9Segmentation::default()
        };
        if past_independence {
            // setup_past_independence() (§7.2).
            ref_deltas = LOOP_FILTER_REF_DELTAS_DEFAULT;
            mode_deltas = [0; 2];
            seg.abs_or_delta_update = false;
            seg.feature_enabled = [[false; SEG_LVL_MAX]; MAX_SEGMENTS];
            seg.feature_data = [[0; SEG_LVL_MAX]; MAX_SEGMENTS];
            sign_bias = [false; 3];
            h.frame_context_idx = 0;
        }
        h.ref_frame_sign_bias = sign_bias;

        // loop_filter_params()
        let lf = &mut h.loop_filter;
        lf.level = r.u(6) as u8;
        lf.sharpness = r.u(3) as u8;
        lf.delta_enabled = r.u(1) != 0;
        if lf.delta_enabled {
            lf.delta_update = r.u(1) != 0;
            if lf.delta_update {
                for (coded, d) in lf.coded_ref_deltas.iter_mut().zip(ref_deltas.iter_mut()) {
                    if r.u(1) == 1 {
                        *d = su6(&mut r);
                        *coded = Some(*d);
                    }
                }
                for (coded, d) in lf.coded_mode_deltas.iter_mut().zip(mode_deltas.iter_mut()) {
                    if r.u(1) == 1 {
                        *d = su6(&mut r);
                        *coded = Some(*d);
                    }
                }
            }
        }
        lf.ref_deltas = ref_deltas;
        lf.mode_deltas = mode_deltas;

        // quantization_params()
        let q = &mut h.quantization;
        q.base_q_idx = r.u(8) as u8;
        q.delta_q_y_dc = delta_q(&mut r);
        q.delta_q_uv_dc = delta_q(&mut r);
        q.delta_q_uv_ac = delta_q(&mut r);
        q.lossless = q.base_q_idx == 0
            && q.delta_q_y_dc == 0
            && q.delta_q_uv_dc == 0
            && q.delta_q_uv_ac == 0;

        // segmentation_params()
        seg.enabled = r.u(1) != 0;
        if seg.enabled {
            seg.update_map = r.u(1) != 0;
            if seg.update_map {
                for p in seg.tree_probs.iter_mut() {
                    *p = read_prob(&mut r);
                }
                seg.temporal_update = r.u(1) != 0;
                for p in seg.pred_probs.iter_mut() {
                    *p = if seg.temporal_update {
                        read_prob(&mut r)
                    } else {
                        255
                    };
                }
            }
            seg.update_data = r.u(1) != 0;
            if seg.update_data {
                seg.abs_or_delta_update = r.u(1) != 0;
                for i in 0..MAX_SEGMENTS {
                    for j in 0..SEG_LVL_MAX {
                        let mut value = 0i16;
                        let enabled = r.u(1) != 0;
                        seg.feature_enabled[i][j] = enabled;
                        if enabled {
                            value = r.u(SEGMENTATION_FEATURE_BITS[j]) as i16;
                            if SEGMENTATION_FEATURE_SIGNED[j] && r.u(1) == 1 {
                                value = -value;
                            }
                        }
                        seg.feature_data[i][j] = value;
                    }
                }
            }
        }
        h.segmentation = seg;

        // tile_info()
        let mi_cols = h.frame_width.div_ceil(8);
        let sb64_cols = mi_cols.div_ceil(8);
        let mut min_log2 = 0u32;
        while (MAX_TILE_WIDTH_B64 << min_log2) < sb64_cols {
            min_log2 += 1;
        }
        let mut max_log2 = 1u32;
        while (sb64_cols >> max_log2) >= MIN_TILE_WIDTH_B64 {
            max_log2 += 1;
        }
        max_log2 -= 1;
        let mut cols = min_log2;
        while cols < max_log2 {
            if r.u(1) == 1 {
                cols += 1;
            } else {
                break;
            }
        }
        h.tile_info.tile_cols_log2 = cols as u8;
        let mut rows = r.u(1);
        if rows == 1 {
            rows += r.u(1);
        }
        h.tile_info.tile_rows_log2 = rows as u8;
        h.header_size_in_bytes = r.u(16) as u16;
        r.align_to_byte();
        h.uncompressed_header_size = r.bit_pos() / 8;
        if h.uncompressed_header_size > frame.len() {
            return Err(BitstreamError::unexpected_end("VP9 uncompressed header"));
        }
        if h.header_size_in_bytes == 0 {
            return Err(BitstreamError::invalid("VP9 header_size_in_bytes == 0"));
        }
        Ok(h)
    }

    /// Record what a decoded frame leaves behind (§7.2 / §8.10
    /// reference update for `refresh_frame_flags`, persistent deltas
    /// and segmentation features). A `show_existing_frame` header
    /// leaves nothing.
    pub fn commit(&mut self, h: &Vp9FrameHeader) {
        if h.show_existing_frame {
            return;
        }
        if h.is_intra() {
            self.color = Some(h.color);
        }
        for i in 0..8 {
            if h.refresh_frame_flags & (1 << i) != 0 {
                self.ref_size[i] = (h.frame_width, h.frame_height);
                self.ref_color[i] = Some(h.color);
            }
        }
        self.loop_filter_ref_deltas = h.loop_filter.ref_deltas;
        self.loop_filter_mode_deltas = h.loop_filter.mode_deltas;
        self.segmentation_abs_or_delta_update = h.segmentation.abs_or_delta_update;
        self.feature_enabled = h.segmentation.feature_enabled;
        self.feature_data = h.segmentation.feature_data;
        if h.segmentation.update_map {
            self.tree_probs = h.segmentation.tree_probs;
            self.pred_probs = h.segmentation.pred_probs;
        }
    }

    /// [`Vp9State::parse_frame`] then [`Vp9State::commit`].
    pub fn decode_frame_header(&mut self, frame: &[u8]) -> Result<Vp9FrameHeader, BitstreamError> {
        let h = self.parse_frame(frame)?;
        self.commit(&h);
        Ok(h)
    }
}

fn sync_code(r: &mut BitReader<'_>) -> Result<(), BitstreamError> {
    if r.u(24) != 0x49_8342 {
        return Err(BitstreamError::invalid("VP9 frame_sync_code"));
    }
    Ok(())
}

fn color_config(r: &mut BitReader<'_>, profile: u8) -> Result<Vp9ColorConfig, BitstreamError> {
    let bit_depth = if profile >= 2 {
        if r.u(1) == 1 { 12 } else { 10 }
    } else {
        8
    };
    let color_space = r.u(3) as u8;
    let mut c = Vp9ColorConfig {
        bit_depth,
        color_space,
        color_range: true,
        subsampling_x: true,
        subsampling_y: true,
    };
    if color_space != CS_RGB {
        c.color_range = r.u(1) != 0;
        if profile == 1 || profile == 3 {
            c.subsampling_x = r.u(1) != 0;
            c.subsampling_y = r.u(1) != 0;
            if r.u(1) != 0 {
                return Err(BitstreamError::invalid(
                    "VP9 color_config reserved_zero set",
                ));
            }
        }
    } else {
        if profile == 0 || profile == 2 {
            return Err(BitstreamError::invalid("VP9 RGB in profile 0 / 2"));
        }
        c.subsampling_x = false;
        c.subsampling_y = false;
        if r.u(1) != 0 {
            return Err(BitstreamError::invalid(
                "VP9 color_config reserved_zero set",
            ));
        }
    }
    Ok(c)
}

fn frame_size(r: &mut BitReader<'_>, h: &mut Vp9FrameHeader) {
    h.frame_width = r.u(16) + 1;
    h.frame_height = r.u(16) + 1;
}

fn render_size(r: &mut BitReader<'_>, h: &mut Vp9FrameHeader) {
    h.render_and_frame_size_different = r.u(1) != 0;
    if h.render_and_frame_size_different {
        h.render_width = r.u(16) + 1;
        h.render_height = r.u(16) + 1;
    } else {
        h.render_width = h.frame_width;
        h.render_height = h.frame_height;
    }
}

/// `s(6)` (§6.2.8): magnitude then sign bit.
fn su6(r: &mut BitReader<'_>) -> i8 {
    let v = r.u(6) as i8;
    if r.u(1) == 1 { -v } else { v }
}

fn delta_q(r: &mut BitReader<'_>) -> i8 {
    if r.u(1) == 1 {
        let v = r.u(4) as i8;
        if r.u(1) == 1 { -v } else { v }
    } else {
        0
    }
}

fn read_prob(r: &mut BitReader<'_>) -> u8 {
    if r.u(1) == 1 { r.u(8) as u8 } else { 255 }
}
