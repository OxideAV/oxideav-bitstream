//! AV1 frame header OBU for every frame type (§5.9) with the reference
//! state it reads and the reference frame update / loading processes
//! (§7.20 / §7.21) that maintain it.
//!
//! [`Av1RefState::parse_frame_header`] walks `uncompressed_header()` for
//! key, inter, intra-only and switch frames and `show_existing_frame`
//! headers: frame ids, `ref_order_hint[]`, `frame_refs_short_signaling`
//! with the §7.8 set_frame_refs process, `frame_size_with_refs()`,
//! superres, tile info, quantization incl. matrices, segmentation and
//! loop filter deltas loaded from the primary reference frame
//! (`load_previous()`) or reset (`setup_past_independence()`), delta
//! q / lf, CDEF, loop restoration, TX mode, reference select, skip
//! mode, warped motion, global motion against `PrevGmParams`, and film
//! grain incl. `load_grain_params()`. The returned header holds every
//! value in force for the frame. [`Av1RefState::update`] then applies
//! the reference frame update process (with the §7.21 load first for a
//! shown existing key frame).
//!
//! Large scale tile decoding (Annex D) is out of scope.

use super::sequence::{SELECT, SequenceHeader};
use super::tables::DIV_LUT;
use crate::BitstreamError;
use crate::bit_reader::BitReader;

pub const NUM_REF_FRAMES: usize = 8;
pub const REFS_PER_FRAME: usize = 7;
pub const TOTAL_REFS_PER_FRAME: usize = 8;
pub const PRIMARY_REF_NONE: u8 = 7;
pub const MAX_SEGMENTS: usize = 8;
pub const SEG_LVL_MAX: usize = 8;
pub const MAX_LOOP_FILTER: i32 = 63;
pub const WARPEDMODEL_PREC_BITS: u32 = 16;
/// `loop_filter_ref_deltas[]` after `setup_past_independence()`
/// (INTRA, LAST, LAST2, LAST3, GOLDEN, BWDREF, ALTREF2, ALTREF).
pub const LOOP_FILTER_REF_DELTAS_DEFAULT: [i8; TOTAL_REFS_PER_FRAME] = [1, 0, 0, 0, -1, 0, -1, -1];

const SEGMENTATION_FEATURE_BITS: [u32; SEG_LVL_MAX] = [8, 6, 6, 6, 6, 3, 0, 0];
const SEGMENTATION_FEATURE_SIGNED: [bool; SEG_LVL_MAX] =
    [true, true, true, true, true, false, false, false];
const SEGMENTATION_FEATURE_MAX: [i32; SEG_LVL_MAX] = [255, 63, 63, 63, 63, 7, 0, 0];

/// `PrevGmParams` / `gm_params` defaults: identity for every reference.
pub fn default_gm_params() -> [[i32; 6]; TOTAL_REFS_PER_FRAME] {
    [[
        0,
        0,
        1 << WARPEDMODEL_PREC_BITS,
        0,
        0,
        1 << WARPEDMODEL_PREC_BITS,
    ]; TOTAL_REFS_PER_FRAME]
}

/// `frame_type` (§6.8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Av1FrameType {
    #[default]
    Key,
    Inter,
    IntraOnly,
    Switch,
}

impl Av1FrameType {
    pub fn from_raw(v: u32) -> Self {
        match v {
            0 => Av1FrameType::Key,
            1 => Av1FrameType::Inter,
            2 => Av1FrameType::IntraOnly,
            _ => Av1FrameType::Switch,
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Av1FrameType::Key => 0,
            Av1FrameType::Inter => 1,
            Av1FrameType::IntraOnly => 2,
            Av1FrameType::Switch => 3,
        }
    }
}

/// `interpolation_filter` (§6.8.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Av1InterpolationFilter {
    #[default]
    EightTap,
    EightTapSmooth,
    EightTapSharp,
    Bilinear,
    Switchable,
}

impl Av1InterpolationFilter {
    /// The coded / spec numeric value (0..=4).
    pub fn code(self) -> u8 {
        match self {
            Av1InterpolationFilter::EightTap => 0,
            Av1InterpolationFilter::EightTapSmooth => 1,
            Av1InterpolationFilter::EightTapSharp => 2,
            Av1InterpolationFilter::Bilinear => 3,
            Av1InterpolationFilter::Switchable => 4,
        }
    }
}

/// `TxMode` (§6.8.21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Av1TxMode {
    #[default]
    Only4x4,
    Largest,
    Select,
}

/// `FrameRestorationType` (§6.10.15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Av1RestorationType {
    #[default]
    None,
    Wiener,
    Sgrproj,
    Switchable,
}

impl Av1RestorationType {
    /// The spec value (RESTORE_NONE 0, WIENER 1, SGRPROJ 2, SWITCHABLE 3).
    pub fn code(self) -> u8 {
        match self {
            Av1RestorationType::None => 0,
            Av1RestorationType::Wiener => 1,
            Av1RestorationType::Sgrproj => 2,
            Av1RestorationType::Switchable => 3,
        }
    }
}

/// Global motion model type (§6.8.17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Av1WarpModel {
    #[default]
    Identity,
    Translation,
    RotZoom,
    Affine,
}

impl Av1WarpModel {
    pub fn code(self) -> u8 {
        match self {
            Av1WarpModel::Identity => 0,
            Av1WarpModel::Translation => 1,
            Av1WarpModel::RotZoom => 2,
            Av1WarpModel::Affine => 3,
        }
    }
}

/// Frame / render / superres sizes (§5.9.5 – §5.9.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Av1FrameSize {
    pub frame_width: u32,
    pub frame_height: u32,
    pub upscaled_width: u32,
    pub render_width: u32,
    pub render_height: u32,
    pub use_superres: bool,
    /// `SuperresDenom` (8 without superres).
    pub superres_denom: u32,
    pub mi_cols: u32,
    pub mi_rows: u32,
    /// `found_ref`: the reference whose size was copied.
    pub found_ref: Option<u8>,
    pub render_and_frame_size_different: bool,
}

/// `tile_info()` (§5.9.15).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Av1TileInfo {
    pub uniform_tile_spacing_flag: bool,
    pub tile_cols_log2: u32,
    pub tile_rows_log2: u32,
    pub tile_cols: u32,
    pub tile_rows: u32,
    /// `MiColStarts[0..=TileCols]`.
    pub mi_col_starts: Vec<u32>,
    /// `MiRowStarts[0..=TileRows]`.
    pub mi_row_starts: Vec<u32>,
    pub context_update_tile_id: u32,
    /// `TileSizeBytes` (4 when not coded).
    pub tile_size_bytes: u8,
}

impl Av1TileInfo {
    /// Tile column widths in superblocks (`sb_shift` 4 or 5).
    pub fn col_widths_sb(&self, sb_shift: u32) -> Vec<u32> {
        let r = (1u32 << sb_shift) - 1;
        self.mi_col_starts
            .windows(2)
            .map(|w| (w[1] - w[0] + r) >> sb_shift)
            .collect()
    }

    /// Tile row heights in superblocks.
    pub fn row_heights_sb(&self, sb_shift: u32) -> Vec<u32> {
        let r = (1u32 << sb_shift) - 1;
        self.mi_row_starts
            .windows(2)
            .map(|w| (w[1] - w[0] + r) >> sb_shift)
            .collect()
    }
}

/// `quantization_params()` (§5.9.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Av1Quantization {
    pub base_q_idx: u8,
    pub delta_q_y_dc: i8,
    pub diff_uv_delta: bool,
    pub delta_q_u_dc: i8,
    pub delta_q_u_ac: i8,
    pub delta_q_v_dc: i8,
    pub delta_q_v_ac: i8,
    pub using_qmatrix: bool,
    pub qm_y: u8,
    pub qm_u: u8,
    pub qm_v: u8,
}

/// `segmentation_params()` (§5.9.14), features in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Av1Segmentation {
    pub enabled: bool,
    pub update_map: bool,
    pub temporal_update: bool,
    pub update_data: bool,
    pub feature_enabled: [[bool; SEG_LVL_MAX]; MAX_SEGMENTS],
    pub feature_data: [[i16; SEG_LVL_MAX]; MAX_SEGMENTS],
    pub seg_id_pre_skip: bool,
    pub last_active_seg_id: u8,
}

/// `delta_q_params()` / `delta_lf_params()` (§5.9.17 / §5.9.18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Av1DeltaParams {
    pub delta_q_present: bool,
    pub delta_q_res: u8,
    pub delta_lf_present: bool,
    pub delta_lf_res: u8,
    pub delta_lf_multi: bool,
}

/// `loop_filter_params()` (§5.9.11), deltas in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Av1LoopFilter {
    /// `[0]` / `[1]` luma vertical / horizontal, `[2]` U, `[3]` V.
    pub level: [u8; 4],
    pub sharpness: u8,
    /// `loop_filter_delta_enabled`. On frames where `loop_filter_params()`
    /// codes nothing (coded lossless or `allow_intrabc`), this is not a coded
    /// value: it is `true` when `primary_ref_frame == PRIMARY_REF_NONE` (the
    /// §7.20 default deltas are in force) and `false` otherwise.
    pub delta_enabled: bool,
    pub delta_update: bool,
    pub ref_deltas: [i8; TOTAL_REFS_PER_FRAME],
    pub mode_deltas: [i8; 2],
}

/// `cdef_params()` (§5.9.19), secondary strengths as used (3 → 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Av1Cdef {
    pub damping: u8,
    pub bits: u8,
    pub y_pri_strength: [u8; 8],
    pub y_sec_strength: [u8; 8],
    pub uv_pri_strength: [u8; 8],
    pub uv_sec_strength: [u8; 8],
}

/// `lr_params()` (§5.9.20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Av1LoopRestoration {
    pub frame_restoration_type: [Av1RestorationType; 3],
    pub uses_lr: bool,
    /// The coded `lr_unit_shift` (+ extra shift, +1 with 128x128 SBs).
    pub lr_unit_shift: u8,
    pub lr_uv_shift: u8,
    /// `LoopRestorationSize[ plane ]`.
    pub loop_restoration_size: [u32; 3],
}

/// `global_motion_params()` (§5.9.24) — index 1..=7 per reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Av1GlobalMotion {
    pub gm_type: [Av1WarpModel; TOTAL_REFS_PER_FRAME],
    pub gm_params: [[i32; 6]; TOTAL_REFS_PER_FRAME],
}

impl Default for Av1GlobalMotion {
    fn default() -> Self {
        Av1GlobalMotion {
            gm_type: [Av1WarpModel::Identity; TOTAL_REFS_PER_FRAME],
            gm_params: default_gm_params(),
        }
    }
}

/// `film_grain_params()` (§5.9.30) — all zero after `reset_grain_params()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Av1FilmGrain {
    pub apply_grain: bool,
    pub grain_seed: u16,
    pub update_grain: bool,
    pub film_grain_params_ref_idx: u8,
    pub num_y_points: u8,
    pub point_y_value: [u8; 16],
    pub point_y_scaling: [u8; 16],
    pub chroma_scaling_from_luma: bool,
    pub num_cb_points: u8,
    pub point_cb_value: [u8; 16],
    pub point_cb_scaling: [u8; 16],
    pub num_cr_points: u8,
    pub point_cr_value: [u8; 16],
    pub point_cr_scaling: [u8; 16],
    pub grain_scaling_minus_8: u8,
    pub ar_coeff_lag: u8,
    pub ar_coeffs_y_plus_128: [u8; 24],
    pub ar_coeffs_cb_plus_128: [u8; 25],
    pub ar_coeffs_cr_plus_128: [u8; 25],
    pub ar_coeff_shift_minus_6: u8,
    pub grain_scale_shift: u8,
    pub cb_mult: u8,
    pub cb_luma_mult: u8,
    pub cb_offset: u16,
    pub cr_mult: u8,
    pub cr_luma_mult: u8,
    pub cr_offset: u16,
    pub overlap_flag: bool,
    pub clip_to_restricted_range: bool,
}

/// A parsed frame header with every value in force.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Av1Frame {
    pub show_existing_frame: bool,
    pub frame_to_show_map_idx: u8,
    pub frame_presentation_time: Option<u32>,
    pub display_frame_id: u32,
    pub frame_type: Av1FrameType,
    /// `FrameIsIntra`.
    pub frame_is_intra: bool,
    pub show_frame: bool,
    pub showable_frame: bool,
    pub error_resilient_mode: bool,
    pub disable_cdf_update: bool,
    pub allow_screen_content_tools: bool,
    pub force_integer_mv: bool,
    pub current_frame_id: u32,
    pub frame_size_override_flag: bool,
    /// `OrderHint`.
    pub order_hint: u32,
    pub primary_ref_frame: u8,
    /// `buffer_removal_time[]` per operating point (`None` when absent).
    pub buffer_removal_time: Vec<Option<u32>>,
    pub refresh_frame_flags: u8,
    /// The coded `ref_order_hint[]` (error-resilient frames).
    pub ref_order_hint: Option<[u32; NUM_REF_FRAMES]>,
    pub size: Av1FrameSize,
    pub allow_intrabc: bool,
    pub frame_refs_short_signaling: bool,
    pub last_frame_idx: u8,
    pub gold_frame_idx: u8,
    /// `ref_frame_idx[ 0..REFS_PER_FRAME ]` (LAST..ALTREF).
    pub ref_frame_idx: [u8; REFS_PER_FRAME],
    pub delta_frame_id_minus_1: [u32; REFS_PER_FRAME],
    pub allow_high_precision_mv: bool,
    pub interpolation_filter: Av1InterpolationFilter,
    pub is_motion_mode_switchable: bool,
    pub use_ref_frame_mvs: bool,
    /// `OrderHints[ LAST_FRAME..=ALTREF_FRAME ]` at index 1..=7.
    pub order_hints: [u32; TOTAL_REFS_PER_FRAME],
    /// `RefFrameSignBias[]` at index 1..=7.
    pub ref_frame_sign_bias: [bool; TOTAL_REFS_PER_FRAME],
    pub disable_frame_end_update_cdf: bool,
    pub tile_info: Av1TileInfo,
    pub quantization: Av1Quantization,
    pub segmentation: Av1Segmentation,
    pub delta: Av1DeltaParams,
    /// `CodedLossless`.
    pub coded_lossless: bool,
    /// `AllLossless`.
    pub all_lossless: bool,
    /// `LosslessArray[]`.
    pub lossless_array: [bool; MAX_SEGMENTS],
    pub loop_filter: Av1LoopFilter,
    pub cdef: Av1Cdef,
    pub lr: Av1LoopRestoration,
    pub tx_mode: Av1TxMode,
    pub reference_select: bool,
    pub skip_mode_present: bool,
    /// `SkipModeFrame[ 0..2 ]` when skip mode is allowed.
    pub skip_mode_frame: Option<[u8; 2]>,
    pub allow_warped_motion: bool,
    pub reduced_tx_set: bool,
    pub global_motion: Av1GlobalMotion,
    /// `PrevGmParams` the global motion parameters were coded against.
    pub prev_gm_params: [[i32; 6]; TOTAL_REFS_PER_FRAME],
    pub film_grain: Av1FilmGrain,
    /// `RefValid[]` after this header's own invalidations.
    pub ref_valid: [bool; NUM_REF_FRAMES],
    /// Bits of `uncompressed_header()`; the frame OBU's tile group
    /// starts at `header_bits.div_ceil(8)` (after `byte_alignment()`).
    pub header_bits: usize,
}

impl Av1Frame {
    /// `get_qindex( 1, segmentId )` (§7.12.2) — ignoring per-block deltas.
    pub fn qindex(&self, segment_id: usize) -> u8 {
        let s = &self.segmentation;
        let base = i32::from(self.quantization.base_q_idx);
        if s.enabled && s.feature_enabled[segment_id][0] {
            (base + i32::from(s.feature_data[segment_id][0])).clamp(0, 255) as u8
        } else {
            base as u8
        }
    }

    /// Superblock size shift in MI units (4 for 64x64, 5 for 128x128).
    pub fn sb_shift(seq: &SequenceHeader) -> u32 {
        if seq.use_128x128_superblock { 5 } else { 4 }
    }
}

/// What one reference slot holds (§7.20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Av1RefSlot {
    pub valid: bool,
    pub frame_id: u32,
    pub upscaled_width: u32,
    pub frame_width: u32,
    pub frame_height: u32,
    pub render_width: u32,
    pub render_height: u32,
    pub mi_cols: u32,
    pub mi_rows: u32,
    pub frame_type: Av1FrameType,
    pub showable_frame: bool,
    pub subsampling_x: bool,
    pub subsampling_y: bool,
    pub bit_depth: u8,
    /// `RefOrderHint`.
    pub order_hint: u32,
    /// `SavedOrderHints[ i ][ 1..=7 ]`.
    pub saved_order_hints: [u32; TOTAL_REFS_PER_FRAME],
    pub gm_params: [[i32; 6]; TOTAL_REFS_PER_FRAME],
    pub loop_filter_ref_deltas: [i8; TOTAL_REFS_PER_FRAME],
    pub loop_filter_mode_deltas: [i8; 2],
    pub feature_enabled: [[bool; SEG_LVL_MAX]; MAX_SEGMENTS],
    pub feature_data: [[i16; SEG_LVL_MAX]; MAX_SEGMENTS],
    pub film_grain: Av1FilmGrain,
}

/// The reference state of an AV1 decoder, as far as headers need it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Av1RefState {
    pub slots: [Av1RefSlot; NUM_REF_FRAMES],
    /// `current_frame_id` of the last frame (`PrevFrameID` source).
    pub current_frame_id: u32,
}

/// `get_relative_dist()` (§5.9.3).
pub fn relative_dist(seq: &SequenceHeader, a: u32, b: u32) -> i32 {
    if !seq.enable_order_hint || seq.order_hint_bits == 0 {
        return 0;
    }
    let diff = a as i32 - b as i32;
    let m = 1i32 << (seq.order_hint_bits - 1);
    (diff & (m - 1)) - (diff & m)
}

/// Output of the setup shear process (§7.11.3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Shear {
    pub warp_valid: bool,
    pub alpha: i32,
    pub beta: i32,
    pub gamma: i32,
    pub delta: i32,
}

fn round2signed(x: i64, n: u32) -> i64 {
    if n == 0 {
        return x;
    }
    if x >= 0 {
        (x + (1 << (n - 1))) >> n
    } else {
        -((-x + (1 << (n - 1))) >> n)
    }
}

/// The resolve divisor process (§7.11.3.7): `(divShift, divFactor)`.
fn resolve_divisor(d: i64) -> (u32, i64) {
    let a = d.unsigned_abs().max(1);
    let n = 63 - a.leading_zeros();
    let e = a as i64 - (1i64 << n);
    let f = if n > 8 {
        round2signed(e, n - 8)
    } else {
        e << (8 - n)
    };
    let factor = i64::from(DIV_LUT[f.clamp(0, 256) as usize]);
    (n + 14, if d < 0 { -factor } else { factor })
}

/// The setup shear process (§7.11.3.6) for one warp model; global
/// motion of a ROTZOOM / AFFINE reference is usable only when
/// `warp_valid`.
pub fn setup_shear(warp: &[i32; 6]) -> Shear {
    let clip = |v: i64| v.clamp(-32768, 32767);
    let alpha0 = clip(i64::from(warp[2]) - (1 << WARPEDMODEL_PREC_BITS));
    let beta0 = clip(i64::from(warp[3]));
    let (shift, factor) = resolve_divisor(i64::from(warp[2]));
    let v = i64::from(warp[4]) << WARPEDMODEL_PREC_BITS;
    let gamma0 = clip(round2signed(v * factor, shift));
    let w = i64::from(warp[3]) * i64::from(warp[4]);
    let delta0 =
        clip(i64::from(warp[5]) - round2signed(w * factor, shift) - (1 << WARPEDMODEL_PREC_BITS));
    let reduce = |x: i64| (round2signed(x, 6) << 6) as i32;
    let (alpha, beta, gamma, delta) = (
        reduce(alpha0),
        reduce(beta0),
        reduce(gamma0),
        reduce(delta0),
    );
    let warp_valid = 4 * alpha.abs() + 7 * beta.abs() < (1 << WARPEDMODEL_PREC_BITS)
        && 4 * gamma.abs() + 4 * delta.abs() < (1 << WARPEDMODEL_PREC_BITS);
    Shear {
        warp_valid,
        alpha,
        beta,
        gamma,
        delta,
    }
}

fn tile_log2(blk: u32, target: u32) -> u32 {
    let mut k = 0;
    while (u64::from(blk) << k) < u64::from(target) {
        k += 1;
    }
    k
}

fn su(r: &mut BitReader<'_>, n: u32) -> Result<i32, BitstreamError> {
    r.su(n)
}

fn read_delta_q(r: &mut BitReader<'_>) -> Result<i8, BitstreamError> {
    Ok(if r.u(1) != 0 { su(r, 7)? as i8 } else { 0 })
}

fn decode_subexp(r: &mut BitReader<'_>, num_syms: u32) -> Result<u32, BitstreamError> {
    let (mut i, mut mk, k) = (0u32, 0u32, 3u32);
    loop {
        let b2 = if i != 0 { k + i - 1 } else { k };
        let a = 1u32 << b2;
        if num_syms <= mk + 3 * a {
            return Ok(r.ns(num_syms - mk)? + mk);
        }
        if r.u(1) != 0 {
            i += 1;
            mk += a;
            if i > 24 {
                return Err(BitstreamError::invalid("AV1 subexp code too long"));
            }
        } else {
            return Ok(r.u(b2) + mk);
        }
    }
}

fn inverse_recenter(r: i32, v: i32) -> i32 {
    if v > 2 * r {
        v
    } else if v & 1 != 0 {
        r - ((v + 1) >> 1)
    } else {
        r + (v >> 1)
    }
}

fn decode_signed_subexp_with_ref(
    rd: &mut BitReader<'_>,
    low: i32,
    high: i32,
    r: i32,
) -> Result<i32, BitstreamError> {
    let mx = high - low;
    let r = r - low;
    let v = decode_subexp(rd, mx as u32)? as i32;
    let x = if (r << 1) <= mx {
        inverse_recenter(r, v)
    } else {
        mx - 1 - inverse_recenter(mx - 1 - r, v)
    };
    Ok(x + low)
}

impl Av1RefState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a frame header OBU payload (or the header part of a frame
    /// OBU). `temporal_id` / `spatial_id` come from the OBU extension
    /// header (0 without one).
    pub fn parse_frame_header(
        &self,
        seq: &SequenceHeader,
        payload: &[u8],
        temporal_id: u8,
        spatial_id: u8,
    ) -> Result<Av1Frame, BitstreamError> {
        let mut r = BitReader::new(payload);
        let mut h = Av1Frame {
            prev_gm_params: default_gm_params(),
            ..Av1Frame::default()
        };
        let id_len = seq.frame_id_length();
        let all_frames = 0xFFu8;
        let mut ref_valid = self.slots.map(|s| s.valid);
        let mut ref_order_hint = self.slots.map(|s| s.order_hint);
        let dm = seq.decoder_model_info;
        if seq.reduced_still_picture_header {
            h.frame_type = Av1FrameType::Key;
            h.frame_is_intra = true;
            h.show_frame = true;
        } else {
            h.show_existing_frame = r.u(1) != 0;
            if h.show_existing_frame {
                h.frame_to_show_map_idx = r.u(3) as u8;
                if let Some(dm) = dm
                    && !seq.equal_picture_interval()
                {
                    h.frame_presentation_time =
                        Some(r.u(u32::from(dm.frame_presentation_time_length_minus_1) + 1));
                }
                if seq.frame_id_numbers_present_flag {
                    h.display_frame_id = r.u(id_len);
                }
                let slot = &self.slots[usize::from(h.frame_to_show_map_idx)];
                if !slot.valid {
                    return Err(BitstreamError::invalid(
                        "AV1 show_existing_frame of an empty slot",
                    ));
                }
                h.frame_type = slot.frame_type;
                h.frame_is_intra =
                    matches!(h.frame_type, Av1FrameType::Key | Av1FrameType::IntraOnly);
                h.show_frame = true;
                if h.frame_type == Av1FrameType::Key {
                    h.refresh_frame_flags = all_frames;
                }
                h.size = Av1FrameSize {
                    frame_width: slot.frame_width,
                    frame_height: slot.frame_height,
                    upscaled_width: slot.upscaled_width,
                    render_width: slot.render_width,
                    render_height: slot.render_height,
                    mi_cols: slot.mi_cols,
                    mi_rows: slot.mi_rows,
                    superres_denom: 8,
                    ..Av1FrameSize::default()
                };
                h.order_hint = slot.order_hint;
                h.order_hints = slot.saved_order_hints;
                h.current_frame_id = slot.frame_id;
                if seq.film_grain_params_present {
                    h.film_grain = slot.film_grain;
                }
                h.global_motion.gm_params = slot.gm_params;
                h.loop_filter.ref_deltas = slot.loop_filter_ref_deltas;
                h.loop_filter.mode_deltas = slot.loop_filter_mode_deltas;
                h.segmentation.feature_enabled = slot.feature_enabled;
                h.segmentation.feature_data = slot.feature_data;
                h.ref_valid = ref_valid;
                h.header_bits = r.bit_pos();
                if h.header_bits > r.total_bits() {
                    return Err(BitstreamError::unexpected_end("AV1 frame header"));
                }
                return Ok(h);
            }
            h.frame_type = Av1FrameType::from_raw(r.u(2));
            h.frame_is_intra = matches!(h.frame_type, Av1FrameType::Key | Av1FrameType::IntraOnly);
            h.show_frame = r.u(1) != 0;
            if h.show_frame
                && let Some(dm) = dm
                && !seq.equal_picture_interval()
            {
                h.frame_presentation_time =
                    Some(r.u(u32::from(dm.frame_presentation_time_length_minus_1) + 1));
            }
            h.showable_frame = if h.show_frame {
                h.frame_type != Av1FrameType::Key
            } else {
                r.u(1) != 0
            };
            h.error_resilient_mode = if h.frame_type == Av1FrameType::Switch
                || (h.frame_type == Av1FrameType::Key && h.show_frame)
            {
                true
            } else {
                r.u(1) != 0
            };
        }
        if h.frame_type == Av1FrameType::Key && h.show_frame {
            ref_valid = [false; NUM_REF_FRAMES];
            ref_order_hint = [0; NUM_REF_FRAMES];
        }
        h.disable_cdf_update = r.u(1) != 0;
        h.allow_screen_content_tools = if seq.seq_force_screen_content_tools == SELECT {
            r.u(1) != 0
        } else {
            seq.seq_force_screen_content_tools != 0
        };
        if h.allow_screen_content_tools {
            h.force_integer_mv = if seq.seq_force_integer_mv == SELECT {
                r.u(1) != 0
            } else {
                seq.seq_force_integer_mv != 0
            };
        }
        if h.frame_is_intra {
            h.force_integer_mv = true;
        }
        if seq.frame_id_numbers_present_flag {
            h.current_frame_id = r.u(id_len);
            // mark_ref_frames( idLen ) (§5.9.4).
            let diff_len = u32::from(seq.delta_frame_id_length_minus_2) + 2;
            let cur = i64::from(h.current_frame_id);
            for (i, valid) in ref_valid.iter_mut().enumerate() {
                let id = i64::from(self.slots[i].frame_id);
                if cur > (1i64 << diff_len) {
                    if id > cur || id < cur - (1i64 << diff_len) {
                        *valid = false;
                    }
                } else if id > cur && id < (1i64 << id_len) + cur - (1i64 << diff_len) {
                    *valid = false;
                }
            }
        }
        h.frame_size_override_flag = if h.frame_type == Av1FrameType::Switch {
            true
        } else if seq.reduced_still_picture_header {
            false
        } else {
            r.u(1) != 0
        };
        h.order_hint = r.u(u32::from(seq.order_hint_bits));
        h.primary_ref_frame = if h.frame_is_intra || h.error_resilient_mode {
            PRIMARY_REF_NONE
        } else {
            r.u(3) as u8
        };
        if let Some(dm) = dm
            && r.u(1) != 0
        {
            for op in &seq.operating_points {
                let mut v = None;
                if op.decoder_model_present && op.contains(temporal_id, spatial_id) {
                    v = Some(r.u(u32::from(dm.buffer_removal_time_length_minus_1) + 1));
                }
                h.buffer_removal_time.push(v);
            }
        }
        h.refresh_frame_flags = if h.frame_type == Av1FrameType::Switch
            || (h.frame_type == Av1FrameType::Key && h.show_frame)
        {
            all_frames
        } else {
            r.u(8) as u8
        };
        if (!h.frame_is_intra || h.refresh_frame_flags != all_frames)
            && h.error_resilient_mode
            && seq.enable_order_hint
        {
            let mut hints = [0u32; NUM_REF_FRAMES];
            for (i, hint) in hints.iter_mut().enumerate() {
                *hint = r.u(u32::from(seq.order_hint_bits));
                if *hint != ref_order_hint[i] {
                    ref_valid[i] = false;
                }
            }
            h.ref_order_hint = Some(hints);
        }
        if h.frame_is_intra {
            self.frame_size(&mut r, seq, &mut h)?;
            render_size(&mut r, &mut h.size);
            if h.allow_screen_content_tools && h.size.upscaled_width == h.size.frame_width {
                h.allow_intrabc = r.u(1) != 0;
            }
        } else {
            if seq.enable_order_hint {
                h.frame_refs_short_signaling = r.u(1) != 0;
                if h.frame_refs_short_signaling {
                    h.last_frame_idx = r.u(3) as u8;
                    h.gold_frame_idx = r.u(3) as u8;
                    h.ref_frame_idx = set_frame_refs(seq, &h, &ref_order_hint);
                }
            }
            for i in 0..REFS_PER_FRAME {
                if !h.frame_refs_short_signaling {
                    h.ref_frame_idx[i] = r.u(3) as u8;
                }
                if seq.frame_id_numbers_present_flag {
                    h.delta_frame_id_minus_1[i] =
                        r.u(u32::from(seq.delta_frame_id_length_minus_2) + 2);
                }
            }
            if h.frame_size_override_flag && !h.error_resilient_mode {
                // frame_size_with_refs()
                for i in 0..REFS_PER_FRAME {
                    if r.u(1) != 0 {
                        let s = &self.slots[usize::from(h.ref_frame_idx[i])];
                        if s.upscaled_width == 0 || s.frame_height == 0 {
                            return Err(BitstreamError::invalid(
                                "AV1 frame size taken from an empty slot",
                            ));
                        }
                        h.size.upscaled_width = s.upscaled_width;
                        h.size.frame_width = s.upscaled_width;
                        h.size.frame_height = s.frame_height;
                        h.size.render_width = s.render_width;
                        h.size.render_height = s.render_height;
                        h.size.found_ref = Some(i as u8);
                        break;
                    }
                }
                if h.size.found_ref.is_none() {
                    self.frame_size(&mut r, seq, &mut h)?;
                    render_size(&mut r, &mut h.size);
                } else {
                    superres_params(&mut r, seq, &mut h.size);
                    compute_image_size(&mut h.size);
                }
            } else {
                self.frame_size(&mut r, seq, &mut h)?;
                render_size(&mut r, &mut h.size);
            }
            h.allow_high_precision_mv = if h.force_integer_mv {
                false
            } else {
                r.u(1) != 0
            };
            h.interpolation_filter = if r.u(1) != 0 {
                Av1InterpolationFilter::Switchable
            } else {
                [
                    Av1InterpolationFilter::EightTap,
                    Av1InterpolationFilter::EightTapSmooth,
                    Av1InterpolationFilter::EightTapSharp,
                    Av1InterpolationFilter::Bilinear,
                ][r.u(2) as usize]
            };
            h.is_motion_mode_switchable = r.u(1) != 0;
            h.use_ref_frame_mvs = if h.error_resilient_mode || !seq.enable_ref_frame_mvs {
                false
            } else {
                r.u(1) != 0
            };
            for i in 0..REFS_PER_FRAME {
                let hint = ref_order_hint[usize::from(h.ref_frame_idx[i])];
                h.order_hints[i + 1] = hint;
                h.ref_frame_sign_bias[i + 1] =
                    seq.enable_order_hint && relative_dist(seq, hint, h.order_hint) > 0;
            }
        }
        h.disable_frame_end_update_cdf = if seq.reduced_still_picture_header || h.disable_cdf_update
        {
            true
        } else {
            r.u(1) != 0
        };
        // setup_past_independence() / load_previous().
        let (mut ref_deltas, mut mode_deltas, prev_features) = if h.primary_ref_frame
            == PRIMARY_REF_NONE
        {
            (
                LOOP_FILTER_REF_DELTAS_DEFAULT,
                [0i8; 2],
                (
                    [[false; SEG_LVL_MAX]; MAX_SEGMENTS],
                    [[0i16; SEG_LVL_MAX]; MAX_SEGMENTS],
                ),
            )
        } else {
            let prev = &self.slots[usize::from(h.ref_frame_idx[usize::from(h.primary_ref_frame)])];
            h.prev_gm_params = prev.gm_params;
            (
                prev.loop_filter_ref_deltas,
                prev.loop_filter_mode_deltas,
                (prev.feature_enabled, prev.feature_data),
            )
        };
        let mut lf_delta_enabled = h.primary_ref_frame == PRIMARY_REF_NONE;
        // tile_info()
        h.tile_info = tile_info(&mut r, seq, &h.size)?;
        // quantization_params()
        let q = &mut h.quantization;
        q.base_q_idx = r.u(8) as u8;
        q.delta_q_y_dc = read_delta_q(&mut r)?;
        if seq.num_planes() > 1 {
            q.diff_uv_delta = seq.color_config.separate_uv_delta_q && r.u(1) != 0;
            q.delta_q_u_dc = read_delta_q(&mut r)?;
            q.delta_q_u_ac = read_delta_q(&mut r)?;
            if q.diff_uv_delta {
                q.delta_q_v_dc = read_delta_q(&mut r)?;
                q.delta_q_v_ac = read_delta_q(&mut r)?;
            } else {
                q.delta_q_v_dc = q.delta_q_u_dc;
                q.delta_q_v_ac = q.delta_q_u_ac;
            }
        }
        q.using_qmatrix = r.u(1) != 0;
        if q.using_qmatrix {
            q.qm_y = r.u(4) as u8;
            q.qm_u = r.u(4) as u8;
            q.qm_v = if seq.color_config.separate_uv_delta_q {
                r.u(4) as u8
            } else {
                q.qm_u
            };
        }
        // segmentation_params()
        let s = &mut h.segmentation;
        s.enabled = r.u(1) != 0;
        if s.enabled {
            if h.primary_ref_frame == PRIMARY_REF_NONE {
                s.update_map = true;
                s.update_data = true;
            } else {
                s.update_map = r.u(1) != 0;
                if s.update_map {
                    s.temporal_update = r.u(1) != 0;
                }
                s.update_data = r.u(1) != 0;
            }
            if s.update_data {
                for i in 0..MAX_SEGMENTS {
                    for j in 0..SEG_LVL_MAX {
                        let enabled = r.u(1) != 0;
                        s.feature_enabled[i][j] = enabled;
                        let mut v = 0i32;
                        if enabled {
                            let bits = SEGMENTATION_FEATURE_BITS[j];
                            let limit = SEGMENTATION_FEATURE_MAX[j];
                            v = if SEGMENTATION_FEATURE_SIGNED[j] {
                                su(&mut r, 1 + bits)?.clamp(-limit, limit)
                            } else {
                                (r.u(bits) as i32).clamp(0, limit)
                            };
                        }
                        s.feature_data[i][j] = v as i16;
                    }
                }
            } else {
                (s.feature_enabled, s.feature_data) = prev_features;
            }
        }
        for i in 0..MAX_SEGMENTS {
            for j in 0..SEG_LVL_MAX {
                if s.feature_enabled[i][j] {
                    s.last_active_seg_id = i as u8;
                    if j >= 5 {
                        s.seg_id_pre_skip = true;
                    }
                }
            }
        }
        // delta_q_params() / delta_lf_params()
        if h.quantization.base_q_idx > 0 {
            h.delta.delta_q_present = r.u(1) != 0;
        }
        if h.delta.delta_q_present {
            h.delta.delta_q_res = r.u(2) as u8;
            if !h.allow_intrabc {
                h.delta.delta_lf_present = r.u(1) != 0;
            }
            if h.delta.delta_lf_present {
                h.delta.delta_lf_res = r.u(2) as u8;
                h.delta.delta_lf_multi = r.u(1) != 0;
            }
        }
        // Lossless (§5.9.2).
        h.coded_lossless = true;
        let qz = &h.quantization;
        for seg in 0..MAX_SEGMENTS {
            let lossless = h.qindex(seg) == 0
                && qz.delta_q_y_dc == 0
                && qz.delta_q_u_ac == 0
                && qz.delta_q_u_dc == 0
                && qz.delta_q_v_ac == 0
                && qz.delta_q_v_dc == 0;
            h.lossless_array[seg] = lossless;
            if !lossless {
                h.coded_lossless = false;
            }
        }
        h.all_lossless = h.coded_lossless && h.size.frame_width == h.size.upscaled_width;
        // loop_filter_params()
        let planes = seq.num_planes();
        if h.coded_lossless || h.allow_intrabc {
            ref_deltas = LOOP_FILTER_REF_DELTAS_DEFAULT;
            mode_deltas = [0; 2];
        } else {
            let lf = &mut h.loop_filter;
            lf.level[0] = r.u(6) as u8;
            lf.level[1] = r.u(6) as u8;
            if planes > 1 && (lf.level[0] != 0 || lf.level[1] != 0) {
                lf.level[2] = r.u(6) as u8;
                lf.level[3] = r.u(6) as u8;
            }
            lf.sharpness = r.u(3) as u8;
            lf_delta_enabled = r.u(1) != 0;
            if lf_delta_enabled {
                lf.delta_update = r.u(1) != 0;
                if lf.delta_update {
                    for d in ref_deltas.iter_mut() {
                        if r.u(1) != 0 {
                            *d = su(&mut r, 7)? as i8;
                        }
                    }
                    for d in mode_deltas.iter_mut() {
                        if r.u(1) != 0 {
                            *d = su(&mut r, 7)? as i8;
                        }
                    }
                }
            }
        }
        h.loop_filter.delta_enabled = lf_delta_enabled;
        h.loop_filter.ref_deltas = ref_deltas;
        h.loop_filter.mode_deltas = mode_deltas;
        // cdef_params()
        if h.coded_lossless || h.allow_intrabc || !seq.enable_cdef {
            h.cdef.damping = 3;
        } else {
            let c = &mut h.cdef;
            c.damping = r.u(2) as u8 + 3;
            c.bits = r.u(2) as u8;
            for i in 0..(1usize << c.bits) {
                c.y_pri_strength[i] = r.u(4) as u8;
                c.y_sec_strength[i] = r.u(2) as u8;
                if c.y_sec_strength[i] == 3 {
                    c.y_sec_strength[i] += 1;
                }
                if planes > 1 {
                    c.uv_pri_strength[i] = r.u(4) as u8;
                    c.uv_sec_strength[i] = r.u(2) as u8;
                    if c.uv_sec_strength[i] == 3 {
                        c.uv_sec_strength[i] += 1;
                    }
                }
            }
        }
        // lr_params()
        if !(h.all_lossless || h.allow_intrabc || !seq.enable_restoration) {
            let lr = &mut h.lr;
            let mut chroma = false;
            for i in 0..planes {
                lr.frame_restoration_type[i] = [
                    Av1RestorationType::None,
                    Av1RestorationType::Switchable,
                    Av1RestorationType::Wiener,
                    Av1RestorationType::Sgrproj,
                ][r.u(2) as usize];
                if lr.frame_restoration_type[i] != Av1RestorationType::None {
                    lr.uses_lr = true;
                    if i > 0 {
                        chroma = true;
                    }
                }
            }
            if lr.uses_lr {
                if seq.use_128x128_superblock {
                    lr.lr_unit_shift = r.u(1) as u8 + 1;
                } else {
                    lr.lr_unit_shift = r.u(1) as u8;
                    if lr.lr_unit_shift != 0 {
                        lr.lr_unit_shift += r.u(1) as u8;
                    }
                }
                lr.loop_restoration_size[0] = 256 >> (2 - u32::from(lr.lr_unit_shift));
                if seq.color_config.subsampling_x && seq.color_config.subsampling_y && chroma {
                    lr.lr_uv_shift = r.u(1) as u8;
                }
                lr.loop_restoration_size[1] = lr.loop_restoration_size[0] >> lr.lr_uv_shift;
                lr.loop_restoration_size[2] = lr.loop_restoration_size[0] >> lr.lr_uv_shift;
            }
        }
        // read_tx_mode()
        h.tx_mode = if h.coded_lossless {
            Av1TxMode::Only4x4
        } else if r.u(1) != 0 {
            Av1TxMode::Select
        } else {
            Av1TxMode::Largest
        };
        // frame_reference_mode()
        if !h.frame_is_intra {
            h.reference_select = r.u(1) != 0;
        }
        // skip_mode_params()
        h.skip_mode_frame = skip_mode_frames(seq, &h, &ref_order_hint);
        if h.skip_mode_frame.is_some() {
            h.skip_mode_present = r.u(1) != 0;
        }
        h.allow_warped_motion =
            if h.frame_is_intra || h.error_resilient_mode || !seq.enable_warped_motion {
                false
            } else {
                r.u(1) != 0
            };
        h.reduced_tx_set = r.u(1) != 0;
        // global_motion_params()
        if !h.frame_is_intra {
            for rf in 1..TOTAL_REFS_PER_FRAME {
                let ty = if r.u(1) != 0 {
                    if r.u(1) != 0 {
                        Av1WarpModel::RotZoom
                    } else if r.u(1) != 0 {
                        Av1WarpModel::Translation
                    } else {
                        Av1WarpModel::Affine
                    }
                } else {
                    Av1WarpModel::Identity
                };
                h.global_motion.gm_type[rf] = ty;
                let prev = h.prev_gm_params[rf];
                let gm = &mut h.global_motion.gm_params[rf];
                let hp = h.allow_high_precision_mv;
                if matches!(ty, Av1WarpModel::RotZoom | Av1WarpModel::Affine) {
                    gm[2] = read_global_param(&mut r, ty, 2, prev[2], hp)?;
                    gm[3] = read_global_param(&mut r, ty, 3, prev[3], hp)?;
                    if ty == Av1WarpModel::Affine {
                        gm[4] = read_global_param(&mut r, ty, 4, prev[4], hp)?;
                        gm[5] = read_global_param(&mut r, ty, 5, prev[5], hp)?;
                    } else {
                        gm[4] = -gm[3];
                        gm[5] = gm[2];
                    }
                }
                if ty != Av1WarpModel::Identity {
                    gm[0] = read_global_param(&mut r, ty, 0, prev[0], hp)?;
                    gm[1] = read_global_param(&mut r, ty, 1, prev[1], hp)?;
                }
            }
        }
        // film_grain_params()
        if seq.film_grain_params_present && (h.show_frame || h.showable_frame) {
            h.film_grain = self.film_grain_params(&mut r, seq, &h)?;
        }
        h.ref_valid = ref_valid;
        h.header_bits = r.bit_pos();
        if h.header_bits > r.total_bits() {
            return Err(BitstreamError::unexpected_end("AV1 frame header"));
        }
        Ok(h)
    }

    fn frame_size(
        &self,
        r: &mut BitReader<'_>,
        seq: &SequenceHeader,
        h: &mut Av1Frame,
    ) -> Result<(), BitstreamError> {
        if h.frame_size_override_flag {
            h.size.frame_width = r.u(u32::from(seq.frame_width_bits_minus_1) + 1) + 1;
            h.size.frame_height = r.u(u32::from(seq.frame_height_bits_minus_1) + 1) + 1;
            if h.size.frame_width > seq.max_frame_width()
                || h.size.frame_height > seq.max_frame_height()
            {
                return Err(BitstreamError::invalid(
                    "AV1 frame larger than the sequence maximum",
                ));
            }
        } else {
            h.size.frame_width = seq.max_frame_width();
            h.size.frame_height = seq.max_frame_height();
        }
        superres_params(r, seq, &mut h.size);
        compute_image_size(&mut h.size);
        Ok(())
    }

    fn film_grain_params(
        &self,
        r: &mut BitReader<'_>,
        seq: &SequenceHeader,
        h: &Av1Frame,
    ) -> Result<Av1FilmGrain, BitstreamError> {
        let mut g = Av1FilmGrain {
            apply_grain: r.u(1) != 0,
            ..Av1FilmGrain::default()
        };
        if !g.apply_grain {
            return Ok(Av1FilmGrain::default());
        }
        g.grain_seed = r.u(16) as u16;
        g.update_grain = if h.frame_type == Av1FrameType::Inter {
            r.u(1) != 0
        } else {
            true
        };
        if !g.update_grain {
            g.film_grain_params_ref_idx = r.u(3) as u8;
            // load_grain_params(): every element from the slot except
            // grain_seed (tempGrainSeed); the coded update_grain /
            // film_grain_params_ref_idx are kept for the caller.
            let mut loaded = self.slots[usize::from(g.film_grain_params_ref_idx)].film_grain;
            loaded.grain_seed = g.grain_seed;
            loaded.update_grain = false;
            loaded.film_grain_params_ref_idx = g.film_grain_params_ref_idx;
            return Ok(loaded);
        }
        g.num_y_points = r.u(4) as u8;
        if g.num_y_points > 14 {
            return Err(BitstreamError::invalid("AV1 num_y_points > 14"));
        }
        for i in 0..usize::from(g.num_y_points) {
            g.point_y_value[i] = r.u(8) as u8;
            g.point_y_scaling[i] = r.u(8) as u8;
        }
        let c = &seq.color_config;
        g.chroma_scaling_from_luma = !c.monochrome && r.u(1) != 0;
        if c.monochrome
            || g.chroma_scaling_from_luma
            || (c.subsampling_x && c.subsampling_y && g.num_y_points == 0)
        {
            g.num_cb_points = 0;
            g.num_cr_points = 0;
        } else {
            g.num_cb_points = r.u(4) as u8;
            if g.num_cb_points > 10 {
                return Err(BitstreamError::invalid("AV1 num_cb_points > 10"));
            }
            for i in 0..usize::from(g.num_cb_points) {
                g.point_cb_value[i] = r.u(8) as u8;
                g.point_cb_scaling[i] = r.u(8) as u8;
            }
            g.num_cr_points = r.u(4) as u8;
            if g.num_cr_points > 10 {
                return Err(BitstreamError::invalid("AV1 num_cr_points > 10"));
            }
            for i in 0..usize::from(g.num_cr_points) {
                g.point_cr_value[i] = r.u(8) as u8;
                g.point_cr_scaling[i] = r.u(8) as u8;
            }
        }
        g.grain_scaling_minus_8 = r.u(2) as u8;
        g.ar_coeff_lag = r.u(2) as u8;
        let lag = usize::from(g.ar_coeff_lag);
        let num_pos_luma = 2 * lag * (lag + 1);
        let num_pos_chroma = if g.num_y_points != 0 {
            for i in 0..num_pos_luma {
                g.ar_coeffs_y_plus_128[i] = r.u(8) as u8;
            }
            num_pos_luma + 1
        } else {
            num_pos_luma
        };
        if g.chroma_scaling_from_luma || g.num_cb_points != 0 {
            for i in 0..num_pos_chroma {
                g.ar_coeffs_cb_plus_128[i] = r.u(8) as u8;
            }
        }
        if g.chroma_scaling_from_luma || g.num_cr_points != 0 {
            for i in 0..num_pos_chroma {
                g.ar_coeffs_cr_plus_128[i] = r.u(8) as u8;
            }
        }
        g.ar_coeff_shift_minus_6 = r.u(2) as u8;
        g.grain_scale_shift = r.u(2) as u8;
        if g.num_cb_points != 0 {
            g.cb_mult = r.u(8) as u8;
            g.cb_luma_mult = r.u(8) as u8;
            g.cb_offset = r.u(9) as u16;
        }
        if g.num_cr_points != 0 {
            g.cr_mult = r.u(8) as u8;
            g.cr_luma_mult = r.u(8) as u8;
            g.cr_offset = r.u(9) as u16;
        }
        g.overlap_flag = r.u(1) != 0;
        g.clip_to_restricted_range = r.u(1) != 0;
        Ok(g)
    }

    /// Apply the decode frame wrapup state changes of `h` (§7.4): for a
    /// shown existing key frame the reference frame loading process
    /// (§7.21), then the reference frame update process (§7.20) for the
    /// slots in `refresh_frame_flags`. `seq` supplies bit depth and
    /// subsampling.
    pub fn update(&mut self, seq: &SequenceHeader, h: &Av1Frame) {
        for (slot, &valid) in self.slots.iter_mut().zip(&h.ref_valid) {
            slot.valid = valid;
        }
        if h.show_existing_frame {
            if h.frame_type != Av1FrameType::Key {
                return;
            }
            let src = self.slots[usize::from(h.frame_to_show_map_idx)];
            for i in 0..NUM_REF_FRAMES {
                if h.refresh_frame_flags & (1 << i) != 0 {
                    self.slots[i] = Av1RefSlot { valid: true, ..src };
                }
            }
            self.current_frame_id = src.frame_id;
            return;
        }
        let c = &seq.color_config;
        let slot = Av1RefSlot {
            valid: true,
            frame_id: h.current_frame_id,
            upscaled_width: h.size.upscaled_width,
            frame_width: h.size.frame_width,
            frame_height: h.size.frame_height,
            render_width: h.size.render_width,
            render_height: h.size.render_height,
            mi_cols: h.size.mi_cols,
            mi_rows: h.size.mi_rows,
            frame_type: h.frame_type,
            showable_frame: h.showable_frame,
            subsampling_x: c.subsampling_x,
            subsampling_y: c.subsampling_y,
            bit_depth: c.bit_depth,
            order_hint: h.order_hint,
            saved_order_hints: h.order_hints,
            gm_params: h.global_motion.gm_params,
            loop_filter_ref_deltas: h.loop_filter.ref_deltas,
            loop_filter_mode_deltas: h.loop_filter.mode_deltas,
            feature_enabled: h.segmentation.feature_enabled,
            feature_data: h.segmentation.feature_data,
            film_grain: if seq.film_grain_params_present {
                h.film_grain
            } else {
                Av1FilmGrain::default()
            },
        };
        for i in 0..NUM_REF_FRAMES {
            if h.refresh_frame_flags & (1 << i) != 0 {
                self.slots[i] = slot;
            }
        }
        self.current_frame_id = h.current_frame_id;
    }
}

fn superres_params(r: &mut BitReader<'_>, seq: &SequenceHeader, s: &mut Av1FrameSize) {
    s.use_superres = seq.enable_superres && r.u(1) != 0;
    s.superres_denom = if s.use_superres { r.u(3) + 9 } else { 8 };
    s.upscaled_width = s.frame_width;
    s.frame_width = (s.upscaled_width * 8 + s.superres_denom / 2) / s.superres_denom;
}

fn compute_image_size(s: &mut Av1FrameSize) {
    s.mi_cols = 2 * ((s.frame_width + 7) >> 3);
    s.mi_rows = 2 * ((s.frame_height + 7) >> 3);
}

fn render_size(r: &mut BitReader<'_>, s: &mut Av1FrameSize) {
    s.render_and_frame_size_different = r.u(1) != 0;
    if s.render_and_frame_size_different {
        s.render_width = r.u(16) + 1;
        s.render_height = r.u(16) + 1;
    } else {
        s.render_width = s.upscaled_width;
        s.render_height = s.frame_height;
    }
}

fn tile_info(
    r: &mut BitReader<'_>,
    seq: &SequenceHeader,
    size: &Av1FrameSize,
) -> Result<Av1TileInfo, BitstreamError> {
    let big = seq.use_128x128_superblock;
    let sb_cols = if big {
        (size.mi_cols + 31) >> 5
    } else {
        (size.mi_cols + 15) >> 4
    };
    let sb_rows = if big {
        (size.mi_rows + 31) >> 5
    } else {
        (size.mi_rows + 15) >> 4
    };
    let sb_shift = if big { 5 } else { 4 };
    let sb_size = sb_shift + 2;
    let max_tile_width_sb = 4096 >> sb_size;
    let mut max_tile_area_sb = (4096 * 2304) >> (2 * sb_size);
    let min_log2_tile_cols = tile_log2(max_tile_width_sb, sb_cols);
    let max_log2_tile_cols = tile_log2(1, sb_cols.min(64));
    let max_log2_tile_rows = tile_log2(1, sb_rows.min(64));
    let min_log2_tiles = min_log2_tile_cols.max(tile_log2(max_tile_area_sb, sb_rows * sb_cols));
    let mut t = Av1TileInfo {
        uniform_tile_spacing_flag: r.u(1) != 0,
        tile_size_bytes: 4,
        ..Av1TileInfo::default()
    };
    if t.uniform_tile_spacing_flag {
        t.tile_cols_log2 = min_log2_tile_cols;
        while t.tile_cols_log2 < max_log2_tile_cols {
            if r.u(1) != 0 {
                t.tile_cols_log2 += 1;
            } else {
                break;
            }
        }
        let w = (sb_cols + (1 << t.tile_cols_log2) - 1) >> t.tile_cols_log2;
        let mut start = 0;
        while start < sb_cols {
            t.mi_col_starts.push(start << sb_shift);
            start += w.max(1);
        }
        t.mi_col_starts.push(size.mi_cols);
        t.tile_cols = t.mi_col_starts.len() as u32 - 1;
        let min_log2_tile_rows = min_log2_tiles.saturating_sub(t.tile_cols_log2);
        t.tile_rows_log2 = min_log2_tile_rows;
        while t.tile_rows_log2 < max_log2_tile_rows {
            if r.u(1) != 0 {
                t.tile_rows_log2 += 1;
            } else {
                break;
            }
        }
        let hgt = (sb_rows + (1 << t.tile_rows_log2) - 1) >> t.tile_rows_log2;
        let mut start = 0;
        while start < sb_rows {
            t.mi_row_starts.push(start << sb_shift);
            start += hgt.max(1);
        }
        t.mi_row_starts.push(size.mi_rows);
        t.tile_rows = t.mi_row_starts.len() as u32 - 1;
    } else {
        let mut widest = 0;
        let mut start = 0;
        while start < sb_cols {
            t.mi_col_starts.push(start << sb_shift);
            let max_w = (sb_cols - start).min(max_tile_width_sb);
            let sz = r.ns(max_w)? + 1;
            widest = widest.max(sz);
            start += sz;
            if t.mi_col_starts.len() > 64 {
                return Err(BitstreamError::invalid("AV1 more than 64 tile columns"));
            }
        }
        t.mi_col_starts.push(size.mi_cols);
        t.tile_cols = t.mi_col_starts.len() as u32 - 1;
        t.tile_cols_log2 = tile_log2(1, t.tile_cols);
        max_tile_area_sb = if min_log2_tiles > 0 {
            (sb_rows * sb_cols) >> (min_log2_tiles + 1)
        } else {
            sb_rows * sb_cols
        };
        let max_h = (max_tile_area_sb / widest.max(1)).max(1);
        let mut start = 0;
        while start < sb_rows {
            t.mi_row_starts.push(start << sb_shift);
            let m = (sb_rows - start).min(max_h);
            start += r.ns(m)? + 1;
            if t.mi_row_starts.len() > 64 {
                return Err(BitstreamError::invalid("AV1 more than 64 tile rows"));
            }
        }
        t.mi_row_starts.push(size.mi_rows);
        t.tile_rows = t.mi_row_starts.len() as u32 - 1;
        t.tile_rows_log2 = tile_log2(1, t.tile_rows);
    }
    if t.tile_cols_log2 > 0 || t.tile_rows_log2 > 0 {
        t.context_update_tile_id = r.u(t.tile_rows_log2 + t.tile_cols_log2);
        t.tile_size_bytes = r.u(2) as u8 + 1;
        if t.context_update_tile_id >= t.tile_cols * t.tile_rows {
            return Err(BitstreamError::invalid(
                "AV1 context_update_tile_id beyond the tiles",
            ));
        }
    }
    Ok(t)
}

/// The set frame refs process (§7.8).
fn set_frame_refs(
    seq: &SequenceHeader,
    h: &Av1Frame,
    ref_order_hint: &[u32; NUM_REF_FRAMES],
) -> [u8; REFS_PER_FRAME] {
    let mut idx = [-1i32; REFS_PER_FRAME];
    idx[0] = i32::from(h.last_frame_idx);
    idx[3] = i32::from(h.gold_frame_idx);
    let mut used = [false; NUM_REF_FRAMES];
    used[usize::from(h.last_frame_idx)] = true;
    used[usize::from(h.gold_frame_idx)] = true;
    let cur = 1i32 << (seq.order_hint_bits.max(1) - 1);
    let shifted: Vec<i32> = ref_order_hint
        .iter()
        .map(|&o| cur + relative_dist(seq, o, h.order_hint))
        .collect();
    let latest_backward = |used: &[bool; NUM_REF_FRAMES]| {
        let mut r: i32 = -1;
        let mut latest = 0;
        for i in 0..NUM_REF_FRAMES {
            let hint = shifted[i];
            if !used[i] && hint >= cur && (r < 0 || hint >= latest) {
                r = i as i32;
                latest = hint;
            }
        }
        r
    };
    let earliest_backward = |used: &[bool; NUM_REF_FRAMES]| {
        let mut r: i32 = -1;
        let mut earliest = 0;
        for i in 0..NUM_REF_FRAMES {
            let hint = shifted[i];
            if !used[i] && hint >= cur && (r < 0 || hint < earliest) {
                r = i as i32;
                earliest = hint;
            }
        }
        r
    };
    let latest_forward = |used: &[bool; NUM_REF_FRAMES]| {
        let mut r: i32 = -1;
        let mut latest = 0;
        for i in 0..NUM_REF_FRAMES {
            let hint = shifted[i];
            if !used[i] && hint < cur && (r < 0 || hint >= latest) {
                r = i as i32;
                latest = hint;
            }
        }
        r
    };
    // ALTREF (index 6), BWDREF (4), ALTREF2 (5).
    for (slot, f) in [(6usize, 0u8), (4, 1), (5, 1)] {
        let r = if f == 0 {
            latest_backward(&used)
        } else {
            earliest_backward(&used)
        };
        if r >= 0 {
            idx[slot] = r;
            used[r as usize] = true;
        }
    }
    // Ref_Frame_List: LAST2, LAST3, BWDREF, ALTREF2, ALTREF.
    for slot in [1usize, 2, 4, 5, 6] {
        if idx[slot] < 0 {
            let r = latest_forward(&used);
            if r >= 0 {
                idx[slot] = r;
                used[r as usize] = true;
            }
        }
    }
    let mut r: i32 = -1;
    let mut earliest = 0;
    for (i, &hint) in shifted.iter().enumerate() {
        if r < 0 || hint < earliest {
            r = i as i32;
            earliest = hint;
        }
    }
    idx.map(|v| if v < 0 { r as u8 } else { v as u8 })
}

/// `skip_mode_params()` (§5.9.22): `SkipModeFrame[]` when allowed.
fn skip_mode_frames(
    seq: &SequenceHeader,
    h: &Av1Frame,
    ref_order_hint: &[u32; NUM_REF_FRAMES],
) -> Option<[u8; 2]> {
    if h.frame_is_intra || !h.reference_select || !seq.enable_order_hint {
        return None;
    }
    let mut fwd: Option<(usize, u32)> = None;
    let mut bwd: Option<(usize, u32)> = None;
    for i in 0..REFS_PER_FRAME {
        let hint = ref_order_hint[usize::from(h.ref_frame_idx[i])];
        if relative_dist(seq, hint, h.order_hint) < 0 {
            if fwd.is_none_or(|(_, f)| relative_dist(seq, hint, f) > 0) {
                fwd = Some((i, hint));
            }
        } else if relative_dist(seq, hint, h.order_hint) > 0
            && bwd.is_none_or(|(_, b)| relative_dist(seq, hint, b) < 0)
        {
            bwd = Some((i, hint));
        }
    }
    let (fi, fh) = fwd?;
    if let Some((bi, _)) = bwd {
        return Some([1 + fi.min(bi) as u8, 1 + fi.max(bi) as u8]);
    }
    let mut second: Option<(usize, u32)> = None;
    for i in 0..REFS_PER_FRAME {
        let hint = ref_order_hint[usize::from(h.ref_frame_idx[i])];
        if relative_dist(seq, hint, fh) < 0
            && second.is_none_or(|(_, s)| relative_dist(seq, hint, s) > 0)
        {
            second = Some((i, hint));
        }
    }
    let (si, _) = second?;
    Some([1 + fi.min(si) as u8, 1 + fi.max(si) as u8])
}

fn read_global_param(
    r: &mut BitReader<'_>,
    ty: Av1WarpModel,
    idx: usize,
    prev: i32,
    allow_high_precision_mv: bool,
) -> Result<i32, BitstreamError> {
    let (mut abs_bits, mut prec_bits) = (12u32, 15u32);
    if idx < 2 {
        if ty == Av1WarpModel::Translation {
            let hp = u32::from(!allow_high_precision_mv);
            abs_bits = 9 - hp;
            prec_bits = 3 - hp;
        } else {
            abs_bits = 12;
            prec_bits = 6;
        }
    }
    let prec_diff = WARPEDMODEL_PREC_BITS - prec_bits;
    let round = if idx % 3 == 2 {
        1i32 << WARPEDMODEL_PREC_BITS
    } else {
        0
    };
    let sub = if idx % 3 == 2 { 1i32 << prec_bits } else { 0 };
    let mx = 1i32 << abs_bits;
    let rr = (prev >> prec_diff) - sub;
    Ok((decode_signed_subexp_with_ref(r, -mx, mx + 1, rr)? << prec_diff) + round)
}

/// One tile of a tile group: where its data sits in the OBU payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Av1Tile {
    pub tile_num: u32,
    pub row: u32,
    pub col: u32,
    /// Byte offset of the tile data in the tile group payload.
    pub offset: usize,
    pub size: usize,
}

/// `tile_group_obu()` (§5.11.1) layout.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Av1TileGroup {
    pub tg_start: u32,
    pub tg_end: u32,
    pub tiles: Vec<Av1Tile>,
}

/// Parse a tile group (an OBU_TILE_GROUP payload, or the bytes of a
/// frame OBU after its header) against the frame's tile info.
pub fn parse_tile_group(ti: &Av1TileInfo, data: &[u8]) -> Result<Av1TileGroup, BitstreamError> {
    let num_tiles = ti.tile_cols * ti.tile_rows;
    if num_tiles == 0 {
        return Err(BitstreamError::invalid("AV1 frame without tiles"));
    }
    let mut r = BitReader::new(data);
    let (mut start, mut end) = (0, num_tiles - 1);
    if num_tiles > 1 && r.u(1) != 0 {
        let bits = ti.tile_cols_log2 + ti.tile_rows_log2;
        start = r.u(bits);
        end = r.u(bits);
    }
    if start > end || end >= num_tiles {
        return Err(BitstreamError::invalid("AV1 tile group range"));
    }
    r.align_to_byte();
    let mut at = r.bit_pos() / 8;
    let mut tiles = Vec::with_capacity((end - start + 1) as usize);
    let tsb = usize::from(ti.tile_size_bytes);
    for n in start..=end {
        let size = if n == end {
            data.len()
                .checked_sub(at)
                .ok_or_else(|| BitstreamError::unexpected_end("AV1 tile group"))?
        } else {
            let field = data
                .get(at..at + tsb)
                .ok_or_else(|| BitstreamError::unexpected_end("AV1 tile size"))?;
            at += tsb;
            field
                .iter()
                .rev()
                .fold(0usize, |v, &b| (v << 8) | usize::from(b))
                + 1
        };
        if size == 0 || at + size > data.len() {
            return Err(BitstreamError::invalid(
                "AV1 tile size beyond the tile group",
            ));
        }
        tiles.push(Av1Tile {
            tile_num: n,
            row: n / ti.tile_cols,
            col: n % ti.tile_cols,
            offset: at,
            size,
        });
        at += size;
    }
    Ok(Av1TileGroup {
        tg_start: start,
        tg_end: end,
        tiles,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(bits: u8) -> SequenceHeader {
        SequenceHeader {
            enable_order_hint: true,
            order_hint_bits: bits,
            ..SequenceHeader::default()
        }
    }

    #[test]
    fn relative_distance_wraps() {
        let s = seq(7);
        assert_eq!(relative_dist(&s, 5, 3), 2);
        assert_eq!(relative_dist(&s, 1, 126), 3);
        assert_eq!(relative_dist(&s, 126, 1), -3);
    }

    #[test]
    fn shear_of_identity_and_of_a_degenerate_model() {
        let id = default_gm_params()[1];
        let s = setup_shear(&id);
        assert!(s.warp_valid);
        assert_eq!((s.alpha, s.beta, s.gamma, s.delta), (0, 0, 0, 0));
        // A strong shear breaks 4·|alpha| + 7·|beta| < 2^16.
        let mut w = id;
        w[3] = 1 << 14;
        assert!(!setup_shear(&w).warp_valid);
        // Div_Lut: resolve_divisor(2^16) = (16 + 14, 16384).
        assert_eq!(resolve_divisor(1 << 16), (30, 16384));
    }

    #[test]
    fn set_frame_refs_follows_7_8() {
        // OrderHint 8; slots hold hints 0..=7 except slot 7 = 10 (a
        // backward reference). LAST = slot 6 (hint 6), GOLDEN = slot 0.
        let s = seq(7);
        let h = Av1Frame {
            order_hint: 8,
            last_frame_idx: 6,
            gold_frame_idx: 0,
            ..Av1Frame::default()
        };
        let hints = [0, 1, 2, 3, 4, 5, 6, 10];
        let r = set_frame_refs(&s, &h, &hints);
        // ALTREF: latest backward = slot 7; BWDREF / ALTREF2: no more
        // backward slots; then LAST2, LAST3, BWDREF, ALTREF2 take the
        // latest forward hints 5, 4, 3, 2.
        assert_eq!(r, [6, 5, 4, 0, 3, 2, 7]);
    }

    #[test]
    fn subexp_with_reference_round_trips_small_values() {
        // decode_subexp( 16 ) with ns(16) "0000" → 0; recentered on r = 3.
        let data = [0u8; 4];
        let mut rd = BitReader::new(&data);
        assert_eq!(decode_signed_subexp_with_ref(&mut rd, -8, 9, 3).unwrap(), 3);
    }
}
