//! HEVC / H.265 minimal IDR header parsing.
//!
//! This module parses just enough VPS / SPS / PPS / slice-segment
//! header to populate the slice-data HW backends' parameter buffers
//! (`VAPictureParameterBufferHEVC`, `VdpPictureInfoHEVC`,
//! `VkVideoDecodeH265PictureInfoKHR`). Same scope philosophy as the
//! H.264 module: enough fields to drive the GPU decode of an IDR
//! access unit, nothing more.
//!
//! The VPS / SPS / PPS walks are complete through their extension
//! flags: scaling lists (§7.3.4), PCM (§7.3.2.2.1), short-term RPS
//! with full §7.4.8 inter-set-prediction derivation (7-59..7-71),
//! long-term RPS, VUI/HRD (§E.2.1/§E.2.2/§E.2.3), tiles, WPP and the
//! range extensions (§7.3.2.2.2/§7.3.2.3.2) all parse. Still refused
//! (returned as [`BitstreamError::Unsupported`]):
//!
//! - SCC / Scalable / Multiview / 3D extension payloads (Annex F/I
//!   syntax; the presence flags themselves parse).
//! - Dependent slice segments in the *slice-header* walk.
//!
//! # Spec references
//!
//! ITU-T H.265 (a.k.a. ISO/IEC 23008-2). Sections of interest:
//! 7.3.2.1 (VPS), 7.3.2.2 (SPS), 7.3.2.3 (PPS), 7.3.4 (scaling list
//! data), 7.3.7 (st_ref_pic_set), 7.3.6 (slice segment header),
//! 7.4.3.2 (SPS semantics), 7.4.8 (ST-RPS derivation), Annex E
//! (VUI/HRD), 9.2 (Exp-Golomb).

use crate::bit_reader::BitReader;
use crate::BitstreamError;

pub mod sei;

// ─────────────────────────── NAL unit types ──────────────────────────────────

/// 7.4.2.2 — IDR_W_RADL slice.
pub const NAL_TYPE_IDR_W_RADL: u8 = 19;
/// 7.4.2.2 — IDR_N_LP slice.
pub const NAL_TYPE_IDR_N_LP: u8 = 20;
/// 7.4.2.2 — CRA slice.
pub const NAL_TYPE_CRA: u8 = 21;
/// 7.4.2.2 — VPS_NUT.
pub const NAL_TYPE_VPS: u8 = 32;
/// 7.4.2.2 — SPS_NUT.
pub const NAL_TYPE_SPS: u8 = 33;
/// 7.4.2.2 — PPS_NUT.
pub const NAL_TYPE_PPS: u8 = 34;
/// 7.4.2.2 — AUD_NUT.
pub const NAL_TYPE_AUD: u8 = 35;

// ─────────────────────────── Annex-B framing ─────────────────────────────────

/// Locate every NAL unit in an Annex-B HEVC bitstream and return
/// slices pointing at the NAL body (start code stripped, two-byte
/// NAL header at index 0..1, emulation bytes still in place — strip
/// those with [`ebsp_to_rbsp`] before bit-level parsing).
pub fn split_annex_b(buf: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0;
    let n = buf.len();
    let mut last_payload_start: Option<usize> = None;
    while i < n {
        let four =
            i + 3 < n && buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 0 && buf[i + 3] == 1;
        let three = !four && i + 2 < n && buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 1;
        if four || three {
            if let Some(start) = last_payload_start.take() {
                out.push(&buf[start..i]);
            }
            i += if four { 4 } else { 3 };
            last_payload_start = Some(i);
            continue;
        }
        i += 1;
    }
    if let Some(start) = last_payload_start.take() {
        out.push(&buf[start..n]);
    }
    out
}

/// Strip H.265 emulation-prevention `0x03` bytes (7.4.1.1). The
/// algorithm is identical to the one ITU-T H.264 §7.4.1.1 and ITU-T
/// H.266 §7.4.2.1 define, so this module re-exports the shared helper
/// from [`crate::nal::ebsp_to_rbsp`] rather than carrying a private
/// copy.
pub use crate::nal::ebsp_to_rbsp;

/// Inspect the two-byte HEVC NAL header. Returns
/// `(forbidden_zero_bit, nal_unit_type, layer_id, temporal_id_plus1)`.
pub fn nal_header(b0: u8, b1: u8) -> (u8, u8, u8, u8) {
    let forbidden = (b0 >> 7) & 1;
    let nal_unit_type = (b0 >> 1) & 0x3f;
    let layer_id = ((b0 & 1) << 5) | ((b1 >> 3) & 0x1f);
    let temporal_id_plus1 = b1 & 0x7;
    (forbidden, nal_unit_type, layer_id, temporal_id_plus1)
}

/// True if `nal_unit_type` is one of the IRAP slice types that this
/// crate treats as a decode entry point (IDR_W_RADL / IDR_N_LP / CRA).
pub fn is_irap(nal_unit_type: u8) -> bool {
    matches!(
        nal_unit_type,
        NAL_TYPE_IDR_W_RADL | NAL_TYPE_IDR_N_LP | NAL_TYPE_CRA
    )
}

// ─────────────────────────── Output structs ──────────────────────────────────

/// Profile / tier / level info from `profile_tier_level()`. Just the
/// fields the HW backends look at; the 32 sub-layer profiles and
/// flags are intentionally skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HevcProfileTierLevel {
    pub general_profile_space: u8,
    pub general_tier_flag: bool,
    pub general_profile_idc: u8,
    /// 32-bit packed `general_profile_compatibility_flag[0..32]`.
    pub general_profile_compatibility_flags: u32,
    pub general_level_idc: u8,
}

/// Conformance cropping rectangle, in luma samples.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HevcConformanceWindow {
    pub left: u32,
    pub right: u32,
    pub top: u32,
    pub bottom: u32,
}

/// Scaling list data (§7.3.4). Four size classes × six matrix ids
/// (for `sizeId == 3` only matrix ids 0 and 3 are coded — the loop
/// steps by 3).
///
/// * `pred_mode_flag[s][m] == false` — the list is predicted:
///   `pred_matrix_id_delta[s][m] == 0` selects the default matrix
///   (§7.4.5), otherwise it references matrix `m - delta` (for
///   `sizeId == 3`, `m - delta * 3`).
/// * `pred_mode_flag[s][m] == true` — explicit coefficients, in the
///   up-right diagonal coding order the §7.3.4 pseudo-code produces.
///   `coeffs` holds `Min(64, (1 << (4 + (sizeId << 1))))` entries
///   (16 for `sizeId == 0`, else 64); `dc_coef_minus8` is coded for
///   `sizeId > 1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HevcScalingListData {
    pub pred_mode_flag: [[bool; 6]; 4],
    pub pred_matrix_id_delta: [[u32; 6]; 4],
    /// Indexed `[sizeId - 2][matrixId]`; only meaningful for
    /// `sizeId` 2 and 3.
    pub dc_coef_minus8: [[i32; 6]; 2],
    /// `[sizeId 0][matrixId]` — 16 coefficients.
    pub list_4x4: [[u8; 16]; 6],
    /// `[sizeId 1..=3][matrixId]` — 64 coefficients each.
    pub list_8x8: [[u8; 64]; 6],
    pub list_16x16: [[u8; 64]; 6],
    pub list_32x32: [[u8; 64]; 6],
}

impl Default for HevcScalingListData {
    fn default() -> Self {
        HevcScalingListData {
            pred_mode_flag: [[false; 6]; 4],
            pred_matrix_id_delta: [[0; 6]; 4],
            dc_coef_minus8: [[0; 6]; 2],
            list_4x4: [[0; 16]; 6],
            list_8x8: [[0; 64]; 6],
            list_16x16: [[0; 64]; 6],
            list_32x32: [[0; 64]; 6],
        }
    }
}

/// Parse `scaling_list_data()` (§7.3.4).
fn parse_scaling_list_data(r: &mut BitReader<'_>) -> Result<HevcScalingListData, BitstreamError> {
    let mut d = HevcScalingListData::default();
    for size_id in 0usize..4 {
        let step = if size_id == 3 { 3 } else { 1 };
        let mut matrix_id = 0usize;
        while matrix_id < 6 {
            let pred_mode = r.u(1) != 0;
            d.pred_mode_flag[size_id][matrix_id] = pred_mode;
            if !pred_mode {
                let delta = r.ue()?;
                // §7.4.5: delta is bounded by matrixId (or matrixId/3
                // for sizeId 3) — it must reference an earlier list.
                let max = if size_id == 3 {
                    matrix_id as u32 / 3
                } else {
                    matrix_id as u32
                };
                if delta > max {
                    return Err(BitstreamError::invalid(format!(
                        "scaling_list_pred_matrix_id_delta={delta} > {max} \
                         (sizeId={size_id}, matrixId={matrix_id}, §7.4.5)"
                    )));
                }
                d.pred_matrix_id_delta[size_id][matrix_id] = delta;
            } else {
                let coef_num = if size_id == 0 { 16 } else { 64 };
                let mut next_coef: i32 = 8;
                if size_id > 1 {
                    let dc = r.se()?;
                    // §7.4.5: −7..=247.
                    if !(-7..=247).contains(&dc) {
                        return Err(BitstreamError::invalid(format!(
                            "scaling_list_dc_coef_minus8={dc} out of -7..=247 (§7.4.5)"
                        )));
                    }
                    d.dc_coef_minus8[size_id - 2][matrix_id] = dc;
                    next_coef = dc + 8;
                }
                for i in 0..coef_num {
                    let delta_coef = r.se()?;
                    // §7.4.5: −128..=127.
                    if !(-128..=127).contains(&delta_coef) {
                        return Err(BitstreamError::invalid(format!(
                            "scaling_list_delta_coef={delta_coef} out of -128..=127 (§7.4.5)"
                        )));
                    }
                    next_coef = (next_coef + delta_coef + 256) % 256;
                    let v = next_coef as u8;
                    match size_id {
                        0 => d.list_4x4[matrix_id][i] = v,
                        1 => d.list_8x8[matrix_id][i] = v,
                        2 => d.list_16x16[matrix_id][i] = v,
                        _ => d.list_32x32[matrix_id][i] = v,
                    }
                }
            }
            matrix_id += step;
        }
    }
    Ok(d)
}

/// One resolved candidate short-term RPS (§7.3.7 / §7.4.8). Both the
/// explicit and the inter-set-predicted codings resolve to the same
/// derived variables, stored here:
///
/// * `delta_poc_s0[i]` — `DeltaPocS0[stRpsIdx][i]` (negative,
///   decreasing).
/// * `delta_poc_s1[i]` — `DeltaPocS1[stRpsIdx][i]` (positive,
///   increasing).
/// * `used_by_curr_pic_s0/s1[i]` — the matching
///   `UsedByCurrPicS0/S1` flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HevcShortTermRps {
    pub delta_poc_s0: Vec<i32>,
    pub used_by_curr_pic_s0: Vec<bool>,
    pub delta_poc_s1: Vec<i32>,
    pub used_by_curr_pic_s1: Vec<bool>,
}

impl HevcShortTermRps {
    /// `NumNegativePics` (7-63).
    pub fn num_negative_pics(&self) -> usize {
        self.delta_poc_s0.len()
    }

    /// `NumPositivePics` (7-64).
    pub fn num_positive_pics(&self) -> usize {
        self.delta_poc_s1.len()
    }

    /// `NumDeltaPocs` (7-71).
    pub fn num_delta_pocs(&self) -> usize {
        self.num_negative_pics() + self.num_positive_pics()
    }
}

/// Parse one `st_ref_pic_set( stRpsIdx )` (§7.3.7) and resolve it to
/// derived `DeltaPocS0/S1` form per §7.4.8.
///
/// `previous` holds the already-resolved candidate sets `0..stRpsIdx`
/// (needed for `inter_ref_pic_set_prediction_flag == 1`);
/// `max_dec_pic_buffering_minus1` bounds `num_negative_pics` /
/// `num_positive_pics` per §7.4.8.
fn parse_st_ref_pic_set(
    r: &mut BitReader<'_>,
    st_rps_idx: usize,
    previous: &[HevcShortTermRps],
    max_dec_pic_buffering_minus1: u32,
) -> Result<HevcShortTermRps, BitstreamError> {
    let inter_pred = if st_rps_idx != 0 { r.u(1) != 0 } else { false };
    if inter_pred {
        // delta_idx_minus1 is only coded when the set sits in a slice
        // header (stRpsIdx == num_short_term_ref_pic_sets); in the SPS
        // it is inferred to 0. This parser only walks SPS-resident
        // sets, so RefRpsIdx = stRpsIdx - 1 (7-59).
        let ref_rps = previous.last().ok_or_else(|| {
            BitstreamError::invalid("st_ref_pic_set inter prediction with no prior set")
        })?;
        let delta_rps_sign = r.u(1);
        let abs_delta_rps_minus1 = r.ue()?;
        // §7.4.8: abs_delta_rps_minus1 in 0..=2^15 - 1.
        if abs_delta_rps_minus1 > (1 << 15) - 1 {
            return Err(BitstreamError::invalid(
                "st_ref_pic_set abs_delta_rps_minus1 out of 0..=32767 (§7.4.8)",
            ));
        }
        let delta_rps = (1 - 2 * delta_rps_sign as i64) as i32 * (abs_delta_rps_minus1 as i32 + 1);
        let num_delta = ref_rps.num_delta_pocs();
        let mut used_by_curr = vec![false; num_delta + 1];
        let mut use_delta = vec![true; num_delta + 1];
        for j in 0..=num_delta {
            used_by_curr[j] = r.u(1) != 0;
            if !used_by_curr[j] {
                use_delta[j] = r.u(1) != 0;
            }
        }
        // Derivation (7-61) / (7-62).
        let ref_neg = ref_rps.num_negative_pics();
        let ref_pos = ref_rps.num_positive_pics();
        let mut out = HevcShortTermRps::default();
        for j in (0..ref_pos).rev() {
            let d_poc = ref_rps.delta_poc_s1[j] + delta_rps;
            if d_poc < 0 && use_delta[ref_neg + j] {
                out.delta_poc_s0.push(d_poc);
                out.used_by_curr_pic_s0.push(used_by_curr[ref_neg + j]);
            }
        }
        if delta_rps < 0 && use_delta[num_delta] {
            out.delta_poc_s0.push(delta_rps);
            out.used_by_curr_pic_s0.push(used_by_curr[num_delta]);
        }
        for j in 0..ref_neg {
            let d_poc = ref_rps.delta_poc_s0[j] + delta_rps;
            if d_poc < 0 && use_delta[j] {
                out.delta_poc_s0.push(d_poc);
                out.used_by_curr_pic_s0.push(used_by_curr[j]);
            }
        }
        for j in (0..ref_neg).rev() {
            let d_poc = ref_rps.delta_poc_s0[j] + delta_rps;
            if d_poc > 0 && use_delta[j] {
                out.delta_poc_s1.push(d_poc);
                out.used_by_curr_pic_s1.push(used_by_curr[j]);
            }
        }
        if delta_rps > 0 && use_delta[num_delta] {
            out.delta_poc_s1.push(delta_rps);
            out.used_by_curr_pic_s1.push(used_by_curr[num_delta]);
        }
        for j in 0..ref_pos {
            let d_poc = ref_rps.delta_poc_s1[j] + delta_rps;
            if d_poc > 0 && use_delta[ref_neg + j] {
                out.delta_poc_s1.push(d_poc);
                out.used_by_curr_pic_s1.push(used_by_curr[ref_neg + j]);
            }
        }
        Ok(out)
    } else {
        let num_negative_pics = r.ue()?;
        let num_positive_pics = r.ue()?;
        // §7.4.8 bounds both counts by
        // sps_max_dec_pic_buffering_minus1 — also bounds the loops on
        // hostile input.
        if num_negative_pics > max_dec_pic_buffering_minus1
            || num_positive_pics > max_dec_pic_buffering_minus1.saturating_sub(num_negative_pics)
        {
            return Err(BitstreamError::invalid(format!(
                "st_ref_pic_set num_negative_pics={num_negative_pics} / \
                 num_positive_pics={num_positive_pics} exceed \
                 sps_max_dec_pic_buffering_minus1={max_dec_pic_buffering_minus1} (§7.4.8)"
            )));
        }
        let mut out = HevcShortTermRps::default();
        let mut prev: i32 = 0;
        for _ in 0..num_negative_pics {
            let d = r.ue()?;
            if d > (1 << 15) - 1 {
                return Err(BitstreamError::invalid(
                    "delta_poc_s0_minus1 out of 0..=32767 (§7.4.8)",
                ));
            }
            // (7-67)/(7-69): each entry is prev − (delta + 1).
            prev -= d as i32 + 1;
            out.delta_poc_s0.push(prev);
            out.used_by_curr_pic_s0.push(r.u(1) != 0);
        }
        let mut prev: i32 = 0;
        for _ in 0..num_positive_pics {
            let d = r.ue()?;
            if d > (1 << 15) - 1 {
                return Err(BitstreamError::invalid(
                    "delta_poc_s1_minus1 out of 0..=32767 (§7.4.8)",
                ));
            }
            // (7-68)/(7-70).
            prev += d as i32 + 1;
            out.delta_poc_s1.push(prev);
            out.used_by_curr_pic_s1.push(r.u(1) != 0);
        }
        Ok(out)
    }
}

// ─────────────────────────── VUI / HRD (Annex E) ────────────────────────────

/// `aspect_ratio_idc` value signalling an explicit
/// `sar_width : sar_height` pair (Table E.1).
pub const HEVC_EXTENDED_SAR: u8 = 255;

/// One CPB schedule entry from `sub_layer_hrd_parameters()` (§E.2.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HevcCpbEntry {
    pub bit_rate_value_minus1: u32,
    pub cpb_size_value_minus1: u32,
    /// Coded only when `sub_pic_hrd_params_present_flag` (§E.2.3).
    pub cpb_size_du_value_minus1: u32,
    pub bit_rate_du_value_minus1: u32,
    pub cbr_flag: bool,
}

/// Per-sub-layer HRD info (the §E.2.2 loop body plus its §E.2.3
/// schedule lists).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HevcHrdSubLayer {
    pub fixed_pic_rate_general_flag: bool,
    /// Inferred equal to `fixed_pic_rate_general_flag` when that flag
    /// is set (§E.3.2).
    pub fixed_pic_rate_within_cvs_flag: bool,
    /// Present iff `fixed_pic_rate_within_cvs_flag` (§E.2.2).
    pub elemental_duration_in_tc_minus1: Option<u32>,
    pub low_delay_hrd_flag: bool,
    /// §E.3.2: 0..=31; inferred 0 when absent.
    pub cpb_cnt_minus1: u32,
    /// `sub_layer_hrd_parameters(i)` for the NAL HRD, when signalled.
    pub nal_cpb: Vec<HevcCpbEntry>,
    /// Same for the VCL HRD.
    pub vcl_cpb: Vec<HevcCpbEntry>,
}

/// `hrd_parameters( commonInfPresentFlag, maxNumSubLayersMinus1 )`
/// (§E.2.2), as embedded in the SPS VUI (`commonInfPresentFlag == 1`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HevcHrdParameters {
    pub nal_hrd_parameters_present_flag: bool,
    pub vcl_hrd_parameters_present_flag: bool,
    pub sub_pic_hrd_params_present_flag: bool,
    pub tick_divisor_minus2: u8,
    pub du_cpb_removal_delay_increment_length_minus1: u8,
    pub sub_pic_cpb_params_in_pic_timing_sei_flag: bool,
    pub dpb_output_delay_du_length_minus1: u8,
    pub bit_rate_scale: u8,
    pub cpb_size_scale: u8,
    pub cpb_size_du_scale: u8,
    pub initial_cpb_removal_delay_length_minus1: u8,
    pub au_cpb_removal_delay_length_minus1: u8,
    pub dpb_output_delay_length_minus1: u8,
    /// One entry per sub-layer `0..=maxNumSubLayersMinus1`.
    pub sub_layers: Vec<HevcHrdSubLayer>,
}

/// Parse `sub_layer_hrd_parameters( subLayerId )` (§E.2.3).
fn parse_sub_layer_hrd(
    r: &mut BitReader<'_>,
    cpb_cnt: u32,
    sub_pic: bool,
) -> Result<Vec<HevcCpbEntry>, BitstreamError> {
    let mut out = Vec::new();
    for _ in 0..cpb_cnt {
        let mut e = HevcCpbEntry {
            bit_rate_value_minus1: r.ue()?,
            cpb_size_value_minus1: r.ue()?,
            ..HevcCpbEntry::default()
        };
        if sub_pic {
            e.cpb_size_du_value_minus1 = r.ue()?;
            e.bit_rate_du_value_minus1 = r.ue()?;
        }
        e.cbr_flag = r.u(1) != 0;
        out.push(e);
    }
    Ok(out)
}

/// Parse `hrd_parameters( 1, max_num_sub_layers_minus1 )` (§E.2.2)
/// as invoked from the SPS VUI.
fn parse_hrd_parameters(
    r: &mut BitReader<'_>,
    max_num_sub_layers_minus1: u8,
) -> Result<HevcHrdParameters, BitstreamError> {
    let mut hrd = HevcHrdParameters {
        nal_hrd_parameters_present_flag: r.u(1) != 0,
        vcl_hrd_parameters_present_flag: r.u(1) != 0,
        ..HevcHrdParameters::default()
    };
    if hrd.nal_hrd_parameters_present_flag || hrd.vcl_hrd_parameters_present_flag {
        hrd.sub_pic_hrd_params_present_flag = r.u(1) != 0;
        if hrd.sub_pic_hrd_params_present_flag {
            hrd.tick_divisor_minus2 = r.u(8) as u8;
            hrd.du_cpb_removal_delay_increment_length_minus1 = r.u(5) as u8;
            hrd.sub_pic_cpb_params_in_pic_timing_sei_flag = r.u(1) != 0;
            hrd.dpb_output_delay_du_length_minus1 = r.u(5) as u8;
        }
        hrd.bit_rate_scale = r.u(4) as u8;
        hrd.cpb_size_scale = r.u(4) as u8;
        if hrd.sub_pic_hrd_params_present_flag {
            hrd.cpb_size_du_scale = r.u(4) as u8;
        }
        hrd.initial_cpb_removal_delay_length_minus1 = r.u(5) as u8;
        hrd.au_cpb_removal_delay_length_minus1 = r.u(5) as u8;
        hrd.dpb_output_delay_length_minus1 = r.u(5) as u8;
    }
    for _ in 0..=max_num_sub_layers_minus1 {
        let mut sl = HevcHrdSubLayer {
            fixed_pic_rate_general_flag: r.u(1) != 0,
            ..HevcHrdSubLayer::default()
        };
        sl.fixed_pic_rate_within_cvs_flag = if sl.fixed_pic_rate_general_flag {
            true // inferred (§E.3.2)
        } else {
            r.u(1) != 0
        };
        if sl.fixed_pic_rate_within_cvs_flag {
            sl.elemental_duration_in_tc_minus1 = Some(r.ue()?);
        } else {
            sl.low_delay_hrd_flag = r.u(1) != 0;
        }
        if !sl.low_delay_hrd_flag {
            let cpb_cnt_minus1 = r.ue()?;
            // §E.3.2: 0..=31 — bounds the schedule loops.
            if cpb_cnt_minus1 > 31 {
                return Err(BitstreamError::invalid(format!(
                    "hrd_parameters cpb_cnt_minus1={cpb_cnt_minus1} (must be 0..=31, §E.3.2)"
                )));
            }
            sl.cpb_cnt_minus1 = cpb_cnt_minus1;
        }
        let cpb_cnt = sl.cpb_cnt_minus1 + 1;
        if hrd.nal_hrd_parameters_present_flag {
            sl.nal_cpb = parse_sub_layer_hrd(r, cpb_cnt, hrd.sub_pic_hrd_params_present_flag)?;
        }
        if hrd.vcl_hrd_parameters_present_flag {
            sl.vcl_cpb = parse_sub_layer_hrd(r, cpb_cnt, hrd.sub_pic_hrd_params_present_flag)?;
        }
        hrd.sub_layers.push(sl);
    }
    Ok(hrd)
}

/// Default display window offsets (§E.2.1), in units of the chroma
/// sampling grid like the conformance window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HevcDefaultDisplayWindow {
    pub left: u32,
    pub right: u32,
    pub top: u32,
    pub bottom: u32,
}

/// VUI parameters (§E.2.1 / §E.3.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HevcVui {
    pub aspect_ratio_info_present_flag: bool,
    /// Table E.1; 255 = [`HEVC_EXTENDED_SAR`].
    pub aspect_ratio_idc: u8,
    pub sar_width: u16,
    pub sar_height: u16,

    pub overscan_info_present_flag: bool,
    pub overscan_appropriate_flag: bool,

    pub video_signal_type_present_flag: bool,
    pub video_format: u8,
    pub video_full_range_flag: bool,
    pub colour_description_present_flag: bool,
    pub colour_primaries: u8,
    pub transfer_characteristics: u8,
    pub matrix_coeffs: u8,

    pub chroma_loc_info_present_flag: bool,
    pub chroma_sample_loc_type_top_field: u32,
    pub chroma_sample_loc_type_bottom_field: u32,

    pub neutral_chroma_indication_flag: bool,
    pub field_seq_flag: bool,
    pub frame_field_info_present_flag: bool,
    pub default_display_window: Option<HevcDefaultDisplayWindow>,

    pub vui_timing_info_present_flag: bool,
    pub vui_num_units_in_tick: u32,
    pub vui_time_scale: u32,
    pub vui_poc_proportional_to_timing_flag: bool,
    pub vui_num_ticks_poc_diff_one_minus1: u32,
    pub hrd_parameters: Option<HevcHrdParameters>,

    pub bitstream_restriction_flag: bool,
    pub tiles_fixed_structure_flag: bool,
    pub motion_vectors_over_pic_boundaries_flag: bool,
    pub restricted_ref_pic_lists_flag: bool,
    pub min_spatial_segmentation_idc: u32,
    pub max_bytes_per_pic_denom: u32,
    pub max_bits_per_min_cu_denom: u32,
    pub log2_max_mv_length_horizontal: u32,
    pub log2_max_mv_length_vertical: u32,
}

impl HevcVui {
    /// Sample aspect ratio `(width, height)` per Table E.1 (fixed
    /// band identical to H.264's Table E-1). `None` for unspecified
    /// (0) and the reserved band 17..=254.
    pub fn sample_aspect_ratio(&self) -> Option<(u16, u16)> {
        if !self.aspect_ratio_info_present_flag {
            return None;
        }
        Some(match self.aspect_ratio_idc {
            1 => (1, 1),
            2 => (12, 11),
            3 => (10, 11),
            4 => (16, 11),
            5 => (40, 33),
            6 => (24, 11),
            7 => (20, 11),
            8 => (32, 11),
            9 => (80, 33),
            10 => (18, 11),
            11 => (15, 11),
            12 => (64, 33),
            13 => (160, 99),
            14 => (4, 3),
            15 => (3, 2),
            16 => (2, 1),
            HEVC_EXTENDED_SAR => (self.sar_width, self.sar_height),
            _ => return None,
        })
    }

    /// Picture rate `vui_time_scale / vui_num_units_in_tick` as a
    /// rational `(num, den)` (§E.3.1 — for HEVC the tick counts whole
    /// pictures, not fields). `None` without timing info or with a
    /// zero denominator.
    pub fn picture_rate(&self) -> Option<(u32, u32)> {
        if !self.vui_timing_info_present_flag || self.vui_num_units_in_tick == 0 {
            return None;
        }
        Some((self.vui_time_scale, self.vui_num_units_in_tick))
    }
}

/// Parse `vui_parameters()` (§E.2.1). `max_num_sub_layers_minus1`
/// flows into the embedded `hrd_parameters()`.
fn parse_vui_parameters(
    r: &mut BitReader<'_>,
    max_num_sub_layers_minus1: u8,
) -> Result<HevcVui, BitstreamError> {
    let mut vui = HevcVui {
        aspect_ratio_info_present_flag: r.u(1) != 0,
        ..HevcVui::default()
    };
    if vui.aspect_ratio_info_present_flag {
        vui.aspect_ratio_idc = r.u(8) as u8;
        if vui.aspect_ratio_idc == HEVC_EXTENDED_SAR {
            vui.sar_width = r.u(16) as u16;
            vui.sar_height = r.u(16) as u16;
        }
    }
    vui.overscan_info_present_flag = r.u(1) != 0;
    if vui.overscan_info_present_flag {
        vui.overscan_appropriate_flag = r.u(1) != 0;
    }
    vui.video_signal_type_present_flag = r.u(1) != 0;
    if vui.video_signal_type_present_flag {
        vui.video_format = r.u(3) as u8;
        vui.video_full_range_flag = r.u(1) != 0;
        vui.colour_description_present_flag = r.u(1) != 0;
        if vui.colour_description_present_flag {
            vui.colour_primaries = r.u(8) as u8;
            vui.transfer_characteristics = r.u(8) as u8;
            vui.matrix_coeffs = r.u(8) as u8;
        }
    }
    vui.chroma_loc_info_present_flag = r.u(1) != 0;
    if vui.chroma_loc_info_present_flag {
        vui.chroma_sample_loc_type_top_field = r.ue()?;
        vui.chroma_sample_loc_type_bottom_field = r.ue()?;
    }
    vui.neutral_chroma_indication_flag = r.u(1) != 0;
    vui.field_seq_flag = r.u(1) != 0;
    vui.frame_field_info_present_flag = r.u(1) != 0;
    if r.u(1) != 0 {
        // default_display_window_flag
        vui.default_display_window = Some(HevcDefaultDisplayWindow {
            left: r.ue()?,
            right: r.ue()?,
            top: r.ue()?,
            bottom: r.ue()?,
        });
    }
    vui.vui_timing_info_present_flag = r.u(1) != 0;
    if vui.vui_timing_info_present_flag {
        vui.vui_num_units_in_tick = r.u(32);
        vui.vui_time_scale = r.u(32);
        vui.vui_poc_proportional_to_timing_flag = r.u(1) != 0;
        if vui.vui_poc_proportional_to_timing_flag {
            vui.vui_num_ticks_poc_diff_one_minus1 = r.ue()?;
        }
        if r.u(1) != 0 {
            // vui_hrd_parameters_present_flag
            vui.hrd_parameters = Some(parse_hrd_parameters(r, max_num_sub_layers_minus1)?);
        }
    }
    vui.bitstream_restriction_flag = r.u(1) != 0;
    if vui.bitstream_restriction_flag {
        vui.tiles_fixed_structure_flag = r.u(1) != 0;
        vui.motion_vectors_over_pic_boundaries_flag = r.u(1) != 0;
        vui.restricted_ref_pic_lists_flag = r.u(1) != 0;
        vui.min_spatial_segmentation_idc = r.ue()?;
        vui.max_bytes_per_pic_denom = r.ue()?;
        vui.max_bits_per_min_cu_denom = r.ue()?;
        vui.log2_max_mv_length_horizontal = r.ue()?;
        vui.log2_max_mv_length_vertical = r.ue()?;
    }
    Ok(vui)
}

/// Video parameter set (7.3.2.1). Reduced — most VPS contents are
/// not consumed by the slice-data HW APIs (they look at the SPS).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HevcVps {
    pub vps_video_parameter_set_id: u8,
    pub vps_max_layers_minus1: u8,
    pub vps_max_sub_layers_minus1: u8,
    pub vps_temporal_id_nesting_flag: bool,
    pub profile_tier_level: HevcProfileTierLevel,
}

/// Sequence parameter set (7.3.2.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HevcSps {
    pub sps_video_parameter_set_id: u8,
    pub sps_max_sub_layers_minus1: u8,
    pub sps_temporal_id_nesting_flag: bool,
    pub profile_tier_level: HevcProfileTierLevel,

    pub sps_seq_parameter_set_id: u8,
    pub chroma_format_idc: u8,
    pub separate_colour_plane_flag: bool,

    pub pic_width_in_luma_samples: u32,
    pub pic_height_in_luma_samples: u32,
    pub conformance_window: Option<HevcConformanceWindow>,

    pub bit_depth_luma_minus8: u8,
    pub bit_depth_chroma_minus8: u8,

    pub log2_max_pic_order_cnt_lsb_minus4: u8,
    /// `sps_max_dec_pic_buffering_minus1[sps_max_sub_layers_minus1]`.
    pub sps_max_dec_pic_buffering_minus1: u32,
    pub sps_max_num_reorder_pics: u32,
    pub sps_max_latency_increase_plus1: u32,

    pub log2_min_luma_coding_block_size_minus3: u8,
    pub log2_diff_max_min_luma_coding_block_size: u8,
    pub log2_min_luma_transform_block_size_minus2: u8,
    pub log2_diff_max_min_luma_transform_block_size: u8,
    pub max_transform_hierarchy_depth_inter: u8,
    pub max_transform_hierarchy_depth_intra: u8,

    pub scaling_list_enabled_flag: bool,
    /// `Some` when `sps_scaling_list_data_present_flag == 1`
    /// (§7.3.2.2.1). `scaling_list_enabled_flag == 1` with `None`
    /// means the default matrices of §7.4.5 apply.
    pub scaling_list_data: Option<HevcScalingListData>,
    pub amp_enabled_flag: bool,
    pub sample_adaptive_offset_enabled_flag: bool,
    pub pcm_enabled_flag: bool,
    /// PCM block fields (§7.3.2.2.1), present iff `pcm_enabled_flag`.
    pub pcm_sample_bit_depth_luma_minus1: u8,
    pub pcm_sample_bit_depth_chroma_minus1: u8,
    pub log2_min_pcm_luma_coding_block_size_minus3: u8,
    pub log2_diff_max_min_pcm_luma_coding_block_size: u8,
    pub pcm_loop_filter_disabled_flag: bool,
    pub num_short_term_ref_pic_sets: u32,
    /// The candidate sets, resolved to `DeltaPocS0/S1` form per
    /// §7.4.8 (inter-set prediction already applied).
    pub short_term_rps: Vec<HevcShortTermRps>,
    pub long_term_ref_pics_present_flag: bool,
    pub num_long_term_ref_pics_sps: u32,
    /// `(lt_ref_pic_poc_lsb_sps[i], used_by_curr_pic_lt_sps_flag[i])`
    /// (§7.3.2.2.1).
    pub long_term_ref_pics: Vec<(u32, bool)>,
    pub sps_temporal_mvp_enabled_flag: bool,
    pub strong_intra_smoothing_enabled_flag: bool,
    /// `Some` when `vui_parameters_present_flag == 1` (Annex E).
    pub vui: Option<HevcVui>,
    /// §7.3.2.2.1 extension flags (all parse; the range extension's
    /// *content* also parses, SCC/multilayer/3D content does not).
    pub sps_range_extension_flag: bool,
    pub sps_multilayer_extension_flag: bool,
    pub sps_3d_extension_flag: bool,
    pub sps_scc_extension_flag: bool,
    /// `Some` when `sps_range_extension_flag == 1` (§7.3.2.2.2).
    pub range_extension: Option<HevcSpsRangeExtension>,
}

/// SPS range extension (§7.3.2.2.2) — nine coding-tool flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HevcSpsRangeExtension {
    pub transform_skip_rotation_enabled_flag: bool,
    pub transform_skip_context_enabled_flag: bool,
    pub implicit_rdpcm_enabled_flag: bool,
    pub explicit_rdpcm_enabled_flag: bool,
    pub extended_precision_processing_flag: bool,
    pub intra_smoothing_disabled_flag: bool,
    pub high_precision_offsets_enabled_flag: bool,
    pub persistent_rice_adaptation_enabled_flag: bool,
    pub cabac_bypass_alignment_enabled_flag: bool,
}

impl HevcSps {
    /// Effective coded width in luma samples (= `pic_width_in_luma_samples`).
    pub fn coded_width(&self) -> u32 {
        self.pic_width_in_luma_samples
    }

    /// Effective coded height in luma samples.
    pub fn coded_height(&self) -> u32 {
        self.pic_height_in_luma_samples
    }

    /// SubWidthC table — H.265 6.2.
    fn sub_width_c(&self) -> u32 {
        match self.chroma_format_idc {
            1 | 2 => 2,
            _ => 1,
        }
    }

    fn sub_height_c(&self) -> u32 {
        match self.chroma_format_idc {
            1 => 2,
            _ => 1,
        }
    }

    /// Display width after applying the conformance window
    /// (7.4.3.2.1).
    pub fn display_width(&self) -> u32 {
        let Some(c) = self.conformance_window else {
            return self.coded_width();
        };
        let sw = self.sub_width_c();
        self.coded_width().saturating_sub((c.left + c.right) * sw)
    }

    /// Display height after applying the conformance window.
    pub fn display_height(&self) -> u32 {
        let Some(c) = self.conformance_window else {
            return self.coded_height();
        };
        let sh = self.sub_height_c();
        self.coded_height().saturating_sub((c.top + c.bottom) * sh)
    }
}

/// Picture parameter set (7.3.2.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HevcPps {
    pub pps_pic_parameter_set_id: u8,
    pub pps_seq_parameter_set_id: u8,
    pub dependent_slice_segments_enabled_flag: bool,
    pub output_flag_present_flag: bool,
    pub num_extra_slice_header_bits: u8,
    pub sign_data_hiding_enabled_flag: bool,
    pub cabac_init_present_flag: bool,
    pub num_ref_idx_l0_default_active_minus1: u8,
    pub num_ref_idx_l1_default_active_minus1: u8,
    pub init_qp_minus26: i32,
    pub constrained_intra_pred_flag: bool,
    pub transform_skip_enabled_flag: bool,
    pub cu_qp_delta_enabled_flag: bool,
    pub diff_cu_qp_delta_depth: u32,
    pub pps_cb_qp_offset: i32,
    pub pps_cr_qp_offset: i32,
    pub pps_slice_chroma_qp_offsets_present_flag: bool,
    pub weighted_pred_flag: bool,
    pub weighted_bipred_flag: bool,
    pub transquant_bypass_enabled_flag: bool,
    pub tiles_enabled_flag: bool,
    pub entropy_coding_sync_enabled_flag: bool,
    /// 7.4.3.3.1 — controls whether the in-loop deblocking filter
    /// crosses slice boundaries.
    pub pps_loop_filter_across_slices_enabled_flag: bool,
    /// 7.4.3.3.1 — gates the deblocking-filter syntax block below.
    pub deblocking_filter_control_present_flag: bool,
    /// 7.4.3.3.1 — when set, allows the slice header to override
    /// the PPS deblocking-filter parameters.
    pub deblocking_filter_override_enabled_flag: bool,
    /// 7.4.3.3.1 — disables the deblocking filter when set.
    pub pps_deblocking_filter_disabled_flag: bool,
    /// 7.4.3.3.1 — beta offset / 2 (signed Exp-Golomb), -6..6.
    pub pps_beta_offset_div2: i32,
    /// 7.4.3.3.1 — tc offset / 2 (signed Exp-Golomb), -6..6.
    pub pps_tc_offset_div2: i32,
    /// 7.4.3.3.1 — controls whether ref-pic-list modification is
    /// signalled in the slice header.
    pub lists_modification_present_flag: bool,
    /// 7.4.3.3.1 — log2 of the minimum CU size that allows
    /// parallel merge candidate derivation.
    pub log2_parallel_merge_level_minus2: u32,
    /// 7.4.3.3.1 — gates the slice-segment header extension block.
    pub slice_segment_header_extension_present_flag: bool,
    /// `Some` when `tiles_enabled_flag == 1` (§7.3.2.3.1).
    pub tiles: Option<HevcTiles>,
    /// `Some` when `pps_scaling_list_data_present_flag == 1`.
    pub scaling_list_data: Option<HevcScalingListData>,
    /// §7.3.2.3.1 extension flags.
    pub pps_range_extension_flag: bool,
    pub pps_multilayer_extension_flag: bool,
    pub pps_3d_extension_flag: bool,
    pub pps_scc_extension_flag: bool,
    /// `Some` when `pps_range_extension_flag == 1` (§7.3.2.3.2).
    pub range_extension: Option<HevcPpsRangeExtension>,
}

/// Tile grid signalled in the PPS (§7.3.2.3.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HevcTiles {
    pub num_tile_columns_minus1: u32,
    pub num_tile_rows_minus1: u32,
    pub uniform_spacing_flag: bool,
    /// `column_width_minus1[i]` — coded only when
    /// `uniform_spacing_flag == 0`.
    pub column_widths_minus1: Vec<u32>,
    /// `row_height_minus1[i]` — likewise.
    pub row_heights_minus1: Vec<u32>,
    pub loop_filter_across_tiles_enabled_flag: bool,
}

/// PPS range extension (§7.3.2.3.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HevcPpsRangeExtension {
    /// Coded only when the PPS's `transform_skip_enabled_flag`.
    pub log2_max_transform_skip_block_size_minus2: u32,
    pub cross_component_prediction_enabled_flag: bool,
    pub chroma_qp_offset_list_enabled_flag: bool,
    pub diff_cu_chroma_qp_offset_depth: u32,
    /// `(cb_qp_offset_list[i], cr_qp_offset_list[i])` pairs.
    pub chroma_qp_offset_list: Vec<(i32, i32)>,
    pub log2_sao_offset_scale_luma: u32,
    pub log2_sao_offset_scale_chroma: u32,
}

/// Minimal slice segment header (7.3.6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HevcSliceHeader {
    pub first_slice_segment_in_pic_flag: bool,
    pub no_output_of_prior_pics_flag: bool,
    pub slice_pic_parameter_set_id: u8,
    /// 0 = B, 1 = P, 2 = I.
    pub slice_type: u8,
    pub slice_pic_order_cnt_lsb: u32,
    pub slice_temporal_mvp_enabled_flag: bool,
    /// True iff this header was parsed from an IRAP NAL
    /// (IDR_*, CRA).
    pub is_irap: bool,
}

/// Convenience structure for [`parse_idr_only`].
#[derive(Debug)]
pub struct HevcIdrParse<'a> {
    pub vps: HevcVps,
    pub sps: HevcSps,
    pub pps: HevcPps,
    pub slice_header: HevcSliceHeader,
    pub nal_unit_type: u8,
    pub idr_access_unit: &'a [u8],
}

// ─────────────────────────── profile_tier_level() ────────────────────────────

fn parse_profile_tier_level(
    r: &mut BitReader<'_>,
    profile_present: bool,
    max_num_sub_layers_minus1: u8,
) -> Result<HevcProfileTierLevel, BitstreamError> {
    let mut ptl = HevcProfileTierLevel::default();
    if profile_present {
        ptl.general_profile_space = r.u(2) as u8;
        ptl.general_tier_flag = r.u(1) != 0;
        ptl.general_profile_idc = r.u(5) as u8;
        ptl.general_profile_compatibility_flags = r.u(32);
        // general_progressive_source_flag, general_interlaced_source_flag,
        // general_non_packed_constraint_flag, general_frame_only_constraint_flag,
        // 43 + 1 = 44 reserved bits.
        let _flags_top = r.u(4);
        // The 43 reserved-zero bits + 1 inbld follow; their semantics
        // depend on profile, but for parsing we just consume them.
        let _flags_mid = r.u(32);
        let _flags_bot = r.u(11);
        let _general_inbld_or_reserved = r.u(1);
    }
    ptl.general_level_idc = r.u(8) as u8;

    // Per-sub-layer flags. We don't expose them, but we have to read
    // them to keep our bit position correct.
    if max_num_sub_layers_minus1 > 0 {
        let mut sub_layer_profile_present = [false; 7];
        let mut sub_layer_level_present = [false; 7];
        for i in 0..max_num_sub_layers_minus1 as usize {
            sub_layer_profile_present[i] = r.u(1) != 0;
            sub_layer_level_present[i] = r.u(1) != 0;
        }
        // 2*(8 - max_num_sub_layers_minus1) reserved-zero bits.
        for _ in max_num_sub_layers_minus1..8 {
            let _ = r.u(2);
        }
        for i in 0..max_num_sub_layers_minus1 as usize {
            if sub_layer_profile_present[i] {
                let _profile_space = r.u(2);
                let _tier_flag = r.u(1);
                let _profile_idc = r.u(5);
                let _compat = r.u(32);
                // 4 source/constraint flags + 43 reserved + 1 inbld
                let _ = r.u(4);
                let _ = r.u(32);
                let _ = r.u(11);
                let _ = r.u(1);
            }
            if sub_layer_level_present[i] {
                let _sub_level_idc = r.u(8);
            }
        }
    }
    Ok(ptl)
}

// ─────────────────────────── Parsers ─────────────────────────────────────────

/// Parse a VPS NAL (with two-byte NAL header at index 0..1).
pub fn parse_vps_nal(nal: &[u8]) -> Result<HevcVps, BitstreamError> {
    if nal.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "VPS NAL shorter than 2 bytes",
        ));
    }
    let (_, nal_type, _, _) = nal_header(nal[0], nal[1]);
    if nal_type != NAL_TYPE_VPS {
        return Err(BitstreamError::invalid(format!(
            "expected VPS NAL (type=32), got type={nal_type}"
        )));
    }
    let rbsp = ebsp_to_rbsp(&nal[2..]);
    let mut r = BitReader::new(&rbsp);
    let mut vps = HevcVps {
        vps_video_parameter_set_id: r.u(4) as u8,
        ..HevcVps::default()
    };
    let _vps_base_layer_internal_flag = r.u(1);
    let _vps_base_layer_available_flag = r.u(1);
    vps.vps_max_layers_minus1 = r.u(6) as u8;
    vps.vps_max_sub_layers_minus1 = r.u(3) as u8;
    vps.vps_temporal_id_nesting_flag = r.u(1) != 0;
    let _vps_reserved_0xffff_16bits = r.u(16);
    vps.profile_tier_level = parse_profile_tier_level(&mut r, true, vps.vps_max_sub_layers_minus1)?;
    // Remaining VPS fields (vps_sub_layer_ordering_info, layer_id_included…,
    // vps_num_hrd_parameters, VUI, extensions) are not consumed.
    Ok(vps)
}

/// Parse an SPS NAL (with two-byte NAL header at index 0..1).
pub fn parse_sps_nal(nal: &[u8]) -> Result<HevcSps, BitstreamError> {
    if nal.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "SPS NAL shorter than 2 bytes",
        ));
    }
    let (_, nal_type, _, _) = nal_header(nal[0], nal[1]);
    if nal_type != NAL_TYPE_SPS {
        return Err(BitstreamError::invalid(format!(
            "expected SPS NAL (type=33), got type={nal_type}"
        )));
    }
    let rbsp = ebsp_to_rbsp(&nal[2..]);
    let mut r = BitReader::new(&rbsp);
    let mut sps = HevcSps {
        sps_video_parameter_set_id: r.u(4) as u8,
        sps_max_sub_layers_minus1: r.u(3) as u8,
        sps_temporal_id_nesting_flag: r.u(1) != 0,
        ..HevcSps::default()
    };
    sps.profile_tier_level = parse_profile_tier_level(&mut r, true, sps.sps_max_sub_layers_minus1)?;
    sps.sps_seq_parameter_set_id = r.ue()? as u8;
    sps.chroma_format_idc = r.ue()? as u8;
    if sps.chroma_format_idc == 3 {
        sps.separate_colour_plane_flag = r.u(1) != 0;
    }
    sps.pic_width_in_luma_samples = r.ue()?;
    sps.pic_height_in_luma_samples = r.ue()?;
    let conformance_window_flag = r.u(1);
    if conformance_window_flag != 0 {
        sps.conformance_window = Some(HevcConformanceWindow {
            left: r.ue()?,
            right: r.ue()?,
            top: r.ue()?,
            bottom: r.ue()?,
        });
    }
    sps.bit_depth_luma_minus8 = r.ue()? as u8;
    sps.bit_depth_chroma_minus8 = r.ue()? as u8;
    // H.265 §7.4.3.2.1 constrains log2_max_pic_order_cnt_lsb_minus4 to
    // 0..=12 (slice_pic_order_cnt_lsb is read as u(value + 4), i.e. at
    // most 16 bits). A larger value from a malformed SPS would later
    // drive `BitReader::u(n > 32)` in the slice-header parser, so reject
    // it here.
    let log2_max_poc_lsb_minus4 = r.ue()?;
    if log2_max_poc_lsb_minus4 > 12 {
        return Err(BitstreamError::invalid(format!(
            "SPS log2_max_pic_order_cnt_lsb_minus4={log2_max_poc_lsb_minus4} (must be 0..=12)"
        )));
    }
    sps.log2_max_pic_order_cnt_lsb_minus4 = log2_max_poc_lsb_minus4 as u8;

    let sps_sub_layer_ordering_info_present_flag = r.u(1);
    let start = if sps_sub_layer_ordering_info_present_flag != 0 {
        0
    } else {
        sps.sps_max_sub_layers_minus1 as usize
    };
    // For each sub-layer in [start, sps_max_sub_layers_minus1], read
    // three ue(v) values. Keep only the [sps_max_sub_layers_minus1]
    // entry (the highest layer — the one DPB sizing uses).
    let mut last_max_dec = 0u32;
    let mut last_max_reorder = 0u32;
    let mut last_max_latency = 0u32;
    for _ in start..=sps.sps_max_sub_layers_minus1 as usize {
        last_max_dec = r.ue()?;
        last_max_reorder = r.ue()?;
        last_max_latency = r.ue()?;
    }
    // §7.4.3.2.1 bounds sps_max_dec_pic_buffering_minus1 by
    // MaxDpbSize − 1, and A.4.2 caps MaxDpbSize at 16. Enforcing the
    // cap here also bounds the st_ref_pic_set entry loops below.
    if last_max_dec > 15 {
        return Err(BitstreamError::invalid(format!(
            "SPS sps_max_dec_pic_buffering_minus1={last_max_dec} (MaxDpbSize caps at 16, §A.4.2)"
        )));
    }
    sps.sps_max_dec_pic_buffering_minus1 = last_max_dec;
    sps.sps_max_num_reorder_pics = last_max_reorder;
    sps.sps_max_latency_increase_plus1 = last_max_latency;

    // Profile conformance (§A.3) requires the derived CtbLog2SizeY
    // (7-10/7-11: log2_min_luma_coding_block_size_minus3 + 3 +
    // log2_diff_max_min_luma_coding_block_size) to be 4..=6. A hostile
    // SPS outside that range would silently truncate through the u8
    // fields and later drive an overflowing `1 << CtbLog2SizeY` in the
    // slice-segment-address width computation, so reject it here.
    let log2_min_cb_minus3 = r.ue()?;
    let log2_diff_cb = r.ue()?;
    let ctb_log2 = log2_min_cb_minus3 as u64 + 3 + log2_diff_cb as u64;
    if !(4..=6).contains(&ctb_log2) {
        return Err(BitstreamError::invalid(format!(
            "SPS CtbLog2SizeY={ctb_log2} (must be 4..=6, §A.3 profile conformance)"
        )));
    }
    sps.log2_min_luma_coding_block_size_minus3 = log2_min_cb_minus3 as u8;
    sps.log2_diff_max_min_luma_coding_block_size = log2_diff_cb as u8;
    sps.log2_min_luma_transform_block_size_minus2 = r.ue()? as u8;
    sps.log2_diff_max_min_luma_transform_block_size = r.ue()? as u8;
    sps.max_transform_hierarchy_depth_inter = r.ue()? as u8;
    sps.max_transform_hierarchy_depth_intra = r.ue()? as u8;

    sps.scaling_list_enabled_flag = r.u(1) != 0;
    if sps.scaling_list_enabled_flag {
        let sps_scaling_list_data_present = r.u(1);
        if sps_scaling_list_data_present != 0 {
            sps.scaling_list_data = Some(parse_scaling_list_data(&mut r)?);
        }
    }
    sps.amp_enabled_flag = r.u(1) != 0;
    sps.sample_adaptive_offset_enabled_flag = r.u(1) != 0;
    sps.pcm_enabled_flag = r.u(1) != 0;
    if sps.pcm_enabled_flag {
        sps.pcm_sample_bit_depth_luma_minus1 = r.u(4) as u8;
        sps.pcm_sample_bit_depth_chroma_minus1 = r.u(4) as u8;
        sps.log2_min_pcm_luma_coding_block_size_minus3 = r.ue()? as u8;
        sps.log2_diff_max_min_pcm_luma_coding_block_size = r.ue()? as u8;
        sps.pcm_loop_filter_disabled_flag = r.u(1) != 0;
    }
    sps.num_short_term_ref_pic_sets = r.ue()?;
    // §7.4.3.2.1: 0..=64 — also bounds the parse loop.
    if sps.num_short_term_ref_pic_sets > 64 {
        return Err(BitstreamError::invalid(format!(
            "SPS num_short_term_ref_pic_sets={} (must be 0..=64, §7.4.3.2.1)",
            sps.num_short_term_ref_pic_sets
        )));
    }
    for i in 0..sps.num_short_term_ref_pic_sets as usize {
        let set = parse_st_ref_pic_set(
            &mut r,
            i,
            &sps.short_term_rps,
            sps.sps_max_dec_pic_buffering_minus1,
        )?;
        sps.short_term_rps.push(set);
    }
    sps.long_term_ref_pics_present_flag = r.u(1) != 0;
    if sps.long_term_ref_pics_present_flag {
        sps.num_long_term_ref_pics_sps = r.ue()?;
        // §7.4.3.2.1: 0..=32 — bounds the loop.
        if sps.num_long_term_ref_pics_sps > 32 {
            return Err(BitstreamError::invalid(format!(
                "SPS num_long_term_ref_pics_sps={} (must be 0..=32, §7.4.3.2.1)",
                sps.num_long_term_ref_pics_sps
            )));
        }
        let poc_bits = sps.log2_max_pic_order_cnt_lsb_minus4 as u32 + 4;
        for _ in 0..sps.num_long_term_ref_pics_sps {
            let lsb = r.u(poc_bits);
            let used = r.u(1) != 0;
            sps.long_term_ref_pics.push((lsb, used));
        }
    }
    sps.sps_temporal_mvp_enabled_flag = r.u(1) != 0;
    sps.strong_intra_smoothing_enabled_flag = r.u(1) != 0;
    let vui_parameters_present_flag = r.u(1);
    if vui_parameters_present_flag != 0 {
        sps.vui = Some(parse_vui_parameters(&mut r, sps.sps_max_sub_layers_minus1)?);
    }
    let sps_extension_present_flag = r.u(1);
    if sps_extension_present_flag != 0 {
        sps.sps_range_extension_flag = r.u(1) != 0;
        sps.sps_multilayer_extension_flag = r.u(1) != 0;
        sps.sps_3d_extension_flag = r.u(1) != 0;
        sps.sps_scc_extension_flag = r.u(1) != 0;
        let _sps_extension_4bits = r.u(4);
    }
    if sps.sps_range_extension_flag {
        sps.range_extension = Some(HevcSpsRangeExtension {
            transform_skip_rotation_enabled_flag: r.u(1) != 0,
            transform_skip_context_enabled_flag: r.u(1) != 0,
            implicit_rdpcm_enabled_flag: r.u(1) != 0,
            explicit_rdpcm_enabled_flag: r.u(1) != 0,
            extended_precision_processing_flag: r.u(1) != 0,
            intra_smoothing_disabled_flag: r.u(1) != 0,
            high_precision_offsets_enabled_flag: r.u(1) != 0,
            persistent_rice_adaptation_enabled_flag: r.u(1) != 0,
            cabac_bypass_alignment_enabled_flag: r.u(1) != 0,
        });
    }
    if sps.sps_multilayer_extension_flag || sps.sps_3d_extension_flag || sps.sps_scc_extension_flag
    {
        return Err(BitstreamError::unsupported(
            "HEVC SPS multilayer/3D/SCC extension payloads not supported",
        ));
    }
    Ok(sps)
}

/// Parse a PPS NAL (with two-byte NAL header at index 0..1).
pub fn parse_pps_nal(nal: &[u8]) -> Result<HevcPps, BitstreamError> {
    if nal.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "PPS NAL shorter than 2 bytes",
        ));
    }
    let (_, nal_type, _, _) = nal_header(nal[0], nal[1]);
    if nal_type != NAL_TYPE_PPS {
        return Err(BitstreamError::invalid(format!(
            "expected PPS NAL (type=34), got type={nal_type}"
        )));
    }
    let rbsp = ebsp_to_rbsp(&nal[2..]);
    let mut r = BitReader::new(&rbsp);
    let mut pps = HevcPps {
        pps_pic_parameter_set_id: r.ue()? as u8,
        pps_seq_parameter_set_id: r.ue()? as u8,
        dependent_slice_segments_enabled_flag: r.u(1) != 0,
        output_flag_present_flag: r.u(1) != 0,
        num_extra_slice_header_bits: r.u(3) as u8,
        sign_data_hiding_enabled_flag: r.u(1) != 0,
        cabac_init_present_flag: r.u(1) != 0,
        num_ref_idx_l0_default_active_minus1: r.ue()? as u8,
        num_ref_idx_l1_default_active_minus1: r.ue()? as u8,
        init_qp_minus26: r.se()?,
        constrained_intra_pred_flag: r.u(1) != 0,
        transform_skip_enabled_flag: r.u(1) != 0,
        cu_qp_delta_enabled_flag: r.u(1) != 0,
        ..HevcPps::default()
    };
    if pps.cu_qp_delta_enabled_flag {
        pps.diff_cu_qp_delta_depth = r.ue()?;
    }
    pps.pps_cb_qp_offset = r.se()?;
    pps.pps_cr_qp_offset = r.se()?;
    pps.pps_slice_chroma_qp_offsets_present_flag = r.u(1) != 0;
    pps.weighted_pred_flag = r.u(1) != 0;
    pps.weighted_bipred_flag = r.u(1) != 0;
    pps.transquant_bypass_enabled_flag = r.u(1) != 0;
    pps.tiles_enabled_flag = r.u(1) != 0;
    pps.entropy_coding_sync_enabled_flag = r.u(1) != 0;
    if pps.tiles_enabled_flag {
        let mut tiles = HevcTiles {
            num_tile_columns_minus1: r.ue()?,
            num_tile_rows_minus1: r.ue()?,
            uniform_spacing_flag: r.u(1) != 0,
            ..HevcTiles::default()
        };
        if !tiles.uniform_spacing_flag {
            // Hostile-input bound: each explicit width/height costs at
            // least one bit, so the declared counts cannot exceed the
            // remaining bits.
            let declared = tiles.num_tile_columns_minus1 as u64 + tiles.num_tile_rows_minus1 as u64;
            if declared > r.bits_remaining() as u64 {
                return Err(BitstreamError::unexpected_end(
                    "PPS tile column/row counts exceed remaining payload",
                ));
            }
            for _ in 0..tiles.num_tile_columns_minus1 {
                tiles.column_widths_minus1.push(r.ue()?);
            }
            for _ in 0..tiles.num_tile_rows_minus1 {
                tiles.row_heights_minus1.push(r.ue()?);
            }
        }
        tiles.loop_filter_across_tiles_enabled_flag = r.u(1) != 0;
        pps.tiles = Some(tiles);
    }
    pps.pps_loop_filter_across_slices_enabled_flag = r.u(1) != 0;
    pps.deblocking_filter_control_present_flag = r.u(1) != 0;
    if pps.deblocking_filter_control_present_flag {
        pps.deblocking_filter_override_enabled_flag = r.u(1) != 0;
        pps.pps_deblocking_filter_disabled_flag = r.u(1) != 0;
        if !pps.pps_deblocking_filter_disabled_flag {
            pps.pps_beta_offset_div2 = r.se()?;
            pps.pps_tc_offset_div2 = r.se()?;
        }
    }
    let pps_scaling_list_data_present_flag = r.u(1);
    if pps_scaling_list_data_present_flag != 0 {
        pps.scaling_list_data = Some(parse_scaling_list_data(&mut r)?);
    }
    pps.lists_modification_present_flag = r.u(1) != 0;
    pps.log2_parallel_merge_level_minus2 = r.ue()?;
    pps.slice_segment_header_extension_present_flag = r.u(1) != 0;
    let pps_extension_present_flag = r.u(1);
    if pps_extension_present_flag != 0 {
        pps.pps_range_extension_flag = r.u(1) != 0;
        pps.pps_multilayer_extension_flag = r.u(1) != 0;
        pps.pps_3d_extension_flag = r.u(1) != 0;
        pps.pps_scc_extension_flag = r.u(1) != 0;
        let _pps_extension_4bits = r.u(4);
    }
    if pps.pps_range_extension_flag {
        let mut ext = HevcPpsRangeExtension::default();
        if pps.transform_skip_enabled_flag {
            ext.log2_max_transform_skip_block_size_minus2 = r.ue()?;
        }
        ext.cross_component_prediction_enabled_flag = r.u(1) != 0;
        ext.chroma_qp_offset_list_enabled_flag = r.u(1) != 0;
        if ext.chroma_qp_offset_list_enabled_flag {
            ext.diff_cu_chroma_qp_offset_depth = r.ue()?;
            let len_minus1 = r.ue()?;
            // §7.4.3.3.2: chroma_qp_offset_list_len_minus1 is 0..=5.
            if len_minus1 > 5 {
                return Err(BitstreamError::invalid(format!(
                    "PPS chroma_qp_offset_list_len_minus1={len_minus1} (must be 0..=5, §7.4.3.3.2)"
                )));
            }
            for _ in 0..=len_minus1 {
                ext.chroma_qp_offset_list.push((r.se()?, r.se()?));
            }
        }
        ext.log2_sao_offset_scale_luma = r.ue()?;
        ext.log2_sao_offset_scale_chroma = r.ue()?;
        pps.range_extension = Some(ext);
    }
    if pps.pps_multilayer_extension_flag || pps.pps_3d_extension_flag || pps.pps_scc_extension_flag
    {
        return Err(BitstreamError::unsupported(
            "HEVC PPS multilayer/3D/SCC extension payloads not supported",
        ));
    }
    Ok(pps)
}

/// Parse a minimal IRAP slice-segment header (7.3.6.1). Only the
/// fields needed to confirm the slice is intra-coded and to populate
/// the HW backends' picture-info struct are read.
pub fn parse_slice_header_minimal(
    nal: &[u8],
    sps: &HevcSps,
    pps: &HevcPps,
) -> Result<HevcSliceHeader, BitstreamError> {
    if nal.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "slice NAL shorter than 2 bytes",
        ));
    }
    let (_, nal_unit_type, _, _) = nal_header(nal[0], nal[1]);
    let is_irap_slice = is_irap(nal_unit_type);

    let rbsp = ebsp_to_rbsp(&nal[2..]);
    let mut r = BitReader::new(&rbsp);
    let mut sh = HevcSliceHeader {
        first_slice_segment_in_pic_flag: r.u(1) != 0,
        ..HevcSliceHeader::default()
    };

    if is_irap_slice {
        sh.no_output_of_prior_pics_flag = r.u(1) != 0;
    }
    sh.slice_pic_parameter_set_id = r.ue()? as u8;

    let dependent_slice_segment_flag =
        if !sh.first_slice_segment_in_pic_flag && pps.dependent_slice_segments_enabled_flag {
            r.u(1) != 0
        } else {
            false
        };
    if dependent_slice_segment_flag {
        return Err(BitstreamError::unsupported(
            "HEVC dependent slice segments not supported by minimal parser",
        ));
    }
    if !sh.first_slice_segment_in_pic_flag {
        // slice_segment_address — ceil(log2(num CTBs)) bits. We don't
        // need it for the HW IDR submit; just consume. The SPS parser
        // guarantees CtbLog2SizeY ∈ 4..=6 (§A.3), but this function
        // also accepts a caller-constructed `HevcSps`, so bound the
        // shift defensively rather than trusting the struct.
        let ctb_log2 = (sps.log2_min_luma_coding_block_size_minus3 as u32)
            .saturating_add(3)
            .saturating_add(sps.log2_diff_max_min_luma_coding_block_size as u32);
        if ctb_log2 > 6 {
            return Err(BitstreamError::invalid(format!(
                "slice header with CtbLog2SizeY={ctb_log2} (must be 4..=6, §A.3)"
            )));
        }
        let ctb_size = 1u32 << ctb_log2;
        let pic_w_in_ctbs = sps.pic_width_in_luma_samples.div_ceil(ctb_size);
        let pic_h_in_ctbs = sps.pic_height_in_luma_samples.div_ceil(ctb_size);
        let total_ctbs = pic_w_in_ctbs as u64 * pic_h_in_ctbs as u64;
        let bits = (64 - total_ctbs.leading_zeros()).min(32);
        let _slice_segment_address = r.u(bits);
    }

    // Skip the encoder-defined extra slice header bits.
    for _ in 0..pps.num_extra_slice_header_bits {
        let _ = r.u(1);
    }
    sh.slice_type = r.ue()? as u8;

    if pps.output_flag_present_flag {
        let _pic_output_flag = r.u(1);
    }
    if sps.separate_colour_plane_flag {
        let _colour_plane_id = r.u(2);
    }

    // For non-IDR slices, slice_pic_order_cnt_lsb is present.
    if !matches!(nal_unit_type, NAL_TYPE_IDR_W_RADL | NAL_TYPE_IDR_N_LP) {
        sh.slice_pic_order_cnt_lsb = r.u(sps.log2_max_pic_order_cnt_lsb_minus4 as u32 + 4);
        // … plus more ref-pic-set logic. We don't follow it in v0;
        // the rest of the slice header is irrelevant to the IRAP HW
        // submit.
    } else {
        sh.slice_pic_order_cnt_lsb = 0;
    }

    sh.is_irap = is_irap_slice;
    // We deliberately do NOT keep parsing past this point. The HW
    // backends only need the fields above to populate the picture
    // info struct; the remainder (slice_temporal_mvp_enabled_flag,
    // sao flags, num_ref_idx_active overrides, …) varies wildly
    // between profiles and is not needed for an IRAP-only submit.
    Ok(sh)
}

/// Walk an Annex-B HEVC stream, locate the first IRAP slice (IDR or
/// CRA), parse VPS / SPS / PPS / slice header, and return everything
/// plus a slice of the original input covering the IRAP access unit.
pub fn parse_idr_only(stream: &[u8]) -> Result<HevcIdrParse<'_>, BitstreamError> {
    let nals = locate_annex_b(stream);
    if nals.is_empty() {
        return Err(BitstreamError::invalid("no NAL units found in stream"));
    }

    let mut vps: Option<HevcVps> = None;
    let mut sps: Option<HevcSps> = None;
    let mut pps: Option<HevcPps> = None;
    let mut irap_idx: Option<usize> = None;
    let mut irap_nal_type: u8 = 0;
    for (idx, n) in nals.iter().enumerate() {
        let body = &stream[n.body_start..n.body_end];
        if body.len() < 2 {
            continue;
        }
        let (_, nal_type, _, _) = nal_header(body[0], body[1]);
        match nal_type {
            NAL_TYPE_VPS if vps.is_none() => vps = Some(parse_vps_nal(body)?),
            NAL_TYPE_SPS if sps.is_none() => sps = Some(parse_sps_nal(body)?),
            NAL_TYPE_PPS if pps.is_none() => pps = Some(parse_pps_nal(body)?),
            t if is_irap(t) && irap_idx.is_none() => {
                irap_idx = Some(idx);
                irap_nal_type = t;
            }
            _ => {}
        }
    }
    let vps = vps.ok_or_else(|| BitstreamError::invalid("stream has no VPS"))?;
    let sps = sps.ok_or_else(|| BitstreamError::invalid("stream has no SPS"))?;
    let pps = pps.ok_or_else(|| BitstreamError::invalid("stream has no PPS"))?;
    let irap_idx = irap_idx.ok_or_else(|| BitstreamError::invalid("stream has no IRAP slice"))?;
    let irap = &nals[irap_idx];
    let body = &stream[irap.body_start..irap.body_end];
    let slice_header = parse_slice_header_minimal(body, &sps, &pps)?;
    let access_unit = &stream[irap.start_code_start..];
    Ok(HevcIdrParse {
        vps,
        sps,
        pps,
        slice_header,
        nal_unit_type: irap_nal_type,
        idr_access_unit: access_unit,
    })
}

// ─────────────────────────── Annex-B index helper ────────────────────────────

#[derive(Debug, Clone, Copy)]
struct NalLoc {
    start_code_start: usize,
    body_start: usize,
    body_end: usize,
}

fn locate_annex_b(buf: &[u8]) -> Vec<NalLoc> {
    let mut out = Vec::new();
    let mut i = 0;
    let n = buf.len();
    let mut current: Option<(usize, usize)> = None;
    while i < n {
        let four =
            i + 3 < n && buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 0 && buf[i + 3] == 1;
        let three = !four && i + 2 < n && buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 1;
        if four || three {
            if let Some((sc, body_start)) = current.take() {
                out.push(NalLoc {
                    start_code_start: sc,
                    body_start,
                    body_end: i,
                });
            }
            let sc = i;
            i += if four { 4 } else { 3 };
            current = Some((sc, i));
            continue;
        }
        i += 1;
    }
    if let Some((sc, body_start)) = current.take() {
        out.push(NalLoc {
            start_code_start: sc,
            body_start,
            body_end: n,
        });
    }
    out
}

// ─────────────────────────── Access unit delimiter ──────────────────────────

/// Access unit delimiter RBSP — H.265 §7.3.2.5 / §7.4.3.5.
///
/// The AUD NAL (type 35) marks the boundary between access units and
/// optionally narrows the set of `slice_type` values that may appear
/// in the coded pictures of the access unit. `pic_type` is the only
/// signalled field; everything else in the NAL is `rbsp_trailing_bits()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HevcAccessUnitDelimiter {
    /// `pic_type` u(3) (§7.4.3.5 / Table 7-2). Conforming bitstreams
    /// MUST use 0, 1 or 2 (I-only / P+I / B+P+I); values 3..=7 are
    /// reserved for future use. Per the spec the decoder MUST accept
    /// reserved values (`Decoders … shall ignore reserved values of
    /// pic_type`) — this parser surfaces the raw 3-bit value
    /// unchanged so callers can decide whether to act on conforming
    /// values, log a warning, or treat reserved values as a
    /// pass-through.
    pub pic_type: u8,
}

/// `pic_type` is u(3) so the spec range is 0..=7 (§7.4.3.5).
pub const HEVC_PIC_TYPE_MAX: u8 = 7;

/// `pic_type` values defined by the current H.265 edition. Conforming
/// bitstreams use only these; the writer accepts the full u(3) range
/// (reserved values are explicitly permitted on the decoder side, so
/// emitting one is well-defined even if not "conforming").
pub const HEVC_PIC_TYPE_I_ONLY: u8 = 0;
pub const HEVC_PIC_TYPE_P_OR_I: u8 = 1;
pub const HEVC_PIC_TYPE_B_P_OR_I: u8 = 2;

/// Parse an AUD NAL — including the two-byte NAL header — recovering
/// `pic_type` and verifying the trailing `rbsp_trailing_bits()`
/// marker (§7.3.2.5).
///
/// Returns [`BitstreamError::InvalidData`] when the NAL type isn't
/// [`NAL_TYPE_AUD`] or when the trailing marker is malformed; returns
/// [`BitstreamError::UnexpectedEnd`] when the NAL is too short for
/// the two-byte header plus a payload byte. Reserved `pic_type`
/// values (3..=7) are returned verbatim rather than rejected — the
/// spec explicitly mandates decoders accept them.
pub fn parse_aud_nal(nal: &[u8]) -> Result<HevcAccessUnitDelimiter, BitstreamError> {
    if nal.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "AUD NAL needs at least the 2-byte header",
        ));
    }
    let (_, nal_type, _, _) = nal_header(nal[0], nal[1]);
    if nal_type != NAL_TYPE_AUD {
        return Err(BitstreamError::invalid(format!(
            "expected AUD NAL (type=35), got type={nal_type}"
        )));
    }
    if nal.len() < 3 {
        return Err(BitstreamError::unexpected_end(
            "AUD NAL has no body after the 2-byte header",
        ));
    }
    let rbsp = ebsp_to_rbsp(&nal[2..]);
    let mut r = BitReader::new(&rbsp);
    let pic_type = r.u(3) as u8;
    r.read_rbsp_trailing_bits()?;
    Ok(HevcAccessUnitDelimiter { pic_type })
}

/// Emit an AUD NAL — two-byte NAL header followed by a 1-byte RBSP
/// that packs `pic_type` u(3) and the `rbsp_trailing_bits()` marker.
///
/// The NAL header fixes `forbidden_zero_bit = 0`, `nuh_layer_id = 0`
/// and `nuh_temporal_id_plus1 = 1` (the canonical base-layer / TID-0
/// choice every conforming encoder uses for AUD NALs). The returned
/// bytes start with the two-byte NAL header; callers that need an
/// Annex-B unit prepend `0x00 0x00 0x01` (or `0x00 0x00 0x00 0x01`)
/// themselves.
///
/// Returns [`BitstreamError::InvalidData`] when `pic_type > 7` (the
/// u(3) envelope). Reserved `pic_type` values (3..=7) are accepted so
/// the writer round-trips against the parser's permissive
/// reserved-value contract.
pub fn write_aud_nal(aud: &HevcAccessUnitDelimiter) -> Result<Vec<u8>, BitstreamError> {
    if aud.pic_type > HEVC_PIC_TYPE_MAX {
        return Err(BitstreamError::invalid(format!(
            "HEVC pic_type = {} > {} (u(3) envelope)",
            aud.pic_type, HEVC_PIC_TYPE_MAX
        )));
    }
    // forbidden_zero=0, nal_unit_type=35, layer_id=0, tid_plus1=1
    let b0: u8 = NAL_TYPE_AUD << 1; // upper bits already zero, layer_id bit5 = 0
    let b1: u8 = 0x01; // layer_id low5 = 0, tid_plus1 = 1
    let mut bw = crate::bit_writer::BitWriter::new();
    bw.write_bits(aud.pic_type as u32, 3);
    bw.write_rbsp_trailing_bits();
    let rbsp = bw.finish();
    // A 1-byte RBSP cannot contain the 0x00 0x00 0x0{0..3} triple the
    // encapsulation rule guards against, so the EBSP equals the RBSP.
    let mut out = Vec::with_capacity(2 + rbsp.len());
    out.push(b0);
    out.push(b1);
    out.extend_from_slice(&rbsp);
    Ok(out)
}

// ─────────────────────────── Tests ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_finds_three_nals() {
        let buf = [
            0, 0, 0, 1, 0x40, 0x01, 0xaa, // VPS
            0, 0, 1, 0x42, 0x01, 0xbb, // SPS
            0, 0, 0, 1, 0x28, 0x01, 0xcc, // IDR
        ];
        let nals = split_annex_b(&buf);
        assert_eq!(nals.len(), 3);
    }

    #[test]
    fn nal_header_decodes_vps() {
        // 0x40 = 0100_0000, 0x01 = 0000_0001.
        // forbidden=0, nal_unit_type = (0x40>>1)&0x3f = 0x20 = 32 (VPS).
        let (f, t, l, tid) = nal_header(0x40, 0x01);
        assert_eq!(f, 0);
        assert_eq!(t, NAL_TYPE_VPS);
        assert_eq!(l, 0);
        assert_eq!(tid, 1);
    }

    #[test]
    fn ebsp_to_rbsp_strips_03_in_zero_zero_run() {
        let ebsp = [0x00, 0x00, 0x03, 0x01];
        let rbsp = ebsp_to_rbsp(&ebsp);
        assert_eq!(rbsp, &[0x00, 0x00, 0x01]);
    }

    /// Emit the SPS body from the start through
    /// `max_transform_hierarchy_depth_intra`, leaving the writer
    /// positioned at `scaling_list_enabled_flag`. Values describe a
    /// simple 320×240 4:2:0 Main-profile stream.
    fn write_sps_prefix(w: &mut crate::bit_writer::BitWriter) {
        w.write_bits(0, 4); // sps_video_parameter_set_id
        w.write_bits(0, 3); // sps_max_sub_layers_minus1
        w.write_bit(1); // sps_temporal_id_nesting_flag
                        // profile_tier_level(1, 0): 2+1+5+32+4+32+11+1 = 88 bits + 8 level
        w.write_bits(0, 2); // general_profile_space
        w.write_bit(0); // general_tier_flag
        w.write_bits(1, 5); // general_profile_idc = 1 (Main)
        w.write_bits(0x6000_0000, 32); // compatibility flags
        w.write_bits(0, 4); // source/constraint top flags
        w.write_bits(0, 32); // reserved mid
        w.write_bits(0, 11); // reserved bottom
        w.write_bit(0); // inbld/reserved
        w.write_bits(63, 8); // general_level_idc
        w.write_ue(0).unwrap(); // sps_seq_parameter_set_id
        w.write_ue(1).unwrap(); // chroma_format_idc = 1
        w.write_ue(320).unwrap(); // pic_width_in_luma_samples
        w.write_ue(240).unwrap(); // pic_height_in_luma_samples
        w.write_bit(0); // conformance_window_flag
        w.write_ue(0).unwrap(); // bit_depth_luma_minus8
        w.write_ue(0).unwrap(); // bit_depth_chroma_minus8
        w.write_ue(4).unwrap(); // log2_max_pic_order_cnt_lsb_minus4
        w.write_bit(1); // sps_sub_layer_ordering_info_present_flag
        w.write_ue(4).unwrap(); // sps_max_dec_pic_buffering_minus1
        w.write_ue(0).unwrap(); // sps_max_num_reorder_pics
        w.write_ue(0).unwrap(); // sps_max_latency_increase_plus1
        w.write_ue(0).unwrap(); // log2_min_luma_coding_block_size_minus3
        w.write_ue(3).unwrap(); // log2_diff_max_min_luma_coding_block_size
        w.write_ue(0).unwrap(); // log2_min_luma_transform_block_size_minus2
        w.write_ue(3).unwrap(); // log2_diff_max_min_luma_transform_block_size
        w.write_ue(0).unwrap(); // max_transform_hierarchy_depth_inter
        w.write_ue(0).unwrap(); // max_transform_hierarchy_depth_intra
    }

    /// Wrap an SPS RBSP into a NAL (2-byte header, type 33).
    fn sps_nal_from(w: crate::bit_writer::BitWriter) -> Vec<u8> {
        let mut nal = vec![NAL_TYPE_SPS << 1, 0x01];
        nal.extend_from_slice(&crate::nal::rbsp_to_ebsp(&w.finish()));
        nal
    }

    #[test]
    fn sps_with_pcm_st_rps_long_term_and_vui_parses() {
        let mut w = crate::bit_writer::BitWriter::new();
        write_sps_prefix(&mut w);
        w.write_bit(0); // scaling_list_enabled_flag
        w.write_bit(1); // amp_enabled_flag
        w.write_bit(1); // sample_adaptive_offset_enabled_flag
        w.write_bit(1); // pcm_enabled_flag
        w.write_bits(7, 4); // pcm_sample_bit_depth_luma_minus1
        w.write_bits(7, 4); // pcm_sample_bit_depth_chroma_minus1
        w.write_ue(0).unwrap(); // log2_min_pcm_luma_coding_block_size_minus3
        w.write_ue(2).unwrap(); // log2_diff_max_min_pcm_luma_coding_block_size
        w.write_bit(1); // pcm_loop_filter_disabled_flag

        // Two short-term RPS: set 0 explicit (2 negative), set 1
        // predicted from set 0 with deltaRps = -1.
        w.write_ue(2).unwrap(); // num_short_term_ref_pic_sets
                                // set 0 (no inter flag for idx 0):
        w.write_ue(2).unwrap(); // num_negative_pics
        w.write_ue(0).unwrap(); // num_positive_pics
        w.write_ue(0).unwrap(); // delta_poc_s0_minus1[0] → DeltaPocS0 = -1
        w.write_bit(1); // used_by_curr_pic_s0_flag[0]
        w.write_ue(0).unwrap(); // delta_poc_s0_minus1[1] → DeltaPocS0 = -2
        w.write_bit(1); // used_by_curr_pic_s0_flag[1]
                        // set 1 (predicted):
        w.write_bit(1); // inter_ref_pic_set_prediction_flag
        w.write_bit(1); // delta_rps_sign = 1
        w.write_ue(0).unwrap(); // abs_delta_rps_minus1 → deltaRps = -1
        w.write_bit(1); // used_by_curr_pic_flag[0]
        w.write_bit(0); // used_by_curr_pic_flag[1]
        w.write_bit(1); // use_delta_flag[1]
        w.write_bit(1); // used_by_curr_pic_flag[2]

        w.write_bit(1); // long_term_ref_pics_present_flag
        w.write_ue(1).unwrap(); // num_long_term_ref_pics_sps
        w.write_bits(200, 8); // lt_ref_pic_poc_lsb_sps[0] (u(4+4))
        w.write_bit(1); // used_by_curr_pic_lt_sps_flag[0]

        w.write_bit(1); // sps_temporal_mvp_enabled_flag
        w.write_bit(1); // strong_intra_smoothing_enabled_flag

        w.write_bit(1); // vui_parameters_present_flag
        w.write_bit(1); // aspect_ratio_info_present_flag
        w.write_bits(255, 8); // EXTENDED_SAR
        w.write_bits(3, 16); // sar_width
        w.write_bits(2, 16); // sar_height
        w.write_bit(0); // overscan_info_present_flag
        w.write_bit(0); // video_signal_type_present_flag
        w.write_bit(0); // chroma_loc_info_present_flag
        w.write_bit(0); // neutral_chroma_indication_flag
        w.write_bit(0); // field_seq_flag
        w.write_bit(0); // frame_field_info_present_flag
        w.write_bit(1); // default_display_window_flag
        w.write_ue(1).unwrap(); // left
        w.write_ue(2).unwrap(); // right
        w.write_ue(3).unwrap(); // top
        w.write_ue(4).unwrap(); // bottom
        w.write_bit(1); // vui_timing_info_present_flag
        w.write_bits(1001, 32); // vui_num_units_in_tick
        w.write_bits(30000, 32); // vui_time_scale
        w.write_bit(0); // vui_poc_proportional_to_timing_flag
        w.write_bit(1); // vui_hrd_parameters_present_flag
                        // hrd_parameters(1, 0):
        w.write_bit(1); // nal_hrd_parameters_present_flag
        w.write_bit(0); // vcl_hrd_parameters_present_flag
        w.write_bit(0); // sub_pic_hrd_params_present_flag
        w.write_bits(1, 4); // bit_rate_scale
        w.write_bits(2, 4); // cpb_size_scale
        w.write_bits(23, 5); // initial_cpb_removal_delay_length_minus1
        w.write_bits(15, 5); // au_cpb_removal_delay_length_minus1
        w.write_bits(5, 5); // dpb_output_delay_length_minus1
                            // sub-layer 0:
        w.write_bit(0); // fixed_pic_rate_general_flag
        w.write_bit(0); // fixed_pic_rate_within_cvs_flag
        w.write_bit(0); // low_delay_hrd_flag
        w.write_ue(0).unwrap(); // cpb_cnt_minus1
                                // sub_layer_hrd_parameters (1 entry, no sub-pic):
        w.write_ue(1999).unwrap(); // bit_rate_value_minus1
        w.write_ue(2999).unwrap(); // cpb_size_value_minus1
        w.write_bit(1); // cbr_flag
        w.write_bit(0); // bitstream_restriction_flag
        w.write_bit(0); // sps_extension_present_flag
        w.write_rbsp_trailing_bits();

        let sps = parse_sps_nal(&sps_nal_from(w)).expect("full SPS parses");
        assert!(sps.pcm_enabled_flag);
        assert_eq!(sps.pcm_sample_bit_depth_luma_minus1, 7);
        assert_eq!(sps.log2_diff_max_min_pcm_luma_coding_block_size, 2);
        assert!(sps.pcm_loop_filter_disabled_flag);

        assert_eq!(sps.num_short_term_ref_pic_sets, 2);
        assert_eq!(sps.short_term_rps.len(), 2);
        let s0 = &sps.short_term_rps[0];
        assert_eq!(s0.delta_poc_s0, vec![-1, -2]);
        assert_eq!(s0.used_by_curr_pic_s0, vec![true, true]);
        assert_eq!(s0.num_positive_pics(), 0);
        // Set 1 derivation (7-61): deltaRps=-1 →
        //   push (deltaRps=-1, used[2]=true),
        //   then -1-1=-2 (used[0]=true), -2-1=-3 (used[1]=false).
        let s1 = &sps.short_term_rps[1];
        assert_eq!(s1.delta_poc_s0, vec![-1, -2, -3]);
        assert_eq!(s1.used_by_curr_pic_s0, vec![true, true, false]);
        assert_eq!(s1.num_delta_pocs(), 3);

        assert!(sps.long_term_ref_pics_present_flag);
        assert_eq!(sps.long_term_ref_pics, vec![(200, true)]);

        let vui = sps.vui.expect("VUI parsed");
        assert_eq!(vui.sample_aspect_ratio(), Some((3, 2)));
        assert_eq!(
            vui.default_display_window,
            Some(HevcDefaultDisplayWindow {
                left: 1,
                right: 2,
                top: 3,
                bottom: 4
            })
        );
        assert_eq!(vui.picture_rate(), Some((30000, 1001)));
        let hrd = vui.hrd_parameters.expect("HRD parsed");
        assert!(hrd.nal_hrd_parameters_present_flag);
        assert_eq!(hrd.bit_rate_scale, 1);
        assert_eq!(hrd.sub_layers.len(), 1);
        let sl = &hrd.sub_layers[0];
        assert_eq!(sl.cpb_cnt_minus1, 0);
        assert_eq!(sl.nal_cpb.len(), 1);
        assert_eq!(sl.nal_cpb[0].bit_rate_value_minus1, 1999);
        assert!(sl.nal_cpb[0].cbr_flag);
        assert!(sl.vcl_cpb.is_empty());
    }

    #[test]
    fn sps_scaling_list_data_explicit_and_predicted() {
        let mut w = crate::bit_writer::BitWriter::new();
        write_sps_prefix(&mut w);
        w.write_bit(1); // scaling_list_enabled_flag
        w.write_bit(1); // sps_scaling_list_data_present_flag
                        // scaling_list_data(): sizeId 0, matrixId 0 explicit ramp;
                        // every other list predicted with delta 0 (default matrix).
        for size_id in 0..4usize {
            let step = if size_id == 3 { 3 } else { 1 };
            let mut m = 0usize;
            while m < 6 {
                if size_id == 0 && m == 0 {
                    w.write_bit(1); // pred_mode = explicit
                    for _ in 0..16 {
                        w.write_se(1).unwrap(); // ramp 9..=24
                    }
                } else if size_id == 2 && m == 0 {
                    w.write_bit(1); // explicit with DC coef
                    w.write_se(8).unwrap(); // dc_coef_minus8 → nextCoef 16
                    for _ in 0..64 {
                        w.write_se(0).unwrap(); // flat 16
                    }
                } else {
                    w.write_bit(0); // predicted
                    w.write_ue(0).unwrap(); // delta 0 → default matrix
                }
                m += step;
            }
        }
        w.write_bit(0); // amp
        w.write_bit(0); // sao
        w.write_bit(0); // pcm
        w.write_ue(0).unwrap(); // num_short_term_ref_pic_sets
        w.write_bit(0); // long_term
        w.write_bit(0); // temporal_mvp
        w.write_bit(0); // strong_intra_smoothing
        w.write_bit(0); // vui
        w.write_bit(0); // sps_extension
        w.write_rbsp_trailing_bits();

        let sps = parse_sps_nal(&sps_nal_from(w)).expect("scaling-list SPS parses");
        assert!(sps.scaling_list_enabled_flag);
        let d = sps.scaling_list_data.expect("scaling list data");
        assert!(d.pred_mode_flag[0][0]);
        let expected: Vec<u8> = (9..=24).collect();
        assert_eq!(&d.list_4x4[0][..], &expected[..]);
        assert!(!d.pred_mode_flag[0][1]);
        assert_eq!(d.pred_matrix_id_delta[0][1], 0);
        assert!(d.pred_mode_flag[2][0]);
        assert_eq!(d.dc_coef_minus8[0][0], 8);
        assert_eq!(d.list_16x16[0], [16u8; 64]);
    }

    #[test]
    fn sps_rejects_out_of_range_st_rps_count_and_dpb() {
        // num_short_term_ref_pic_sets = 65 → InvalidData (§7.4.3.2.1).
        let mut w = crate::bit_writer::BitWriter::new();
        write_sps_prefix(&mut w);
        w.write_bit(0); // scaling_list_enabled_flag
        w.write_bit(0); // amp
        w.write_bit(0); // sao
        w.write_bit(0); // pcm
        w.write_ue(65).unwrap();
        let err = parse_sps_nal(&sps_nal_from(w)).unwrap_err();
        assert!(matches!(err, BitstreamError::InvalidData(_)));
    }

    #[test]
    fn sps_rejects_out_of_range_ctb_log2() {
        // Fuzz regression: a hostile SPS declaring huge coding-block
        // log2 fields drove `1u32 << CtbLog2SizeY` past 31 in the
        // slice-segment-address width computation. §A.3 profile
        // conformance pins CtbLog2SizeY to 4..=6; both parse paths
        // must reject anything else.
        let mut w = crate::bit_writer::BitWriter::new();
        write_sps_prefix_custom(&mut w, 60, 60); // ctb_log2 = 123
        let err = parse_sps_nal(&sps_nal_from(w)).unwrap_err();
        assert!(matches!(err, BitstreamError::InvalidData(_)), "{err:?}");

        // CtbLog2SizeY = 3 (too small) is also rejected.
        let mut w = crate::bit_writer::BitWriter::new();
        write_sps_prefix_custom(&mut w, 0, 0); // 0 + 3 + 0 = 3
        let err = parse_sps_nal(&sps_nal_from(w)).unwrap_err();
        assert!(matches!(err, BitstreamError::InvalidData(_)), "{err:?}");
    }

    #[test]
    fn slice_header_rejects_hand_built_bad_ctb_log2() {
        // The slice parser must not trust a caller-constructed SPS.
        let sps = HevcSps {
            log2_min_luma_coding_block_size_minus3: 255,
            log2_diff_max_min_luma_coding_block_size: 255,
            pic_width_in_luma_samples: 320,
            pic_height_in_luma_samples: 240,
            ..HevcSps::default()
        };
        let pps = HevcPps::default();
        // first_slice_segment_in_pic_flag = 0 forces the
        // slice_segment_address branch.
        let nal = [0x02u8, 0x01, 0x00, 0x80];
        let err = parse_slice_header_minimal(&nal, &sps, &pps).unwrap_err();
        assert!(matches!(err, BitstreamError::InvalidData(_)), "{err:?}");
    }

    /// Like [`write_sps_prefix`] but with custom coding-block log2
    /// fields (used by the CtbLog2SizeY range tests).
    fn write_sps_prefix_custom(
        w: &mut crate::bit_writer::BitWriter,
        log2_min: u32,
        log2_diff: u32,
    ) {
        w.write_bits(0, 4);
        w.write_bits(0, 3);
        w.write_bit(1);
        w.write_bits(0, 2);
        w.write_bit(0);
        w.write_bits(1, 5);
        w.write_bits(0x6000_0000, 32);
        w.write_bits(0, 4);
        w.write_bits(0, 32);
        w.write_bits(0, 11);
        w.write_bit(0);
        w.write_bits(63, 8);
        w.write_ue(0).unwrap();
        w.write_ue(1).unwrap();
        w.write_ue(320).unwrap();
        w.write_ue(240).unwrap();
        w.write_bit(0);
        w.write_ue(0).unwrap();
        w.write_ue(0).unwrap();
        w.write_ue(4).unwrap();
        w.write_bit(1);
        w.write_ue(4).unwrap();
        w.write_ue(0).unwrap();
        w.write_ue(0).unwrap();
        w.write_ue(log2_min).unwrap();
        w.write_ue(log2_diff).unwrap();
    }

    #[test]
    fn pps_with_tiles_and_range_extension_parses() {
        let mut w = crate::bit_writer::BitWriter::new();
        w.write_ue(0).unwrap(); // pps_pic_parameter_set_id
        w.write_ue(0).unwrap(); // pps_seq_parameter_set_id
        w.write_bit(0); // dependent_slice_segments_enabled_flag
        w.write_bit(0); // output_flag_present_flag
        w.write_bits(0, 3); // num_extra_slice_header_bits
        w.write_bit(0); // sign_data_hiding_enabled_flag
        w.write_bit(0); // cabac_init_present_flag
        w.write_ue(0).unwrap(); // num_ref_idx_l0_default_active_minus1
        w.write_ue(0).unwrap(); // num_ref_idx_l1_default_active_minus1
        w.write_se(0).unwrap(); // init_qp_minus26
        w.write_bit(0); // constrained_intra_pred_flag
        w.write_bit(1); // transform_skip_enabled_flag
        w.write_bit(0); // cu_qp_delta_enabled_flag
        w.write_se(0).unwrap(); // pps_cb_qp_offset
        w.write_se(0).unwrap(); // pps_cr_qp_offset
        w.write_bit(0); // pps_slice_chroma_qp_offsets_present_flag
        w.write_bit(0); // weighted_pred_flag
        w.write_bit(0); // weighted_bipred_flag
        w.write_bit(0); // transquant_bypass_enabled_flag
        w.write_bit(1); // tiles_enabled_flag
        w.write_bit(1); // entropy_coding_sync_enabled_flag (WPP now parses)
        w.write_ue(2).unwrap(); // num_tile_columns_minus1
        w.write_ue(1).unwrap(); // num_tile_rows_minus1
        w.write_bit(0); // uniform_spacing_flag
        w.write_ue(5).unwrap(); // column_width_minus1[0]
        w.write_ue(7).unwrap(); // column_width_minus1[1]
        w.write_ue(4).unwrap(); // row_height_minus1[0]
        w.write_bit(1); // loop_filter_across_tiles_enabled_flag
        w.write_bit(1); // pps_loop_filter_across_slices_enabled_flag
        w.write_bit(0); // deblocking_filter_control_present_flag
        w.write_bit(0); // pps_scaling_list_data_present_flag
        w.write_bit(0); // lists_modification_present_flag
        w.write_ue(0).unwrap(); // log2_parallel_merge_level_minus2
        w.write_bit(0); // slice_segment_header_extension_present_flag
        w.write_bit(1); // pps_extension_present_flag
        w.write_bit(1); // pps_range_extension_flag
        w.write_bit(0); // multilayer
        w.write_bit(0); // 3d
        w.write_bit(0); // scc
        w.write_bits(0, 4); // pps_extension_4bits
                            // pps_range_extension():
        w.write_ue(2).unwrap(); // log2_max_transform_skip_block_size_minus2
        w.write_bit(1); // cross_component_prediction_enabled_flag
        w.write_bit(1); // chroma_qp_offset_list_enabled_flag
        w.write_ue(1).unwrap(); // diff_cu_chroma_qp_offset_depth
        w.write_ue(1).unwrap(); // chroma_qp_offset_list_len_minus1 → 2 pairs
        w.write_se(-1).unwrap();
        w.write_se(1).unwrap();
        w.write_se(2).unwrap();
        w.write_se(-2).unwrap();
        w.write_ue(0).unwrap(); // log2_sao_offset_scale_luma
        w.write_ue(0).unwrap(); // log2_sao_offset_scale_chroma
        w.write_rbsp_trailing_bits();

        let mut nal = vec![NAL_TYPE_PPS << 1, 0x01];
        nal.extend_from_slice(&crate::nal::rbsp_to_ebsp(&w.finish()));
        let pps = parse_pps_nal(&nal).expect("tiled PPS parses");
        assert!(pps.tiles_enabled_flag);
        assert!(pps.entropy_coding_sync_enabled_flag);
        let tiles = pps.tiles.expect("tiles");
        assert_eq!(tiles.num_tile_columns_minus1, 2);
        assert_eq!(tiles.num_tile_rows_minus1, 1);
        assert!(!tiles.uniform_spacing_flag);
        assert_eq!(tiles.column_widths_minus1, vec![5, 7]);
        assert_eq!(tiles.row_heights_minus1, vec![4]);
        assert!(tiles.loop_filter_across_tiles_enabled_flag);
        let ext = pps.range_extension.expect("range extension");
        assert_eq!(ext.log2_max_transform_skip_block_size_minus2, 2);
        assert!(ext.cross_component_prediction_enabled_flag);
        assert_eq!(ext.chroma_qp_offset_list, vec![(-1, 1), (2, -2)]);
    }

    #[test]
    fn aud_write_then_parse_roundtrips_every_pic_type() {
        for pt in 0u8..=HEVC_PIC_TYPE_MAX {
            let in_ = HevcAccessUnitDelimiter { pic_type: pt };
            let bytes = write_aud_nal(&in_).expect("AUD NAL writes");
            let parsed = parse_aud_nal(&bytes).expect("AUD NAL parses");
            assert_eq!(parsed, in_, "round-trip pic_type={pt}");
        }
    }

    #[test]
    fn aud_writer_canonical_layer0_tid0() {
        // NAL header: type=35 -> 0x46, layer=0/tid+1=1 -> 0x01.
        // RBSP for pic_type=0: 000 + 1 + 0000 = 0x10.
        let bytes = write_aud_nal(&HevcAccessUnitDelimiter { pic_type: 0 }).unwrap();
        assert_eq!(bytes, vec![0x46, 0x01, 0x10]);
    }

    #[test]
    fn aud_writer_pic_type_2_canonical_bytes() {
        // pic_type=2 (010) + stop-one (1) + four alignment zeros = 0x50.
        let bytes = write_aud_nal(&HevcAccessUnitDelimiter {
            pic_type: HEVC_PIC_TYPE_B_P_OR_I,
        })
        .unwrap();
        assert_eq!(bytes, vec![0x46, 0x01, 0x50]);
    }

    #[test]
    fn aud_parser_accepts_reserved_pic_type() {
        // The spec mandates decoders accept reserved (3..=7) pic_type
        // values. Round-trip both ends and confirm the value is
        // surfaced unchanged.
        for pt in 3u8..=7 {
            let bytes = write_aud_nal(&HevcAccessUnitDelimiter { pic_type: pt }).unwrap();
            let parsed = parse_aud_nal(&bytes).unwrap();
            assert_eq!(parsed.pic_type, pt);
        }
    }

    #[test]
    fn aud_writer_rejects_out_of_range_pic_type() {
        let err = write_aud_nal(&HevcAccessUnitDelimiter { pic_type: 8 })
            .expect_err("pic_type=8 outside u(3) envelope");
        assert!(matches!(err, BitstreamError::InvalidData(_)));
    }

    #[test]
    fn aud_parser_rejects_wrong_nal_type() {
        // VPS NAL header (type=32) where AUD was expected.
        let nal = [0x40u8, 0x01, 0x10];
        let err = parse_aud_nal(&nal).expect_err("wrong nal type rejected");
        assert!(matches!(err, BitstreamError::InvalidData(_)));
    }

    #[test]
    fn aud_parser_rejects_header_only_nal() {
        let nal = [0x46u8, 0x01];
        let err = parse_aud_nal(&nal).expect_err("header-only NAL rejected");
        assert!(matches!(err, BitstreamError::UnexpectedEnd(_)));
    }

    #[test]
    fn aud_parser_rejects_truncated_input() {
        let err = parse_aud_nal(&[0x46u8]).expect_err("1-byte NAL rejected");
        assert!(matches!(err, BitstreamError::UnexpectedEnd(_)));
    }

    #[test]
    fn aud_parser_rejects_missing_stop_bit() {
        // pic_type bits followed by all-zero padding -> reader sees
        // no rbsp_stop_one_bit and rejects.
        let nal = [0x46u8, 0x01, 0x00];
        let err = parse_aud_nal(&nal).expect_err("missing stop bit rejected");
        assert!(
            matches!(
                err,
                BitstreamError::InvalidData(_) | BitstreamError::UnexpectedEnd(_)
            ),
            "got: {err:?}"
        );
    }
}
