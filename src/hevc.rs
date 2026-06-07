//! HEVC / H.265 minimal IDR header parsing.
//!
//! This module parses just enough VPS / SPS / PPS / slice-segment
//! header to populate the slice-data HW backends' parameter buffers
//! (`VAPictureParameterBufferHEVC`, `VdpPictureInfoHEVC`,
//! `VkVideoDecodeH265PictureInfoKHR`). Same scope philosophy as the
//! H.264 module: enough fields to drive the GPU decode of an IDR
//! access unit, nothing more.
//!
//! Refused (returned as [`BitstreamError::Unsupported`]):
//!
//! - SPS scaling list (`scaling_list_enabled_flag = 1`).
//! - PCM coding (`pcm_enabled_flag = 1`).
//! - Multiple short-term RPS (`num_short_term_ref_pic_sets > 0`).
//! - Long-term RPS (`long_term_ref_pics_present_flag = 1`).
//! - PPS scaling list, dependent slice segments, tiles, WPP.
//! - Range / SCC / Scalable / Multiview extensions.
//!
//! # Spec references
//!
//! ITU-T H.265 v9 (a.k.a. ISO/IEC 23008-2). Sections of interest:
//! 7.3.2.1 (VPS), 7.3.2.2 (SPS), 7.3.2.3 (PPS), 7.3.6 (slice
//! segment header), 7.4.3.2 (SPS semantics), 9.2 (Exp-Golomb).

use crate::bit_reader::BitReader;
use crate::BitstreamError;

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
    pub amp_enabled_flag: bool,
    pub sample_adaptive_offset_enabled_flag: bool,
    pub pcm_enabled_flag: bool,
    pub num_short_term_ref_pic_sets: u32,
    pub long_term_ref_pics_present_flag: bool,
    /// `num_long_term_ref_pics_sps`. The minimal parser refuses
    /// `long_term_ref_pics_present_flag = 1`, so this is always 0
    /// in practice — but the field is plumbed through to
    /// `VdpPictureInfoHEVC` regardless and is therefore preserved.
    pub num_long_term_ref_pics_sps: u32,
    pub sps_temporal_mvp_enabled_flag: bool,
    pub strong_intra_smoothing_enabled_flag: bool,
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

// ─────────────────────────── ST-RPS skipper ──────────────────────────────────

/// Skip past a single `st_ref_pic_set( stRpsIdx )` entry (7.3.7).
/// We can't keep state across multiple sets, so this is only callable
/// when the current set is the first one (or, in the version used
/// inside the SPS, when there is only ever going to be one). For the
/// minimal-parser scope we *forbid* `num_short_term_ref_pic_sets > 0`
/// in the SPS, so this routine is here mainly for the slice-header
/// path's potential future use; today it short-circuits.
#[allow(dead_code)]
fn skip_st_ref_pic_set(_r: &mut BitReader<'_>) -> Result<(), BitstreamError> {
    Err(BitstreamError::unsupported(
        "HEVC st_ref_pic_set parsing not implemented in minimal parser",
    ))
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
    sps.log2_max_pic_order_cnt_lsb_minus4 = r.ue()? as u8;

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
    sps.sps_max_dec_pic_buffering_minus1 = last_max_dec;
    sps.sps_max_num_reorder_pics = last_max_reorder;
    sps.sps_max_latency_increase_plus1 = last_max_latency;

    sps.log2_min_luma_coding_block_size_minus3 = r.ue()? as u8;
    sps.log2_diff_max_min_luma_coding_block_size = r.ue()? as u8;
    sps.log2_min_luma_transform_block_size_minus2 = r.ue()? as u8;
    sps.log2_diff_max_min_luma_transform_block_size = r.ue()? as u8;
    sps.max_transform_hierarchy_depth_inter = r.ue()? as u8;
    sps.max_transform_hierarchy_depth_intra = r.ue()? as u8;

    sps.scaling_list_enabled_flag = r.u(1) != 0;
    if sps.scaling_list_enabled_flag {
        return Err(BitstreamError::unsupported(
            "HEVC SPS scaling_list_enabled_flag=1 not supported by minimal parser",
        ));
    }
    sps.amp_enabled_flag = r.u(1) != 0;
    sps.sample_adaptive_offset_enabled_flag = r.u(1) != 0;
    sps.pcm_enabled_flag = r.u(1) != 0;
    if sps.pcm_enabled_flag {
        return Err(BitstreamError::unsupported(
            "HEVC SPS pcm_enabled_flag=1 not supported by minimal parser",
        ));
    }
    sps.num_short_term_ref_pic_sets = r.ue()?;
    if sps.num_short_term_ref_pic_sets > 0 {
        return Err(BitstreamError::unsupported(
            "HEVC SPS num_short_term_ref_pic_sets>0 not supported by minimal parser",
        ));
    }
    sps.long_term_ref_pics_present_flag = r.u(1) != 0;
    if sps.long_term_ref_pics_present_flag {
        return Err(BitstreamError::unsupported(
            "HEVC SPS long_term_ref_pics_present_flag=1 not supported by minimal parser",
        ));
    }
    sps.sps_temporal_mvp_enabled_flag = r.u(1) != 0;
    sps.strong_intra_smoothing_enabled_flag = r.u(1) != 0;
    // VUI / sps_extension flags follow but are not consumed here.
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
        return Err(BitstreamError::unsupported(
            "HEVC PPS tiles_enabled_flag=1 not supported by minimal parser",
        ));
    }
    if pps.entropy_coding_sync_enabled_flag {
        return Err(BitstreamError::unsupported(
            "HEVC PPS entropy_coding_sync_enabled_flag=1 (WPP) not supported by minimal parser",
        ));
    }
    // 7.3.2.3.1 continued. The tile-related block is skipped because
    // we already refused `tiles_enabled_flag=1` above.
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
        return Err(BitstreamError::unsupported(
            "HEVC PPS pps_scaling_list_data_present_flag=1 not supported by minimal parser",
        ));
    }
    pps.lists_modification_present_flag = r.u(1) != 0;
    pps.log2_parallel_merge_level_minus2 = r.ue()?;
    pps.slice_segment_header_extension_present_flag = r.u(1) != 0;
    // pps_extension_present_flag and any extension blocks are not
    // consulted — they belong to the range / SCC / etc. extensions
    // which the minimal parser does not surface.
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
        // need it for the HW IDR submit; just consume.
        let ctb_log2 = sps.log2_min_luma_coding_block_size_minus3 as u32
            + 3
            + sps.log2_diff_max_min_luma_coding_block_size as u32;
        let ctb_size = 1u32 << ctb_log2;
        let pic_w_in_ctbs = sps.pic_width_in_luma_samples.div_ceil(ctb_size);
        let pic_h_in_ctbs = sps.pic_height_in_luma_samples.div_ceil(ctb_size);
        let total_ctbs = pic_w_in_ctbs as u64 * pic_h_in_ctbs as u64;
        let bits = 64 - total_ctbs.leading_zeros();
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
