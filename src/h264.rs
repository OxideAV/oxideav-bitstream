//! H.264 / AVC minimal IDR header parsing.
//!
//! This module parses just enough of an H.264 Annex-B bitstream to
//! populate any of the slice-data HW backends' parameter buffers
//! ([`VAPictureParameterBufferH264`], [`VdpPictureInfoH264`],
//! [`VkVideoDecodeH264PictureInfoKHR`]). It does NOT handle:
//!
//! - DCT, entropy decode, inverse transform, motion compensation,
//!   in-loop filtering — the GPU does all of that.
//! - FMO / ASO (`num_slice_groups_minus1 > 0`).
//! - Redundant slices.
//! - B / SP / SI slice header complexity.
//!
//! It DOES parse the complete SPS including scaling lists
//! (§7.3.2.1.1.1) and VUI/HRD (Annex E), and the complete PPS
//! including scaling lists when the SPS context is supplied
//! ([`parse_pps_with_sps`]).
//!
//! The boundary is the same the workspace's other "minimal IDR" code
//! has used in `crates/oxideav-vdpau/src/h264.rs` since Round 3.
//!
//! # Spec references
//!
//! ITU-T H.264 / ISO/IEC 14496-10. The sections you'll see referenced
//! in the comments below are 7.3.2.1.1 (SPS), 7.3.2.2 (PPS), 7.3.3
//! (slice header), 7.3.2.1.1.1 (frame cropping), 7.4.5 (slice header
//! semantics), 9.1 (Exp-Golomb).

use crate::bit_reader::BitReader;
use crate::BitstreamError;

// ─────────────────────────── NAL unit types ──────────────────────────────────

/// H.264 NAL unit type 5 — Coded slice of an IDR picture (7.4.1).
pub const NAL_TYPE_IDR: u8 = 5;
/// H.264 NAL unit type 7 — Sequence parameter set.
pub const NAL_TYPE_SPS: u8 = 7;
/// H.264 NAL unit type 8 — Picture parameter set.
pub const NAL_TYPE_PPS: u8 = 8;
/// H.264 NAL unit type 1 — Coded slice of a non-IDR picture.
pub const NAL_TYPE_NON_IDR_SLICE: u8 = 1;
/// H.264 NAL unit type 9 — Access unit delimiter.
pub const NAL_TYPE_AUD: u8 = 9;

// ─────────────────────────── Annex-B framing ─────────────────────────────────

/// Locate every NAL unit in an Annex-B bitstream and return slices
/// pointing at the NAL body (start-code stripped, NAL header byte at
/// index 0, emulation bytes still in place — those are stripped only
/// during bit-level parsing via [`ebsp_to_rbsp`]).
///
/// The HW backends keep the original Annex-B bytes around for
/// submission to the GPU; this function is for *parsing* only.
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

/// Strip H.264 emulation-prevention `0x03` bytes from an EBSP to
/// produce an RBSP (7.4.1.1). Inserted by the encoder after `00 00 0x`
/// to keep start codes unique inside the payload.
///
/// The implementation lives in [`crate::nal::ebsp_to_rbsp`]; H.264,
/// HEVC and H.266 all use the same rule, so the codec module re-exports
/// the shared helper rather than carrying a private copy.
pub use crate::nal::ebsp_to_rbsp;

/// Inspect the NAL header byte and return `(forbidden_zero_bit,
/// nal_ref_idc, nal_unit_type)`.
pub fn nal_header(byte: u8) -> (u8, u8, u8) {
    let forbidden = (byte >> 7) & 1;
    let nal_ref_idc = (byte >> 5) & 0x3;
    let nal_type = byte & 0x1f;
    (forbidden, nal_ref_idc, nal_type)
}

// ─────────────────────────── Output structs ──────────────────────────────────

/// Frame cropping rectangle in *picture* (output-image) sample units.
/// The values themselves are the four offsets that
/// `frame_crop_*_offset` evaluate to after the SubWidth/SubHeight
/// scaling rules in 6.4 / 7.4.2.1.1.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct H264FrameCropping {
    pub left: u32,
    pub right: u32,
    pub top: u32,
    pub bottom: u32,
}

/// Scaling lists recovered from a `seq_scaling_matrix_present_flag`
/// or `pic_scaling_matrix_present_flag` block (§7.3.2.1.1 SPS /
/// §7.3.2.2 PPS, list bodies per §7.3.2.1.1.1).
///
/// Twelve list slots exist: indices 0..=5 are the 4×4 lists
/// (Intra Y/Cb/Cr then Inter Y/Cb/Cr, §7.4.2.1.1 Table 7-2) and
/// indices 6..=11 the 8×8 lists. When `chroma_format_idc != 3` only
/// the first two 8×8 slots (indices 6, 7) are coded; slots 8..=11
/// stay `present == false`.
///
/// Semantics of each slot:
///
/// * `present[i] == false` — the list was not signalled; the decoder
///   applies the fall-back rules of Table 7-2 (SPS) / Table 7-4 (PPS).
/// * `present[i] && use_default[i]` — the list was signalled with
///   `delta_scale` driving `nextScale` to 0 on the first coefficient
///   (`UseDefaultScalingMatrixFlag`, §7.3.2.1.1.1), selecting the
///   default matrix of Tables 7-3/7-4.
/// * `present[i] && !use_default[i]` — the raw coefficients are in
///   `list_4x4[i]` / `list_8x8[i - 6]`, in coding (zig-zag delta)
///   order as reconstructed by the §7.3.2.1.1.1 pseudo-code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H264ScalingLists {
    pub present: [bool; 12],
    pub use_default: [bool; 12],
    pub list_4x4: [[u8; 16]; 6],
    pub list_8x8: [[u8; 64]; 6],
}

impl Default for H264ScalingLists {
    fn default() -> Self {
        H264ScalingLists {
            present: [false; 12],
            use_default: [false; 12],
            list_4x4: [[0; 16]; 6],
            list_8x8: [[0; 64]; 6],
        }
    }
}

/// Parse one `scaling_list( scalingList, sizeOfScalingList,
/// useDefaultScalingMatrixFlag )` structure (§7.3.2.1.1.1) into
/// `out`. Returns the `UseDefaultScalingMatrixFlag` result.
///
/// The reconstruction follows the spec pseudo-code exactly:
/// `nextScale = ( lastScale + delta_scale + 256 ) % 256`, a
/// `nextScale` of 0 on the first coefficient selects the default
/// matrix, and once `nextScale` reaches 0 the remaining entries
/// repeat `lastScale`.
fn parse_scaling_list(r: &mut BitReader<'_>, out: &mut [u8]) -> Result<bool, BitstreamError> {
    let mut last_scale: i32 = 8;
    let mut next_scale: i32 = 8;
    let mut use_default = false;
    for (j, slot) in out.iter_mut().enumerate() {
        if next_scale != 0 {
            let delta_scale = r.se()?;
            // §7.4.2.1.1.1: delta_scale shall be in the range of
            // −128 to +127, inclusive.
            if !(-128..=127).contains(&delta_scale) {
                return Err(BitstreamError::invalid(format!(
                    "scaling_list delta_scale={delta_scale} (must be -128..=127)"
                )));
            }
            next_scale = (last_scale + delta_scale + 256) % 256;
            if j == 0 && next_scale == 0 {
                use_default = true;
            }
        }
        *slot = if next_scale == 0 {
            last_scale as u8
        } else {
            next_scale as u8
        };
        last_scale = *slot as i32;
    }
    Ok(use_default)
}

/// Parse the list block shared by the SPS (`seq_scaling_matrix`) and
/// PPS (`pic_scaling_matrix`) syntax. `count` is 8 when
/// `chroma_format_idc != 3`, 12 otherwise (SPS §7.3.2.1.1); the PPS
/// variant passes `6 + (chroma != 3 ? 2 : 6)` only when
/// `transform_8x8_mode_flag` is set, 6 otherwise (§7.3.2.2).
fn parse_scaling_matrix(
    r: &mut BitReader<'_>,
    count: usize,
) -> Result<H264ScalingLists, BitstreamError> {
    let mut lists = H264ScalingLists::default();
    for i in 0..count.min(12) {
        lists.present[i] = r.u(1) != 0;
        if lists.present[i] {
            let use_default = if i < 6 {
                parse_scaling_list(r, &mut lists.list_4x4[i])?
            } else {
                parse_scaling_list(r, &mut lists.list_8x8[i - 6])?
            };
            lists.use_default[i] = use_default;
        }
    }
    Ok(lists)
}

// ─────────────────────────── VUI (Annex E) ──────────────────────────────────

/// `aspect_ratio_idc` value that signals an explicit
/// `sar_width : sar_height` pair (Table E-1).
pub const H264_EXTENDED_SAR: u8 = 255;

/// One CPB schedule entry from `hrd_parameters()` (§E.1.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct H264CpbEntry {
    pub bit_rate_value_minus1: u32,
    pub cpb_size_value_minus1: u32,
    pub cbr_flag: bool,
}

/// HRD parameters (§E.1.2 / §E.2.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct H264HrdParameters {
    /// §E.2.2 constrains this to 0..=31; the parser enforces it.
    pub cpb_cnt_minus1: u32,
    pub bit_rate_scale: u8,
    pub cpb_size_scale: u8,
    /// `cpb_cnt_minus1 + 1` schedule entries.
    pub cpb: Vec<H264CpbEntry>,
    pub initial_cpb_removal_delay_length_minus1: u8,
    pub cpb_removal_delay_length_minus1: u8,
    pub dpb_output_delay_length_minus1: u8,
    pub time_offset_length: u8,
}

impl H264HrdParameters {
    /// Bit rate of schedule entry `idx` in bits/second:
    /// `( bit_rate_value_minus1 + 1 ) << ( 6 + bit_rate_scale )`
    /// (§E.2.2 BitRate derivation).
    pub fn bit_rate(&self, idx: usize) -> Option<u64> {
        let e = self.cpb.get(idx)?;
        Some((e.bit_rate_value_minus1 as u64 + 1) << (6 + self.bit_rate_scale as u32))
    }

    /// CPB size of schedule entry `idx` in bits:
    /// `( cpb_size_value_minus1 + 1 ) << ( 4 + cpb_size_scale )`
    /// (§E.2.2 CpbSize derivation).
    pub fn cpb_size(&self, idx: usize) -> Option<u64> {
        let e = self.cpb.get(idx)?;
        Some((e.cpb_size_value_minus1 as u64 + 1) << (4 + self.cpb_size_scale as u32))
    }
}

/// VUI parameters (§E.1.1 / §E.2.1). Every syntax element is
/// surfaced; conditional fields default to 0 / false when their
/// presence flag is clear.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct H264Vui {
    pub aspect_ratio_info_present_flag: bool,
    /// Table E-1. 255 = [`H264_EXTENDED_SAR`].
    pub aspect_ratio_idc: u8,
    pub sar_width: u16,
    pub sar_height: u16,

    pub overscan_info_present_flag: bool,
    pub overscan_appropriate_flag: bool,

    pub video_signal_type_present_flag: bool,
    /// Table E-2.
    pub video_format: u8,
    pub video_full_range_flag: bool,
    pub colour_description_present_flag: bool,
    /// Table E-3.
    pub colour_primaries: u8,
    /// Table E-4.
    pub transfer_characteristics: u8,
    /// Table E-5.
    pub matrix_coefficients: u8,

    pub chroma_loc_info_present_flag: bool,
    pub chroma_sample_loc_type_top_field: u32,
    pub chroma_sample_loc_type_bottom_field: u32,

    pub timing_info_present_flag: bool,
    pub num_units_in_tick: u32,
    pub time_scale: u32,
    pub fixed_frame_rate_flag: bool,

    pub nal_hrd_parameters: Option<H264HrdParameters>,
    pub vcl_hrd_parameters: Option<H264HrdParameters>,
    /// Present only when either HRD block is (§E.1.1).
    pub low_delay_hrd_flag: bool,
    pub pic_struct_present_flag: bool,

    pub bitstream_restriction_flag: bool,
    pub motion_vectors_over_pic_boundaries_flag: bool,
    pub max_bytes_per_pic_denom: u32,
    pub max_bits_per_mb_denom: u32,
    pub log2_max_mv_length_horizontal: u32,
    pub log2_max_mv_length_vertical: u32,
    pub max_num_reorder_frames: u32,
    pub max_dec_frame_buffering: u32,
}

impl H264Vui {
    /// Sample aspect ratio as `(width, height)` per Table E-1.
    /// Returns `None` for `aspect_ratio_idc == 0` (unspecified) and
    /// for the reserved band 17..=254.
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
            H264_EXTENDED_SAR => (self.sar_width, self.sar_height),
            _ => return None,
        })
    }

    /// Field rate `time_scale / num_units_in_tick` expressed as a
    /// rational `(num, den)`. Per §E.2.1, for frame-coded content two
    /// fields make a frame, so the *frame* rate of progressive
    /// streams is `time_scale / (2 * num_units_in_tick)` — use
    /// [`H264Vui::frame_rate`] for that. `None` when timing info is
    /// absent or `num_units_in_tick == 0`.
    pub fn field_rate(&self) -> Option<(u32, u32)> {
        if !self.timing_info_present_flag || self.num_units_in_tick == 0 {
            return None;
        }
        Some((self.time_scale, self.num_units_in_tick))
    }

    /// Frame rate `time_scale / (2 * num_units_in_tick)` as a
    /// rational `(num, den)` (§E.2.1 formula for frame-coded video).
    pub fn frame_rate(&self) -> Option<(u32, u64)> {
        let (n, d) = self.field_rate()?;
        Some((n, 2 * d as u64))
    }
}

/// Parse a `hrd_parameters()` structure (§E.1.2).
fn parse_hrd_parameters(r: &mut BitReader<'_>) -> Result<H264HrdParameters, BitstreamError> {
    let cpb_cnt_minus1 = r.ue()?;
    // §E.2.2: cpb_cnt_minus1 shall be in the range of 0 to 31,
    // inclusive. Enforcing it also bounds the schedule loop below on
    // hostile input.
    if cpb_cnt_minus1 > 31 {
        return Err(BitstreamError::invalid(format!(
            "hrd_parameters cpb_cnt_minus1={cpb_cnt_minus1} (must be 0..=31)"
        )));
    }
    let mut hrd = H264HrdParameters {
        cpb_cnt_minus1,
        bit_rate_scale: r.u(4) as u8,
        cpb_size_scale: r.u(4) as u8,
        ..H264HrdParameters::default()
    };
    for _ in 0..=cpb_cnt_minus1 {
        hrd.cpb.push(H264CpbEntry {
            bit_rate_value_minus1: r.ue()?,
            cpb_size_value_minus1: r.ue()?,
            cbr_flag: r.u(1) != 0,
        });
    }
    hrd.initial_cpb_removal_delay_length_minus1 = r.u(5) as u8;
    hrd.cpb_removal_delay_length_minus1 = r.u(5) as u8;
    hrd.dpb_output_delay_length_minus1 = r.u(5) as u8;
    hrd.time_offset_length = r.u(5) as u8;
    Ok(hrd)
}

/// Parse a `vui_parameters()` structure (§E.1.1).
fn parse_vui_parameters(r: &mut BitReader<'_>) -> Result<H264Vui, BitstreamError> {
    let mut vui = H264Vui {
        aspect_ratio_info_present_flag: r.u(1) != 0,
        ..H264Vui::default()
    };
    if vui.aspect_ratio_info_present_flag {
        vui.aspect_ratio_idc = r.u(8) as u8;
        if vui.aspect_ratio_idc == H264_EXTENDED_SAR {
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
            vui.matrix_coefficients = r.u(8) as u8;
        }
    }
    vui.chroma_loc_info_present_flag = r.u(1) != 0;
    if vui.chroma_loc_info_present_flag {
        vui.chroma_sample_loc_type_top_field = r.ue()?;
        vui.chroma_sample_loc_type_bottom_field = r.ue()?;
    }
    vui.timing_info_present_flag = r.u(1) != 0;
    if vui.timing_info_present_flag {
        vui.num_units_in_tick = r.u(32);
        vui.time_scale = r.u(32);
        vui.fixed_frame_rate_flag = r.u(1) != 0;
    }
    let nal_hrd = r.u(1) != 0;
    if nal_hrd {
        vui.nal_hrd_parameters = Some(parse_hrd_parameters(r)?);
    }
    let vcl_hrd = r.u(1) != 0;
    if vcl_hrd {
        vui.vcl_hrd_parameters = Some(parse_hrd_parameters(r)?);
    }
    if nal_hrd || vcl_hrd {
        vui.low_delay_hrd_flag = r.u(1) != 0;
    }
    vui.pic_struct_present_flag = r.u(1) != 0;
    vui.bitstream_restriction_flag = r.u(1) != 0;
    if vui.bitstream_restriction_flag {
        vui.motion_vectors_over_pic_boundaries_flag = r.u(1) != 0;
        vui.max_bytes_per_pic_denom = r.ue()?;
        vui.max_bits_per_mb_denom = r.ue()?;
        vui.log2_max_mv_length_horizontal = r.ue()?;
        vui.log2_max_mv_length_vertical = r.ue()?;
        vui.max_num_reorder_frames = r.ue()?;
        vui.max_dec_frame_buffering = r.ue()?;
    }
    Ok(vui)
}

/// Sequence parameter set. Carries every field the three slice-data
/// HW APIs look at, plus a few derived helpers.
///
/// See H.264 7.3.2.1.1 for the syntax this is filled from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct H264Sps {
    pub profile_idc: u8,
    /// Bits 7..0 of the constraint_set_flags + reserved_zero block
    /// in the order the encoder emitted them — useful for round-tripping.
    pub constraint_set_flags: u8,
    pub level_idc: u8,
    pub seq_parameter_set_id: u8,

    pub chroma_format_idc: u8,
    pub separate_colour_plane_flag: bool,
    pub bit_depth_luma_minus8: u8,
    pub bit_depth_chroma_minus8: u8,
    /// §7.4.2.1.1 — lossless-bypass gate (High 4:4:4 class profiles).
    pub qpprime_y_zero_transform_bypass_flag: bool,
    /// `Some` when `seq_scaling_matrix_present_flag == 1` (§7.3.2.1.1).
    pub seq_scaling_lists: Option<H264ScalingLists>,

    pub log2_max_frame_num_minus4: u8,
    pub pic_order_cnt_type: u8,
    pub log2_max_pic_order_cnt_lsb_minus4: u8,
    pub delta_pic_order_always_zero_flag: bool,
    pub max_num_ref_frames: u32,
    pub gaps_in_frame_num_value_allowed_flag: bool,

    pub pic_width_in_mbs_minus1: u32,
    pub pic_height_in_map_units_minus1: u32,
    pub frame_mbs_only_flag: bool,
    pub mb_adaptive_frame_field_flag: bool,
    pub direct_8x8_inference_flag: bool,

    pub frame_cropping: Option<H264FrameCropping>,

    /// `Some` when `vui_parameters_present_flag == 1` (§7.3.2.1.1 /
    /// Annex E).
    pub vui: Option<H264Vui>,
}

impl H264Sps {
    /// Whether this SPS requires the High-profile syntax extension
    /// (chroma_format / bit_depth / scaling_matrix block).
    pub fn has_high_profile_extension(profile_idc: u8) -> bool {
        matches!(
            profile_idc,
            100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
        )
    }

    /// Coded width in luma samples (pic_width_in_mbs * 16). 7.4.2.1.1.
    pub fn coded_width(&self) -> u32 {
        (self.pic_width_in_mbs_minus1 + 1) * 16
    }

    /// Coded height in luma samples. Accounts for
    /// `frame_mbs_only_flag` per 7.4.2.1.1.
    pub fn coded_height(&self) -> u32 {
        let mb_only = if self.frame_mbs_only_flag { 1 } else { 0 };
        (self.pic_height_in_map_units_minus1 + 1) * 16 * (2 - mb_only)
    }

    /// Per the SubWidthC table in 6.2 (only the values we actually
    /// hit — 1 for 4:2:0/4:2:2, 1 for 4:4:4 monochrome handled
    /// separately).
    fn sub_width_c(&self) -> u32 {
        match self.chroma_format_idc {
            1 | 2 => 2, // 4:2:0, 4:2:2
            3 => 1,     // 4:4:4
            _ => 1,
        }
    }

    fn sub_height_c(&self) -> u32 {
        match self.chroma_format_idc {
            1 => 2,     // 4:2:0
            2 | 3 => 1, // 4:2:2, 4:4:4
            _ => 1,
        }
    }

    /// Display width in luma samples after applying the frame
    /// cropping rectangle (6.4 / 7.4.2.1.1.1). For monochrome
    /// (chroma_format_idc==0) the offsets are interpreted in luma
    /// samples directly.
    pub fn display_width(&self) -> u32 {
        let coded = self.coded_width();
        let Some(c) = self.frame_cropping else {
            return coded;
        };
        let crop_x = if self.chroma_format_idc == 0 || self.separate_colour_plane_flag {
            1
        } else {
            self.sub_width_c()
        };
        coded.saturating_sub((c.left + c.right) * crop_x)
    }

    /// Display height in luma samples after frame cropping.
    pub fn display_height(&self) -> u32 {
        let coded = self.coded_height();
        let Some(c) = self.frame_cropping else {
            return coded;
        };
        let crop_y = if self.chroma_format_idc == 0 || self.separate_colour_plane_flag {
            2 - if self.frame_mbs_only_flag { 1 } else { 0 }
        } else {
            self.sub_height_c() * (2 - if self.frame_mbs_only_flag { 1 } else { 0 })
        };
        coded.saturating_sub((c.top + c.bottom) * crop_y)
    }
}

/// Picture parameter set (7.3.2.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct H264Pps {
    pub pic_parameter_set_id: u8,
    pub seq_parameter_set_id: u8,
    pub entropy_coding_mode_flag: bool,
    pub bottom_field_pic_order_in_frame_present_flag: bool,
    pub num_slice_groups_minus1: u32,
    pub num_ref_idx_l0_default_active_minus1: u8,
    pub num_ref_idx_l1_default_active_minus1: u8,
    pub weighted_pred_flag: bool,
    pub weighted_bipred_idc: u8,
    pub pic_init_qp_minus26: i32,
    pub pic_init_qs_minus26: i32,
    pub chroma_qp_index_offset: i32,
    pub deblocking_filter_control_present_flag: bool,
    pub constrained_intra_pred_flag: bool,
    pub redundant_pic_cnt_present_flag: bool,
    /// Only meaningful when the High-profile extension block is
    /// present; otherwise defaulted to false.
    pub transform_8x8_mode_flag: bool,
    /// `Some` when `pic_scaling_matrix_present_flag == 1` (§7.3.2.2).
    /// Only recoverable via [`parse_pps_with_sps`] — the list count
    /// depends on the active SPS's `chroma_format_idc`.
    pub pic_scaling_lists: Option<H264ScalingLists>,
    /// Defaults to a copy of `chroma_qp_index_offset` when the
    /// High-profile extension block is absent (per 7.4.2.2).
    pub second_chroma_qp_index_offset: i32,
}

/// Minimal slice header (7.3.3 + 7.4.3). Only the fields needed to
/// (a) confirm we have an IDR access unit and (b) populate the HW
/// backends' picture-info structs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct H264SliceHeader {
    pub first_mb_in_slice: u32,
    /// `slice_type` value as emitted; not modulo-5. 0..9.
    pub slice_type: u8,
    pub pic_parameter_set_id: u8,
    pub frame_num: u32,
    pub field_pic_flag: bool,
    pub bottom_field_flag: bool,
    /// Present only when this is an IDR slice (NAL type 5).
    pub idr_pic_id: Option<u32>,
    pub pic_order_cnt_lsb: u32,
}

impl H264SliceHeader {
    /// True if `slice_type % 5 == 2` (per 7.4.3 — slice_type values
    /// 2 and 7 are I-slices).
    pub fn is_i_slice(&self) -> bool {
        self.slice_type % 5 == 2
    }
}

/// Convenience structure for [`parse_idr_only`].
#[derive(Debug)]
pub struct H264IdrParse<'a> {
    pub sps: H264Sps,
    pub pps: H264Pps,
    pub slice_header: H264SliceHeader,
    /// The raw Annex-B bytes covering the IDR access unit (from the
    /// start code that precedes the IDR NAL through the end of the
    /// input). The HW backends submit this slab to the GPU as-is.
    pub idr_access_unit: &'a [u8],
}

// ─────────────────────────── Parsers ─────────────────────────────────────────

/// Parse a SPS RBSP (the bytes *after* emulation-prevention stripping
/// and *after* the NAL header byte).
///
/// Note: pass the RBSP payload, not the raw NAL. Use
/// [`parse_sps_nal`] if you have a NAL with header byte at index 0.
pub fn parse_sps(rbsp: &[u8]) -> Result<H264Sps, BitstreamError> {
    if rbsp.len() < 3 {
        return Err(BitstreamError::unexpected_end("SPS shorter than 3 bytes"));
    }
    let mut r = BitReader::new(rbsp);

    let profile_idc = r.u(8) as u8;
    let constraint_set_flags = r.u(8) as u8;
    let level_idc = r.u(8) as u8;
    let mut sps = H264Sps {
        profile_idc,
        constraint_set_flags,
        level_idc,
        ..H264Sps::default()
    };
    sps.seq_parameter_set_id = r.ue()? as u8;

    if H264Sps::has_high_profile_extension(profile_idc) {
        sps.chroma_format_idc = r.ue()? as u8;
        if sps.chroma_format_idc == 3 {
            sps.separate_colour_plane_flag = r.u(1) != 0;
        }
        sps.bit_depth_luma_minus8 = r.ue()? as u8;
        sps.bit_depth_chroma_minus8 = r.ue()? as u8;
        sps.qpprime_y_zero_transform_bypass_flag = r.u(1) != 0;
        let seq_scaling_matrix_present = r.u(1);
        if seq_scaling_matrix_present != 0 {
            // §7.3.2.1.1: 8 lists for non-4:4:4, 12 for 4:4:4.
            let count = if sps.chroma_format_idc != 3 { 8 } else { 12 };
            sps.seq_scaling_lists = Some(parse_scaling_matrix(&mut r, count)?);
        }
    } else {
        sps.chroma_format_idc = 1; // implicit 4:2:0
    }

    // H.264 §7.4.2.1.1 constrains log2_max_frame_num_minus4 to 0..=12
    // (frame_num is read as u(log2_max_frame_num_minus4 + 4), i.e. at
    // most 16 bits). A malformed SPS with a larger value would later
    // drive `BitReader::u(n > 32)` in the slice-header parser, so
    // reject it here rather than letting it propagate.
    let log2_max_frame_num_minus4 = r.ue()?;
    if log2_max_frame_num_minus4 > 12 {
        return Err(BitstreamError::invalid(format!(
            "SPS log2_max_frame_num_minus4={log2_max_frame_num_minus4} (must be 0..=12)"
        )));
    }
    sps.log2_max_frame_num_minus4 = log2_max_frame_num_minus4 as u8;
    sps.pic_order_cnt_type = r.ue()? as u8;
    match sps.pic_order_cnt_type {
        0 => {
            // §7.4.2.1.1 likewise constrains log2_max_pic_order_cnt_lsb_minus4
            // to 0..=12 (pic_order_cnt_lsb is u(value + 4), at most 16 bits).
            let log2_max_poc_lsb_minus4 = r.ue()?;
            if log2_max_poc_lsb_minus4 > 12 {
                return Err(BitstreamError::invalid(format!(
                    "SPS log2_max_pic_order_cnt_lsb_minus4={log2_max_poc_lsb_minus4} (must be 0..=12)"
                )));
            }
            sps.log2_max_pic_order_cnt_lsb_minus4 = log2_max_poc_lsb_minus4 as u8;
        }
        1 => {
            sps.delta_pic_order_always_zero_flag = r.u(1) != 0;
            let _offset_for_non_ref_pic = r.se()?;
            let _offset_for_top_to_bottom_field = r.se()?;
            let num_ref_frames_in_pic_order_cnt_cycle = r.ue()?;
            for _ in 0..num_ref_frames_in_pic_order_cnt_cycle {
                let _offset_for_ref_frame = r.se()?;
            }
        }
        2 => { /* nothing further */ }
        other => {
            return Err(BitstreamError::invalid(format!(
                "SPS pic_order_cnt_type={other} (must be 0..2)"
            )));
        }
    }
    sps.max_num_ref_frames = r.ue()?;
    sps.gaps_in_frame_num_value_allowed_flag = r.u(1) != 0;
    sps.pic_width_in_mbs_minus1 = r.ue()?;
    sps.pic_height_in_map_units_minus1 = r.ue()?;
    sps.frame_mbs_only_flag = r.u(1) != 0;
    if !sps.frame_mbs_only_flag {
        sps.mb_adaptive_frame_field_flag = r.u(1) != 0;
    }
    sps.direct_8x8_inference_flag = r.u(1) != 0;
    let frame_cropping_flag = r.u(1);
    if frame_cropping_flag != 0 {
        let left = r.ue()?;
        let right = r.ue()?;
        let top = r.ue()?;
        let bottom = r.ue()?;
        sps.frame_cropping = Some(H264FrameCropping {
            left,
            right,
            top,
            bottom,
        });
    }
    let vui_parameters_present_flag = r.u(1);
    if vui_parameters_present_flag != 0 {
        sps.vui = Some(parse_vui_parameters(&mut r)?);
    }
    Ok(sps)
}

/// Parse a SPS NAL — including the NAL header byte at index 0. Errors
/// out if the NAL type isn't 7.
pub fn parse_sps_nal(nal: &[u8]) -> Result<H264Sps, BitstreamError> {
    if nal.is_empty() {
        return Err(BitstreamError::unexpected_end("empty SPS NAL"));
    }
    let (_, _, nal_type) = nal_header(nal[0]);
    if nal_type != NAL_TYPE_SPS {
        return Err(BitstreamError::invalid(format!(
            "expected SPS NAL (type=7), got type={nal_type}"
        )));
    }
    let rbsp = ebsp_to_rbsp(&nal[1..]);
    parse_sps(&rbsp)
}

/// Parse a PPS RBSP (after emulation-prevention stripping and after
/// the NAL header byte).
///
/// PPS scaling lists (`pic_scaling_matrix_present_flag == 1`) are
/// refused by this context-free entry point because the §7.3.2.2
/// list count reads `chroma_format_idc` from the active SPS. Use
/// [`parse_pps_with_sps`] when the SPS is at hand.
pub fn parse_pps(rbsp: &[u8]) -> Result<H264Pps, BitstreamError> {
    parse_pps_inner(rbsp, None)
}

/// Parse a PPS RBSP with the active SPS as context, enabling the
/// `pic_scaling_matrix_present_flag` block (§7.3.2.2) whose list
/// count is `6 + ( ( chroma_format_idc != 3 ) ? 2 : 6 ) *
/// transform_8x8_mode_flag`.
pub fn parse_pps_with_sps(rbsp: &[u8], sps: &H264Sps) -> Result<H264Pps, BitstreamError> {
    parse_pps_inner(rbsp, Some(sps))
}

fn parse_pps_inner(rbsp: &[u8], sps: Option<&H264Sps>) -> Result<H264Pps, BitstreamError> {
    if rbsp.is_empty() {
        return Err(BitstreamError::unexpected_end("empty PPS"));
    }
    let mut r = BitReader::new(rbsp);
    let mut pps = H264Pps {
        pic_parameter_set_id: r.ue()? as u8,
        seq_parameter_set_id: r.ue()? as u8,
        entropy_coding_mode_flag: r.u(1) != 0,
        bottom_field_pic_order_in_frame_present_flag: r.u(1) != 0,
        num_slice_groups_minus1: r.ue()?,
        ..H264Pps::default()
    };
    if pps.num_slice_groups_minus1 != 0 {
        return Err(BitstreamError::unsupported(
            "PPS num_slice_groups_minus1>0 (FMO/ASO) not supported by minimal parser",
        ));
    }
    pps.num_ref_idx_l0_default_active_minus1 = r.ue()? as u8;
    pps.num_ref_idx_l1_default_active_minus1 = r.ue()? as u8;
    pps.weighted_pred_flag = r.u(1) != 0;
    pps.weighted_bipred_idc = r.u(2) as u8;
    pps.pic_init_qp_minus26 = r.se()?;
    pps.pic_init_qs_minus26 = r.se()?;
    pps.chroma_qp_index_offset = r.se()?;
    pps.deblocking_filter_control_present_flag = r.u(1) != 0;
    pps.constrained_intra_pred_flag = r.u(1) != 0;
    pps.redundant_pic_cnt_present_flag = r.u(1) != 0;

    if r.more_rbsp_data() {
        pps.transform_8x8_mode_flag = r.u(1) != 0;
        let pic_scaling_matrix_present = r.u(1);
        if pic_scaling_matrix_present != 0 {
            let Some(sps) = sps else {
                return Err(BitstreamError::unsupported(
                    "PPS pic_scaling_matrix_present_flag=1 needs SPS context — \
                     use parse_pps_with_sps",
                ));
            };
            // §7.3.2.2: 6 + ( ( chroma_format_idc != 3 ) ? 2 : 6 ) *
            // transform_8x8_mode_flag lists.
            let extra = if pps.transform_8x8_mode_flag {
                if sps.chroma_format_idc != 3 {
                    2
                } else {
                    6
                }
            } else {
                0
            };
            pps.pic_scaling_lists = Some(parse_scaling_matrix(&mut r, 6 + extra)?);
        }
        pps.second_chroma_qp_index_offset = r.se()?;
    } else {
        pps.second_chroma_qp_index_offset = pps.chroma_qp_index_offset;
    }
    Ok(pps)
}

/// Parse a PPS NAL — including the NAL header byte at index 0.
pub fn parse_pps_nal(nal: &[u8]) -> Result<H264Pps, BitstreamError> {
    parse_pps_nal_inner(nal, None)
}

/// Parse a PPS NAL with the active SPS as context (enables PPS
/// scaling lists — see [`parse_pps_with_sps`]).
pub fn parse_pps_nal_with_sps(nal: &[u8], sps: &H264Sps) -> Result<H264Pps, BitstreamError> {
    parse_pps_nal_inner(nal, Some(sps))
}

fn parse_pps_nal_inner(nal: &[u8], sps: Option<&H264Sps>) -> Result<H264Pps, BitstreamError> {
    if nal.is_empty() {
        return Err(BitstreamError::unexpected_end("empty PPS NAL"));
    }
    let (_, _, nal_type) = nal_header(nal[0]);
    if nal_type != NAL_TYPE_PPS {
        return Err(BitstreamError::invalid(format!(
            "expected PPS NAL (type=8), got type={nal_type}"
        )));
    }
    let rbsp = ebsp_to_rbsp(&nal[1..]);
    parse_pps_inner(&rbsp, sps)
}

/// Parse just enough of a slice header to fill the fields the HW
/// backends need (7.3.3). The `nal_unit_type` is needed because IDR
/// slices include `idr_pic_id` and non-IDR slices skip it.
///
/// `rbsp` must already be the post-emulation-prevention bytes that
/// follow the NAL header byte. `sps` and `pps` provide the
/// dependent-fixed-length-code widths (`log2_max_frame_num_minus4`,
/// `pic_order_cnt_type`, etc.).
pub fn parse_slice_header_minimal(
    rbsp: &[u8],
    nal_unit_type: u8,
    sps: &H264Sps,
    pps: &H264Pps,
) -> Result<H264SliceHeader, BitstreamError> {
    let _ = pps; // currently consulted only for shape; reserved for future fields
    let mut r = BitReader::new(rbsp);
    let mut sh = H264SliceHeader {
        first_mb_in_slice: r.ue()?,
        slice_type: r.ue()? as u8,
        pic_parameter_set_id: r.ue()? as u8,
        ..H264SliceHeader::default()
    };
    if sps.separate_colour_plane_flag {
        let _colour_plane_id = r.u(2);
    }
    sh.frame_num = r.u(sps.log2_max_frame_num_minus4 as u32 + 4);
    if !sps.frame_mbs_only_flag {
        sh.field_pic_flag = r.u(1) != 0;
        if sh.field_pic_flag {
            sh.bottom_field_flag = r.u(1) != 0;
        }
    }
    if nal_unit_type == NAL_TYPE_IDR {
        sh.idr_pic_id = Some(r.ue()?);
    }
    if sps.pic_order_cnt_type == 0 {
        sh.pic_order_cnt_lsb = r.u(sps.log2_max_pic_order_cnt_lsb_minus4 as u32 + 4);
    }
    // The remaining slice-header fields (ref_pic_list_modification,
    // pred_weight_table, dec_ref_pic_marking, slice_qp_delta, …) are
    // not needed to identify an IDR or to populate the IDR-only
    // parameter buffer, so we stop here.
    Ok(sh)
}

/// Walk an Annex-B stream, find the first IDR access unit, parse the
/// SPS, PPS, and IDR slice header, and return them along with a slice
/// of the original input covering the IDR access unit.
///
/// Errors out if the stream contains no SPS, no PPS, no IDR NAL, or
/// any of the parsers fails.
pub fn parse_idr_only(stream: &[u8]) -> Result<H264IdrParse<'_>, BitstreamError> {
    // Locate the byte ranges of every Annex-B NAL — we need indices
    // into `stream` (not just borrows of NAL bodies) to slice the
    // returned `idr_access_unit`.
    let nals = locate_annex_b(stream);
    if nals.is_empty() {
        return Err(BitstreamError::invalid("no NAL units found in stream"));
    }

    let mut sps: Option<H264Sps> = None;
    let mut pps: Option<H264Pps> = None;
    let mut idr_idx: Option<usize> = None;
    for (idx, n) in nals.iter().enumerate() {
        let body = &stream[n.body_start..n.body_end];
        if body.is_empty() {
            continue;
        }
        let (_, _, nal_type) = nal_header(body[0]);
        match nal_type {
            NAL_TYPE_SPS if sps.is_none() => {
                sps = Some(parse_sps_nal(body)?);
            }
            NAL_TYPE_PPS if pps.is_none() => {
                // Use the SPS as context when it has already been seen
                // (the conforming SPS-before-PPS ordering) so PPS
                // scaling lists parse instead of erroring out.
                pps = Some(match &sps {
                    Some(s) => parse_pps_nal_with_sps(body, s)?,
                    None => parse_pps_nal(body)?,
                });
            }
            NAL_TYPE_IDR if idr_idx.is_none() => {
                idr_idx = Some(idx);
            }
            _ => {}
        }
    }
    let sps = sps.ok_or_else(|| BitstreamError::invalid("stream has no SPS NAL"))?;
    let pps = pps.ok_or_else(|| BitstreamError::invalid("stream has no PPS NAL"))?;
    let idr_idx = idr_idx.ok_or_else(|| BitstreamError::invalid("stream has no IDR NAL"))?;

    let idr_nal = &nals[idr_idx];
    let body = &stream[idr_nal.body_start..idr_nal.body_end];
    let rbsp = ebsp_to_rbsp(&body[1..]);
    let slice_header = parse_slice_header_minimal(&rbsp, NAL_TYPE_IDR, &sps, &pps)?;

    let access_unit = &stream[idr_nal.start_code_start..];
    Ok(H264IdrParse {
        sps,
        pps,
        slice_header,
        idr_access_unit: access_unit,
    })
}

// ─────────────────────────── Annex-B index helper ────────────────────────────

#[derive(Debug, Clone, Copy)]
struct NalLoc {
    /// Index of the first byte of the start code (00 00 [00] 01).
    start_code_start: usize,
    body_start: usize,
    body_end: usize,
}

fn locate_annex_b(buf: &[u8]) -> Vec<NalLoc> {
    let mut out = Vec::new();
    let mut i = 0;
    let n = buf.len();
    let mut current: Option<(usize, usize)> = None; // (start_code_start, body_start)
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

/// Access unit delimiter RBSP — H.264 §7.3.2.4 / §7.4.2.4.
///
/// The AUD NAL (type 9) marks the boundary between access units and
/// optionally narrows the set of `slice_type` values that may appear
/// in the primary coded picture. `primary_pic_type` is the only
/// signalled field; everything else in the NAL is `rbsp_trailing_bits()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H264AccessUnitDelimiter {
    /// `primary_pic_type` u(3) (§7.4.2.4 / Table 7-5). Spec range 0..=7.
    pub primary_pic_type: u8,
}

/// `primary_pic_type` is u(3) so the spec range is 0..=7
/// (§7.4.2.4 / Table 7-5).
pub const H264_PRIMARY_PIC_TYPE_MAX: u8 = 7;

/// Parse an AUD NAL — including the NAL header byte at index 0 —
/// recovering `primary_pic_type` and verifying the trailing
/// `rbsp_trailing_bits()` marker (§7.3.2.4).
///
/// Returns [`BitstreamError::InvalidData`] when the NAL type isn't
/// [`NAL_TYPE_AUD`] or when the trailing marker is malformed; returns
/// [`BitstreamError::UnexpectedEnd`] when the NAL is too short to
/// carry a 3-bit pic-type field plus its byte-aligning marker.
pub fn parse_aud_nal(nal: &[u8]) -> Result<H264AccessUnitDelimiter, BitstreamError> {
    if nal.is_empty() {
        return Err(BitstreamError::unexpected_end("empty AUD NAL"));
    }
    let (_, _, nal_type) = nal_header(nal[0]);
    if nal_type != NAL_TYPE_AUD {
        return Err(BitstreamError::invalid(format!(
            "expected AUD NAL (type=9), got type={nal_type}"
        )));
    }
    if nal.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "AUD NAL has no body after header byte",
        ));
    }
    let rbsp = ebsp_to_rbsp(&nal[1..]);
    let mut r = BitReader::new(&rbsp);
    let primary_pic_type = r.u(3) as u8;
    r.read_rbsp_trailing_bits()?;
    Ok(H264AccessUnitDelimiter { primary_pic_type })
}

/// Emit an AUD NAL — header byte followed by a 1-byte RBSP that packs
/// `primary_pic_type` u(3) and the `rbsp_trailing_bits()` marker. The
/// `0x00 0x00 0x00` / `0x00 0x00 0x01` start-code triples can never
/// appear inside a single-byte RBSP, so no emulation-prevention
/// byte-stuffing is required.
///
/// The NAL header byte fixes `forbidden_zero_bit = 0` and
/// `nal_ref_idc = 0` — the latter being the H.264 §7.4.1 requirement
/// that any AUD NAL must have `nal_ref_idc = 0`. The returned bytes
/// start with the NAL header byte; callers that need an Annex-B unit
/// prepend `0x00 0x00 0x01` (or `0x00 0x00 0x00 0x01`) themselves.
///
/// Returns [`BitstreamError::InvalidData`] when
/// `primary_pic_type > 7` (the u(3) envelope).
pub fn write_aud_nal(aud: &H264AccessUnitDelimiter) -> Result<Vec<u8>, BitstreamError> {
    if aud.primary_pic_type > H264_PRIMARY_PIC_TYPE_MAX {
        return Err(BitstreamError::invalid(format!(
            "H.264 primary_pic_type = {} > {} (u(3) envelope)",
            aud.primary_pic_type, H264_PRIMARY_PIC_TYPE_MAX
        )));
    }
    // NAL header: forbidden_zero=0, nal_ref_idc=0, nal_unit_type=9.
    let nal_header_byte: u8 = NAL_TYPE_AUD; // upper bits already zero
    let mut bw = crate::bit_writer::BitWriter::new();
    bw.write_bits(aud.primary_pic_type as u32, 3);
    bw.write_rbsp_trailing_bits();
    let rbsp = bw.finish();
    // Encapsulate: a 1-byte RBSP cannot trigger the 00-00-{00..03}
    // pattern that emulation-prevention guards against, so the EBSP
    // is byte-identical to the RBSP.
    let mut out = Vec::with_capacity(1 + rbsp.len());
    out.push(nal_header_byte);
    out.extend_from_slice(&rbsp);
    Ok(out)
}

// ─────────────────────────── Tests ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_finds_three_nal_starts_in_synthetic_buffer() {
        let buf = [
            0, 0, 0, 1, 0x67, 0xaa, // NAL 1
            0, 0, 1, 0x68, 0xbb, // NAL 2
            0, 0, 0, 1, 0x65, 0xcc, 0xdd, // NAL 3
        ];
        let nals = split_annex_b(&buf);
        assert_eq!(nals.len(), 3);
        assert_eq!(nals[0], &[0x67, 0xaa]);
        assert_eq!(nals[1], &[0x68, 0xbb]);
        assert_eq!(nals[2], &[0x65, 0xcc, 0xdd]);
    }

    #[test]
    fn ebsp_to_rbsp_strips_03_in_zero_zero_run() {
        let ebsp = [0x00, 0x00, 0x03, 0x01, 0x02, 0x03];
        let rbsp = ebsp_to_rbsp(&ebsp);
        assert_eq!(rbsp, &[0x00, 0x00, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn nal_header_decodes_idr_byte() {
        // 0x65 = 0110_0101 → forbidden=0, nal_ref_idc=3, nal_type=5
        let (f, nri, t) = nal_header(0x65);
        assert_eq!(f, 0);
        assert_eq!(nri, 3);
        assert_eq!(t, NAL_TYPE_IDR);
    }

    #[test]
    fn aud_write_then_parse_roundtrips_every_pic_type() {
        for pt in 0u8..=H264_PRIMARY_PIC_TYPE_MAX {
            let in_ = H264AccessUnitDelimiter {
                primary_pic_type: pt,
            };
            let bytes = write_aud_nal(&in_).expect("AUD NAL writes");
            let parsed = parse_aud_nal(&bytes).expect("AUD NAL parses");
            assert_eq!(parsed, in_, "round-trip primary_pic_type={pt}");
        }
    }

    #[test]
    fn aud_write_pic_type_0_canonical_bytes() {
        // pic_type=0 (000) followed by stop-one (1) + four zero
        // alignment bits = 0b0001_0000 = 0x10. The NAL header byte
        // for an AUD with nal_ref_idc=0 is 0x09.
        let bytes = write_aud_nal(&H264AccessUnitDelimiter {
            primary_pic_type: 0,
        })
        .unwrap();
        assert_eq!(bytes, vec![0x09, 0x10]);
    }

    #[test]
    fn aud_write_pic_type_7_canonical_bytes() {
        // pic_type=7 (111) + stop-one (1) + four zero alignment bits
        // = 0b1111_0000 = 0xF0.
        let bytes = write_aud_nal(&H264AccessUnitDelimiter {
            primary_pic_type: 7,
        })
        .unwrap();
        assert_eq!(bytes, vec![0x09, 0xf0]);
    }

    #[test]
    fn aud_writer_rejects_out_of_range_pic_type() {
        let err = write_aud_nal(&H264AccessUnitDelimiter {
            primary_pic_type: 8,
        })
        .expect_err("pic_type=8 is outside u(3) envelope");
        assert!(matches!(err, BitstreamError::InvalidData(_)));
    }

    #[test]
    fn aud_parser_rejects_wrong_nal_type() {
        // SPS NAL header byte where an AUD was expected.
        let nal = [0x67u8, 0x10];
        let err = parse_aud_nal(&nal).expect_err("wrong nal type rejected");
        assert!(matches!(err, BitstreamError::InvalidData(_)));
    }

    #[test]
    fn aud_parser_rejects_empty_input() {
        let err = parse_aud_nal(&[]).expect_err("empty NAL rejected");
        assert!(matches!(err, BitstreamError::UnexpectedEnd(_)));
    }

    #[test]
    fn aud_parser_rejects_header_only_nal() {
        // NAL with only the header byte and no payload byte.
        let err = parse_aud_nal(&[0x09u8]).expect_err("header-only NAL rejected");
        assert!(matches!(err, BitstreamError::UnexpectedEnd(_)));
    }

    #[test]
    fn aud_parser_rejects_missing_stop_bit() {
        // pic_type=0 (000) followed by all-zero alignment bits — no
        // rbsp_stop_one_bit anywhere -> reader's marker check fails.
        let nal = [0x09u8, 0x00];
        let err = parse_aud_nal(&nal).expect_err("missing stop bit rejected");
        assert!(
            matches!(
                err,
                BitstreamError::InvalidData(_) | BitstreamError::UnexpectedEnd(_)
            ),
            "got: {err:?}"
        );
    }

    /// Build a minimal baseline-profile SPS RBSP with the given
    /// `log2_max_frame_num_minus4` value and `pic_order_cnt_type = 2`
    /// (so no further POC fields are read). Used to exercise the
    /// out-of-range guard without needing a full valid SPS.
    fn baseline_sps_with_log2_max_frame_num(log2_max_frame_num_minus4: u32) -> Vec<u8> {
        let mut w = crate::bit_writer::BitWriter::new();
        w.write_bits(66, 8); // profile_idc = 66 (baseline, no high-profile ext)
        w.write_bits(0, 8); // constraint_set_flags
        w.write_bits(0, 8); // level_idc
        w.write_ue(0).unwrap(); // seq_parameter_set_id
        w.write_ue(log2_max_frame_num_minus4).unwrap();
        w.write_ue(2).unwrap(); // pic_order_cnt_type = 2 (no extra POC fields)
        w.finish()
    }

    #[test]
    fn parse_sps_accepts_max_log2_max_frame_num() {
        // log2_max_frame_num_minus4 = 12 is the spec maximum (§7.4.2.1.1).
        let rbsp = baseline_sps_with_log2_max_frame_num(12);
        let sps = parse_sps(&rbsp).expect("log2_max_frame_num_minus4=12 is in range");
        assert_eq!(sps.log2_max_frame_num_minus4, 12);
    }

    #[test]
    fn parse_sps_rejects_oversized_log2_max_frame_num() {
        // log2_max_frame_num_minus4 = 13 would make frame_num a u(17)
        // read in the slice-header parser, which panics in BitReader::u.
        // The SPS parser must reject it up front.
        let rbsp = baseline_sps_with_log2_max_frame_num(13);
        let err = parse_sps(&rbsp).expect_err("log2_max_frame_num_minus4=13 is out of range");
        assert!(
            matches!(err, BitstreamError::InvalidData(_)),
            "got: {err:?}"
        );
    }

    /// Write the common baseline-profile SPS body through the frame
    /// cropping flag (set to 0), leaving the writer positioned at
    /// `vui_parameters_present_flag`.
    fn baseline_sps_body_to_vui_flag(w: &mut crate::bit_writer::BitWriter) {
        w.write_bits(66, 8); // profile_idc = 66 (baseline)
        w.write_bits(0, 8); // constraint_set_flags
        w.write_bits(30, 8); // level_idc
        w.write_ue(0).unwrap(); // seq_parameter_set_id
        w.write_ue(4).unwrap(); // log2_max_frame_num_minus4
        w.write_ue(2).unwrap(); // pic_order_cnt_type = 2
        w.write_ue(1).unwrap(); // max_num_ref_frames
        w.write_bit(0); // gaps_in_frame_num_value_allowed_flag
        w.write_ue(19).unwrap(); // pic_width_in_mbs_minus1 (320)
        w.write_ue(14).unwrap(); // pic_height_in_map_units_minus1 (240)
        w.write_bit(1); // frame_mbs_only_flag
        w.write_bit(1); // direct_8x8_inference_flag
        w.write_bit(0); // frame_cropping_flag
    }

    #[test]
    fn parse_sps_with_full_vui_and_hrd() {
        let mut w = crate::bit_writer::BitWriter::new();
        baseline_sps_body_to_vui_flag(&mut w);
        w.write_bit(1); // vui_parameters_present_flag
                        // vui_parameters() — §E.1.1
        w.write_bit(1); // aspect_ratio_info_present_flag
        w.write_bits(255, 8); // aspect_ratio_idc = Extended_SAR
        w.write_bits(4, 16); // sar_width
        w.write_bits(3, 16); // sar_height
        w.write_bit(1); // overscan_info_present_flag
        w.write_bit(1); // overscan_appropriate_flag
        w.write_bit(1); // video_signal_type_present_flag
        w.write_bits(5, 3); // video_format = 5 (unspecified)
        w.write_bit(1); // video_full_range_flag
        w.write_bit(1); // colour_description_present_flag
        w.write_bits(1, 8); // colour_primaries (BT.709)
        w.write_bits(1, 8); // transfer_characteristics
        w.write_bits(1, 8); // matrix_coefficients
        w.write_bit(1); // chroma_loc_info_present_flag
        w.write_ue(1).unwrap(); // chroma_sample_loc_type_top_field
        w.write_ue(2).unwrap(); // chroma_sample_loc_type_bottom_field
        w.write_bit(1); // timing_info_present_flag
        w.write_bits(1001, 32); // num_units_in_tick
        w.write_bits(60000, 32); // time_scale
        w.write_bit(1); // fixed_frame_rate_flag
        w.write_bit(1); // nal_hrd_parameters_present_flag
                        // hrd_parameters() — §E.1.2, cpb_cnt_minus1 = 1 → 2 entries
        w.write_ue(1).unwrap(); // cpb_cnt_minus1
        w.write_bits(2, 4); // bit_rate_scale
        w.write_bits(3, 4); // cpb_size_scale
        w.write_ue(999).unwrap(); // bit_rate_value_minus1[0]
        w.write_ue(1999).unwrap(); // cpb_size_value_minus1[0]
        w.write_bit(1); // cbr_flag[0]
        w.write_ue(499).unwrap(); // bit_rate_value_minus1[1]
        w.write_ue(999).unwrap(); // cpb_size_value_minus1[1]
        w.write_bit(0); // cbr_flag[1]
        w.write_bits(23, 5); // initial_cpb_removal_delay_length_minus1
        w.write_bits(15, 5); // cpb_removal_delay_length_minus1
        w.write_bits(5, 5); // dpb_output_delay_length_minus1
        w.write_bits(24, 5); // time_offset_length
        w.write_bit(0); // vcl_hrd_parameters_present_flag
        w.write_bit(1); // low_delay_hrd_flag
        w.write_bit(1); // pic_struct_present_flag
        w.write_bit(1); // bitstream_restriction_flag
        w.write_bit(1); // motion_vectors_over_pic_boundaries_flag
        w.write_ue(2).unwrap(); // max_bytes_per_pic_denom
        w.write_ue(1).unwrap(); // max_bits_per_mb_denom
        w.write_ue(16).unwrap(); // log2_max_mv_length_horizontal
        w.write_ue(16).unwrap(); // log2_max_mv_length_vertical
        w.write_ue(0).unwrap(); // max_num_reorder_frames
        w.write_ue(1).unwrap(); // max_dec_frame_buffering
        w.write_rbsp_trailing_bits();

        let sps = parse_sps(&w.finish()).expect("SPS with full VUI parses");
        let vui = sps.vui.expect("VUI captured");
        assert_eq!(vui.aspect_ratio_idc, H264_EXTENDED_SAR);
        assert_eq!(vui.sample_aspect_ratio(), Some((4, 3)));
        assert!(vui.overscan_appropriate_flag);
        assert_eq!(vui.video_format, 5);
        assert!(vui.video_full_range_flag);
        assert_eq!(vui.colour_primaries, 1);
        assert_eq!(vui.chroma_sample_loc_type_top_field, 1);
        assert_eq!(vui.chroma_sample_loc_type_bottom_field, 2);
        assert_eq!(vui.num_units_in_tick, 1001);
        assert_eq!(vui.time_scale, 60000);
        assert_eq!(vui.field_rate(), Some((60000, 1001)));
        assert_eq!(vui.frame_rate(), Some((60000, 2002)));
        let hrd = vui.nal_hrd_parameters.as_ref().expect("NAL HRD captured");
        assert_eq!(hrd.cpb_cnt_minus1, 1);
        assert_eq!(hrd.cpb.len(), 2);
        assert!(hrd.cpb[0].cbr_flag);
        assert!(!hrd.cpb[1].cbr_flag);
        // BitRate[0] = 1000 << (6 + 2) = 256000 (§E.2.2).
        assert_eq!(hrd.bit_rate(0), Some(256_000));
        // CpbSize[0] = 2000 << (4 + 3) = 256000 (§E.2.2).
        assert_eq!(hrd.cpb_size(0), Some(256_000));
        assert!(vui.vcl_hrd_parameters.is_none());
        assert!(vui.low_delay_hrd_flag);
        assert!(vui.pic_struct_present_flag);
        assert!(vui.bitstream_restriction_flag);
        assert_eq!(vui.log2_max_mv_length_horizontal, 16);
        assert_eq!(vui.max_num_reorder_frames, 0);
        assert_eq!(vui.max_dec_frame_buffering, 1);
    }

    #[test]
    fn parse_vui_table_e1_fixed_ratios() {
        // Spot-check the Table E-1 mapping helper for the fixed idc
        // band and the unspecified/reserved cases.
        let mut vui = H264Vui {
            aspect_ratio_info_present_flag: true,
            aspect_ratio_idc: 1,
            ..H264Vui::default()
        };
        assert_eq!(vui.sample_aspect_ratio(), Some((1, 1)));
        vui.aspect_ratio_idc = 13;
        assert_eq!(vui.sample_aspect_ratio(), Some((160, 99)));
        vui.aspect_ratio_idc = 16;
        assert_eq!(vui.sample_aspect_ratio(), Some((2, 1)));
        vui.aspect_ratio_idc = 0; // unspecified
        assert_eq!(vui.sample_aspect_ratio(), None);
        vui.aspect_ratio_idc = 17; // reserved
        assert_eq!(vui.sample_aspect_ratio(), None);
    }

    #[test]
    fn parse_hrd_rejects_out_of_range_cpb_cnt() {
        // A VUI whose HRD block claims cpb_cnt_minus1 = 32 (§E.2.2
        // caps it at 31) must be rejected, bounding the schedule loop.
        let mut w = crate::bit_writer::BitWriter::new();
        baseline_sps_body_to_vui_flag(&mut w);
        w.write_bit(1); // vui_parameters_present_flag
        w.write_bit(0); // aspect_ratio_info_present_flag
        w.write_bit(0); // overscan_info_present_flag
        w.write_bit(0); // video_signal_type_present_flag
        w.write_bit(0); // chroma_loc_info_present_flag
        w.write_bit(0); // timing_info_present_flag
        w.write_bit(1); // nal_hrd_parameters_present_flag
        w.write_ue(32).unwrap(); // cpb_cnt_minus1 — out of range
        let err = parse_sps(&w.finish()).expect_err("cpb_cnt_minus1=32 rejected");
        assert!(matches!(err, BitstreamError::InvalidData(_)));
    }

    /// Build a High-profile (100) 4:2:0 SPS RBSP with
    /// `seq_scaling_matrix_present_flag = 1` and the given per-list
    /// closure emitting each of the 8 list slots.
    fn high_sps_with_scaling_matrix(
        emit: impl Fn(&mut crate::bit_writer::BitWriter, usize),
    ) -> Vec<u8> {
        let mut w = crate::bit_writer::BitWriter::new();
        w.write_bits(100, 8); // profile_idc = 100 (High)
        w.write_bits(0, 8);
        w.write_bits(30, 8);
        w.write_ue(0).unwrap(); // seq_parameter_set_id
        w.write_ue(1).unwrap(); // chroma_format_idc = 1 (4:2:0)
        w.write_ue(0).unwrap(); // bit_depth_luma_minus8
        w.write_ue(0).unwrap(); // bit_depth_chroma_minus8
        w.write_bit(0); // qpprime_y_zero_transform_bypass_flag
        w.write_bit(1); // seq_scaling_matrix_present_flag
        for i in 0..8 {
            emit(&mut w, i);
        }
        w.write_ue(4).unwrap(); // log2_max_frame_num_minus4
        w.write_ue(2).unwrap(); // pic_order_cnt_type
        w.write_ue(1).unwrap(); // max_num_ref_frames
        w.write_bit(0);
        w.write_ue(19).unwrap();
        w.write_ue(14).unwrap();
        w.write_bit(1); // frame_mbs_only
        w.write_bit(1); // direct_8x8
        w.write_bit(0); // cropping
        w.write_bit(0); // vui
        w.write_rbsp_trailing_bits();
        w.finish()
    }

    #[test]
    fn parse_sps_scaling_matrix_explicit_default_and_absent() {
        // List 0: explicit ramp (delta_scale +1 for each of 16 coeffs
        // starting from lastScale 8 → 9,10,...,24).
        // List 1: use-default (first delta_scale = -8 → nextScale 0).
        // Lists 2..7: absent.
        let rbsp = high_sps_with_scaling_matrix(|w, i| match i {
            0 => {
                w.write_bit(1); // seq_scaling_list_present_flag[0]
                for _ in 0..16 {
                    w.write_se(1).unwrap(); // delta_scale = +1
                }
            }
            1 => {
                w.write_bit(1); // present
                w.write_se(-8).unwrap(); // nextScale = (8 - 8 + 256) % 256 = 0
            }
            _ => w.write_bit(0), // absent
        });
        let sps = parse_sps(&rbsp).expect("High SPS with scaling matrix parses");
        let lists = sps.seq_scaling_lists.expect("scaling lists captured");
        assert!(lists.present[0]);
        assert!(!lists.use_default[0]);
        let expected: Vec<u8> = (9..=24).collect();
        assert_eq!(&lists.list_4x4[0][..], &expected[..]);
        assert!(lists.present[1]);
        assert!(lists.use_default[1], "delta to 0 on j=0 selects default");
        for i in 2..12 {
            assert!(!lists.present[i], "list {i} absent");
        }
        assert!(!sps.qpprime_y_zero_transform_bypass_flag);
    }

    #[test]
    fn parse_sps_scaling_list_stops_updating_after_zero() {
        // §7.3.2.1.1.1: once nextScale hits 0 at j>0, the remaining
        // entries repeat lastScale and no further delta_scale is read.
        let rbsp = high_sps_with_scaling_matrix(|w, i| {
            if i == 0 {
                w.write_bit(1);
                w.write_se(2).unwrap(); // j=0: nextScale=10
                w.write_se(-10).unwrap(); // j=1: nextScale=0 → freeze at 10
                                          // no more delta_scale coded for j=2..15
            } else {
                w.write_bit(0);
            }
        });
        let sps = parse_sps(&rbsp).expect("frozen scaling list parses");
        let lists = sps.seq_scaling_lists.expect("lists");
        assert_eq!(lists.list_4x4[0], [10u8; 16]);
        assert!(!lists.use_default[0]);
    }

    /// Emit a PPS RBSP with the High-profile tail and one explicit
    /// 4×4 scaling list.
    fn pps_with_scaling_matrix(transform_8x8: bool) -> Vec<u8> {
        let mut w = crate::bit_writer::BitWriter::new();
        w.write_ue(0).unwrap(); // pic_parameter_set_id
        w.write_ue(0).unwrap(); // seq_parameter_set_id
        w.write_bit(1); // entropy_coding_mode_flag (CABAC)
        w.write_bit(0); // bottom_field_pic_order_in_frame_present_flag
        w.write_ue(0).unwrap(); // num_slice_groups_minus1
        w.write_ue(0).unwrap(); // num_ref_idx_l0_default_active_minus1
        w.write_ue(0).unwrap(); // num_ref_idx_l1_default_active_minus1
        w.write_bit(0); // weighted_pred_flag
        w.write_bits(0, 2); // weighted_bipred_idc
        w.write_se(0).unwrap(); // pic_init_qp_minus26
        w.write_se(0).unwrap(); // pic_init_qs_minus26
        w.write_se(2).unwrap(); // chroma_qp_index_offset
        w.write_bit(1); // deblocking_filter_control_present_flag
        w.write_bit(0); // constrained_intra_pred_flag
        w.write_bit(0); // redundant_pic_cnt_present_flag
        w.write_bit(u32::from(transform_8x8)); // transform_8x8_mode_flag
        w.write_bit(1); // pic_scaling_matrix_present_flag
        let count = if transform_8x8 { 8 } else { 6 };
        for i in 0..count {
            if i == 0 {
                w.write_bit(1); // pic_scaling_list_present_flag[0]
                for _ in 0..16 {
                    w.write_se(1).unwrap();
                }
            } else {
                w.write_bit(0);
            }
        }
        w.write_se(-2).unwrap(); // second_chroma_qp_index_offset
        w.write_rbsp_trailing_bits();
        w.finish()
    }

    #[test]
    fn parse_pps_with_sps_recovers_scaling_lists() {
        let sps = H264Sps {
            chroma_format_idc: 1,
            ..H264Sps::default()
        };
        for &t8 in &[false, true] {
            let rbsp = pps_with_scaling_matrix(t8);
            let pps = parse_pps_with_sps(&rbsp, &sps).expect("PPS with scaling lists parses");
            assert_eq!(pps.transform_8x8_mode_flag, t8);
            let lists = pps.pic_scaling_lists.expect("PPS lists captured");
            assert!(lists.present[0]);
            let expected: Vec<u8> = (9..=24).collect();
            assert_eq!(&lists.list_4x4[0][..], &expected[..]);
            assert_eq!(pps.second_chroma_qp_index_offset, -2);
            assert_eq!(pps.chroma_qp_index_offset, 2);
        }
    }

    #[test]
    fn parse_pps_without_sps_context_refuses_scaling_lists() {
        let rbsp = pps_with_scaling_matrix(false);
        let err = parse_pps(&rbsp).expect_err("context-free PPS scaling lists refused");
        assert!(matches!(err, BitstreamError::Unsupported(_)));
    }

    #[test]
    fn parse_sps_rejects_oversized_log2_max_pic_order_cnt_lsb() {
        // Baseline SPS with pic_order_cnt_type = 0 and an out-of-range
        // log2_max_pic_order_cnt_lsb_minus4 = 13.
        let mut w = crate::bit_writer::BitWriter::new();
        w.write_bits(66, 8); // profile_idc = 66
        w.write_bits(0, 8); // constraint_set_flags
        w.write_bits(0, 8); // level_idc
        w.write_ue(0).unwrap(); // seq_parameter_set_id
        w.write_ue(4).unwrap(); // log2_max_frame_num_minus4 (in range)
        w.write_ue(0).unwrap(); // pic_order_cnt_type = 0
        w.write_ue(13).unwrap(); // log2_max_pic_order_cnt_lsb_minus4 (out of range)
        let rbsp = w.finish();
        let err =
            parse_sps(&rbsp).expect_err("log2_max_pic_order_cnt_lsb_minus4=13 is out of range");
        assert!(
            matches!(err, BitstreamError::InvalidData(_)),
            "got: {err:?}"
        );
    }
}
