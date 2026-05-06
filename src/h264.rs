//! H.264 / AVC minimal IDR header parsing.
//!
//! This module parses just enough of an H.264 Annex-B bitstream to
//! populate any of the slice-data HW backends' parameter buffers
//! ([`VAPictureParameterBufferH264`], [`VdpPictureInfoH264`],
//! [`VkVideoDecodeH264PictureInfoKHR`]). It does NOT handle:
//!
//! - DCT, entropy decode, inverse transform, motion compensation,
//!   in-loop filtering — the GPU does all of that.
//! - Scaling lists (`seq_scaling_matrix_present_flag` / PPS scaling
//!   lists). The IDR-only backends submit flat 16/16, which is what
//!   the encoder default emits.
//! - FMO / ASO (`num_slice_groups_minus1 > 0`).
//! - Redundant slices.
//! - B / SP / SI slice header complexity.
//! - VUI parsing — only the cropping rectangle is captured.
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
pub fn ebsp_to_rbsp(ebsp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ebsp.len());
    let mut i = 0;
    let n = ebsp.len();
    while i < n {
        if i + 2 < n && ebsp[i] == 0 && ebsp[i + 1] == 0 && ebsp[i + 2] == 3 {
            out.push(0);
            out.push(0);
            i += 3;
        } else {
            out.push(ebsp[i]);
            i += 1;
        }
    }
    out
}

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
        let _qpprime_y_zero_transform_bypass = r.u(1);
        let seq_scaling_matrix_present = r.u(1);
        if seq_scaling_matrix_present != 0 {
            return Err(BitstreamError::unsupported(
                "SPS seq_scaling_matrix_present_flag=1 not supported by minimal parser",
            ));
        }
    } else {
        sps.chroma_format_idc = 1; // implicit 4:2:0
    }

    sps.log2_max_frame_num_minus4 = r.ue()? as u8;
    sps.pic_order_cnt_type = r.ue()? as u8;
    match sps.pic_order_cnt_type {
        0 => {
            sps.log2_max_pic_order_cnt_lsb_minus4 = r.ue()? as u8;
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
    // VUI is not parsed.
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
pub fn parse_pps(rbsp: &[u8]) -> Result<H264Pps, BitstreamError> {
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

    if more_rbsp_data(&r) {
        pps.transform_8x8_mode_flag = r.u(1) != 0;
        let pic_scaling_matrix_present = r.u(1);
        if pic_scaling_matrix_present != 0 {
            return Err(BitstreamError::unsupported(
                "PPS pic_scaling_matrix_present_flag=1 not supported by minimal parser",
            ));
        }
        pps.second_chroma_qp_index_offset = r.se()?;
    } else {
        pps.second_chroma_qp_index_offset = pps.chroma_qp_index_offset;
    }
    Ok(pps)
}

/// Parse a PPS NAL — including the NAL header byte at index 0.
pub fn parse_pps_nal(nal: &[u8]) -> Result<H264Pps, BitstreamError> {
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
    parse_pps(&rbsp)
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
                pps = Some(parse_pps_nal(body)?);
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

// ─────────────────────────── more_rbsp_data() ────────────────────────────────

/// H.264 7.2 `more_rbsp_data()`. There is more RBSP data if the
/// current bit position is not at the start of the trailing-bit
/// marker (a `1` followed by 0..7 zero bits, byte-aligned). We scan
/// forward looking for any `1` after the *next* `1` — if we find
/// one, the next `1` was not the marker and there's more data.
fn more_rbsp_data(r: &BitReader<'_>) -> bool {
    let total_bits = r.bytes.len() * 8;
    if r.bit_pos >= total_bits {
        return false;
    }
    let mut saw_one = false;
    for p in r.bit_pos..total_bits {
        let b = (r.bytes[p / 8] >> (7 - (p % 8))) & 1;
        if !saw_one {
            if b == 1 {
                saw_one = true;
            }
        } else if b == 1 {
            return true;
        }
    }
    false
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
}
