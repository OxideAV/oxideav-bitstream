//! HEVC complete slice segment header (§7.3.6.1).
//!
//! [`parse_slice_segment_header`] walks `slice_segment_header()` to its
//! end for every slice type of a single-layer, non-SCC stream: the
//! short-term RPS (SPS-indexed or coded inline, incl. inter-set
//! prediction with `delta_idx_minus1`), long-term pictures,
//! `ref_pic_lists_modification()`, `pred_weight_table()` (§7.3.6.3),
//! collocated / temporal MVP fields, QP offsets, deblocking overrides,
//! entry points and the header extension, then `byte_alignment()`. A
//! dependent slice segment copies the fields it does not code from the
//! preceding independent segment (§7.4.7.1).
//!
//! The result records where the slice data begins both in RBSP bytes
//! and in the escaped NAL unit, and the bit size of an inline
//! `st_ref_pic_set()` — the extra numbers hardware slice-parameter
//! buffers ask for.

use super::{
    HevcPps, HevcShortTermRps, HevcSps, NAL_TYPE_IDR_N_LP, NAL_TYPE_IDR_W_RADL, ebsp_to_rbsp,
    nal_header, parse_st_ref_pic_set_body,
};
use crate::BitstreamError;
use crate::bit_reader::BitReader;

/// `slice_type` (§7.4.7.1 Table 7-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum HevcSliceType {
    B,
    P,
    #[default]
    I,
}

impl HevcSliceType {
    pub fn from_raw(v: u32) -> Result<Self, BitstreamError> {
        match v {
            0 => Ok(HevcSliceType::B),
            1 => Ok(HevcSliceType::P),
            2 => Ok(HevcSliceType::I),
            _ => Err(BitstreamError::invalid(format!("slice_type={v}"))),
        }
    }

    /// The coded value (0 = B, 1 = P, 2 = I).
    pub fn code(self) -> u8 {
        match self {
            HevcSliceType::B => 0,
            HevcSliceType::P => 1,
            HevcSliceType::I => 2,
        }
    }

    pub fn is_inter(self) -> bool {
        self != HevcSliceType::I
    }
}

/// One long-term entry of the slice header (§7.3.6.1), with the
/// §7.4.7.1 derived values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct LongTermRef {
    /// `Some(lt_idx_sps)` for entries taken from the SPS list.
    pub lt_idx_sps: Option<u32>,
    /// `PocLsbLt[i]` (from the SPS for `lt_idx_sps` entries).
    pub poc_lsb_lt: u32,
    /// `UsedByCurrPicLt[i]`.
    pub used_by_curr_pic_lt: bool,
    pub delta_poc_msb_present_flag: bool,
    /// The coded `delta_poc_msb_cycle_lt[i]`.
    pub delta_poc_msb_cycle_lt: u32,
    /// `DeltaPocMsbCycleLt[i]` (eq. 7-52, accumulated).
    pub delta_poc_msb_cycle_lt_acc: u32,
}

/// One list entry of `pred_weight_table()`: the coded deltas plus the
/// §7.4.7.3 derived `LumaWeightLX` / `ChromaWeightLX` / `ChromaOffsetLX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct HevcPredWeight {
    pub luma_weight_flag: bool,
    pub delta_luma_weight: i32,
    pub luma_offset: i32,
    pub chroma_weight_flag: bool,
    pub delta_chroma_weight: [i32; 2],
    pub delta_chroma_offset: [i32; 2],
    /// `LumaWeightLX[i]` (eq. 7-54).
    pub luma_weight: i32,
    /// `ChromaWeightLX[i][j]` (eq. 7-55).
    pub chroma_weight: [i32; 2],
    /// `ChromaOffsetLX[i][j]` (eq. 7-56).
    pub chroma_offset: [i32; 2],
}

/// `pred_weight_table()` (§7.3.6.3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct HevcPredWeightTable {
    pub luma_log2_weight_denom: u32,
    pub delta_chroma_log2_weight_denom: i32,
    /// `ChromaLog2WeightDenom`.
    pub chroma_log2_weight_denom: u32,
    pub l0: Vec<HevcPredWeight>,
    pub l1: Vec<HevcPredWeight>,
}

/// `ref_pic_lists_modification()` (§7.3.6.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct RefPicListsModification {
    pub ref_pic_list_modification_flag_l0: bool,
    pub list_entry_l0: Vec<u32>,
    pub ref_pic_list_modification_flag_l1: bool,
    pub list_entry_l1: Vec<u32>,
}

/// Every field of `slice_segment_header()`, inferred values filled in.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct SliceSegmentHeader {
    pub nal_unit_type: u8,
    pub nuh_layer_id: u8,
    /// `TemporalId`.
    pub temporal_id: u8,
    pub first_slice_segment_in_pic_flag: bool,
    pub no_output_of_prior_pics_flag: bool,
    pub slice_pic_parameter_set_id: u8,
    pub dependent_slice_segment_flag: bool,
    pub slice_segment_address: u32,
    /// `slice_reserved_flag[i]` packed LSB-first.
    pub slice_reserved_flags: u32,
    pub slice_type: HevcSliceType,
    pub pic_output_flag: bool,
    pub colour_plane_id: u8,
    pub slice_pic_order_cnt_lsb: u32,
    pub short_term_ref_pic_set_sps_flag: bool,
    /// `short_term_ref_pic_set_idx` (SPS-indexed RPS).
    pub short_term_ref_pic_set_idx: u32,
    /// The coded `delta_idx_minus1` of an inline inter-predicted RPS.
    pub delta_idx_minus1: u32,
    /// The short-term RPS in force (`CurrRpsIdx`), resolved.
    pub short_term_rps: HevcShortTermRps,
    /// Bits of the inline `st_ref_pic_set()` (0 when SPS-indexed).
    pub st_rps_bits: u32,
    pub num_long_term_sps: u32,
    pub num_long_term_pics: u32,
    pub long_term_refs: Vec<LongTermRef>,
    pub slice_temporal_mvp_enabled_flag: bool,
    pub slice_sao_luma_flag: bool,
    pub slice_sao_chroma_flag: bool,
    pub num_ref_idx_active_override_flag: bool,
    /// In force (PPS default unless overridden); 0 for I slices.
    pub num_ref_idx_l0_active_minus1: u32,
    /// In force for B slices; 0 otherwise.
    pub num_ref_idx_l1_active_minus1: u32,
    pub ref_pic_lists_modification: RefPicListsModification,
    pub mvd_l1_zero_flag: bool,
    pub cabac_init_flag: bool,
    /// Inferred 1 when absent.
    pub collocated_from_l0_flag: bool,
    pub collocated_ref_idx: u32,
    pub pred_weight_table: Option<HevcPredWeightTable>,
    pub five_minus_max_num_merge_cand: u32,
    pub slice_qp_delta: i32,
    pub slice_cb_qp_offset: i32,
    pub slice_cr_qp_offset: i32,
    pub cu_chroma_qp_offset_enabled_flag: bool,
    pub deblocking_filter_override_flag: bool,
    /// In force (PPS value unless overridden).
    pub slice_deblocking_filter_disabled_flag: bool,
    pub slice_beta_offset_div2: i32,
    pub slice_tc_offset_div2: i32,
    /// In force (PPS value unless coded).
    pub slice_loop_filter_across_slices_enabled_flag: bool,
    pub num_entry_point_offsets: u32,
    pub offset_len_minus1: u32,
    pub entry_point_offset_minus1: Vec<u32>,
    pub slice_segment_header_extension_length: u32,
    /// RBSP bytes after the 2-byte NAL unit header up to the first
    /// slice data byte (`byte_alignment()` included).
    pub header_bytes: usize,
    /// Emulation prevention bytes inside those header bytes.
    pub header_emulation_bytes: usize,
}

impl SliceSegmentHeader {
    pub fn is_idr(&self) -> bool {
        matches!(self.nal_unit_type, NAL_TYPE_IDR_W_RADL | NAL_TYPE_IDR_N_LP)
    }

    /// IRAP NAL unit types 16..=23.
    pub fn is_irap(&self) -> bool {
        (16..=23).contains(&self.nal_unit_type)
    }

    /// `NumPicTotalCurr` (eq. 7-55 without the SCC current-picture term).
    pub fn num_pic_total_curr(&self) -> u32 {
        let st = self
            .short_term_rps
            .used_by_curr_pic_s0
            .iter()
            .chain(&self.short_term_rps.used_by_curr_pic_s1)
            .filter(|&&u| u)
            .count();
        let lt = self
            .long_term_refs
            .iter()
            .filter(|l| l.used_by_curr_pic_lt)
            .count();
        (st + lt) as u32
    }

    /// `SliceQpY` (eq. 7-54).
    pub fn slice_qp_y(&self, pps: &HevcPps) -> i32 {
        26 + pps.init_qp_minus26 + self.slice_qp_delta
    }

    /// Offset of the first slice data byte in the escaped NAL unit
    /// (2-byte NAL unit header included).
    pub fn slice_data_byte_offset(&self) -> usize {
        2 + self.header_bytes + self.header_emulation_bytes
    }
}

fn ceil_log2(v: u64) -> u32 {
    if v <= 1 {
        0
    } else {
        64 - (v - 1).leading_zeros()
    }
}

/// `PicSizeInCtbsY` of `sps`, or an error for an out-of-range CTB size.
pub fn pic_size_in_ctbs(sps: &HevcSps) -> Result<u64, BitstreamError> {
    let log2 = u32::from(sps.log2_min_luma_coding_block_size_minus3)
        + 3
        + u32::from(sps.log2_diff_max_min_luma_coding_block_size);
    if !(3..=6).contains(&log2) {
        return Err(BitstreamError::invalid(format!("CtbLog2SizeY={log2}")));
    }
    let ctb = 1u64 << log2;
    let w = u64::from(sps.pic_width_in_luma_samples).div_ceil(ctb);
    let h = u64::from(sps.pic_height_in_luma_samples).div_ceil(ctb);
    Ok(w * h)
}

fn check_end(r: &BitReader<'_>, what: &str) -> Result<(), BitstreamError> {
    if r.bit_pos() > r.total_bits() {
        return Err(BitstreamError::unexpected_end(format!(
            "slice segment header truncated in {what}"
        )));
    }
    Ok(())
}

/// `slice_pic_parameter_set_id` of a slice NAL unit (header included).
pub fn peek_slice_pps_id(nal: &[u8]) -> Result<u8, BitstreamError> {
    if nal.len() < 3 {
        return Err(BitstreamError::unexpected_end("slice NAL unit"));
    }
    let (_, nal_unit_type, _, _) = nal_header(nal[0], nal[1]);
    let rbsp = ebsp_to_rbsp(&nal[2..nal.len().min(16)]);
    let mut r = BitReader::new(&rbsp);
    r.u(1);
    if (16..=23).contains(&nal_unit_type) {
        r.u(1);
    }
    let id = r.ue()?;
    if id > 63 {
        return Err(BitstreamError::invalid("slice_pic_parameter_set_id > 63"));
    }
    Ok(id as u8)
}

/// Parse a complete slice segment header from a whole NAL unit (2-byte
/// header first, emulation prevention bytes in place). `prev` is the
/// preceding independent slice segment header of the same picture; it
/// is required for a dependent slice segment.
pub fn parse_slice_segment_header(
    nal: &[u8],
    sps: &HevcSps,
    pps: &HevcPps,
    prev: Option<&SliceSegmentHeader>,
) -> Result<SliceSegmentHeader, BitstreamError> {
    if nal.len() < 3 {
        return Err(BitstreamError::unexpected_end("slice NAL unit"));
    }
    let (forbidden, nal_unit_type, nuh_layer_id, tid_plus1) = nal_header(nal[0], nal[1]);
    if forbidden != 0 || tid_plus1 == 0 {
        return Err(BitstreamError::invalid("HEVC NAL unit header"));
    }
    if nal_unit_type > 21 || matches!(nal_unit_type, 10..=15) {
        return Err(BitstreamError::invalid(format!(
            "nal_unit_type {nal_unit_type} is not a coded slice"
        )));
    }
    if sps.sps_scc_extension_flag || sps.sps_multilayer_extension_flag || sps.sps_3d_extension_flag
    {
        return Err(BitstreamError::unsupported(
            "slice headers of SCC / multilayer / 3D sequences",
        ));
    }
    if pps.pps_scc_extension_flag || pps.pps_multilayer_extension_flag || pps.pps_3d_extension_flag
    {
        return Err(BitstreamError::unsupported(
            "slice headers with SCC / multilayer / 3D picture parameter sets",
        ));
    }
    let escaped = &nal[2..];
    let rbsp = ebsp_to_rbsp(escaped);
    let mut r = BitReader::new(&rbsp);
    let mut h = SliceSegmentHeader {
        nal_unit_type,
        nuh_layer_id,
        temporal_id: tid_plus1 - 1,
        first_slice_segment_in_pic_flag: r.u(1) != 0,
        pic_output_flag: true,
        collocated_from_l0_flag: true,
        ..SliceSegmentHeader::default()
    };
    if (16..=23).contains(&nal_unit_type) {
        h.no_output_of_prior_pics_flag = r.u(1) != 0;
    }
    let pps_id = r.ue()?;
    if pps_id > 63 || pps_id as u8 != pps.pps_pic_parameter_set_id {
        return Err(BitstreamError::invalid(format!(
            "slice_pic_parameter_set_id {pps_id} against PPS {}",
            pps.pps_pic_parameter_set_id
        )));
    }
    h.slice_pic_parameter_set_id = pps_id as u8;
    if !h.first_slice_segment_in_pic_flag {
        if pps.dependent_slice_segments_enabled_flag {
            h.dependent_slice_segment_flag = r.u(1) != 0;
        }
        let ctbs = pic_size_in_ctbs(sps)?;
        h.slice_segment_address = r.u(ceil_log2(ctbs));
        if u64::from(h.slice_segment_address) >= ctbs {
            return Err(BitstreamError::invalid(
                "slice_segment_address beyond the picture",
            ));
        }
    }
    let chroma_array_type = if sps.separate_colour_plane_flag {
        0
    } else {
        sps.chroma_format_idc
    };
    if h.dependent_slice_segment_flag {
        let p = prev.ok_or_else(|| {
            BitstreamError::invalid("dependent slice segment without an independent one")
        })?;
        // §7.4.7.1: the fields are inferred from the independent segment.
        let keep = (
            h.nal_unit_type,
            h.nuh_layer_id,
            h.temporal_id,
            h.first_slice_segment_in_pic_flag,
            h.no_output_of_prior_pics_flag,
            h.slice_segment_address,
        );
        h = SliceSegmentHeader {
            dependent_slice_segment_flag: true,
            num_entry_point_offsets: 0,
            offset_len_minus1: 0,
            entry_point_offset_minus1: Vec::new(),
            slice_segment_header_extension_length: 0,
            st_rps_bits: p.st_rps_bits,
            ..p.clone()
        };
        (
            h.nal_unit_type,
            h.nuh_layer_id,
            h.temporal_id,
            h.first_slice_segment_in_pic_flag,
            h.no_output_of_prior_pics_flag,
            h.slice_segment_address,
        ) = keep;
    } else {
        parse_independent(&mut r, &mut h, sps, pps, chroma_array_type)?;
    }
    if pps.tiles.is_some() || pps.entropy_coding_sync_enabled_flag {
        h.num_entry_point_offsets = r.ue()?;
        // §7.4.7.1 bounds: at most one per CTB.
        let max = pic_size_in_ctbs(sps)?;
        if u64::from(h.num_entry_point_offsets) > max {
            return Err(BitstreamError::invalid(
                "num_entry_point_offsets beyond the CTB count",
            ));
        }
        if h.num_entry_point_offsets > 0 {
            h.offset_len_minus1 = r.ue()?;
            if h.offset_len_minus1 > 31 {
                return Err(BitstreamError::invalid("offset_len_minus1 > 31"));
            }
            for _ in 0..h.num_entry_point_offsets {
                h.entry_point_offset_minus1
                    .push(r.u(h.offset_len_minus1 + 1));
                check_end(&r, "entry points")?;
            }
        }
    }
    if pps.slice_segment_header_extension_present_flag {
        h.slice_segment_header_extension_length = r.ue()?;
        if h.slice_segment_header_extension_length > 256 {
            return Err(BitstreamError::invalid(
                "slice_segment_header_extension_length > 256",
            ));
        }
        r.skip(8 * h.slice_segment_header_extension_length as usize);
    }
    // byte_alignment(): alignment_bit_equal_to_one then zeros.
    if r.u(1) != 1 {
        return Err(BitstreamError::invalid(
            "byte_alignment() without its one bit",
        ));
    }
    r.align_to_byte();
    check_end(&r, "byte_alignment")?;
    h.header_bytes = r.bit_pos() / 8;
    h.header_emulation_bytes =
        crate::nal::emulation_prevention_bytes_before(escaped, h.header_bytes);
    Ok(h)
}

fn parse_independent(
    r: &mut BitReader<'_>,
    h: &mut SliceSegmentHeader,
    sps: &HevcSps,
    pps: &HevcPps,
    chroma_array_type: u8,
) -> Result<(), BitstreamError> {
    for i in 0..u32::from(pps.num_extra_slice_header_bits) {
        h.slice_reserved_flags |= r.u(1) << i;
    }
    h.slice_type = HevcSliceType::from_raw(r.ue()?)?;
    if h.is_irap() && h.nuh_layer_id == 0 && h.slice_type != HevcSliceType::I {
        return Err(BitstreamError::invalid("IRAP slice that is not an I slice"));
    }
    if pps.output_flag_present_flag {
        h.pic_output_flag = r.u(1) != 0;
    }
    if sps.separate_colour_plane_flag {
        h.colour_plane_id = r.u(2) as u8;
    }
    if !h.is_idr() {
        h.slice_pic_order_cnt_lsb = r.u(u32::from(sps.log2_max_pic_order_cnt_lsb_minus4) + 4);
        h.short_term_ref_pic_set_sps_flag = r.u(1) != 0;
        let num_sets = sps.short_term_rps.len();
        if !h.short_term_ref_pic_set_sps_flag {
            let start = r.bit_pos();
            // st_ref_pic_set( num_short_term_ref_pic_sets ).
            let inter = num_sets != 0 && r.u(1) != 0;
            let ref_rps = if inter {
                h.delta_idx_minus1 = r.ue()?;
                let back = h.delta_idx_minus1 as usize + 1;
                if back > num_sets {
                    return Err(BitstreamError::invalid(
                        "delta_idx_minus1 beyond the SPS sets",
                    ));
                }
                Some(&sps.short_term_rps[num_sets - back])
            } else {
                None
            };
            h.short_term_rps =
                parse_st_ref_pic_set_body(r, ref_rps, sps.sps_max_dec_pic_buffering_minus1)?;
            h.st_rps_bits = (r.bit_pos() - start) as u32;
        } else {
            if num_sets == 0 {
                return Err(BitstreamError::invalid(
                    "short_term_ref_pic_set_sps_flag with no SPS sets",
                ));
            }
            if num_sets > 1 {
                h.short_term_ref_pic_set_idx = r.u(ceil_log2(num_sets as u64));
            }
            h.short_term_rps = sps
                .short_term_rps
                .get(h.short_term_ref_pic_set_idx as usize)
                .cloned()
                .ok_or_else(|| BitstreamError::invalid("short_term_ref_pic_set_idx"))?;
        }
        if sps.long_term_ref_pics_present_flag {
            let num_lt_sps = sps.long_term_ref_pics.len() as u32;
            if num_lt_sps > 0 {
                h.num_long_term_sps = r.ue()?;
                if h.num_long_term_sps > num_lt_sps {
                    return Err(BitstreamError::invalid("num_long_term_sps"));
                }
            }
            h.num_long_term_pics = r.ue()?;
            if h.num_long_term_sps + h.num_long_term_pics > 32 {
                return Err(BitstreamError::invalid("too many long-term pictures"));
            }
            let poc_bits = u32::from(sps.log2_max_pic_order_cnt_lsb_minus4) + 4;
            let mut acc = 0u32;
            for i in 0..h.num_long_term_sps + h.num_long_term_pics {
                let mut lt = LongTermRef::default();
                if i < h.num_long_term_sps {
                    let idx = if num_lt_sps > 1 {
                        r.u(ceil_log2(u64::from(num_lt_sps)))
                    } else {
                        0
                    };
                    let (lsb, used) = *sps
                        .long_term_ref_pics
                        .get(idx as usize)
                        .ok_or_else(|| BitstreamError::invalid("lt_idx_sps"))?;
                    lt.lt_idx_sps = Some(idx);
                    lt.poc_lsb_lt = lsb;
                    lt.used_by_curr_pic_lt = used;
                } else {
                    lt.poc_lsb_lt = r.u(poc_bits);
                    lt.used_by_curr_pic_lt = r.u(1) != 0;
                }
                lt.delta_poc_msb_present_flag = r.u(1) != 0;
                if lt.delta_poc_msb_present_flag {
                    lt.delta_poc_msb_cycle_lt = r.ue()?;
                }
                // eq. 7-52
                acc = if i == 0 || i == h.num_long_term_sps {
                    lt.delta_poc_msb_cycle_lt
                } else {
                    acc.checked_add(lt.delta_poc_msb_cycle_lt)
                        .ok_or_else(|| BitstreamError::invalid("DeltaPocMsbCycleLt overflow"))?
                };
                lt.delta_poc_msb_cycle_lt_acc = acc;
                h.long_term_refs.push(lt);
                check_end(r, "long-term pictures")?;
            }
        }
        if sps.sps_temporal_mvp_enabled_flag {
            h.slice_temporal_mvp_enabled_flag = r.u(1) != 0;
        }
    }
    if sps.sample_adaptive_offset_enabled_flag {
        h.slice_sao_luma_flag = r.u(1) != 0;
        if chroma_array_type != 0 {
            h.slice_sao_chroma_flag = r.u(1) != 0;
        }
    }
    let is_b = h.slice_type == HevcSliceType::B;
    if h.slice_type.is_inter() {
        h.num_ref_idx_l0_active_minus1 = u32::from(pps.num_ref_idx_l0_default_active_minus1);
        if is_b {
            h.num_ref_idx_l1_active_minus1 = u32::from(pps.num_ref_idx_l1_default_active_minus1);
        }
        h.num_ref_idx_active_override_flag = r.u(1) != 0;
        if h.num_ref_idx_active_override_flag {
            h.num_ref_idx_l0_active_minus1 = r.ue()?;
            if is_b {
                h.num_ref_idx_l1_active_minus1 = r.ue()?;
            }
        }
        if h.num_ref_idx_l0_active_minus1 > 14 || h.num_ref_idx_l1_active_minus1 > 14 {
            return Err(BitstreamError::invalid("num_ref_idx_active_minus1 > 14"));
        }
        let total = h.num_pic_total_curr();
        if pps.lists_modification_present_flag && total > 1 {
            let bits = ceil_log2(u64::from(total));
            let m = &mut h.ref_pic_lists_modification;
            m.ref_pic_list_modification_flag_l0 = r.u(1) != 0;
            if m.ref_pic_list_modification_flag_l0 {
                for _ in 0..=h.num_ref_idx_l0_active_minus1 {
                    m.list_entry_l0.push(r.u(bits));
                }
            }
            if is_b {
                m.ref_pic_list_modification_flag_l1 = r.u(1) != 0;
                if m.ref_pic_list_modification_flag_l1 {
                    for _ in 0..=h.num_ref_idx_l1_active_minus1 {
                        m.list_entry_l1.push(r.u(bits));
                    }
                }
            }
            if m.list_entry_l0
                .iter()
                .chain(&m.list_entry_l1)
                .any(|&e| e >= total)
            {
                return Err(BitstreamError::invalid("list_entry beyond NumPicTotalCurr"));
            }
        }
        if is_b {
            h.mvd_l1_zero_flag = r.u(1) != 0;
        }
        if pps.cabac_init_present_flag {
            h.cabac_init_flag = r.u(1) != 0;
        }
        if h.slice_temporal_mvp_enabled_flag {
            if is_b {
                h.collocated_from_l0_flag = r.u(1) != 0;
            }
            if (h.collocated_from_l0_flag && h.num_ref_idx_l0_active_minus1 > 0)
                || (!h.collocated_from_l0_flag && h.num_ref_idx_l1_active_minus1 > 0)
            {
                h.collocated_ref_idx = r.ue()?;
                let max = if h.collocated_from_l0_flag {
                    h.num_ref_idx_l0_active_minus1
                } else {
                    h.num_ref_idx_l1_active_minus1
                };
                if h.collocated_ref_idx > max {
                    return Err(BitstreamError::invalid(
                        "collocated_ref_idx beyond the list",
                    ));
                }
            }
        }
        if (pps.weighted_pred_flag && h.slice_type == HevcSliceType::P)
            || (pps.weighted_bipred_flag && is_b)
        {
            h.pred_weight_table = Some(parse_pred_weight_table(r, h, sps, chroma_array_type)?);
        }
        h.five_minus_max_num_merge_cand = r.ue()?;
        if h.five_minus_max_num_merge_cand > 4 {
            return Err(BitstreamError::invalid("five_minus_max_num_merge_cand > 4"));
        }
    }
    h.slice_qp_delta = r.se()?;
    let qp_bd = 6 * i32::from(sps.bit_depth_luma_minus8);
    let qp = h.slice_qp_y(pps);
    if !(-qp_bd..=51).contains(&qp) {
        return Err(BitstreamError::invalid(format!("SliceQpY={qp}")));
    }
    if pps.pps_slice_chroma_qp_offsets_present_flag {
        h.slice_cb_qp_offset = r.se()?;
        h.slice_cr_qp_offset = r.se()?;
        if !(-12..=12).contains(&h.slice_cb_qp_offset)
            || !(-12..=12).contains(&h.slice_cr_qp_offset)
        {
            return Err(BitstreamError::invalid(
                "slice chroma QP offsets outside -12..=12",
            ));
        }
    }
    if pps
        .range_extension
        .as_ref()
        .is_some_and(|e| e.chroma_qp_offset_list_enabled_flag)
    {
        h.cu_chroma_qp_offset_enabled_flag = r.u(1) != 0;
    }
    if pps.deblocking_filter_override_enabled_flag {
        h.deblocking_filter_override_flag = r.u(1) != 0;
    }
    h.slice_deblocking_filter_disabled_flag = pps.pps_deblocking_filter_disabled_flag;
    h.slice_beta_offset_div2 = pps.pps_beta_offset_div2;
    h.slice_tc_offset_div2 = pps.pps_tc_offset_div2;
    if h.deblocking_filter_override_flag {
        h.slice_deblocking_filter_disabled_flag = r.u(1) != 0;
        if !h.slice_deblocking_filter_disabled_flag {
            h.slice_beta_offset_div2 = r.se()?;
            h.slice_tc_offset_div2 = r.se()?;
            if !(-6..=6).contains(&h.slice_beta_offset_div2)
                || !(-6..=6).contains(&h.slice_tc_offset_div2)
            {
                return Err(BitstreamError::invalid(
                    "slice deblocking offsets outside -6..=6",
                ));
            }
        }
    }
    h.slice_loop_filter_across_slices_enabled_flag = pps.pps_loop_filter_across_slices_enabled_flag;
    if pps.pps_loop_filter_across_slices_enabled_flag
        && (h.slice_sao_luma_flag
            || h.slice_sao_chroma_flag
            || !h.slice_deblocking_filter_disabled_flag)
    {
        h.slice_loop_filter_across_slices_enabled_flag = r.u(1) != 0;
    }
    check_end(r, "slice header body")
}

fn parse_pred_weight_table(
    r: &mut BitReader<'_>,
    h: &SliceSegmentHeader,
    sps: &HevcSps,
    chroma_array_type: u8,
) -> Result<HevcPredWeightTable, BitstreamError> {
    let mut t = HevcPredWeightTable {
        luma_log2_weight_denom: r.ue()?,
        ..HevcPredWeightTable::default()
    };
    if t.luma_log2_weight_denom > 7 {
        return Err(BitstreamError::invalid("luma_log2_weight_denom > 7"));
    }
    let chroma = chroma_array_type != 0;
    if chroma {
        t.delta_chroma_log2_weight_denom = r.se()?;
        let c = t.luma_log2_weight_denom as i32 + t.delta_chroma_log2_weight_denom;
        if !(0..=7).contains(&c) {
            return Err(BitstreamError::invalid(
                "ChromaLog2WeightDenom outside 0..=7",
            ));
        }
        t.chroma_log2_weight_denom = c as u32;
    }
    let high_precision = sps
        .range_extension
        .is_some_and(|e| e.high_precision_offsets_enabled_flag);
    // WpOffsetHalfRangeC (eq. 7-31 family).
    let half_c: i32 = if high_precision {
        1 << (sps.bit_depth_chroma_minus8 + 7)
    } else {
        1 << 7
    };
    let half_y: i32 = if high_precision {
        1 << (sps.bit_depth_luma_minus8 + 7)
    } else {
        1 << 7
    };
    let lists = if h.slice_type == HevcSliceType::B {
        2
    } else {
        1
    };
    for x in 0..lists {
        let n = if x == 0 {
            h.num_ref_idx_l0_active_minus1
        } else {
            h.num_ref_idx_l1_active_minus1
        } as usize
            + 1;
        // Single-layer, non-SCC: no reference shares the current POC, so
        // every flag is present.
        let mut w = vec![HevcPredWeight::default(); n];
        for e in w.iter_mut() {
            e.luma_weight_flag = r.u(1) != 0;
        }
        if chroma {
            for e in w.iter_mut() {
                e.chroma_weight_flag = r.u(1) != 0;
            }
        }
        for e in w.iter_mut() {
            e.luma_weight = 1 << t.luma_log2_weight_denom;
            e.chroma_weight = [1 << t.chroma_log2_weight_denom; 2];
            if e.luma_weight_flag {
                e.delta_luma_weight = r.se()?;
                e.luma_offset = r.se()?;
                if !(-128..=127).contains(&e.delta_luma_weight)
                    || !(-half_y..half_y).contains(&e.luma_offset)
                {
                    return Err(BitstreamError::invalid("luma weight / offset out of range"));
                }
                e.luma_weight += e.delta_luma_weight;
            }
            if e.chroma_weight_flag {
                for j in 0..2 {
                    e.delta_chroma_weight[j] = r.se()?;
                    e.delta_chroma_offset[j] = r.se()?;
                    if !(-128..=127).contains(&e.delta_chroma_weight[j])
                        || !(-4 * half_c..4 * half_c).contains(&e.delta_chroma_offset[j])
                    {
                        return Err(BitstreamError::invalid(
                            "chroma weight / offset out of range",
                        ));
                    }
                    e.chroma_weight[j] += e.delta_chroma_weight[j];
                    // eq. 7-56
                    e.chroma_offset[j] = (half_c
                        - ((half_c * e.chroma_weight[j]) >> t.chroma_log2_weight_denom)
                        + e.delta_chroma_offset[j])
                        .clamp(-half_c, half_c - 1);
                }
            }
            check_end(r, "pred_weight_table")?;
        }
        if x == 0 {
            t.l0 = w;
        } else {
            t.l1 = w;
        }
    }
    Ok(t)
}
