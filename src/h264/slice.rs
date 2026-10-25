//! H.264 complete slice header (§7.3.3) for every slice type.
//!
//! [`parse_slice_header`] walks `slice_header()` to its last syntax
//! element for I, P, B, SP and SI slices — including
//! `ref_pic_list_modification()` (§7.3.3.1), `pred_weight_table()`
//! (§7.3.3.2) and `dec_ref_pic_marking()` (§7.3.3.3) — given the active
//! SPS and PPS, and records where `slice_data()` begins so a hardware
//! bridge can point the decoder at it.
//!
//! The parser enforces the §7.4.3 value ranges that bound later
//! processing (list sizes, weight denominators, MMCO / modification
//! opcodes, deblocking offsets) so hostile counts cannot drive
//! unbounded loops.

use super::{H264Pps, H264Sps, NAL_TYPE_IDR, ebsp_to_rbsp, nal_header};
use crate::BitstreamError;
use crate::bit_reader::BitReader;

/// `slice_type % 5` (§7.4.3 Table 7-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SliceType {
    P,
    B,
    #[default]
    I,
    SP,
    SI,
}

impl SliceType {
    /// Map a raw `slice_type` (0..=9) to its class.
    pub fn from_raw(raw: u32) -> Result<Self, BitstreamError> {
        Ok(match raw {
            0 | 5 => SliceType::P,
            1 | 6 => SliceType::B,
            2 | 7 => SliceType::I,
            3 | 8 => SliceType::SP,
            4 | 9 => SliceType::SI,
            _ => {
                return Err(BitstreamError::invalid(format!(
                    "slice_type={raw} (must be 0..=9)"
                )));
            }
        })
    }

    /// The `slice_type % 5` code.
    pub fn code(self) -> u8 {
        match self {
            SliceType::P => 0,
            SliceType::B => 1,
            SliceType::I => 2,
            SliceType::SP => 3,
            SliceType::SI => 4,
        }
    }

    /// P, SP and B slices use RefPicList0.
    pub fn has_list0(self) -> bool {
        matches!(self, SliceType::P | SliceType::SP | SliceType::B)
    }

    /// Only B slices use RefPicList1.
    pub fn has_list1(self) -> bool {
        self == SliceType::B
    }

    /// I and SI slices.
    pub fn is_intra(self) -> bool {
        matches!(self, SliceType::I | SliceType::SI)
    }
}

/// One `modification_of_pic_nums_idc` command (§7.4.3.1 Table 7-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefPicListModificationOp {
    /// idc 0: `abs_diff_pic_num_minus1`, subtracted from the prediction.
    SubtractPicNum(u32),
    /// idc 1: `abs_diff_pic_num_minus1`, added to the prediction.
    AddPicNum(u32),
    /// idc 2: `long_term_pic_num`.
    LongTermPicNum(u32),
}

/// `ref_pic_list_modification()` (§7.3.3.1). An empty list means the
/// flag was 0 (or the list does not exist for this slice type).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct RefPicListModification {
    pub ref_pic_list_modification_flag_l0: bool,
    pub modifications_l0: Vec<RefPicListModificationOp>,
    pub ref_pic_list_modification_flag_l1: bool,
    pub modifications_l1: Vec<RefPicListModificationOp>,
}

/// One list entry of `pred_weight_table()` with the §7.4.3.2 inferred
/// defaults applied: when `luma_weight_lX_flag` is 0 the weight is
/// `2^luma_log2_weight_denom` and the offset 0 (chroma likewise).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct PredWeight {
    pub luma_weight_flag: bool,
    pub luma_weight: i32,
    pub luma_offset: i32,
    pub chroma_weight_flag: bool,
    /// `[Cb, Cr]`.
    pub chroma_weight: [i32; 2],
    /// `[Cb, Cr]`.
    pub chroma_offset: [i32; 2],
}

/// `pred_weight_table()` (§7.3.3.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct PredWeightTable {
    pub luma_log2_weight_denom: u32,
    /// 0 when `ChromaArrayType == 0` (not coded).
    pub chroma_log2_weight_denom: u32,
    /// `num_ref_idx_l0_active_minus1 + 1` entries.
    pub l0: Vec<PredWeight>,
    /// `num_ref_idx_l1_active_minus1 + 1` entries for B slices, else empty.
    pub l1: Vec<PredWeight>,
}

/// One `memory_management_control_operation` (§7.4.3.3 Table 7-9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MmcoOp {
    /// 1: `difference_of_pic_nums_minus1`.
    MarkShortTermUnused { difference_of_pic_nums_minus1: u32 },
    /// 2: `long_term_pic_num`.
    MarkLongTermUnused { long_term_pic_num: u32 },
    /// 3: short-term picture becomes long-term.
    AssignLongTerm {
        difference_of_pic_nums_minus1: u32,
        long_term_frame_idx: u32,
    },
    /// 4: `max_long_term_frame_idx_plus1`.
    SetMaxLongTermFrameIdx { max_long_term_frame_idx_plus1: u32 },
    /// 5: every reference picture becomes unused.
    MarkAllUnused,
    /// 6: the current picture becomes long-term.
    AssignCurrentLongTerm { long_term_frame_idx: u32 },
}

impl MmcoOp {
    /// The `memory_management_control_operation` code.
    pub fn code(self) -> u32 {
        match self {
            MmcoOp::MarkShortTermUnused { .. } => 1,
            MmcoOp::MarkLongTermUnused { .. } => 2,
            MmcoOp::AssignLongTerm { .. } => 3,
            MmcoOp::SetMaxLongTermFrameIdx { .. } => 4,
            MmcoOp::MarkAllUnused => 5,
            MmcoOp::AssignCurrentLongTerm { .. } => 6,
        }
    }
}

/// `dec_ref_pic_marking()` (§7.3.3.3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct DecRefPicMarking {
    /// IDR only.
    pub no_output_of_prior_pics_flag: bool,
    /// IDR only.
    pub long_term_reference_flag: bool,
    /// Non-IDR only.
    pub adaptive_ref_pic_marking_mode_flag: bool,
    /// The commands in bitstream order (the terminating 0 excluded).
    pub mmco: Vec<MmcoOp>,
}

impl DecRefPicMarking {
    /// True when the commands include `memory_management_control_operation` 5.
    pub fn has_mmco5(&self) -> bool {
        self.mmco
            .iter()
            .any(|op| matches!(op, MmcoOp::MarkAllUnused))
    }
}

/// Every field of `slice_header()` (§7.3.3), with the §7.4.3 inferred
/// values filled in for absent elements.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct SliceHeader {
    /// `nal_unit_type` of the carrying NAL unit (1 or 5).
    pub nal_unit_type: u8,
    /// `nal_ref_idc` of the carrying NAL unit.
    pub nal_ref_idc: u8,
    pub first_mb_in_slice: u32,
    /// Raw `slice_type` (0..=9).
    pub slice_type_raw: u32,
    pub slice_type: SliceType,
    pub pic_parameter_set_id: u8,
    pub colour_plane_id: u8,
    pub frame_num: u32,
    pub field_pic_flag: bool,
    pub bottom_field_flag: bool,
    /// 0 for non-IDR slices.
    pub idr_pic_id: u32,
    pub pic_order_cnt_lsb: u32,
    pub delta_pic_order_cnt_bottom: i32,
    pub delta_pic_order_cnt: [i32; 2],
    pub redundant_pic_cnt: u32,
    pub direct_spatial_mv_pred_flag: bool,
    pub num_ref_idx_active_override_flag: bool,
    /// The value in force (PPS default unless overridden). 0 for I/SI.
    pub num_ref_idx_l0_active_minus1: u32,
    /// The value in force for B slices; 0 otherwise.
    pub num_ref_idx_l1_active_minus1: u32,
    pub ref_pic_list_modification: RefPicListModification,
    /// `Some` when the slice codes explicit weights (§7.3.3).
    pub pred_weight_table: Option<PredWeightTable>,
    /// `Some` when `nal_ref_idc != 0`.
    pub dec_ref_pic_marking: Option<DecRefPicMarking>,
    pub cabac_init_idc: u32,
    pub slice_qp_delta: i32,
    pub sp_for_switch_flag: bool,
    pub slice_qs_delta: i32,
    pub disable_deblocking_filter_idc: u32,
    pub slice_alpha_c0_offset_div2: i32,
    pub slice_beta_offset_div2: i32,
    pub slice_group_change_cycle: u32,
    /// RBSP bits of `slice_header()` (after the one-byte NAL unit
    /// header): `slice_data()` starts at this bit of the RBSP.
    pub header_bits: usize,
}

impl SliceHeader {
    /// `IdrPicFlag`.
    pub fn is_idr(&self) -> bool {
        self.nal_unit_type == NAL_TYPE_IDR
    }

    /// `MbaffFrameFlag` (eq. 7-27).
    pub fn mbaff_frame_flag(&self, sps: &H264Sps) -> bool {
        sps.mb_adaptive_frame_field_flag && !self.field_pic_flag
    }

    /// `SliceQPY` (eq. 7-30).
    pub fn slice_qp_y(&self, pps: &H264Pps) -> i32 {
        26 + pps.pic_init_qp_minus26 + self.slice_qp_delta
    }

    /// `CurrPicNum` (§7.4.3): `frame_num` for frames, `2 * frame_num + 1`
    /// for fields.
    pub fn curr_pic_num(&self) -> u32 {
        if self.field_pic_flag {
            2 * self.frame_num + 1
        } else {
            self.frame_num
        }
    }

    /// `MaxPicNum` (§7.4.3).
    pub fn max_pic_num(&self, sps: &H264Sps) -> u32 {
        sps.max_frame_num() << u32::from(self.field_pic_flag)
    }

    /// True when the slice codes `memory_management_control_operation` 5.
    pub fn has_mmco5(&self) -> bool {
        self.dec_ref_pic_marking
            .as_ref()
            .is_some_and(DecRefPicMarking::has_mmco5)
    }

    /// Bit offset of `slice_data()` inside the escaped NAL unit `nal`
    /// (NAL header byte included, emulation prevention bytes counted),
    /// the form hardware slice-parameter buffers address.
    pub fn slice_data_bit_offset_in_nal(&self, nal: &[u8]) -> usize {
        let body = nal.get(1..).unwrap_or(&[]);
        let byte = self.header_bits / 8;
        8 + 8 * crate::nal::rbsp_offset_to_ebsp(body, byte) + self.header_bits % 8
    }
}

fn check_end(r: &BitReader<'_>, what: &str) -> Result<(), BitstreamError> {
    if r.bit_pos() > r.total_bits() {
        return Err(BitstreamError::unexpected_end(format!(
            "slice header truncated in {what}"
        )));
    }
    Ok(())
}

/// Parse a complete `slice_header()` from the RBSP that follows the NAL
/// unit header byte. `nal_unit_type` / `nal_ref_idc` come from that
/// header byte (§7.3.1). Slice data partitions (types 2..=4) and the
/// MVC / 3D extension slices are not slice headers of this form.
pub fn parse_slice_header(
    rbsp: &[u8],
    nal_unit_type: u8,
    nal_ref_idc: u8,
    sps: &H264Sps,
    pps: &H264Pps,
) -> Result<SliceHeader, BitstreamError> {
    if !matches!(nal_unit_type, 1 | NAL_TYPE_IDR) {
        return Err(BitstreamError::unsupported(format!(
            "slice header in nal_unit_type {nal_unit_type} (only 1 and 5)"
        )));
    }
    let idr = nal_unit_type == NAL_TYPE_IDR;
    if idr && nal_ref_idc == 0 {
        return Err(BitstreamError::invalid("IDR slice with nal_ref_idc 0"));
    }
    let mut r = BitReader::new(rbsp);
    let mut h = SliceHeader {
        nal_unit_type,
        nal_ref_idc,
        first_mb_in_slice: r.ue()?,
        ..SliceHeader::default()
    };
    h.slice_type_raw = r.ue()?;
    h.slice_type = SliceType::from_raw(h.slice_type_raw)?;
    if idr && !h.slice_type.is_intra() {
        return Err(BitstreamError::invalid(format!(
            "IDR slice of slice_type {}",
            h.slice_type_raw
        )));
    }
    let pps_id = r.ue()?;
    if pps_id > 255 {
        return Err(BitstreamError::invalid(format!(
            "pic_parameter_set_id={pps_id} (must be 0..=255)"
        )));
    }
    h.pic_parameter_set_id = pps_id as u8;
    if pps_id as u8 != pps.pic_parameter_set_id {
        return Err(BitstreamError::invalid(format!(
            "slice refers to PPS {pps_id}, parsed against PPS {}",
            pps.pic_parameter_set_id
        )));
    }
    if sps.separate_colour_plane_flag {
        h.colour_plane_id = r.u(2) as u8;
        if h.colour_plane_id > 2 {
            return Err(BitstreamError::invalid("colour_plane_id=3"));
        }
    }
    h.frame_num = r.u(u32::from(sps.log2_max_frame_num_minus4) + 4);
    if !sps.frame_mbs_only_flag {
        h.field_pic_flag = r.u(1) != 0;
        if h.field_pic_flag {
            h.bottom_field_flag = r.u(1) != 0;
        }
    }
    let pic_height_in_mbs = u64::from(sps.frame_height_in_mbs()) >> u32::from(h.field_pic_flag);
    let pic_size_in_mbs = u64::from(sps.pic_width_in_mbs()) * pic_height_in_mbs;
    let units = if h.mbaff_frame_flag(sps) {
        pic_size_in_mbs / 2
    } else {
        pic_size_in_mbs
    };
    if u64::from(h.first_mb_in_slice) >= units.max(1) {
        return Err(BitstreamError::invalid(format!(
            "first_mb_in_slice={} (picture has {units} slice units)",
            h.first_mb_in_slice
        )));
    }
    if idr {
        h.idr_pic_id = r.ue()?;
        if h.idr_pic_id > 65535 {
            return Err(BitstreamError::invalid("idr_pic_id > 65535"));
        }
    }
    if sps.pic_order_cnt_type == 0 {
        h.pic_order_cnt_lsb = r.u(u32::from(sps.log2_max_pic_order_cnt_lsb_minus4) + 4);
        if pps.bottom_field_pic_order_in_frame_present_flag && !h.field_pic_flag {
            h.delta_pic_order_cnt_bottom = r.se()?;
        }
    }
    if sps.pic_order_cnt_type == 1 && !sps.delta_pic_order_always_zero_flag {
        h.delta_pic_order_cnt[0] = r.se()?;
        if pps.bottom_field_pic_order_in_frame_present_flag && !h.field_pic_flag {
            h.delta_pic_order_cnt[1] = r.se()?;
        }
    }
    if pps.redundant_pic_cnt_present_flag {
        h.redundant_pic_cnt = r.ue()?;
        if h.redundant_pic_cnt > 127 {
            return Err(BitstreamError::invalid("redundant_pic_cnt > 127"));
        }
    }
    if h.slice_type == SliceType::B {
        h.direct_spatial_mv_pred_flag = r.u(1) != 0;
    }
    if h.slice_type.has_list0() {
        h.num_ref_idx_l0_active_minus1 = u32::from(pps.num_ref_idx_l0_default_active_minus1);
        if h.slice_type.has_list1() {
            h.num_ref_idx_l1_active_minus1 = u32::from(pps.num_ref_idx_l1_default_active_minus1);
        }
        h.num_ref_idx_active_override_flag = r.u(1) != 0;
        if h.num_ref_idx_active_override_flag {
            h.num_ref_idx_l0_active_minus1 = r.ue()?;
            if h.slice_type.has_list1() {
                h.num_ref_idx_l1_active_minus1 = r.ue()?;
            }
        }
        // §7.4.3: 0..=31 for frames, 0..=63 for fields.
        let max = if h.field_pic_flag { 63 } else { 31 };
        if h.num_ref_idx_l0_active_minus1 > max || h.num_ref_idx_l1_active_minus1 > max {
            return Err(BitstreamError::invalid(format!(
                "num_ref_idx_active_minus1 ({}, {}) above {max}",
                h.num_ref_idx_l0_active_minus1, h.num_ref_idx_l1_active_minus1
            )));
        }
    }
    check_end(&r, "list sizes")?;
    // nal_unit_type 20 / 21 carry ref_pic_list_mvc_modification(); only
    // 1 and 5 reach here.
    if h.slice_type.has_list0() {
        h.ref_pic_list_modification
            .ref_pic_list_modification_flag_l0 = r.u(1) != 0;
        if h.ref_pic_list_modification
            .ref_pic_list_modification_flag_l0
        {
            h.ref_pic_list_modification.modifications_l0 = parse_modifications(&mut r)?;
        }
    }
    if h.slice_type.has_list1() {
        h.ref_pic_list_modification
            .ref_pic_list_modification_flag_l1 = r.u(1) != 0;
        if h.ref_pic_list_modification
            .ref_pic_list_modification_flag_l1
        {
            h.ref_pic_list_modification.modifications_l1 = parse_modifications(&mut r)?;
        }
    }
    let weighted = (pps.weighted_pred_flag && matches!(h.slice_type, SliceType::P | SliceType::SP))
        || (pps.weighted_bipred_idc == 1 && h.slice_type == SliceType::B);
    if weighted {
        h.pred_weight_table = Some(parse_pred_weight_table(&mut r, &h, sps)?);
    }
    if nal_ref_idc != 0 {
        h.dec_ref_pic_marking = Some(parse_dec_ref_pic_marking(&mut r, idr)?);
    }
    if pps.entropy_coding_mode_flag && !h.slice_type.is_intra() {
        h.cabac_init_idc = r.ue()?;
        if h.cabac_init_idc > 2 {
            return Err(BitstreamError::invalid("cabac_init_idc > 2"));
        }
    }
    h.slice_qp_delta = r.se()?;
    let qp = h.slice_qp_y(pps);
    let qp_min = -6 * i32::from(sps.bit_depth_luma_minus8);
    if !(qp_min..=51).contains(&qp) {
        return Err(BitstreamError::invalid(format!(
            "SliceQPY={qp} outside {qp_min}..=51"
        )));
    }
    if matches!(h.slice_type, SliceType::SP | SliceType::SI) {
        if h.slice_type == SliceType::SP {
            h.sp_for_switch_flag = r.u(1) != 0;
        }
        h.slice_qs_delta = r.se()?;
    }
    if pps.deblocking_filter_control_present_flag {
        h.disable_deblocking_filter_idc = r.ue()?;
        if h.disable_deblocking_filter_idc > 2 {
            return Err(BitstreamError::invalid("disable_deblocking_filter_idc > 2"));
        }
        if h.disable_deblocking_filter_idc != 1 {
            h.slice_alpha_c0_offset_div2 = r.se()?;
            h.slice_beta_offset_div2 = r.se()?;
            if !(-6..=6).contains(&h.slice_alpha_c0_offset_div2)
                || !(-6..=6).contains(&h.slice_beta_offset_div2)
            {
                return Err(BitstreamError::invalid(
                    "slice deblocking offsets outside -6..=6",
                ));
            }
        }
    }
    // num_slice_groups_minus1 > 0 is refused by the PPS parser, so the
    // slice_group_change_cycle element is never present here.
    h.header_bits = r.bit_pos();
    check_end(&r, "slice header tail")?;
    Ok(h)
}

/// Parse a slice header from a whole NAL unit (header byte at index 0,
/// emulation prevention bytes in place).
pub fn parse_slice_header_nal(
    nal: &[u8],
    sps: &H264Sps,
    pps: &H264Pps,
) -> Result<SliceHeader, BitstreamError> {
    let first = *nal
        .first()
        .ok_or_else(|| BitstreamError::unexpected_end("empty slice NAL"))?;
    let (_, nal_ref_idc, nal_unit_type) = nal_header(first);
    let rbsp = ebsp_to_rbsp(&nal[1..]);
    parse_slice_header(&rbsp, nal_unit_type, nal_ref_idc, sps, pps)
}

/// `pic_parameter_set_id` of a slice RBSP without the active parameter
/// sets (the third `ue(v)` of §7.3.3).
pub fn peek_slice_pps_id(rbsp: &[u8]) -> Result<u8, BitstreamError> {
    let mut r = BitReader::new(rbsp);
    r.ue()?;
    r.ue()?;
    let id = r.ue()?;
    if id > 255 || r.bit_pos() > r.total_bits() {
        return Err(BitstreamError::invalid("slice pic_parameter_set_id"));
    }
    Ok(id as u8)
}

/// Bound on modification / MMCO command loops: more commands than list
/// entries (or DPB slots) cannot be conforming.
const MAX_COMMANDS: usize = 66;

fn parse_modifications(
    r: &mut BitReader<'_>,
) -> Result<Vec<RefPicListModificationOp>, BitstreamError> {
    let mut ops = Vec::new();
    loop {
        let idc = r.ue()?;
        let op = match idc {
            0 => RefPicListModificationOp::SubtractPicNum(r.ue()?),
            1 => RefPicListModificationOp::AddPicNum(r.ue()?),
            2 => RefPicListModificationOp::LongTermPicNum(r.ue()?),
            3 => break,
            _ => {
                return Err(BitstreamError::invalid(format!(
                    "modification_of_pic_nums_idc={idc}"
                )));
            }
        };
        ops.push(op);
        if ops.len() > MAX_COMMANDS {
            return Err(BitstreamError::invalid(
                "ref_pic_list_modification command loop does not terminate",
            ));
        }
        check_end(r, "ref_pic_list_modification")?;
    }
    Ok(ops)
}

fn parse_weights(
    r: &mut BitReader<'_>,
    count: u32,
    luma_denom: u32,
    chroma_denom: u32,
    chroma: bool,
) -> Result<Vec<PredWeight>, BitstreamError> {
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut w = PredWeight {
            luma_weight: 1 << luma_denom,
            chroma_weight: [1 << chroma_denom; 2],
            ..PredWeight::default()
        };
        w.luma_weight_flag = r.u(1) != 0;
        if w.luma_weight_flag {
            w.luma_weight = r.se()?;
            w.luma_offset = r.se()?;
            if !(-128..=127).contains(&w.luma_weight) || !(-128..=127).contains(&w.luma_offset) {
                return Err(BitstreamError::invalid(
                    "luma weight/offset outside -128..=127",
                ));
            }
        }
        if chroma {
            w.chroma_weight_flag = r.u(1) != 0;
            if w.chroma_weight_flag {
                for j in 0..2 {
                    w.chroma_weight[j] = r.se()?;
                    w.chroma_offset[j] = r.se()?;
                    if !(-128..=127).contains(&w.chroma_weight[j])
                        || !(-128..=127).contains(&w.chroma_offset[j])
                    {
                        return Err(BitstreamError::invalid(
                            "chroma weight/offset outside -128..=127",
                        ));
                    }
                }
            }
        }
        check_end(r, "pred_weight_table")?;
        out.push(w);
    }
    Ok(out)
}

fn parse_pred_weight_table(
    r: &mut BitReader<'_>,
    h: &SliceHeader,
    sps: &H264Sps,
) -> Result<PredWeightTable, BitstreamError> {
    let chroma = sps.chroma_array_type() != 0;
    let mut t = PredWeightTable {
        luma_log2_weight_denom: r.ue()?,
        ..PredWeightTable::default()
    };
    if chroma {
        t.chroma_log2_weight_denom = r.ue()?;
    }
    if t.luma_log2_weight_denom > 7 || t.chroma_log2_weight_denom > 7 {
        return Err(BitstreamError::invalid("log2_weight_denom > 7"));
    }
    t.l0 = parse_weights(
        r,
        h.num_ref_idx_l0_active_minus1 + 1,
        t.luma_log2_weight_denom,
        t.chroma_log2_weight_denom,
        chroma,
    )?;
    if h.slice_type == SliceType::B {
        t.l1 = parse_weights(
            r,
            h.num_ref_idx_l1_active_minus1 + 1,
            t.luma_log2_weight_denom,
            t.chroma_log2_weight_denom,
            chroma,
        )?;
    }
    Ok(t)
}

fn parse_dec_ref_pic_marking(
    r: &mut BitReader<'_>,
    idr: bool,
) -> Result<DecRefPicMarking, BitstreamError> {
    let mut m = DecRefPicMarking::default();
    if idr {
        m.no_output_of_prior_pics_flag = r.u(1) != 0;
        m.long_term_reference_flag = r.u(1) != 0;
        return Ok(m);
    }
    m.adaptive_ref_pic_marking_mode_flag = r.u(1) != 0;
    if !m.adaptive_ref_pic_marking_mode_flag {
        return Ok(m);
    }
    loop {
        let code = r.ue()?;
        let op = match code {
            0 => break,
            1 => MmcoOp::MarkShortTermUnused {
                difference_of_pic_nums_minus1: r.ue()?,
            },
            2 => MmcoOp::MarkLongTermUnused {
                long_term_pic_num: r.ue()?,
            },
            3 => MmcoOp::AssignLongTerm {
                difference_of_pic_nums_minus1: r.ue()?,
                long_term_frame_idx: r.ue()?,
            },
            4 => MmcoOp::SetMaxLongTermFrameIdx {
                max_long_term_frame_idx_plus1: r.ue()?,
            },
            5 => MmcoOp::MarkAllUnused,
            6 => MmcoOp::AssignCurrentLongTerm {
                long_term_frame_idx: r.ue()?,
            },
            _ => {
                return Err(BitstreamError::invalid(format!(
                    "memory_management_control_operation={code}"
                )));
            }
        };
        m.mmco.push(op);
        if m.mmco.len() > MAX_COMMANDS {
            return Err(BitstreamError::invalid(
                "dec_ref_pic_marking command loop does not terminate",
            ));
        }
        check_end(r, "dec_ref_pic_marking")?;
    }
    Ok(m)
}
