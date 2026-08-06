//! H.266 / VVC shared parameter sub-structures — parse + byte-exact write.
//!
//! These syntax structures are embedded inside the SPS (and, for the
//! DPB / HRD family, also the VPS) rather than carried in their own
//! NAL units:
//!
//! - `dpb_parameters()` (§7.3.4) — per-sublayer decoded-picture-buffer
//!   sizing triples,
//! - `general_timing_hrd_parameters()` (§7.3.5.1) — clock tick +
//!   CPB-schedule scales shared by every OLS HRD,
//! - `ols_timing_hrd_parameters()` (§7.3.5.2) — per-sublayer fixed
//!   picture-rate / low-delay signalling plus the NAL and VCL
//!   `sublayer_hrd_parameters()` (§7.3.5.3) CPB schedule lists,
//! - `ref_pic_list_struct()` (§7.3.10) — short-term / long-term /
//!   inter-layer reference-picture list templates,
//! - the SPS subpicture layout block (§7.3.2.4).
//!
//! Each `parse_*` takes a positioned [`BitReader`] plus the syntax
//! context the spec threads in (loop bounds, presence flags, `u(v)`
//! bit widths); each `write_*` is its byte-exact inverse on the same
//! context. Value-range enforcement follows §7.4 semantics so hostile
//! counts can never drive unbounded loops.
//!
//! # Spec references
//!
//! ITU-T H.266 (V4) (01/2026): §7.3.4 / §7.4.5 (DPB), §7.3.5 / §7.4.6
//! (timing + HRD), §7.3.10 / §7.4.11 (ref pic list struct), §7.3.2.4 /
//! §7.4.3.4 (SPS subpicture block), §6.5.1 (CTB scanning derivations),
//! Table A.2 (`MaxSlicesPerAu` ≤ 1000), §A.4.2 (`MaxDpbSize` ≤ 16).

use crate::bit_reader::BitReader;
use crate::bit_writer::BitWriter;
use crate::BitstreamError;

/// `Ceil(Log2(x))` for `x >= 1`; 0 for `x <= 1`. Bit width of the
/// SPS/PPS `u(v)` fields whose range is `0..x-1`.
pub(crate) fn ceil_log2_u64(x: u64) -> u32 {
    if x <= 1 {
        0
    } else {
        64 - (x - 1).leading_zeros()
    }
}

// ─────────────────────────── dpb_parameters (7.3.4) ──────────────────────────

/// One sublayer's DPB sizing triple (§7.3.4 / §7.4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VvcDpbEntry {
    /// `dpb_max_dec_pic_buffering_minus1[i]` ue(v) — 0..=15
    /// (`MaxDpbSize` caps at 16 per §A.4.2).
    pub dpb_max_dec_pic_buffering_minus1: u32,
    /// `dpb_max_num_reorder_pics[i]` ue(v) — must not exceed
    /// `dpb_max_dec_pic_buffering_minus1[i]`.
    pub dpb_max_num_reorder_pics: u32,
    /// `dpb_max_latency_increase_plus1[i]` ue(v).
    pub dpb_max_latency_increase_plus1: u32,
}

/// `dpb_parameters(MaxSubLayersMinus1, subLayerInfoFlag)` (§7.3.4).
///
/// `entries` holds exactly the walked sublayers: all
/// `MaxSubLayersMinus1 + 1` of them when `subLayerInfoFlag = 1`, only
/// the highest sublayer's triple otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcDpbParameters {
    /// Walked `(buffering, reorder, latency)` triples, lowest walked
    /// sublayer first.
    pub entries: Vec<VvcDpbEntry>,
}

/// Parse a `dpb_parameters()` structure at the reader's position.
pub fn parse_dpb_parameters(
    r: &mut BitReader<'_>,
    max_sublayers_minus1: u32,
    sublayer_info_flag: bool,
) -> Result<VvcDpbParameters, BitstreamError> {
    let first = if sublayer_info_flag {
        0
    } else {
        max_sublayers_minus1
    };
    let mut entries = Vec::with_capacity((max_sublayers_minus1 - first + 1) as usize);
    for _ in first..=max_sublayers_minus1 {
        let dpb_max_dec_pic_buffering_minus1 = r.ue()?;
        if dpb_max_dec_pic_buffering_minus1 > 15 {
            return Err(BitstreamError::invalid(format!(
                "dpb_max_dec_pic_buffering_minus1 = {dpb_max_dec_pic_buffering_minus1} > 15 (MaxDpbSize ≤ 16, A.4.2)"
            )));
        }
        let dpb_max_num_reorder_pics = r.ue()?;
        if dpb_max_num_reorder_pics > dpb_max_dec_pic_buffering_minus1 {
            return Err(BitstreamError::invalid(format!(
                "dpb_max_num_reorder_pics = {dpb_max_num_reorder_pics} > dpb_max_dec_pic_buffering_minus1 = {dpb_max_dec_pic_buffering_minus1}"
            )));
        }
        let dpb_max_latency_increase_plus1 = r.ue()?;
        entries.push(VvcDpbEntry {
            dpb_max_dec_pic_buffering_minus1,
            dpb_max_num_reorder_pics,
            dpb_max_latency_increase_plus1,
        });
    }
    Ok(VvcDpbParameters { entries })
}

/// Emit a `dpb_parameters()` structure — byte-exact inverse of
/// [`parse_dpb_parameters`] on the same context.
pub fn write_dpb_parameters(
    w: &mut BitWriter,
    dpb: &VvcDpbParameters,
    max_sublayers_minus1: u32,
    sublayer_info_flag: bool,
) -> Result<(), BitstreamError> {
    let expected = if sublayer_info_flag {
        max_sublayers_minus1 + 1
    } else {
        1
    };
    if dpb.entries.len() != expected as usize {
        return Err(BitstreamError::invalid(format!(
            "dpb_parameters entry count {} != walked sublayer count {expected}",
            dpb.entries.len()
        )));
    }
    for e in &dpb.entries {
        w.write_ue(e.dpb_max_dec_pic_buffering_minus1)?;
        w.write_ue(e.dpb_max_num_reorder_pics)?;
        w.write_ue(e.dpb_max_latency_increase_plus1)?;
    }
    Ok(())
}

// ──────────────── general_timing_hrd_parameters (7.3.5.1) ────────────────────

/// `general_timing_hrd_parameters()` (§7.3.5.1 / §7.4.6.1).
///
/// The fields after `general_vcl_hrd_params_present_flag` are only
/// coded when at least one of the NAL / VCL presence flags is set;
/// when absent they carry their spec-inferred defaults
/// (`general_du_hrd_params_present_flag = 0`, `hrd_cpb_cnt_minus1 =
/// 0`, scales 0).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcGeneralTimingHrd {
    /// `num_units_in_tick` u(32) — must be > 0.
    pub num_units_in_tick: u32,
    /// `time_scale` u(32) — must be > 0.
    pub time_scale: u32,
    /// `general_nal_hrd_params_present_flag` u(1).
    pub general_nal_hrd_params_present_flag: u8,
    /// `general_vcl_hrd_params_present_flag` u(1).
    pub general_vcl_hrd_params_present_flag: u8,
    /// `general_same_pic_timing_in_all_ols_flag` u(1) — coded only
    /// when a NAL or VCL HRD is present.
    pub general_same_pic_timing_in_all_ols_flag: u8,
    /// `general_du_hrd_params_present_flag` u(1) — coded only when a
    /// NAL or VCL HRD is present; inferred 0 otherwise.
    pub general_du_hrd_params_present_flag: u8,
    /// `tick_divisor_minus2` u(8) — coded only when DU HRD present.
    pub tick_divisor_minus2: u8,
    /// `bit_rate_scale` u(4).
    pub bit_rate_scale: u8,
    /// `cpb_size_scale` u(4).
    pub cpb_size_scale: u8,
    /// `cpb_size_du_scale` u(4) — coded only when DU HRD present.
    pub cpb_size_du_scale: u8,
    /// `hrd_cpb_cnt_minus1` ue(v) — 0..=31 (§7.4.6.1); inferred 0
    /// when the NAL/VCL block is absent.
    pub hrd_cpb_cnt_minus1: u32,
}

impl VvcGeneralTimingHrd {
    /// True when either the NAL or the VCL HRD schedule block is
    /// present (the gate for the second half of §7.3.5.1 and for the
    /// `sublayer_hrd_parameters()` lists in §7.3.5.2).
    pub fn any_hrd_present(&self) -> bool {
        self.general_nal_hrd_params_present_flag != 0
            || self.general_vcl_hrd_params_present_flag != 0
    }
}

/// Parse a `general_timing_hrd_parameters()` structure.
pub fn parse_general_timing_hrd(
    r: &mut BitReader<'_>,
) -> Result<VvcGeneralTimingHrd, BitstreamError> {
    let mut g = VvcGeneralTimingHrd {
        num_units_in_tick: r.u(32),
        time_scale: r.u(32),
        general_nal_hrd_params_present_flag: r.u(1) as u8,
        general_vcl_hrd_params_present_flag: r.u(1) as u8,
        ..Default::default()
    };
    if g.num_units_in_tick == 0 || g.time_scale == 0 {
        return Err(BitstreamError::invalid(
            "general_timing_hrd_parameters: num_units_in_tick and time_scale must be > 0 (7.4.6.1)",
        ));
    }
    if g.any_hrd_present() {
        g.general_same_pic_timing_in_all_ols_flag = r.u(1) as u8;
        g.general_du_hrd_params_present_flag = r.u(1) as u8;
        if g.general_du_hrd_params_present_flag != 0 {
            g.tick_divisor_minus2 = r.u(8) as u8;
        }
        g.bit_rate_scale = r.u(4) as u8;
        g.cpb_size_scale = r.u(4) as u8;
        if g.general_du_hrd_params_present_flag != 0 {
            g.cpb_size_du_scale = r.u(4) as u8;
        }
        g.hrd_cpb_cnt_minus1 = r.ue()?;
        if g.hrd_cpb_cnt_minus1 > 31 {
            return Err(BitstreamError::invalid(format!(
                "hrd_cpb_cnt_minus1 = {} > 31 (7.4.6.1)",
                g.hrd_cpb_cnt_minus1
            )));
        }
    }
    Ok(g)
}

/// Emit a `general_timing_hrd_parameters()` structure — byte-exact
/// inverse of [`parse_general_timing_hrd`].
pub fn write_general_timing_hrd(
    w: &mut BitWriter,
    g: &VvcGeneralTimingHrd,
) -> Result<(), BitstreamError> {
    if g.num_units_in_tick == 0 || g.time_scale == 0 {
        return Err(BitstreamError::invalid(
            "general_timing_hrd_parameters: num_units_in_tick and time_scale must be > 0 (7.4.6.1)",
        ));
    }
    w.write_bits(g.num_units_in_tick, 32);
    w.write_bits(g.time_scale, 32);
    w.write_bit(u32::from(g.general_nal_hrd_params_present_flag != 0));
    w.write_bit(u32::from(g.general_vcl_hrd_params_present_flag != 0));
    if g.any_hrd_present() {
        w.write_bit(u32::from(g.general_same_pic_timing_in_all_ols_flag != 0));
        w.write_bit(u32::from(g.general_du_hrd_params_present_flag != 0));
        if g.general_du_hrd_params_present_flag != 0 {
            w.write_bits(g.tick_divisor_minus2 as u32, 8);
        }
        w.write_bits((g.bit_rate_scale & 0x0f) as u32, 4);
        w.write_bits((g.cpb_size_scale & 0x0f) as u32, 4);
        if g.general_du_hrd_params_present_flag != 0 {
            w.write_bits((g.cpb_size_du_scale & 0x0f) as u32, 4);
        }
        if g.hrd_cpb_cnt_minus1 > 31 {
            return Err(BitstreamError::invalid(format!(
                "hrd_cpb_cnt_minus1 = {} > 31 (7.4.6.1)",
                g.hrd_cpb_cnt_minus1
            )));
        }
        w.write_ue(g.hrd_cpb_cnt_minus1)?;
    }
    Ok(())
}

// ──────────────── sublayer_hrd_parameters (7.3.5.3) ─────────────────────────

/// One CPB delivery schedule inside `sublayer_hrd_parameters()`
/// (§7.3.5.3 / §7.4.6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VvcCpbSchedule {
    /// `bit_rate_value_minus1[i][j]` ue(v).
    pub bit_rate_value_minus1: u32,
    /// `cpb_size_value_minus1[i][j]` ue(v).
    pub cpb_size_value_minus1: u32,
    /// `(cpb_size_du_value_minus1, bit_rate_du_value_minus1)` — coded
    /// (in that order) only when `general_du_hrd_params_present_flag`.
    pub du_values_minus1: Option<(u32, u32)>,
    /// `cbr_flag[i][j]` u(1).
    pub cbr_flag: u8,
}

/// `sublayer_hrd_parameters(subLayerId)` — `hrd_cpb_cnt_minus1 + 1`
/// CPB schedules (§7.3.5.3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcSublayerHrd {
    /// Exactly `hrd_cpb_cnt_minus1 + 1` schedules.
    pub schedules: Vec<VvcCpbSchedule>,
}

fn parse_sublayer_hrd(
    r: &mut BitReader<'_>,
    g: &VvcGeneralTimingHrd,
) -> Result<VvcSublayerHrd, BitstreamError> {
    let du = g.general_du_hrd_params_present_flag != 0;
    let n = g.hrd_cpb_cnt_minus1 as usize + 1;
    let mut schedules = Vec::with_capacity(n);
    for _ in 0..n {
        let bit_rate_value_minus1 = r.ue()?;
        let cpb_size_value_minus1 = r.ue()?;
        let du_values_minus1 = if du {
            let cpb_du = r.ue()?;
            let br_du = r.ue()?;
            Some((cpb_du, br_du))
        } else {
            None
        };
        let cbr_flag = r.u(1) as u8;
        schedules.push(VvcCpbSchedule {
            bit_rate_value_minus1,
            cpb_size_value_minus1,
            du_values_minus1,
            cbr_flag,
        });
    }
    Ok(VvcSublayerHrd { schedules })
}

fn write_sublayer_hrd(
    w: &mut BitWriter,
    s: &VvcSublayerHrd,
    g: &VvcGeneralTimingHrd,
) -> Result<(), BitstreamError> {
    let du = g.general_du_hrd_params_present_flag != 0;
    if s.schedules.len() != g.hrd_cpb_cnt_minus1 as usize + 1 {
        return Err(BitstreamError::invalid(format!(
            "sublayer_hrd_parameters schedule count {} != hrd_cpb_cnt_minus1 + 1 = {}",
            s.schedules.len(),
            g.hrd_cpb_cnt_minus1 + 1
        )));
    }
    for sched in &s.schedules {
        w.write_ue(sched.bit_rate_value_minus1)?;
        w.write_ue(sched.cpb_size_value_minus1)?;
        match (du, sched.du_values_minus1) {
            (true, Some((cpb_du, br_du))) => {
                w.write_ue(cpb_du)?;
                w.write_ue(br_du)?;
            }
            (false, None) => {}
            _ => {
                return Err(BitstreamError::invalid(
                    "CPB schedule DU values must be present iff general_du_hrd_params_present_flag",
                ));
            }
        }
        w.write_bit(u32::from(sched.cbr_flag != 0));
    }
    Ok(())
}

// ──────────────── ols_timing_hrd_parameters (7.3.5.2) ───────────────────────

/// One sublayer's entry in `ols_timing_hrd_parameters()` (§7.3.5.2 /
/// §7.4.6.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcOlsTimingHrdSublayer {
    /// `fixed_pic_rate_general_flag[i]` u(1).
    pub fixed_pic_rate_general_flag: u8,
    /// `fixed_pic_rate_within_cvs_flag[i]` u(1) — coded only when the
    /// general flag is 0; inferred 1 when it is 1 (§7.4.6.2).
    pub fixed_pic_rate_within_cvs_flag: u8,
    /// `elemental_duration_in_tc_minus1[i]` ue(v) 0..=2047 — coded
    /// only when `fixed_pic_rate_within_cvs_flag`.
    pub elemental_duration_in_tc_minus1: u32,
    /// `low_delay_hrd_flag[i]` u(1) — coded only when no fixed pic
    /// rate, an HRD is present and `hrd_cpb_cnt_minus1 == 0`;
    /// inferred 0 otherwise.
    pub low_delay_hrd_flag: u8,
    /// NAL `sublayer_hrd_parameters(i)` — present iff
    /// `general_nal_hrd_params_present_flag`.
    pub nal_hrd: Option<VvcSublayerHrd>,
    /// VCL `sublayer_hrd_parameters(i)` — present iff
    /// `general_vcl_hrd_params_present_flag`.
    pub vcl_hrd: Option<VvcSublayerHrd>,
}

/// `ols_timing_hrd_parameters(firstSubLayer, MaxSubLayersVal)`
/// (§7.3.5.2) — one entry per sublayer in
/// `firstSubLayer..=MaxSubLayersVal`, lowest first.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcOlsTimingHrd {
    /// Walked sublayer entries (`MaxSubLayersVal - firstSubLayer + 1`
    /// of them).
    pub sublayers: Vec<VvcOlsTimingHrdSublayer>,
}

/// Parse an `ols_timing_hrd_parameters()` structure. `g` must be the
/// `general_timing_hrd_parameters()` that precedes it in the SPS/VPS.
pub fn parse_ols_timing_hrd(
    r: &mut BitReader<'_>,
    first_sublayer: u32,
    max_sublayers_val: u32,
    g: &VvcGeneralTimingHrd,
) -> Result<VvcOlsTimingHrd, BitstreamError> {
    let mut sublayers = Vec::with_capacity((max_sublayers_val - first_sublayer + 1) as usize);
    for _ in first_sublayer..=max_sublayers_val {
        let mut e = VvcOlsTimingHrdSublayer {
            fixed_pic_rate_general_flag: r.u(1) as u8,
            ..Default::default()
        };
        e.fixed_pic_rate_within_cvs_flag = if e.fixed_pic_rate_general_flag != 0 {
            1 // inferred (§7.4.6.2)
        } else {
            r.u(1) as u8
        };
        if e.fixed_pic_rate_within_cvs_flag != 0 {
            e.elemental_duration_in_tc_minus1 = r.ue()?;
            if e.elemental_duration_in_tc_minus1 > 2047 {
                return Err(BitstreamError::invalid(format!(
                    "elemental_duration_in_tc_minus1 = {} > 2047 (7.4.6.2)",
                    e.elemental_duration_in_tc_minus1
                )));
            }
        } else if g.any_hrd_present() && g.hrd_cpb_cnt_minus1 == 0 {
            e.low_delay_hrd_flag = r.u(1) as u8;
        }
        if g.general_nal_hrd_params_present_flag != 0 {
            e.nal_hrd = Some(parse_sublayer_hrd(r, g)?);
        }
        if g.general_vcl_hrd_params_present_flag != 0 {
            e.vcl_hrd = Some(parse_sublayer_hrd(r, g)?);
        }
        sublayers.push(e);
    }
    Ok(VvcOlsTimingHrd { sublayers })
}

/// Emit an `ols_timing_hrd_parameters()` structure — byte-exact
/// inverse of [`parse_ols_timing_hrd`] on the same context.
pub fn write_ols_timing_hrd(
    w: &mut BitWriter,
    o: &VvcOlsTimingHrd,
    first_sublayer: u32,
    max_sublayers_val: u32,
    g: &VvcGeneralTimingHrd,
) -> Result<(), BitstreamError> {
    let expected = (max_sublayers_val - first_sublayer + 1) as usize;
    if o.sublayers.len() != expected {
        return Err(BitstreamError::invalid(format!(
            "ols_timing_hrd_parameters sublayer count {} != walked count {expected}",
            o.sublayers.len()
        )));
    }
    for e in &o.sublayers {
        w.write_bit(u32::from(e.fixed_pic_rate_general_flag != 0));
        if e.fixed_pic_rate_general_flag == 0 {
            w.write_bit(u32::from(e.fixed_pic_rate_within_cvs_flag != 0));
        }
        if e.fixed_pic_rate_within_cvs_flag != 0 {
            if e.elemental_duration_in_tc_minus1 > 2047 {
                return Err(BitstreamError::invalid(format!(
                    "elemental_duration_in_tc_minus1 = {} > 2047 (7.4.6.2)",
                    e.elemental_duration_in_tc_minus1
                )));
            }
            w.write_ue(e.elemental_duration_in_tc_minus1)?;
        } else if g.any_hrd_present() && g.hrd_cpb_cnt_minus1 == 0 {
            w.write_bit(u32::from(e.low_delay_hrd_flag != 0));
        }
        match (&e.nal_hrd, g.general_nal_hrd_params_present_flag != 0) {
            (Some(s), true) => write_sublayer_hrd(w, s, g)?,
            (None, false) => {}
            _ => {
                return Err(BitstreamError::invalid(
                    "NAL sublayer_hrd must be present iff general_nal_hrd_params_present_flag",
                ));
            }
        }
        match (&e.vcl_hrd, g.general_vcl_hrd_params_present_flag != 0) {
            (Some(s), true) => write_sublayer_hrd(w, s, g)?,
            (None, false) => {}
            _ => {
                return Err(BitstreamError::invalid(
                    "VCL sublayer_hrd must be present iff general_vcl_hrd_params_present_flag",
                ));
            }
        }
    }
    Ok(())
}

// ──────────────── ref_pic_list_struct (7.3.10) ──────────────────────────────

/// One entry of a `ref_pic_list_struct()` (§7.3.10 / §7.4.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VvcRplsEntry {
    /// Short-term reference picture: `abs_delta_poc_st` ue(v) 0..=2¹⁵−1
    /// plus `strp_entry_sign_flag` (coded only when the derived
    /// `AbsDeltaPocSt > 0`; inferred 0 otherwise).
    ShortTerm {
        abs_delta_poc_st: u32,
        strp_entry_sign_flag: u8,
    },
    /// Long-term reference picture. `rpls_poc_lsb_lt` (u(v),
    /// `sps_log2_max_pic_order_cnt_lsb_minus4 + 4` bits) is `None`
    /// when `ltrp_in_header_flag = 1` (the POC LSBs then travel in the
    /// PH / slice header instead).
    LongTerm { rpls_poc_lsb_lt: Option<u32> },
    /// Inter-layer reference picture: `ilrp_idx` ue(v).
    InterLayer { ilrp_idx: u32 },
}

/// A parsed `ref_pic_list_struct(listIdx, rplsIdx)` (§7.3.10).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcRefPicListStruct {
    /// `ltrp_in_header_flag` — coded only when
    /// `sps_long_term_ref_pics_flag`, `rplsIdx <
    /// sps_num_ref_pic_lists[listIdx]` and `num_ref_entries > 0`;
    /// inferred 1 for the PH/SH-coded extra structure (§7.4.11).
    pub ltrp_in_header_flag: u8,
    /// The `num_ref_entries` entries in coded order.
    pub entries: Vec<VvcRplsEntry>,
}

/// Context the spec threads into `ref_pic_list_struct()` from the SPS.
#[derive(Debug, Clone, Copy)]
pub struct VvcRplsContext {
    /// `sps_long_term_ref_pics_flag`.
    pub long_term_ref_pics: bool,
    /// `sps_inter_layer_prediction_enabled_flag`.
    pub inter_layer_prediction: bool,
    /// True when `rplsIdx < sps_num_ref_pic_lists[listIdx]` (always
    /// the case for the SPS-coded template lists; false only for the
    /// extra PH/SH-coded structure).
    pub in_sps_list: bool,
}

/// Spec bound on `num_ref_entries` (§7.4.11): `MaxDpbSize + 13` with
/// `MaxDpbSize ≤ 16` (§A.4.2).
pub const VVC_NUM_REF_ENTRIES_MAX: u32 = 29;

/// Parse a `ref_pic_list_struct(listIdx, rplsIdx)` at the reader's
/// position. `poc_lsb_bits` is the `rpls_poc_lsb_lt` field width,
/// `sps_log2_max_pic_order_cnt_lsb_minus4 + 4` (§7.4.11).
pub fn parse_ref_pic_list_struct(
    r: &mut BitReader<'_>,
    ctx: &VvcRplsContext,
    poc_lsb_bits: u32,
) -> Result<VvcRefPicListStruct, BitstreamError> {
    let num_ref_entries = r.ue()?;
    if num_ref_entries > VVC_NUM_REF_ENTRIES_MAX {
        return Err(BitstreamError::invalid(format!(
            "num_ref_entries = {num_ref_entries} > {VVC_NUM_REF_ENTRIES_MAX} (MaxDpbSize + 13, 7.4.11)"
        )));
    }
    let ltrp_in_header_flag = if ctx.long_term_ref_pics && ctx.in_sps_list && num_ref_entries > 0 {
        r.u(1) as u8
    } else {
        1 // inferred (§7.4.11)
    };
    let mut entries = Vec::with_capacity(num_ref_entries as usize);
    for _ in 0..num_ref_entries {
        let inter_layer = ctx.inter_layer_prediction && r.u(1) != 0;
        if inter_layer {
            entries.push(VvcRplsEntry::InterLayer { ilrp_idx: r.ue()? });
            continue;
        }
        let st = if ctx.long_term_ref_pics {
            r.u(1) != 0
        } else {
            true // inferred 1 (§7.4.11)
        };
        if st {
            let abs_delta_poc_st = r.ue()?;
            if abs_delta_poc_st > (1 << 15) - 1 {
                return Err(BitstreamError::invalid(format!(
                    "abs_delta_poc_st = {abs_delta_poc_st} > 2^15 - 1 (7.4.11)"
                )));
            }
            let strp_entry_sign_flag = if abs_delta_poc_st > 0 {
                r.u(1) as u8
            } else {
                0 // inferred (§7.4.11)
            };
            entries.push(VvcRplsEntry::ShortTerm {
                abs_delta_poc_st,
                strp_entry_sign_flag,
            });
        } else {
            let rpls_poc_lsb_lt = if ltrp_in_header_flag == 0 {
                Some(r.u(poc_lsb_bits))
            } else {
                None
            };
            entries.push(VvcRplsEntry::LongTerm { rpls_poc_lsb_lt });
        }
    }
    Ok(VvcRefPicListStruct {
        ltrp_in_header_flag,
        entries,
    })
}

/// Emit a `ref_pic_list_struct()` — byte-exact inverse of the parse on
/// the same context.
pub fn write_ref_pic_list_struct(
    w: &mut BitWriter,
    rpls: &VvcRefPicListStruct,
    ctx: &VvcRplsContext,
    poc_lsb_bits: u32,
) -> Result<(), BitstreamError> {
    let num_ref_entries = rpls.entries.len() as u32;
    if num_ref_entries > VVC_NUM_REF_ENTRIES_MAX {
        return Err(BitstreamError::invalid(format!(
            "num_ref_entries = {num_ref_entries} > {VVC_NUM_REF_ENTRIES_MAX} (MaxDpbSize + 13, 7.4.11)"
        )));
    }
    w.write_ue(num_ref_entries)?;
    if ctx.long_term_ref_pics && ctx.in_sps_list && num_ref_entries > 0 {
        w.write_bit(u32::from(rpls.ltrp_in_header_flag != 0));
    }
    for e in &rpls.entries {
        if ctx.inter_layer_prediction {
            w.write_bit(u32::from(matches!(e, VvcRplsEntry::InterLayer { .. })));
        }
        match e {
            VvcRplsEntry::InterLayer { ilrp_idx } => {
                if !ctx.inter_layer_prediction {
                    return Err(BitstreamError::invalid(
                        "inter-layer RPLS entry without sps_inter_layer_prediction_enabled_flag",
                    ));
                }
                w.write_ue(*ilrp_idx)?;
            }
            VvcRplsEntry::ShortTerm {
                abs_delta_poc_st,
                strp_entry_sign_flag,
            } => {
                if ctx.long_term_ref_pics {
                    w.write_bit(1); // st_ref_pic_flag
                }
                if *abs_delta_poc_st > (1 << 15) - 1 {
                    return Err(BitstreamError::invalid(format!(
                        "abs_delta_poc_st = {abs_delta_poc_st} > 2^15 - 1 (7.4.11)"
                    )));
                }
                w.write_ue(*abs_delta_poc_st)?;
                if *abs_delta_poc_st > 0 {
                    w.write_bit(u32::from(*strp_entry_sign_flag != 0));
                }
            }
            VvcRplsEntry::LongTerm { rpls_poc_lsb_lt } => {
                if !ctx.long_term_ref_pics {
                    return Err(BitstreamError::invalid(
                        "long-term RPLS entry without sps_long_term_ref_pics_flag",
                    ));
                }
                w.write_bit(0); // st_ref_pic_flag
                match (rpls_poc_lsb_lt, rpls.ltrp_in_header_flag == 0) {
                    (Some(v), true) => {
                        if poc_lsb_bits < 32 && *v >= (1u32 << poc_lsb_bits) {
                            return Err(BitstreamError::invalid(format!(
                                "rpls_poc_lsb_lt = {v} does not fit u({poc_lsb_bits})"
                            )));
                        }
                        w.write_bits(*v, poc_lsb_bits);
                    }
                    (None, false) => {}
                    _ => {
                        return Err(BitstreamError::invalid(
                            "rpls_poc_lsb_lt must be present iff ltrp_in_header_flag == 0",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
