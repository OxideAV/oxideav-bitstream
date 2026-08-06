//! H.266 / VVC sequence parameter set (§7.3.2.4) — complete walk,
//! parse + byte-exact write.
//!
//! [`parse_sps`] walks every syntax element of
//! `seq_parameter_set_rbsp()` through `rbsp_trailing_bits()` and
//! retains them losslessly; [`write_sps`] is its byte-exact inverse
//! (`write_sps(parse_sps(x)) == x` for every RBSP the parser
//! accepts). The embedded sub-structures — subpicture layout,
//! `dpb_parameters()`, `general_timing_hrd_parameters()` /
//! `ols_timing_hrd_parameters()`, `ref_pic_list_struct()` — live in
//! [`super::params`]; `profile_tier_level()` reuses the lossless
//! walker in the parent module. The `vui_payload()` is preserved as
//! its raw byte block (§7.3.2.4 signals its size explicitly and
//! byte-aligns before it, so no VUI field parsing is needed for
//! byte-exact round-trips), and `sps_extension_data_flag` bits are
//! retained verbatim.
//!
//! # Spec references
//!
//! ITU-T H.266 (V4) (01/2026): §7.3.2.4 / §7.4.3.4 (SPS RBSP),
//! §7.3.3.1 (profile / tier / level), §7.3.4 (DPB), §7.3.5 (timing +
//! HRD), §7.3.10 (ref pic list struct), the `sps_range_extension()`
//! syntax, Table A.2 (`MaxSlicesPerAu`), §A.4.2 (`MaxDpbSize`).

use super::params::{
    ceil_log2_u64, parse_dpb_parameters, parse_general_timing_hrd, parse_ols_timing_hrd,
    parse_ref_pic_list_struct, write_dpb_parameters, write_general_timing_hrd,
    write_ols_timing_hrd, write_ref_pic_list_struct, VvcDpbParameters, VvcGeneralTimingHrd,
    VvcOlsTimingHrd, VvcRefPicListStruct, VvcRplsContext,
};
use super::{
    ebsp_to_rbsp, parse_nal_header, parse_profile_tier_level, write_profile_tier_level,
    VvcProfileTierLevel, NAL_TYPE_SPS,
};
use crate::bit_reader::BitReader;
use crate::bit_writer::BitWriter;
use crate::BitstreamError;

/// Spec upper bound on `sps_log2_max_pic_order_cnt_lsb_minus4`
/// (§7.4.3.4): `MaxPicOrderCntLsb` is bounded by 2^16, hence
/// `sps_log2_max_pic_order_cnt_lsb_minus4 ≤ 12`. Surfaced so callers
/// can validate against the same envelope the parser enforces.
pub const SPS_LOG2_MAX_PIC_ORDER_CNT_LSB_MINUS4_MAX: u8 = 12;

/// Table A.2 bound: `MaxSlicesPerAu ≤ 1000`, so
/// `sps_num_subpics_minus1 ≤ 999` (§7.4.3.4).
pub const SPS_NUM_SUBPICS_MINUS1_MAX: u32 = 999;

// ─────────────────────────── Subpicture layout ───────────────────────────────

/// One subpicture's layout entry (§7.3.2.4 / §7.4.3.4). Fields not
/// coded for this index (per the `u(v)` presence conditions) carry
/// their spec-inferred values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VvcSubpicEntry {
    /// `sps_subpic_ctu_top_left_x[i]` u(v) in CTU units — coded only
    /// when `i > 0` and the picture is wider than one CTU.
    pub sps_subpic_ctu_top_left_x: u32,
    /// `sps_subpic_ctu_top_left_y[i]` u(v) in CTU units.
    pub sps_subpic_ctu_top_left_y: u32,
    /// `sps_subpic_width_minus1[i]` u(v) in CTU units — coded only
    /// when `i < sps_num_subpics_minus1` and the picture is wider
    /// than one CTU.
    pub sps_subpic_width_minus1: u32,
    /// `sps_subpic_height_minus1[i]` u(v) in CTU units.
    pub sps_subpic_height_minus1: u32,
    /// `sps_subpic_treated_as_pic_flag[i]` u(1) — coded only when
    /// `!sps_independent_subpics_flag`; inferred 1 otherwise.
    pub sps_subpic_treated_as_pic_flag: u8,
    /// `sps_loop_filter_across_subpic_enabled_flag[i]` u(1) — coded
    /// only when `!sps_independent_subpics_flag`; inferred 0.
    pub sps_loop_filter_across_subpic_enabled_flag: u8,
}

/// The SPS subpicture info block (§7.3.2.4, present iff
/// `sps_subpic_info_present_flag`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcSubpicInfo {
    /// `sps_num_subpics_minus1` ue(v) — 0..=999 (Table A.2).
    pub sps_num_subpics_minus1: u32,
    /// `sps_independent_subpics_flag` u(1) — coded only when
    /// `sps_num_subpics_minus1 > 0`; inferred 1 otherwise.
    pub sps_independent_subpics_flag: u8,
    /// `sps_subpic_same_size_flag` u(1) — coded only when
    /// `sps_num_subpics_minus1 > 0`; inferred 0 otherwise.
    pub sps_subpic_same_size_flag: u8,
    /// Per-subpicture entries. Empty when `sps_num_subpics_minus1 ==
    /// 0` (the per-`i` loop does not run then, §7.3.2.4); otherwise
    /// exactly `sps_num_subpics_minus1 + 1` entries with inferred
    /// values filled in for uncoded fields.
    pub entries: Vec<VvcSubpicEntry>,
    /// `sps_subpic_id_len_minus1` ue(v) — 0..=15, and
    /// `1 << (len + 1)` must cover `sps_num_subpics_minus1 + 1`.
    pub sps_subpic_id_len_minus1: u32,
    /// `sps_subpic_id_mapping_explicitly_signalled_flag` u(1).
    pub sps_subpic_id_mapping_explicitly_signalled_flag: u8,
    /// `sps_subpic_id_mapping_present_flag` u(1) — coded only when
    /// the mapping is explicitly signalled; inferred 0.
    pub sps_subpic_id_mapping_present_flag: u8,
    /// `sps_subpic_id[i]` u(v) — `sps_num_subpics_minus1 + 1` ids,
    /// present iff `sps_subpic_id_mapping_present_flag`.
    pub sps_subpic_ids: Vec<u32>,
}

fn parse_subpic_info(
    r: &mut BitReader<'_>,
    tmp_width_val: u64,
    tmp_height_val: u64,
) -> Result<VvcSubpicInfo, BitstreamError> {
    let mut sp = VvcSubpicInfo {
        sps_num_subpics_minus1: r.ue()?,
        sps_independent_subpics_flag: 1,
        ..Default::default()
    };
    if sp.sps_num_subpics_minus1 > SPS_NUM_SUBPICS_MINUS1_MAX {
        return Err(BitstreamError::invalid(format!(
            "sps_num_subpics_minus1 = {} > {SPS_NUM_SUBPICS_MINUS1_MAX} (MaxSlicesPerAu, Table A.2)",
            sp.sps_num_subpics_minus1
        )));
    }
    let num = sp.sps_num_subpics_minus1;
    let wbits = ceil_log2_u64(tmp_width_val);
    let hbits = ceil_log2_u64(tmp_height_val);
    if num > 0 {
        sp.sps_independent_subpics_flag = r.u(1) as u8;
        sp.sps_subpic_same_size_flag = r.u(1) as u8;
        let same = sp.sps_subpic_same_size_flag != 0;
        let mut entries: Vec<VvcSubpicEntry> = Vec::with_capacity(num as usize + 1);
        for i in 0..=num {
            let mut e = VvcSubpicEntry {
                sps_subpic_treated_as_pic_flag: 1,
                ..Default::default()
            };
            if !same || i == 0 {
                if i > 0 && tmp_width_val > 1 {
                    e.sps_subpic_ctu_top_left_x = r.u(wbits);
                }
                if i > 0 && tmp_height_val > 1 {
                    e.sps_subpic_ctu_top_left_y = r.u(hbits);
                }
                if i < num && tmp_width_val > 1 {
                    e.sps_subpic_width_minus1 = r.u(wbits);
                } else {
                    // Inferred: tmpWidthVal - top_left_x - 1 (§7.4.3.4).
                    e.sps_subpic_width_minus1 = tmp_width_val
                        .checked_sub(e.sps_subpic_ctu_top_left_x as u64 + 1)
                        .ok_or_else(|| {
                            BitstreamError::invalid(
                                "sps_subpic_ctu_top_left_x exceeds the picture width in CTUs",
                            )
                        })? as u32;
                }
                if i < num && tmp_height_val > 1 {
                    e.sps_subpic_height_minus1 = r.u(hbits);
                } else {
                    e.sps_subpic_height_minus1 = tmp_height_val
                        .checked_sub(e.sps_subpic_ctu_top_left_y as u64 + 1)
                        .ok_or_else(|| {
                            BitstreamError::invalid(
                                "sps_subpic_ctu_top_left_y exceeds the picture height in CTUs",
                            )
                        })? as u32;
                }
            } else {
                // sps_subpic_same_size_flag == 1, i > 0: geometry is
                // fully inferred from entry 0 (§7.4.3.4).
                let w0 = entries[0].sps_subpic_width_minus1 as u64 + 1;
                let h0 = entries[0].sps_subpic_height_minus1 as u64 + 1;
                if tmp_width_val % w0 != 0 || tmp_height_val % h0 != 0 {
                    return Err(BitstreamError::invalid(
                        "sps_subpic_same_size_flag = 1 requires the subpicture grid to tile the \
                         picture exactly (7.4.3.4)",
                    ));
                }
                let num_subpic_cols = tmp_width_val / w0;
                if num_subpic_cols * (tmp_height_val / h0) != num as u64 + 1 {
                    return Err(BitstreamError::invalid(
                        "sps_subpic_same_size_flag = 1 grid does not yield \
                         sps_num_subpics_minus1 + 1 subpictures (7.4.3.4)",
                    ));
                }
                e.sps_subpic_ctu_top_left_x = ((i as u64 % num_subpic_cols) * w0) as u32;
                e.sps_subpic_ctu_top_left_y = ((i as u64 / num_subpic_cols) * h0) as u32;
                e.sps_subpic_width_minus1 = entries[0].sps_subpic_width_minus1;
                e.sps_subpic_height_minus1 = entries[0].sps_subpic_height_minus1;
            }
            if e.sps_subpic_ctu_top_left_x as u64 + e.sps_subpic_width_minus1 as u64 + 1
                > tmp_width_val
                || e.sps_subpic_ctu_top_left_y as u64 + e.sps_subpic_height_minus1 as u64 + 1
                    > tmp_height_val
            {
                return Err(BitstreamError::invalid(format!(
                    "subpicture {i} exceeds the picture grid (7.4.3.4)"
                )));
            }
            if sp.sps_independent_subpics_flag == 0 {
                e.sps_subpic_treated_as_pic_flag = r.u(1) as u8;
                e.sps_loop_filter_across_subpic_enabled_flag = r.u(1) as u8;
            }
            entries.push(e);
        }
        sp.entries = entries;
    }
    sp.sps_subpic_id_len_minus1 = r.ue()?;
    if sp.sps_subpic_id_len_minus1 > 15 {
        return Err(BitstreamError::invalid(format!(
            "sps_subpic_id_len_minus1 = {} > 15 (7.4.3.4)",
            sp.sps_subpic_id_len_minus1
        )));
    }
    if sp.sps_subpic_id_len_minus1 < 31
        && (1u64 << (sp.sps_subpic_id_len_minus1 + 1)) < num as u64 + 1
    {
        return Err(BitstreamError::invalid(
            "1 << (sps_subpic_id_len_minus1 + 1) must cover sps_num_subpics_minus1 + 1 (7.4.3.4)",
        ));
    }
    sp.sps_subpic_id_mapping_explicitly_signalled_flag = r.u(1) as u8;
    if sp.sps_subpic_id_mapping_explicitly_signalled_flag != 0 {
        sp.sps_subpic_id_mapping_present_flag = r.u(1) as u8;
        if sp.sps_subpic_id_mapping_present_flag != 0 {
            let id_bits = sp.sps_subpic_id_len_minus1 + 1;
            sp.sps_subpic_ids = (0..=num).map(|_| r.u(id_bits)).collect();
        }
    }
    Ok(sp)
}

fn write_subpic_info(
    w: &mut BitWriter,
    sp: &VvcSubpicInfo,
    tmp_width_val: u64,
    tmp_height_val: u64,
) -> Result<(), BitstreamError> {
    let num = sp.sps_num_subpics_minus1;
    if num > SPS_NUM_SUBPICS_MINUS1_MAX {
        return Err(BitstreamError::invalid(format!(
            "sps_num_subpics_minus1 = {num} > {SPS_NUM_SUBPICS_MINUS1_MAX} (Table A.2)"
        )));
    }
    w.write_ue(num)?;
    let wbits = ceil_log2_u64(tmp_width_val);
    let hbits = ceil_log2_u64(tmp_height_val);
    if num > 0 {
        if sp.entries.len() != num as usize + 1 {
            return Err(BitstreamError::invalid(format!(
                "subpicture entry count {} != sps_num_subpics_minus1 + 1 = {}",
                sp.entries.len(),
                num + 1
            )));
        }
        w.write_bit(u32::from(sp.sps_independent_subpics_flag != 0));
        w.write_bit(u32::from(sp.sps_subpic_same_size_flag != 0));
        let same = sp.sps_subpic_same_size_flag != 0;
        for (i, e) in sp.entries.iter().enumerate() {
            let i = i as u32;
            if !same || i == 0 {
                if i > 0 && tmp_width_val > 1 {
                    w.write_bits(e.sps_subpic_ctu_top_left_x, wbits);
                }
                if i > 0 && tmp_height_val > 1 {
                    w.write_bits(e.sps_subpic_ctu_top_left_y, hbits);
                }
                if i < num && tmp_width_val > 1 {
                    w.write_bits(e.sps_subpic_width_minus1, wbits);
                }
                if i < num && tmp_height_val > 1 {
                    w.write_bits(e.sps_subpic_height_minus1, hbits);
                }
            }
            if sp.sps_independent_subpics_flag == 0 {
                w.write_bit(u32::from(e.sps_subpic_treated_as_pic_flag != 0));
                w.write_bit(u32::from(e.sps_loop_filter_across_subpic_enabled_flag != 0));
            }
        }
    } else if !sp.entries.is_empty() {
        return Err(BitstreamError::invalid(
            "subpicture entries must be empty when sps_num_subpics_minus1 == 0",
        ));
    }
    if sp.sps_subpic_id_len_minus1 > 15 {
        return Err(BitstreamError::invalid(format!(
            "sps_subpic_id_len_minus1 = {} > 15 (7.4.3.4)",
            sp.sps_subpic_id_len_minus1
        )));
    }
    w.write_ue(sp.sps_subpic_id_len_minus1)?;
    w.write_bit(u32::from(
        sp.sps_subpic_id_mapping_explicitly_signalled_flag != 0,
    ));
    if sp.sps_subpic_id_mapping_explicitly_signalled_flag != 0 {
        w.write_bit(u32::from(sp.sps_subpic_id_mapping_present_flag != 0));
        if sp.sps_subpic_id_mapping_present_flag != 0 {
            if sp.sps_subpic_ids.len() != num as usize + 1 {
                return Err(BitstreamError::invalid(format!(
                    "sps_subpic_id count {} != sps_num_subpics_minus1 + 1 = {}",
                    sp.sps_subpic_ids.len(),
                    num + 1
                )));
            }
            let id_bits = sp.sps_subpic_id_len_minus1 + 1;
            for &id in &sp.sps_subpic_ids {
                if id_bits < 32 && id >= (1u32 << id_bits) {
                    return Err(BitstreamError::invalid(format!(
                        "sps_subpic_id = {id} does not fit u({id_bits})"
                    )));
                }
                w.write_bits(id, id_bits);
            }
        }
    } else if sp.sps_subpic_id_mapping_present_flag != 0 {
        return Err(BitstreamError::invalid(
            "sps_subpic_id_mapping_present_flag requires \
             sps_subpic_id_mapping_explicitly_signalled_flag (7.3.2.4)",
        ));
    }
    Ok(())
}

// ─────────────────────────── Small sub-blocks ────────────────────────────────

/// One chroma QP mapping table (§7.3.2.4 / §7.4.3.4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcChromaQpTable {
    /// `sps_qp_table_start_minus26[i]` se(v) — `-26 - QpBdOffset ..= 36`.
    pub sps_qp_table_start_minus26: i32,
    /// `(sps_delta_qp_in_val_minus1[i][j], sps_delta_qp_diff_val[i][j])`
    /// pairs; the list length is `sps_num_points_in_qp_table_minus1[i]
    /// + 1` (0..=`36 - sps_qp_table_start_minus26[i]`).
    pub points: Vec<(u32, u32)>,
}

/// The `sps_ladf_*` block (§7.3.2.4, present iff
/// `sps_ladf_enabled_flag`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcLadf {
    /// `sps_ladf_lowest_interval_qp_offset` se(v).
    pub sps_ladf_lowest_interval_qp_offset: i32,
    /// `(sps_ladf_qp_offset[i], sps_ladf_delta_threshold_minus1[i])`
    /// pairs; the count is `sps_num_ladf_intervals_minus2 + 1`
    /// (1..=4, `sps_num_ladf_intervals_minus2` is u(2)).
    pub intervals: Vec<(i32, u32)>,
}

/// `sps_range_extension()` syntax structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VvcSpsRangeExtension {
    /// `sps_extended_precision_flag` u(1).
    pub sps_extended_precision_flag: u8,
    /// `sps_ts_residual_coding_rice_present_in_sh_flag` u(1) — coded
    /// only when `sps_transform_skip_enabled_flag`; inferred 0.
    pub sps_ts_residual_coding_rice_present_in_sh_flag: u8,
    /// `sps_rrc_rice_extension_flag` u(1).
    pub sps_rrc_rice_extension_flag: u8,
    /// `sps_persistent_rice_adaptation_enabled_flag` u(1).
    pub sps_persistent_rice_adaptation_enabled_flag: u8,
    /// `sps_reverse_last_sig_coeff_enabled_flag` u(1).
    pub sps_reverse_last_sig_coeff_enabled_flag: u8,
}

/// The SPS timing/HRD block (§7.3.2.4, present iff
/// `sps_timing_hrd_params_present_flag`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcSpsTimingHrd {
    /// `general_timing_hrd_parameters()` (§7.3.5.1).
    pub general: VvcGeneralTimingHrd,
    /// `sps_sublayer_cpb_params_present_flag` u(1) — coded only when
    /// `sps_max_sublayers_minus1 > 0`; inferred 0. Determines
    /// `firstSubLayer` for the OLS HRD walk.
    pub sps_sublayer_cpb_params_present_flag: u8,
    /// `ols_timing_hrd_parameters(firstSubLayer,
    /// sps_max_sublayers_minus1)` (§7.3.5.2).
    pub ols: VvcOlsTimingHrd,
}

// ─────────────────────────── The SPS itself ──────────────────────────────────

/// A completely-walked VVC SPS (§7.3.2.4). Every syntax element is
/// retained (or spec-inferred when its presence condition failed), so
/// [`write_sps`] can re-emit the RBSP byte-exactly.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcSps {
    /// `sps_seq_parameter_set_id` u(4).
    pub sps_seq_parameter_set_id: u8,
    /// `sps_video_parameter_set_id` u(4).
    pub sps_video_parameter_set_id: u8,
    /// `sps_max_sublayers_minus1` u(3) — 0..=6 (7 is reserved).
    pub sps_max_sublayers_minus1: u8,
    /// `sps_chroma_format_idc` u(2) — 0 = 4:0:0, 1 = 4:2:0, 2 =
    /// 4:2:2, 3 = 4:4:4.
    pub sps_chroma_format_idc: u8,
    /// `sps_log2_ctu_size_minus5` u(2) — 0..=2 (CTU 32 / 64 / 128).
    pub sps_log2_ctu_size_minus5: u8,
    /// `profile_tier_level(1, sps_max_sublayers_minus1)` — present
    /// iff `sps_ptl_dpb_hrd_params_present_flag`.
    pub profile_tier_level: Option<VvcProfileTierLevel>,
    /// `sps_gdr_enabled_flag` u(1).
    pub sps_gdr_enabled_flag: u8,
    /// `sps_ref_pic_resampling_enabled_flag` u(1).
    pub sps_ref_pic_resampling_enabled_flag: u8,
    /// `sps_res_change_in_clvs_allowed_flag` u(1) — coded only when
    /// ref-pic resampling is enabled; inferred 0.
    pub sps_res_change_in_clvs_allowed_flag: u8,
    /// `sps_pic_width_max_in_luma_samples` ue(v) — must be > 0.
    pub sps_pic_width_max_in_luma_samples: u32,
    /// `sps_pic_height_max_in_luma_samples` ue(v) — must be > 0.
    pub sps_pic_height_max_in_luma_samples: u32,
    /// `(left, right, top, bottom)` `sps_conf_win_*_offset` values —
    /// present iff `sps_conformance_window_flag`.
    pub sps_conf_win_offsets: Option<(u32, u32, u32, u32)>,
    /// Subpicture layout block — present iff
    /// `sps_subpic_info_present_flag`.
    pub subpic_info: Option<VvcSubpicInfo>,
    /// `sps_bitdepth_minus8` ue(v) — 0..=8 (`BitDepth ≤ 16`).
    pub sps_bitdepth_minus8: u32,
    /// `sps_entropy_coding_sync_enabled_flag` u(1) (WPP).
    pub sps_entropy_coding_sync_enabled_flag: u8,
    /// `sps_entry_point_offsets_present_flag` u(1).
    pub sps_entry_point_offsets_present_flag: u8,
    /// `sps_log2_max_pic_order_cnt_lsb_minus4` u(4) — 0..=12.
    pub sps_log2_max_pic_order_cnt_lsb_minus4: u8,
    /// `sps_poc_msb_cycle_len_minus1` ue(v) — present iff
    /// `sps_poc_msb_cycle_flag`; range `0..=32 -
    /// sps_log2_max_pic_order_cnt_lsb_minus4 - 5`.
    pub sps_poc_msb_cycle_len_minus1: Option<u32>,
    /// `sps_extra_ph_bit_present_flag[i]` bits —
    /// `sps_num_extra_ph_bytes * 8` of them (0..=2 bytes).
    pub sps_extra_ph_bit_present_flags: Vec<u8>,
    /// `sps_extra_sh_bit_present_flag[i]` bits.
    pub sps_extra_sh_bit_present_flags: Vec<u8>,
    /// `sps_sublayer_dpb_params_flag` u(1) — coded only when PTL/DPB/
    /// HRD present and `sps_max_sublayers_minus1 > 0`; inferred 0.
    pub sps_sublayer_dpb_params_flag: u8,
    /// `dpb_parameters(sps_max_sublayers_minus1,
    /// sps_sublayer_dpb_params_flag)` — present iff
    /// `sps_ptl_dpb_hrd_params_present_flag`.
    pub dpb_parameters: Option<VvcDpbParameters>,
    /// `sps_log2_min_luma_coding_block_size_minus2` ue(v) —
    /// `MinCbLog2SizeY ≤ Min(6, CtbLog2SizeY)`.
    pub sps_log2_min_luma_coding_block_size_minus2: u32,
    /// `sps_partition_constraints_override_enabled_flag` u(1).
    pub sps_partition_constraints_override_enabled_flag: u8,
    /// `sps_log2_diff_min_qt_min_cb_intra_slice_luma` ue(v).
    pub sps_log2_diff_min_qt_min_cb_intra_slice_luma: u32,
    /// `sps_max_mtt_hierarchy_depth_intra_slice_luma` ue(v).
    pub sps_max_mtt_hierarchy_depth_intra_slice_luma: u32,
    /// `sps_log2_diff_max_bt_min_qt_intra_slice_luma` ue(v) — coded
    /// only when the intra-luma MTT depth is nonzero; inferred 0.
    pub sps_log2_diff_max_bt_min_qt_intra_slice_luma: u32,
    /// `sps_log2_diff_max_tt_min_qt_intra_slice_luma` ue(v) — ditto.
    pub sps_log2_diff_max_tt_min_qt_intra_slice_luma: u32,
    /// `sps_qtbtt_dual_tree_intra_flag` u(1) — coded only when
    /// `sps_chroma_format_idc != 0`; inferred 0.
    pub sps_qtbtt_dual_tree_intra_flag: u8,
    /// `sps_log2_diff_min_qt_min_cb_intra_slice_chroma` ue(v) — coded
    /// only when dual-tree intra; inferred 0.
    pub sps_log2_diff_min_qt_min_cb_intra_slice_chroma: u32,
    /// `sps_max_mtt_hierarchy_depth_intra_slice_chroma` ue(v) — ditto.
    pub sps_max_mtt_hierarchy_depth_intra_slice_chroma: u32,
    /// `sps_log2_diff_max_bt_min_qt_intra_slice_chroma` ue(v).
    pub sps_log2_diff_max_bt_min_qt_intra_slice_chroma: u32,
    /// `sps_log2_diff_max_tt_min_qt_intra_slice_chroma` ue(v).
    pub sps_log2_diff_max_tt_min_qt_intra_slice_chroma: u32,
    /// `sps_log2_diff_min_qt_min_cb_inter_slice` ue(v).
    pub sps_log2_diff_min_qt_min_cb_inter_slice: u32,
    /// `sps_max_mtt_hierarchy_depth_inter_slice` ue(v).
    pub sps_max_mtt_hierarchy_depth_inter_slice: u32,
    /// `sps_log2_diff_max_bt_min_qt_inter_slice` ue(v) — coded only
    /// when the inter MTT depth is nonzero; inferred 0.
    pub sps_log2_diff_max_bt_min_qt_inter_slice: u32,
    /// `sps_log2_diff_max_tt_min_qt_inter_slice` ue(v) — ditto.
    pub sps_log2_diff_max_tt_min_qt_inter_slice: u32,
    /// `sps_max_luma_transform_size_64_flag` u(1) — coded only when
    /// `CtbSizeY > 32`; inferred 0.
    pub sps_max_luma_transform_size_64_flag: u8,
    /// `sps_transform_skip_enabled_flag` u(1).
    pub sps_transform_skip_enabled_flag: u8,
    /// `sps_log2_transform_skip_max_size_minus2` ue(v) — 0..=3, coded
    /// only when transform skip is enabled.
    pub sps_log2_transform_skip_max_size_minus2: u32,
    /// `sps_bdpcm_enabled_flag` u(1) — coded only when transform skip
    /// is enabled; inferred 0.
    pub sps_bdpcm_enabled_flag: u8,
    /// `sps_mts_enabled_flag` u(1).
    pub sps_mts_enabled_flag: u8,
    /// `sps_explicit_mts_intra_enabled_flag` u(1) — coded only when
    /// MTS is enabled; inferred 0.
    pub sps_explicit_mts_intra_enabled_flag: u8,
    /// `sps_explicit_mts_inter_enabled_flag` u(1) — ditto.
    pub sps_explicit_mts_inter_enabled_flag: u8,
    /// `sps_lfnst_enabled_flag` u(1).
    pub sps_lfnst_enabled_flag: u8,
    /// `sps_joint_cbcr_enabled_flag` u(1) — coded only when chroma is
    /// present; inferred 0.
    pub sps_joint_cbcr_enabled_flag: u8,
    /// `sps_same_qp_table_for_chroma_flag` u(1) — coded only when
    /// chroma is present; inferred 1 (§7.4.3.4).
    pub sps_same_qp_table_for_chroma_flag: u8,
    /// Chroma QP mapping tables — `numQpTables` of them (1, 2 or 3
    /// depending on the two flags above); empty for monochrome.
    pub chroma_qp_tables: Vec<VvcChromaQpTable>,
    /// `sps_sao_enabled_flag` u(1).
    pub sps_sao_enabled_flag: u8,
    /// `sps_alf_enabled_flag` u(1).
    pub sps_alf_enabled_flag: u8,
    /// `sps_ccalf_enabled_flag` u(1) — coded only when ALF is enabled
    /// and chroma is present; inferred 0.
    pub sps_ccalf_enabled_flag: u8,
    /// `sps_lmcs_enabled_flag` u(1).
    pub sps_lmcs_enabled_flag: u8,
    /// `sps_weighted_pred_flag` u(1).
    pub sps_weighted_pred_flag: u8,
    /// `sps_weighted_bipred_flag` u(1).
    pub sps_weighted_bipred_flag: u8,
    /// `sps_long_term_ref_pics_flag` u(1).
    pub sps_long_term_ref_pics_flag: u8,
    /// `sps_inter_layer_prediction_enabled_flag` u(1) — coded only
    /// when `sps_video_parameter_set_id > 0`; inferred 0.
    pub sps_inter_layer_prediction_enabled_flag: u8,
    /// `sps_idr_rpl_present_flag` u(1).
    pub sps_idr_rpl_present_flag: u8,
    /// `sps_rpl1_same_as_rpl0_flag` u(1).
    pub sps_rpl1_same_as_rpl0_flag: u8,
    /// The `ref_pic_list_struct(i, j)` template lists. `[1]` is empty
    /// when `sps_rpl1_same_as_rpl0_flag` (list 1 mirrors list 0 and
    /// is not coded). Each list holds ≤ 64 structures (§7.4.3.4).
    pub sps_ref_pic_lists: [Vec<VvcRefPicListStruct>; 2],
    /// `sps_ref_wraparound_enabled_flag` u(1).
    pub sps_ref_wraparound_enabled_flag: u8,
    /// `sps_temporal_mvp_enabled_flag` u(1).
    pub sps_temporal_mvp_enabled_flag: u8,
    /// `sps_sbtmvp_enabled_flag` u(1) — coded only when temporal MVP
    /// is enabled; inferred 0.
    pub sps_sbtmvp_enabled_flag: u8,
    /// `sps_amvr_enabled_flag` u(1).
    pub sps_amvr_enabled_flag: u8,
    /// `sps_bdof_enabled_flag` u(1).
    pub sps_bdof_enabled_flag: u8,
    /// `sps_bdof_control_present_in_ph_flag` u(1) — coded only when
    /// BDOF is enabled; inferred 0.
    pub sps_bdof_control_present_in_ph_flag: u8,
    /// `sps_smvd_enabled_flag` u(1).
    pub sps_smvd_enabled_flag: u8,
    /// `sps_dmvr_enabled_flag` u(1).
    pub sps_dmvr_enabled_flag: u8,
    /// `sps_dmvr_control_present_in_ph_flag` u(1) — coded only when
    /// DMVR is enabled; inferred 0.
    pub sps_dmvr_control_present_in_ph_flag: u8,
    /// `sps_mmvd_enabled_flag` u(1).
    pub sps_mmvd_enabled_flag: u8,
    /// `sps_mmvd_fullpel_only_enabled_flag` u(1) — coded only when
    /// MMVD is enabled; inferred 0.
    pub sps_mmvd_fullpel_only_enabled_flag: u8,
    /// `sps_six_minus_max_num_merge_cand` ue(v) — 0..=5
    /// (`MaxNumMergeCand = 6 - value`).
    pub sps_six_minus_max_num_merge_cand: u32,
    /// `sps_sbt_enabled_flag` u(1).
    pub sps_sbt_enabled_flag: u8,
    /// `sps_affine_enabled_flag` u(1).
    pub sps_affine_enabled_flag: u8,
    /// `sps_five_minus_max_num_subblock_merge_cand` ue(v) — coded
    /// only when affine is enabled; 0..=`5 - sps_sbtmvp_enabled_flag`.
    pub sps_five_minus_max_num_subblock_merge_cand: u32,
    /// `sps_6param_affine_enabled_flag` u(1) — coded only when affine
    /// is enabled; inferred 0.
    pub sps_6param_affine_enabled_flag: u8,
    /// `sps_affine_amvr_enabled_flag` u(1) — coded only when affine
    /// and AMVR are both enabled; inferred 0.
    pub sps_affine_amvr_enabled_flag: u8,
    /// `sps_affine_prof_enabled_flag` u(1) — coded only when affine
    /// is enabled; inferred 0.
    pub sps_affine_prof_enabled_flag: u8,
    /// `sps_prof_control_present_in_ph_flag` u(1) — coded only when
    /// affine PROF is enabled; inferred 0.
    pub sps_prof_control_present_in_ph_flag: u8,
    /// `sps_bcw_enabled_flag` u(1).
    pub sps_bcw_enabled_flag: u8,
    /// `sps_ciip_enabled_flag` u(1).
    pub sps_ciip_enabled_flag: u8,
    /// `sps_gpm_enabled_flag` u(1) — coded only when
    /// `MaxNumMergeCand >= 2`; inferred 0.
    pub sps_gpm_enabled_flag: u8,
    /// `sps_max_num_merge_cand_minus_max_num_gpm_cand` ue(v) — coded
    /// only when GPM is enabled and `MaxNumMergeCand >= 3`; range
    /// 0..=`MaxNumMergeCand - 2`.
    pub sps_max_num_merge_cand_minus_max_num_gpm_cand: u32,
    /// `sps_log2_parallel_merge_level_minus2` ue(v) — 0..=`CtbLog2SizeY - 2`.
    pub sps_log2_parallel_merge_level_minus2: u32,
    /// `sps_isp_enabled_flag` u(1).
    pub sps_isp_enabled_flag: u8,
    /// `sps_mrl_enabled_flag` u(1).
    pub sps_mrl_enabled_flag: u8,
    /// `sps_mip_enabled_flag` u(1).
    pub sps_mip_enabled_flag: u8,
    /// `sps_cclm_enabled_flag` u(1) — coded only when chroma is
    /// present; inferred 0.
    pub sps_cclm_enabled_flag: u8,
    /// `sps_chroma_horizontal_collocated_flag` u(1) — coded only for
    /// 4:2:0; inferred 1 (§7.4.3.4).
    pub sps_chroma_horizontal_collocated_flag: u8,
    /// `sps_chroma_vertical_collocated_flag` u(1) — ditto.
    pub sps_chroma_vertical_collocated_flag: u8,
    /// `sps_palette_enabled_flag` u(1).
    pub sps_palette_enabled_flag: u8,
    /// `sps_act_enabled_flag` u(1) — coded only for 4:4:4 with the
    /// 64-luma-transform flag clear; inferred 0.
    pub sps_act_enabled_flag: u8,
    /// `sps_min_qp_prime_ts` ue(v) — 0..=8, coded only when transform
    /// skip or palette is enabled.
    pub sps_min_qp_prime_ts: u32,
    /// `sps_ibc_enabled_flag` u(1).
    pub sps_ibc_enabled_flag: u8,
    /// `sps_six_minus_max_num_ibc_merge_cand` ue(v) — 0..=5, coded
    /// only when IBC is enabled.
    pub sps_six_minus_max_num_ibc_merge_cand: u32,
    /// LADF block — present iff `sps_ladf_enabled_flag`.
    pub ladf: Option<VvcLadf>,
    /// `sps_explicit_scaling_list_enabled_flag` u(1).
    pub sps_explicit_scaling_list_enabled_flag: u8,
    /// `sps_scaling_matrix_for_lfnst_disabled_flag` u(1) — coded only
    /// when LFNST and explicit scaling lists are both enabled;
    /// inferred 0.
    pub sps_scaling_matrix_for_lfnst_disabled_flag: u8,
    /// `sps_scaling_matrix_for_alternative_colour_space_disabled_flag`
    /// u(1) — coded only when ACT and explicit scaling lists are both
    /// enabled; inferred 0.
    pub sps_scaling_matrix_for_alternative_colour_space_disabled_flag: u8,
    /// `sps_scaling_matrix_designated_colour_space_flag` u(1) — coded
    /// only when the previous flag is set; inferred 0.
    pub sps_scaling_matrix_designated_colour_space_flag: u8,
    /// `sps_dep_quant_enabled_flag` u(1).
    pub sps_dep_quant_enabled_flag: u8,
    /// `sps_sign_data_hiding_enabled_flag` u(1).
    pub sps_sign_data_hiding_enabled_flag: u8,
    /// `sps_virtual_boundaries_enabled_flag` u(1).
    pub sps_virtual_boundaries_enabled_flag: u8,
    /// `sps_virtual_boundaries_present_flag` u(1) — coded only when
    /// virtual boundaries are enabled; inferred 0.
    pub sps_virtual_boundaries_present_flag: u8,
    /// `sps_virtual_boundary_pos_x_minus1[i]` ue(v) — ≤ 3 entries.
    pub sps_virtual_boundary_pos_x_minus1: Vec<u32>,
    /// `sps_virtual_boundary_pos_y_minus1[i]` ue(v) — ≤ 3 entries.
    pub sps_virtual_boundary_pos_y_minus1: Vec<u32>,
    /// Timing/HRD block — present iff
    /// `sps_timing_hrd_params_present_flag` (which itself is only
    /// coded when `sps_ptl_dpb_hrd_params_present_flag`).
    pub timing_hrd: Option<VvcSpsTimingHrd>,
    /// `sps_field_seq_flag` u(1).
    pub sps_field_seq_flag: u8,
    /// Raw `vui_payload()` bytes (`sps_vui_payload_size_minus1 + 1`
    /// of them, 1..=1024) — present iff
    /// `sps_vui_parameters_present_flag`. Preserved opaquely; §7.3.2.4
    /// byte-aligns before the payload so the block round-trips
    /// byte-exactly without VUI field parsing.
    pub vui_payload: Option<Vec<u8>>,
    /// `sps_extension_flag` u(1).
    pub sps_extension_flag: u8,
    /// `sps_range_extension()` — present iff `sps_range_extension_flag`
    /// (only coded when `sps_extension_flag`).
    pub range_extension: Option<VvcSpsRangeExtension>,
    /// `sps_extension_7bits` u(7) — coded only when
    /// `sps_extension_flag`; inferred 0.
    pub sps_extension_7bits: u8,
    /// `sps_extension_data_flag` bits (0/1 each) — the
    /// `more_rbsp_data()`-driven tail present when
    /// `sps_extension_7bits != 0`. Retained verbatim so the writer
    /// stays byte-exact.
    pub sps_extension_data: Vec<u8>,
}

impl VvcSps {
    /// `CtbLog2SizeY = sps_log2_ctu_size_minus5 + 5` (§7.4.3.4).
    pub fn ctb_log2_size_y(&self) -> u32 {
        self.sps_log2_ctu_size_minus5 as u32 + 5
    }

    /// `CtbSizeY = 1 << CtbLog2SizeY`.
    pub fn ctb_size_y(&self) -> u32 {
        1u32 << self.ctb_log2_size_y()
    }

    /// Effective sample bit depth (`8 + sps_bitdepth_minus8`).
    pub fn bit_depth(&self) -> u32 {
        8 + self.sps_bitdepth_minus8
    }

    /// Width of `ph_pic_order_cnt_lsb` in bits (§7.4.3.4 / §7.4.3.8):
    /// `sps_log2_max_pic_order_cnt_lsb_minus4 + 4`.
    pub fn poc_lsb_width(&self) -> u32 {
        self.sps_log2_max_pic_order_cnt_lsb_minus4 as u32 + 4
    }

    /// `MaxPicOrderCntLsb = 1 << poc_lsb_width()` (§7.4.3.4).
    pub fn max_pic_order_cnt_lsb(&self) -> u32 {
        1u32 << self.poc_lsb_width()
    }

    /// `sps_ptl_dpb_hrd_params_present_flag` — in this representation
    /// the flag is carried by the presence of
    /// [`VvcSps::profile_tier_level`] / [`VvcSps::dpb_parameters`].
    pub fn ptl_dpb_hrd_params_present(&self) -> bool {
        self.profile_tier_level.is_some()
    }

    /// `MaxNumMergeCand = 6 - sps_six_minus_max_num_merge_cand`
    /// (§7.4.3.4).
    pub fn max_num_merge_cand(&self) -> u32 {
        6 - self.sps_six_minus_max_num_merge_cand.min(5)
    }

    /// `(sps_pic_width_max_in_luma_samples + CtbSizeY - 1) / CtbSizeY`
    /// — the picture width in CTUs (`tmpWidthVal`, §7.4.3.4).
    pub fn pic_width_in_ctbs(&self) -> u64 {
        (self.sps_pic_width_max_in_luma_samples as u64).div_ceil(self.ctb_size_y() as u64)
    }

    /// `tmpHeightVal` (§7.4.3.4) — the picture height in CTUs.
    pub fn pic_height_in_ctbs(&self) -> u64 {
        (self.sps_pic_height_max_in_luma_samples as u64).div_ceil(self.ctb_size_y() as u64)
    }
}

// ─────────────────────────── parse_sps ───────────────────────────────────────

/// Parse a complete VVC SPS NAL (two-byte NAL header at index 0..1)
/// per §7.3.2.4, through `rbsp_trailing_bits()`.
///
/// The input slice MUST point at the start of the NAL body (i.e.
/// after [`super::split_annex_b`]). Emulation-prevention bytes are
/// stripped via [`ebsp_to_rbsp`] before bit-level parsing. Every
/// syntax element is retained (or spec-inferred when absent), and the
/// declared §7.4 value ranges are enforced, so [`write_sps`]
/// round-trips the RBSP byte-exactly.
pub fn parse_sps(nal_body: &[u8]) -> Result<VvcSps, BitstreamError> {
    if nal_body.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "H.266 SPS NAL needs at least the 2-byte header",
        ));
    }
    let header = parse_nal_header(nal_body)?;
    if header.nal_unit_type != NAL_TYPE_SPS {
        return Err(BitstreamError::invalid(format!(
            "expected SPS NAL (type {}), got {}",
            NAL_TYPE_SPS, header.nal_unit_type
        )));
    }
    let rbsp = ebsp_to_rbsp(&nal_body[2..]);
    let mut r = BitReader::new(&rbsp);
    let mut s = VvcSps {
        sps_seq_parameter_set_id: r.u(4) as u8,
        sps_video_parameter_set_id: r.u(4) as u8,
        sps_max_sublayers_minus1: r.u(3) as u8,
        sps_chroma_format_idc: r.u(2) as u8,
        sps_log2_ctu_size_minus5: r.u(2) as u8,
        ..Default::default()
    };
    if s.sps_max_sublayers_minus1 > 6 {
        return Err(BitstreamError::invalid(
            "sps_max_sublayers_minus1 = 7 is reserved (7.4.3.4)",
        ));
    }
    if s.sps_log2_ctu_size_minus5 > 2 {
        return Err(BitstreamError::invalid(format!(
            "sps_log2_ctu_size_minus5 = {} > 2 (spec range 0..=2)",
            s.sps_log2_ctu_size_minus5
        )));
    }
    let ptl_present = r.u(1) != 0;
    if ptl_present {
        s.profile_tier_level = Some(parse_profile_tier_level(
            &mut r,
            true,
            s.sps_max_sublayers_minus1 as u32,
        )?);
    }
    s.sps_gdr_enabled_flag = r.u(1) as u8;
    s.sps_ref_pic_resampling_enabled_flag = r.u(1) as u8;
    if s.sps_ref_pic_resampling_enabled_flag != 0 {
        s.sps_res_change_in_clvs_allowed_flag = r.u(1) as u8;
    }
    s.sps_pic_width_max_in_luma_samples = r.ue()?;
    s.sps_pic_height_max_in_luma_samples = r.ue()?;
    if s.sps_pic_width_max_in_luma_samples == 0 || s.sps_pic_height_max_in_luma_samples == 0 {
        return Err(BitstreamError::invalid(
            "sps_pic_width/height_max_in_luma_samples must be > 0 (7.4.3.4)",
        ));
    }
    if r.u(1) != 0 {
        // sps_conformance_window_flag
        let l = r.ue()?;
        let rt = r.ue()?;
        let t = r.ue()?;
        let b = r.ue()?;
        s.sps_conf_win_offsets = Some((l, rt, t, b));
    }
    let tmp_w = s.pic_width_in_ctbs();
    let tmp_h = s.pic_height_in_ctbs();
    if r.u(1) != 0 {
        // sps_subpic_info_present_flag
        s.subpic_info = Some(parse_subpic_info(&mut r, tmp_w, tmp_h)?);
    }
    s.sps_bitdepth_minus8 = r.ue()?;
    if s.sps_bitdepth_minus8 > 8 {
        return Err(BitstreamError::invalid(format!(
            "sps_bitdepth_minus8 = {} > 8 (BitDepth ≤ 16)",
            s.sps_bitdepth_minus8
        )));
    }
    s.sps_entropy_coding_sync_enabled_flag = r.u(1) as u8;
    s.sps_entry_point_offsets_present_flag = r.u(1) as u8;
    s.sps_log2_max_pic_order_cnt_lsb_minus4 = r.u(4) as u8;
    if s.sps_log2_max_pic_order_cnt_lsb_minus4 > SPS_LOG2_MAX_PIC_ORDER_CNT_LSB_MINUS4_MAX {
        return Err(BitstreamError::invalid(format!(
            "sps_log2_max_pic_order_cnt_lsb_minus4 = {} > {SPS_LOG2_MAX_PIC_ORDER_CNT_LSB_MINUS4_MAX} (MaxPicOrderCntLsb ≤ 2^16)",
            s.sps_log2_max_pic_order_cnt_lsb_minus4
        )));
    }
    if r.u(1) != 0 {
        // sps_poc_msb_cycle_flag
        let len = r.ue()?;
        let max = 32 - s.sps_log2_max_pic_order_cnt_lsb_minus4 as u32 - 5;
        if len > max {
            return Err(BitstreamError::invalid(format!(
                "sps_poc_msb_cycle_len_minus1 = {len} > {max} (7.4.3.4)"
            )));
        }
        s.sps_poc_msb_cycle_len_minus1 = Some(len);
    }
    let num_extra_ph_bytes = r.u(2);
    if num_extra_ph_bytes > 2 {
        return Err(BitstreamError::invalid(
            "sps_num_extra_ph_bytes = 3 is outside this version's envelope (7.4.3.4)",
        ));
    }
    s.sps_extra_ph_bit_present_flags = (0..num_extra_ph_bytes * 8).map(|_| r.u(1) as u8).collect();
    let num_extra_sh_bytes = r.u(2);
    if num_extra_sh_bytes > 2 {
        return Err(BitstreamError::invalid(
            "sps_num_extra_sh_bytes = 3 is outside this version's envelope (7.4.3.4)",
        ));
    }
    s.sps_extra_sh_bit_present_flags = (0..num_extra_sh_bytes * 8).map(|_| r.u(1) as u8).collect();
    if ptl_present {
        if s.sps_max_sublayers_minus1 > 0 {
            s.sps_sublayer_dpb_params_flag = r.u(1) as u8;
        }
        s.dpb_parameters = Some(parse_dpb_parameters(
            &mut r,
            s.sps_max_sublayers_minus1 as u32,
            s.sps_sublayer_dpb_params_flag != 0,
        )?);
    }
    s.sps_log2_min_luma_coding_block_size_minus2 = r.ue()?;
    let min_cb_log2 = s.sps_log2_min_luma_coding_block_size_minus2 + 2;
    if min_cb_log2 > 6.min(s.ctb_log2_size_y()) {
        return Err(BitstreamError::invalid(format!(
            "MinCbLog2SizeY = {min_cb_log2} > Min(6, CtbLog2SizeY = {}) (7.4.3.4)",
            s.ctb_log2_size_y()
        )));
    }
    s.sps_partition_constraints_override_enabled_flag = r.u(1) as u8;
    s.sps_log2_diff_min_qt_min_cb_intra_slice_luma = r.ue()?;
    s.sps_max_mtt_hierarchy_depth_intra_slice_luma = r.ue()?;
    if s.sps_max_mtt_hierarchy_depth_intra_slice_luma != 0 {
        s.sps_log2_diff_max_bt_min_qt_intra_slice_luma = r.ue()?;
        s.sps_log2_diff_max_tt_min_qt_intra_slice_luma = r.ue()?;
    }
    if s.sps_chroma_format_idc != 0 {
        s.sps_qtbtt_dual_tree_intra_flag = r.u(1) as u8;
    }
    if s.sps_qtbtt_dual_tree_intra_flag != 0 {
        s.sps_log2_diff_min_qt_min_cb_intra_slice_chroma = r.ue()?;
        s.sps_max_mtt_hierarchy_depth_intra_slice_chroma = r.ue()?;
        if s.sps_max_mtt_hierarchy_depth_intra_slice_chroma != 0 {
            s.sps_log2_diff_max_bt_min_qt_intra_slice_chroma = r.ue()?;
            s.sps_log2_diff_max_tt_min_qt_intra_slice_chroma = r.ue()?;
        }
    }
    s.sps_log2_diff_min_qt_min_cb_inter_slice = r.ue()?;
    s.sps_max_mtt_hierarchy_depth_inter_slice = r.ue()?;
    if s.sps_max_mtt_hierarchy_depth_inter_slice != 0 {
        s.sps_log2_diff_max_bt_min_qt_inter_slice = r.ue()?;
        s.sps_log2_diff_max_tt_min_qt_inter_slice = r.ue()?;
    }
    if s.ctb_size_y() > 32 {
        s.sps_max_luma_transform_size_64_flag = r.u(1) as u8;
    }
    s.sps_transform_skip_enabled_flag = r.u(1) as u8;
    if s.sps_transform_skip_enabled_flag != 0 {
        s.sps_log2_transform_skip_max_size_minus2 = r.ue()?;
        if s.sps_log2_transform_skip_max_size_minus2 > 3 {
            return Err(BitstreamError::invalid(format!(
                "sps_log2_transform_skip_max_size_minus2 = {} > 3 (7.4.3.4)",
                s.sps_log2_transform_skip_max_size_minus2
            )));
        }
        s.sps_bdpcm_enabled_flag = r.u(1) as u8;
    }
    s.sps_mts_enabled_flag = r.u(1) as u8;
    if s.sps_mts_enabled_flag != 0 {
        s.sps_explicit_mts_intra_enabled_flag = r.u(1) as u8;
        s.sps_explicit_mts_inter_enabled_flag = r.u(1) as u8;
    }
    s.sps_lfnst_enabled_flag = r.u(1) as u8;
    s.sps_same_qp_table_for_chroma_flag = 1; // inferred (§7.4.3.4)
    if s.sps_chroma_format_idc != 0 {
        s.sps_joint_cbcr_enabled_flag = r.u(1) as u8;
        s.sps_same_qp_table_for_chroma_flag = r.u(1) as u8;
        let num_qp_tables = if s.sps_same_qp_table_for_chroma_flag != 0 {
            1
        } else if s.sps_joint_cbcr_enabled_flag != 0 {
            3
        } else {
            2
        };
        let qp_bd_offset = 6 * s.sps_bitdepth_minus8 as i32;
        for _ in 0..num_qp_tables {
            let start = r.se()?;
            if start < -26 - qp_bd_offset || start > 36 {
                return Err(BitstreamError::invalid(format!(
                    "sps_qp_table_start_minus26 = {start} outside -26 - QpBdOffset ..= 36 (7.4.3.4)"
                )));
            }
            let num_points_minus1 = r.ue()?;
            if num_points_minus1 as i64 > 36 - start as i64 {
                return Err(BitstreamError::invalid(format!(
                    "sps_num_points_in_qp_table_minus1 = {num_points_minus1} > 36 - start (7.4.3.4)"
                )));
            }
            let mut points = Vec::with_capacity(num_points_minus1 as usize + 1);
            for _ in 0..=num_points_minus1 {
                let in_val = r.ue()?;
                let diff_val = r.ue()?;
                points.push((in_val, diff_val));
            }
            s.chroma_qp_tables.push(VvcChromaQpTable {
                sps_qp_table_start_minus26: start,
                points,
            });
        }
    }
    s.sps_sao_enabled_flag = r.u(1) as u8;
    s.sps_alf_enabled_flag = r.u(1) as u8;
    if s.sps_alf_enabled_flag != 0 && s.sps_chroma_format_idc != 0 {
        s.sps_ccalf_enabled_flag = r.u(1) as u8;
    }
    s.sps_lmcs_enabled_flag = r.u(1) as u8;
    s.sps_weighted_pred_flag = r.u(1) as u8;
    s.sps_weighted_bipred_flag = r.u(1) as u8;
    s.sps_long_term_ref_pics_flag = r.u(1) as u8;
    if s.sps_video_parameter_set_id > 0 {
        s.sps_inter_layer_prediction_enabled_flag = r.u(1) as u8;
    }
    s.sps_idr_rpl_present_flag = r.u(1) as u8;
    s.sps_rpl1_same_as_rpl0_flag = r.u(1) as u8;
    let rpls_ctx = VvcRplsContext {
        long_term_ref_pics: s.sps_long_term_ref_pics_flag != 0,
        inter_layer_prediction: s.sps_inter_layer_prediction_enabled_flag != 0,
        in_sps_list: true,
    };
    let num_lists = if s.sps_rpl1_same_as_rpl0_flag != 0 {
        1
    } else {
        2
    };
    for list in 0..num_lists {
        let num_rpls = r.ue()?;
        if num_rpls > 64 {
            return Err(BitstreamError::invalid(format!(
                "sps_num_ref_pic_lists[{list}] = {num_rpls} > 64 (7.4.3.4)"
            )));
        }
        for _ in 0..num_rpls {
            let rpls = parse_ref_pic_list_struct(&mut r, &rpls_ctx, s.poc_lsb_width())?;
            s.sps_ref_pic_lists[list].push(rpls);
        }
    }
    s.sps_ref_wraparound_enabled_flag = r.u(1) as u8;
    s.sps_temporal_mvp_enabled_flag = r.u(1) as u8;
    if s.sps_temporal_mvp_enabled_flag != 0 {
        s.sps_sbtmvp_enabled_flag = r.u(1) as u8;
    }
    s.sps_amvr_enabled_flag = r.u(1) as u8;
    s.sps_bdof_enabled_flag = r.u(1) as u8;
    if s.sps_bdof_enabled_flag != 0 {
        s.sps_bdof_control_present_in_ph_flag = r.u(1) as u8;
    }
    s.sps_smvd_enabled_flag = r.u(1) as u8;
    s.sps_dmvr_enabled_flag = r.u(1) as u8;
    if s.sps_dmvr_enabled_flag != 0 {
        s.sps_dmvr_control_present_in_ph_flag = r.u(1) as u8;
    }
    s.sps_mmvd_enabled_flag = r.u(1) as u8;
    if s.sps_mmvd_enabled_flag != 0 {
        s.sps_mmvd_fullpel_only_enabled_flag = r.u(1) as u8;
    }
    s.sps_six_minus_max_num_merge_cand = r.ue()?;
    if s.sps_six_minus_max_num_merge_cand > 5 {
        return Err(BitstreamError::invalid(format!(
            "sps_six_minus_max_num_merge_cand = {} > 5 (7.4.3.4)",
            s.sps_six_minus_max_num_merge_cand
        )));
    }
    s.sps_sbt_enabled_flag = r.u(1) as u8;
    s.sps_affine_enabled_flag = r.u(1) as u8;
    if s.sps_affine_enabled_flag != 0 {
        s.sps_five_minus_max_num_subblock_merge_cand = r.ue()?;
        if s.sps_five_minus_max_num_subblock_merge_cand > 5 - s.sps_sbtmvp_enabled_flag as u32 {
            return Err(BitstreamError::invalid(format!(
                "sps_five_minus_max_num_subblock_merge_cand = {} > 5 - sps_sbtmvp_enabled_flag (7.4.3.4)",
                s.sps_five_minus_max_num_subblock_merge_cand
            )));
        }
        s.sps_6param_affine_enabled_flag = r.u(1) as u8;
        if s.sps_amvr_enabled_flag != 0 {
            s.sps_affine_amvr_enabled_flag = r.u(1) as u8;
        }
        s.sps_affine_prof_enabled_flag = r.u(1) as u8;
        if s.sps_affine_prof_enabled_flag != 0 {
            s.sps_prof_control_present_in_ph_flag = r.u(1) as u8;
        }
    }
    s.sps_bcw_enabled_flag = r.u(1) as u8;
    s.sps_ciip_enabled_flag = r.u(1) as u8;
    let max_merge = s.max_num_merge_cand();
    if max_merge >= 2 {
        s.sps_gpm_enabled_flag = r.u(1) as u8;
        if s.sps_gpm_enabled_flag != 0 && max_merge >= 3 {
            s.sps_max_num_merge_cand_minus_max_num_gpm_cand = r.ue()?;
            if s.sps_max_num_merge_cand_minus_max_num_gpm_cand > max_merge - 2 {
                return Err(BitstreamError::invalid(format!(
                    "sps_max_num_merge_cand_minus_max_num_gpm_cand = {} > MaxNumMergeCand - 2 (7.4.3.4)",
                    s.sps_max_num_merge_cand_minus_max_num_gpm_cand
                )));
            }
        }
    }
    s.sps_log2_parallel_merge_level_minus2 = r.ue()?;
    if s.sps_log2_parallel_merge_level_minus2 > s.ctb_log2_size_y() - 2 {
        return Err(BitstreamError::invalid(format!(
            "sps_log2_parallel_merge_level_minus2 = {} > CtbLog2SizeY - 2 (7.4.3.4)",
            s.sps_log2_parallel_merge_level_minus2
        )));
    }
    s.sps_isp_enabled_flag = r.u(1) as u8;
    s.sps_mrl_enabled_flag = r.u(1) as u8;
    s.sps_mip_enabled_flag = r.u(1) as u8;
    s.sps_chroma_horizontal_collocated_flag = 1; // inferred (§7.4.3.4)
    s.sps_chroma_vertical_collocated_flag = 1; // inferred (§7.4.3.4)
    if s.sps_chroma_format_idc != 0 {
        s.sps_cclm_enabled_flag = r.u(1) as u8;
    }
    if s.sps_chroma_format_idc == 1 {
        s.sps_chroma_horizontal_collocated_flag = r.u(1) as u8;
        s.sps_chroma_vertical_collocated_flag = r.u(1) as u8;
    }
    s.sps_palette_enabled_flag = r.u(1) as u8;
    if s.sps_chroma_format_idc == 3 && s.sps_max_luma_transform_size_64_flag == 0 {
        s.sps_act_enabled_flag = r.u(1) as u8;
    }
    if s.sps_transform_skip_enabled_flag != 0 || s.sps_palette_enabled_flag != 0 {
        s.sps_min_qp_prime_ts = r.ue()?;
        if s.sps_min_qp_prime_ts > 8 {
            return Err(BitstreamError::invalid(format!(
                "sps_min_qp_prime_ts = {} > 8 (7.4.3.4)",
                s.sps_min_qp_prime_ts
            )));
        }
    }
    s.sps_ibc_enabled_flag = r.u(1) as u8;
    if s.sps_ibc_enabled_flag != 0 {
        s.sps_six_minus_max_num_ibc_merge_cand = r.ue()?;
        if s.sps_six_minus_max_num_ibc_merge_cand > 5 {
            return Err(BitstreamError::invalid(format!(
                "sps_six_minus_max_num_ibc_merge_cand = {} > 5 (7.4.3.4)",
                s.sps_six_minus_max_num_ibc_merge_cand
            )));
        }
    }
    if r.u(1) != 0 {
        // sps_ladf_enabled_flag
        let num_intervals_minus2 = r.u(2);
        let sps_ladf_lowest_interval_qp_offset = r.se()?;
        let mut intervals = Vec::with_capacity(num_intervals_minus2 as usize + 1);
        for _ in 0..num_intervals_minus2 + 1 {
            let qp_offset = r.se()?;
            let delta_threshold_minus1 = r.ue()?;
            intervals.push((qp_offset, delta_threshold_minus1));
        }
        s.ladf = Some(VvcLadf {
            sps_ladf_lowest_interval_qp_offset,
            intervals,
        });
    }
    s.sps_explicit_scaling_list_enabled_flag = r.u(1) as u8;
    if s.sps_lfnst_enabled_flag != 0 && s.sps_explicit_scaling_list_enabled_flag != 0 {
        s.sps_scaling_matrix_for_lfnst_disabled_flag = r.u(1) as u8;
    }
    if s.sps_act_enabled_flag != 0 && s.sps_explicit_scaling_list_enabled_flag != 0 {
        s.sps_scaling_matrix_for_alternative_colour_space_disabled_flag = r.u(1) as u8;
    }
    if s.sps_scaling_matrix_for_alternative_colour_space_disabled_flag != 0 {
        s.sps_scaling_matrix_designated_colour_space_flag = r.u(1) as u8;
    }
    s.sps_dep_quant_enabled_flag = r.u(1) as u8;
    s.sps_sign_data_hiding_enabled_flag = r.u(1) as u8;
    s.sps_virtual_boundaries_enabled_flag = r.u(1) as u8;
    if s.sps_virtual_boundaries_enabled_flag != 0 {
        s.sps_virtual_boundaries_present_flag = r.u(1) as u8;
        if s.sps_virtual_boundaries_present_flag != 0 {
            let num_ver = r.ue()?;
            let max_ver = if s.sps_pic_width_max_in_luma_samples <= 8 {
                0
            } else {
                3
            };
            if num_ver > max_ver {
                return Err(BitstreamError::invalid(format!(
                    "sps_num_ver_virtual_boundaries = {num_ver} > {max_ver} (7.4.3.4)"
                )));
            }
            s.sps_virtual_boundary_pos_x_minus1 =
                (0..num_ver).map(|_| r.ue()).collect::<Result<_, _>>()?;
            let num_hor = r.ue()?;
            let max_hor = if s.sps_pic_height_max_in_luma_samples <= 8 {
                0
            } else {
                3
            };
            if num_hor > max_hor {
                return Err(BitstreamError::invalid(format!(
                    "sps_num_hor_virtual_boundaries = {num_hor} > {max_hor} (7.4.3.4)"
                )));
            }
            s.sps_virtual_boundary_pos_y_minus1 =
                (0..num_hor).map(|_| r.ue()).collect::<Result<_, _>>()?;
        }
    }
    if ptl_present && r.u(1) != 0 {
        // sps_timing_hrd_params_present_flag
        let general = parse_general_timing_hrd(&mut r)?;
        let mut sublayer_cpb = 0u8;
        if s.sps_max_sublayers_minus1 > 0 {
            sublayer_cpb = r.u(1) as u8;
        }
        let first_sublayer = if sublayer_cpb != 0 {
            0
        } else {
            s.sps_max_sublayers_minus1 as u32
        };
        let ols = parse_ols_timing_hrd(
            &mut r,
            first_sublayer,
            s.sps_max_sublayers_minus1 as u32,
            &general,
        )?;
        s.timing_hrd = Some(VvcSpsTimingHrd {
            general,
            sps_sublayer_cpb_params_present_flag: sublayer_cpb,
            ols,
        });
    }
    s.sps_field_seq_flag = r.u(1) as u8;
    if r.u(1) != 0 {
        // sps_vui_parameters_present_flag
        let size_minus1 = r.ue()?;
        if size_minus1 > 1023 {
            return Err(BitstreamError::invalid(format!(
                "sps_vui_payload_size_minus1 = {size_minus1} > 1023 (7.4.3.4)"
            )));
        }
        while !r.byte_aligned() {
            if r.u(1) != 0 {
                return Err(BitstreamError::invalid(
                    "sps_vui_alignment_zero_bit must be 0 (7.3.2.4)",
                ));
            }
        }
        if r.bits_remaining() < (size_minus1 as usize + 1) * 8 {
            return Err(BitstreamError::unexpected_end(
                "vui_payload() extends past the end of the SPS RBSP",
            ));
        }
        let payload = (0..=size_minus1).map(|_| r.u(8) as u8).collect();
        s.vui_payload = Some(payload);
    }
    s.sps_extension_flag = r.u(1) as u8;
    if s.sps_extension_flag != 0 {
        let range_ext_flag = r.u(1) != 0;
        s.sps_extension_7bits = r.u(7) as u8;
        if range_ext_flag {
            let mut ext = VvcSpsRangeExtension {
                sps_extended_precision_flag: r.u(1) as u8,
                ..Default::default()
            };
            if s.sps_transform_skip_enabled_flag != 0 {
                ext.sps_ts_residual_coding_rice_present_in_sh_flag = r.u(1) as u8;
            }
            ext.sps_rrc_rice_extension_flag = r.u(1) as u8;
            ext.sps_persistent_rice_adaptation_enabled_flag = r.u(1) as u8;
            ext.sps_reverse_last_sig_coeff_enabled_flag = r.u(1) as u8;
            s.range_extension = Some(ext);
        }
    }
    if s.sps_extension_7bits != 0 {
        while r.more_rbsp_data() {
            s.sps_extension_data.push(r.u(1) as u8);
        }
    }
    r.read_rbsp_trailing_bits()?;
    Ok(s)
}

// ─────────────────────────── write_sps ───────────────────────────────────────

/// Emit a `seq_parameter_set_rbsp()` (§7.3.2.4 including
/// `rbsp_trailing_bits()`) — the byte-exact inverse of [`parse_sps`]'s
/// RBSP walk: `write_sps(&parse_sps(nal)?)` reproduces the NAL's RBSP
/// bytes exactly for every input the parser accepts.
pub fn write_sps(s: &VvcSps) -> Result<Vec<u8>, BitstreamError> {
    let mut w = BitWriter::new();
    if s.sps_seq_parameter_set_id > 15 || s.sps_video_parameter_set_id > 15 {
        return Err(BitstreamError::invalid("SPS/VPS id does not fit u(4)"));
    }
    if s.sps_max_sublayers_minus1 > 6 {
        return Err(BitstreamError::invalid(
            "sps_max_sublayers_minus1 = 7 is reserved (7.4.3.4)",
        ));
    }
    if s.sps_chroma_format_idc > 3 || s.sps_log2_ctu_size_minus5 > 2 {
        return Err(BitstreamError::invalid(
            "sps_chroma_format_idc / sps_log2_ctu_size_minus5 out of range",
        ));
    }
    w.write_bits(s.sps_seq_parameter_set_id as u32, 4);
    w.write_bits(s.sps_video_parameter_set_id as u32, 4);
    w.write_bits(s.sps_max_sublayers_minus1 as u32, 3);
    w.write_bits(s.sps_chroma_format_idc as u32, 2);
    w.write_bits(s.sps_log2_ctu_size_minus5 as u32, 2);
    let ptl_present = s.profile_tier_level.is_some();
    w.write_bit(u32::from(ptl_present));
    if let Some(ptl) = &s.profile_tier_level {
        write_profile_tier_level(&mut w, ptl, true, s.sps_max_sublayers_minus1 as u32)?;
    }
    w.write_bit(u32::from(s.sps_gdr_enabled_flag != 0));
    w.write_bit(u32::from(s.sps_ref_pic_resampling_enabled_flag != 0));
    if s.sps_ref_pic_resampling_enabled_flag != 0 {
        w.write_bit(u32::from(s.sps_res_change_in_clvs_allowed_flag != 0));
    }
    if s.sps_pic_width_max_in_luma_samples == 0 || s.sps_pic_height_max_in_luma_samples == 0 {
        return Err(BitstreamError::invalid(
            "sps_pic_width/height_max_in_luma_samples must be > 0 (7.4.3.4)",
        ));
    }
    w.write_ue(s.sps_pic_width_max_in_luma_samples)?;
    w.write_ue(s.sps_pic_height_max_in_luma_samples)?;
    w.write_bit(u32::from(s.sps_conf_win_offsets.is_some()));
    if let Some((l, r_, t, b)) = s.sps_conf_win_offsets {
        w.write_ue(l)?;
        w.write_ue(r_)?;
        w.write_ue(t)?;
        w.write_ue(b)?;
    }
    w.write_bit(u32::from(s.subpic_info.is_some()));
    if let Some(sp) = &s.subpic_info {
        write_subpic_info(&mut w, sp, s.pic_width_in_ctbs(), s.pic_height_in_ctbs())?;
    }
    if s.sps_bitdepth_minus8 > 8 {
        return Err(BitstreamError::invalid(
            "sps_bitdepth_minus8 > 8 (BitDepth ≤ 16)",
        ));
    }
    w.write_ue(s.sps_bitdepth_minus8)?;
    w.write_bit(u32::from(s.sps_entropy_coding_sync_enabled_flag != 0));
    w.write_bit(u32::from(s.sps_entry_point_offsets_present_flag != 0));
    if s.sps_log2_max_pic_order_cnt_lsb_minus4 > SPS_LOG2_MAX_PIC_ORDER_CNT_LSB_MINUS4_MAX {
        return Err(BitstreamError::invalid(
            "sps_log2_max_pic_order_cnt_lsb_minus4 > 12",
        ));
    }
    w.write_bits(s.sps_log2_max_pic_order_cnt_lsb_minus4 as u32, 4);
    w.write_bit(u32::from(s.sps_poc_msb_cycle_len_minus1.is_some()));
    if let Some(len) = s.sps_poc_msb_cycle_len_minus1 {
        let max = 32 - s.sps_log2_max_pic_order_cnt_lsb_minus4 as u32 - 5;
        if len > max {
            return Err(BitstreamError::invalid(format!(
                "sps_poc_msb_cycle_len_minus1 = {len} > {max} (7.4.3.4)"
            )));
        }
        w.write_ue(len)?;
    }
    for (flags, name) in [
        (&s.sps_extra_ph_bit_present_flags, "ph"),
        (&s.sps_extra_sh_bit_present_flags, "sh"),
    ] {
        if flags.len() % 8 != 0 || flags.len() > 16 {
            return Err(BitstreamError::invalid(format!(
                "sps_extra_{name}_bit_present_flags length must be 0, 8 or 16 bits"
            )));
        }
        w.write_bits((flags.len() / 8) as u32, 2);
        for &bit in flags.iter() {
            w.write_bit(u32::from(bit != 0));
        }
    }
    match (&s.dpb_parameters, ptl_present) {
        (Some(dpb), true) => {
            if s.sps_max_sublayers_minus1 > 0 {
                w.write_bit(u32::from(s.sps_sublayer_dpb_params_flag != 0));
            }
            write_dpb_parameters(
                &mut w,
                dpb,
                s.sps_max_sublayers_minus1 as u32,
                s.sps_sublayer_dpb_params_flag != 0,
            )?;
        }
        (None, false) => {}
        _ => {
            return Err(BitstreamError::invalid(
                "dpb_parameters must be present iff profile_tier_level is (7.3.2.4)",
            ));
        }
    }
    let min_cb_log2 = s.sps_log2_min_luma_coding_block_size_minus2 + 2;
    if min_cb_log2 > 6.min(s.ctb_log2_size_y()) {
        return Err(BitstreamError::invalid(
            "MinCbLog2SizeY > Min(6, CtbLog2SizeY) (7.4.3.4)",
        ));
    }
    w.write_ue(s.sps_log2_min_luma_coding_block_size_minus2)?;
    w.write_bit(u32::from(
        s.sps_partition_constraints_override_enabled_flag != 0,
    ));
    w.write_ue(s.sps_log2_diff_min_qt_min_cb_intra_slice_luma)?;
    w.write_ue(s.sps_max_mtt_hierarchy_depth_intra_slice_luma)?;
    if s.sps_max_mtt_hierarchy_depth_intra_slice_luma != 0 {
        w.write_ue(s.sps_log2_diff_max_bt_min_qt_intra_slice_luma)?;
        w.write_ue(s.sps_log2_diff_max_tt_min_qt_intra_slice_luma)?;
    }
    if s.sps_chroma_format_idc != 0 {
        w.write_bit(u32::from(s.sps_qtbtt_dual_tree_intra_flag != 0));
    }
    if s.sps_qtbtt_dual_tree_intra_flag != 0 {
        if s.sps_chroma_format_idc == 0 {
            return Err(BitstreamError::invalid(
                "sps_qtbtt_dual_tree_intra_flag requires chroma (7.3.2.4)",
            ));
        }
        w.write_ue(s.sps_log2_diff_min_qt_min_cb_intra_slice_chroma)?;
        w.write_ue(s.sps_max_mtt_hierarchy_depth_intra_slice_chroma)?;
        if s.sps_max_mtt_hierarchy_depth_intra_slice_chroma != 0 {
            w.write_ue(s.sps_log2_diff_max_bt_min_qt_intra_slice_chroma)?;
            w.write_ue(s.sps_log2_diff_max_tt_min_qt_intra_slice_chroma)?;
        }
    }
    w.write_ue(s.sps_log2_diff_min_qt_min_cb_inter_slice)?;
    w.write_ue(s.sps_max_mtt_hierarchy_depth_inter_slice)?;
    if s.sps_max_mtt_hierarchy_depth_inter_slice != 0 {
        w.write_ue(s.sps_log2_diff_max_bt_min_qt_inter_slice)?;
        w.write_ue(s.sps_log2_diff_max_tt_min_qt_inter_slice)?;
    }
    if s.ctb_size_y() > 32 {
        w.write_bit(u32::from(s.sps_max_luma_transform_size_64_flag != 0));
    }
    w.write_bit(u32::from(s.sps_transform_skip_enabled_flag != 0));
    if s.sps_transform_skip_enabled_flag != 0 {
        if s.sps_log2_transform_skip_max_size_minus2 > 3 {
            return Err(BitstreamError::invalid(
                "sps_log2_transform_skip_max_size_minus2 > 3 (7.4.3.4)",
            ));
        }
        w.write_ue(s.sps_log2_transform_skip_max_size_minus2)?;
        w.write_bit(u32::from(s.sps_bdpcm_enabled_flag != 0));
    }
    w.write_bit(u32::from(s.sps_mts_enabled_flag != 0));
    if s.sps_mts_enabled_flag != 0 {
        w.write_bit(u32::from(s.sps_explicit_mts_intra_enabled_flag != 0));
        w.write_bit(u32::from(s.sps_explicit_mts_inter_enabled_flag != 0));
    }
    w.write_bit(u32::from(s.sps_lfnst_enabled_flag != 0));
    if s.sps_chroma_format_idc != 0 {
        w.write_bit(u32::from(s.sps_joint_cbcr_enabled_flag != 0));
        w.write_bit(u32::from(s.sps_same_qp_table_for_chroma_flag != 0));
        let num_qp_tables = if s.sps_same_qp_table_for_chroma_flag != 0 {
            1
        } else if s.sps_joint_cbcr_enabled_flag != 0 {
            3
        } else {
            2
        };
        if s.chroma_qp_tables.len() != num_qp_tables {
            return Err(BitstreamError::invalid(format!(
                "chroma_qp_tables count {} != numQpTables = {num_qp_tables} (7.3.2.4)",
                s.chroma_qp_tables.len()
            )));
        }
        let qp_bd_offset = 6 * s.sps_bitdepth_minus8 as i32;
        for t in &s.chroma_qp_tables {
            let start = t.sps_qp_table_start_minus26;
            if start < -26 - qp_bd_offset || start > 36 {
                return Err(BitstreamError::invalid(
                    "sps_qp_table_start_minus26 outside -26 - QpBdOffset ..= 36 (7.4.3.4)",
                ));
            }
            if t.points.is_empty() || t.points.len() as i64 - 1 > 36 - start as i64 {
                return Err(BitstreamError::invalid(
                    "chroma QP table point count out of range (7.4.3.4)",
                ));
            }
            w.write_se(start)?;
            w.write_ue(t.points.len() as u32 - 1)?;
            for &(in_val, diff_val) in &t.points {
                w.write_ue(in_val)?;
                w.write_ue(diff_val)?;
            }
        }
    } else if !s.chroma_qp_tables.is_empty() {
        return Err(BitstreamError::invalid(
            "chroma_qp_tables must be empty for monochrome (7.3.2.4)",
        ));
    }
    w.write_bit(u32::from(s.sps_sao_enabled_flag != 0));
    w.write_bit(u32::from(s.sps_alf_enabled_flag != 0));
    if s.sps_alf_enabled_flag != 0 && s.sps_chroma_format_idc != 0 {
        w.write_bit(u32::from(s.sps_ccalf_enabled_flag != 0));
    }
    w.write_bit(u32::from(s.sps_lmcs_enabled_flag != 0));
    w.write_bit(u32::from(s.sps_weighted_pred_flag != 0));
    w.write_bit(u32::from(s.sps_weighted_bipred_flag != 0));
    w.write_bit(u32::from(s.sps_long_term_ref_pics_flag != 0));
    if s.sps_video_parameter_set_id > 0 {
        w.write_bit(u32::from(s.sps_inter_layer_prediction_enabled_flag != 0));
    }
    w.write_bit(u32::from(s.sps_idr_rpl_present_flag != 0));
    w.write_bit(u32::from(s.sps_rpl1_same_as_rpl0_flag != 0));
    let rpls_ctx = VvcRplsContext {
        long_term_ref_pics: s.sps_long_term_ref_pics_flag != 0,
        inter_layer_prediction: s.sps_inter_layer_prediction_enabled_flag != 0,
        in_sps_list: true,
    };
    let num_lists = if s.sps_rpl1_same_as_rpl0_flag != 0 {
        1
    } else {
        2
    };
    if s.sps_rpl1_same_as_rpl0_flag != 0 && !s.sps_ref_pic_lists[1].is_empty() {
        return Err(BitstreamError::invalid(
            "sps_ref_pic_lists[1] must be empty when sps_rpl1_same_as_rpl0_flag (7.3.2.4)",
        ));
    }
    for list in s.sps_ref_pic_lists.iter().take(num_lists) {
        if list.len() > 64 {
            return Err(BitstreamError::invalid(
                "sps_num_ref_pic_lists > 64 (7.4.3.4)",
            ));
        }
        w.write_ue(list.len() as u32)?;
        for rpls in list {
            write_ref_pic_list_struct(&mut w, rpls, &rpls_ctx, s.poc_lsb_width())?;
        }
    }
    w.write_bit(u32::from(s.sps_ref_wraparound_enabled_flag != 0));
    w.write_bit(u32::from(s.sps_temporal_mvp_enabled_flag != 0));
    if s.sps_temporal_mvp_enabled_flag != 0 {
        w.write_bit(u32::from(s.sps_sbtmvp_enabled_flag != 0));
    }
    w.write_bit(u32::from(s.sps_amvr_enabled_flag != 0));
    w.write_bit(u32::from(s.sps_bdof_enabled_flag != 0));
    if s.sps_bdof_enabled_flag != 0 {
        w.write_bit(u32::from(s.sps_bdof_control_present_in_ph_flag != 0));
    }
    w.write_bit(u32::from(s.sps_smvd_enabled_flag != 0));
    w.write_bit(u32::from(s.sps_dmvr_enabled_flag != 0));
    if s.sps_dmvr_enabled_flag != 0 {
        w.write_bit(u32::from(s.sps_dmvr_control_present_in_ph_flag != 0));
    }
    w.write_bit(u32::from(s.sps_mmvd_enabled_flag != 0));
    if s.sps_mmvd_enabled_flag != 0 {
        w.write_bit(u32::from(s.sps_mmvd_fullpel_only_enabled_flag != 0));
    }
    if s.sps_six_minus_max_num_merge_cand > 5 {
        return Err(BitstreamError::invalid(
            "sps_six_minus_max_num_merge_cand > 5 (7.4.3.4)",
        ));
    }
    w.write_ue(s.sps_six_minus_max_num_merge_cand)?;
    w.write_bit(u32::from(s.sps_sbt_enabled_flag != 0));
    w.write_bit(u32::from(s.sps_affine_enabled_flag != 0));
    if s.sps_affine_enabled_flag != 0 {
        w.write_ue(s.sps_five_minus_max_num_subblock_merge_cand)?;
        w.write_bit(u32::from(s.sps_6param_affine_enabled_flag != 0));
        if s.sps_amvr_enabled_flag != 0 {
            w.write_bit(u32::from(s.sps_affine_amvr_enabled_flag != 0));
        }
        w.write_bit(u32::from(s.sps_affine_prof_enabled_flag != 0));
        if s.sps_affine_prof_enabled_flag != 0 {
            w.write_bit(u32::from(s.sps_prof_control_present_in_ph_flag != 0));
        }
    }
    w.write_bit(u32::from(s.sps_bcw_enabled_flag != 0));
    w.write_bit(u32::from(s.sps_ciip_enabled_flag != 0));
    let max_merge = s.max_num_merge_cand();
    if max_merge >= 2 {
        w.write_bit(u32::from(s.sps_gpm_enabled_flag != 0));
        if s.sps_gpm_enabled_flag != 0 && max_merge >= 3 {
            if s.sps_max_num_merge_cand_minus_max_num_gpm_cand > max_merge - 2 {
                return Err(BitstreamError::invalid(
                    "sps_max_num_merge_cand_minus_max_num_gpm_cand > MaxNumMergeCand - 2",
                ));
            }
            w.write_ue(s.sps_max_num_merge_cand_minus_max_num_gpm_cand)?;
        }
    }
    if s.sps_log2_parallel_merge_level_minus2 > s.ctb_log2_size_y() - 2 {
        return Err(BitstreamError::invalid(
            "sps_log2_parallel_merge_level_minus2 > CtbLog2SizeY - 2 (7.4.3.4)",
        ));
    }
    w.write_ue(s.sps_log2_parallel_merge_level_minus2)?;
    w.write_bit(u32::from(s.sps_isp_enabled_flag != 0));
    w.write_bit(u32::from(s.sps_mrl_enabled_flag != 0));
    w.write_bit(u32::from(s.sps_mip_enabled_flag != 0));
    if s.sps_chroma_format_idc != 0 {
        w.write_bit(u32::from(s.sps_cclm_enabled_flag != 0));
    }
    if s.sps_chroma_format_idc == 1 {
        w.write_bit(u32::from(s.sps_chroma_horizontal_collocated_flag != 0));
        w.write_bit(u32::from(s.sps_chroma_vertical_collocated_flag != 0));
    }
    w.write_bit(u32::from(s.sps_palette_enabled_flag != 0));
    if s.sps_chroma_format_idc == 3 && s.sps_max_luma_transform_size_64_flag == 0 {
        w.write_bit(u32::from(s.sps_act_enabled_flag != 0));
    }
    if s.sps_transform_skip_enabled_flag != 0 || s.sps_palette_enabled_flag != 0 {
        if s.sps_min_qp_prime_ts > 8 {
            return Err(BitstreamError::invalid("sps_min_qp_prime_ts > 8 (7.4.3.4)"));
        }
        w.write_ue(s.sps_min_qp_prime_ts)?;
    }
    w.write_bit(u32::from(s.sps_ibc_enabled_flag != 0));
    if s.sps_ibc_enabled_flag != 0 {
        if s.sps_six_minus_max_num_ibc_merge_cand > 5 {
            return Err(BitstreamError::invalid(
                "sps_six_minus_max_num_ibc_merge_cand > 5 (7.4.3.4)",
            ));
        }
        w.write_ue(s.sps_six_minus_max_num_ibc_merge_cand)?;
    }
    w.write_bit(u32::from(s.ladf.is_some()));
    if let Some(ladf) = &s.ladf {
        if ladf.intervals.is_empty() || ladf.intervals.len() > 4 {
            return Err(BitstreamError::invalid(
                "LADF interval count must be 1..=4 (sps_num_ladf_intervals_minus2 is u(2))",
            ));
        }
        w.write_bits(ladf.intervals.len() as u32 - 1, 2);
        w.write_se(ladf.sps_ladf_lowest_interval_qp_offset)?;
        for &(qp_offset, delta_threshold_minus1) in &ladf.intervals {
            w.write_se(qp_offset)?;
            w.write_ue(delta_threshold_minus1)?;
        }
    }
    w.write_bit(u32::from(s.sps_explicit_scaling_list_enabled_flag != 0));
    if s.sps_lfnst_enabled_flag != 0 && s.sps_explicit_scaling_list_enabled_flag != 0 {
        w.write_bit(u32::from(s.sps_scaling_matrix_for_lfnst_disabled_flag != 0));
    }
    if s.sps_act_enabled_flag != 0 && s.sps_explicit_scaling_list_enabled_flag != 0 {
        w.write_bit(u32::from(
            s.sps_scaling_matrix_for_alternative_colour_space_disabled_flag != 0,
        ));
    }
    if s.sps_scaling_matrix_for_alternative_colour_space_disabled_flag != 0 {
        w.write_bit(u32::from(
            s.sps_scaling_matrix_designated_colour_space_flag != 0,
        ));
    }
    w.write_bit(u32::from(s.sps_dep_quant_enabled_flag != 0));
    w.write_bit(u32::from(s.sps_sign_data_hiding_enabled_flag != 0));
    w.write_bit(u32::from(s.sps_virtual_boundaries_enabled_flag != 0));
    if s.sps_virtual_boundaries_enabled_flag != 0 {
        w.write_bit(u32::from(s.sps_virtual_boundaries_present_flag != 0));
        if s.sps_virtual_boundaries_present_flag != 0 {
            if s.sps_virtual_boundary_pos_x_minus1.len() > 3
                || s.sps_virtual_boundary_pos_y_minus1.len() > 3
            {
                return Err(BitstreamError::invalid(
                    "at most 3 virtual boundaries per direction (7.4.3.4)",
                ));
            }
            w.write_ue(s.sps_virtual_boundary_pos_x_minus1.len() as u32)?;
            for &pos in &s.sps_virtual_boundary_pos_x_minus1 {
                w.write_ue(pos)?;
            }
            w.write_ue(s.sps_virtual_boundary_pos_y_minus1.len() as u32)?;
            for &pos in &s.sps_virtual_boundary_pos_y_minus1 {
                w.write_ue(pos)?;
            }
        }
    }
    if ptl_present {
        w.write_bit(u32::from(s.timing_hrd.is_some()));
        if let Some(th) = &s.timing_hrd {
            write_general_timing_hrd(&mut w, &th.general)?;
            if s.sps_max_sublayers_minus1 > 0 {
                w.write_bit(u32::from(th.sps_sublayer_cpb_params_present_flag != 0));
            }
            let first_sublayer = if th.sps_sublayer_cpb_params_present_flag != 0 {
                0
            } else {
                s.sps_max_sublayers_minus1 as u32
            };
            write_ols_timing_hrd(
                &mut w,
                &th.ols,
                first_sublayer,
                s.sps_max_sublayers_minus1 as u32,
                &th.general,
            )?;
        }
    } else if s.timing_hrd.is_some() {
        return Err(BitstreamError::invalid(
            "timing_hrd requires sps_ptl_dpb_hrd_params_present_flag (7.3.2.4)",
        ));
    }
    w.write_bit(u32::from(s.sps_field_seq_flag != 0));
    w.write_bit(u32::from(s.vui_payload.is_some()));
    if let Some(payload) = &s.vui_payload {
        if payload.is_empty() || payload.len() > 1024 {
            return Err(BitstreamError::invalid(
                "vui_payload must be 1..=1024 bytes (7.4.3.4)",
            ));
        }
        w.write_ue(payload.len() as u32 - 1)?;
        while !w.byte_aligned() {
            w.write_bit(0); // sps_vui_alignment_zero_bit
        }
        w.write_bytes(payload)?;
    }
    w.write_bit(u32::from(s.sps_extension_flag != 0));
    if s.sps_extension_flag != 0 {
        w.write_bit(u32::from(s.range_extension.is_some()));
        w.write_bits(s.sps_extension_7bits as u32 & 0x7f, 7);
        if let Some(ext) = &s.range_extension {
            w.write_bit(u32::from(ext.sps_extended_precision_flag != 0));
            if s.sps_transform_skip_enabled_flag != 0 {
                w.write_bit(u32::from(
                    ext.sps_ts_residual_coding_rice_present_in_sh_flag != 0,
                ));
            }
            w.write_bit(u32::from(ext.sps_rrc_rice_extension_flag != 0));
            w.write_bit(u32::from(
                ext.sps_persistent_rice_adaptation_enabled_flag != 0,
            ));
            w.write_bit(u32::from(ext.sps_reverse_last_sig_coeff_enabled_flag != 0));
        }
    } else if s.range_extension.is_some() || s.sps_extension_7bits != 0 {
        return Err(BitstreamError::invalid(
            "extension payloads require sps_extension_flag (7.3.2.4)",
        ));
    }
    if s.sps_extension_7bits != 0 {
        if s.sps_extension_data.last() == Some(&0) {
            return Err(BitstreamError::invalid(
                "sps_extension_data must end in a 1 bit — a trailing 0 is indistinguishable \
                 from rbsp_trailing_bits padding under more_rbsp_data() (7.2)",
            ));
        }
        for &bit in &s.sps_extension_data {
            w.write_bit(u32::from(bit != 0));
        }
    } else if !s.sps_extension_data.is_empty() {
        return Err(BitstreamError::invalid(
            "sps_extension_data requires sps_extension_7bits != 0 (7.3.2.4)",
        ));
    }
    w.write_rbsp_trailing_bits();
    Ok(w.finish())
}

/// Emit a complete SPS NAL (canonical header: layer 0, TID 0),
/// emulation-prevention framed.
pub fn write_sps_nal(s: &VvcSps) -> Result<Vec<u8>, BitstreamError> {
    let rbsp = write_sps(s)?;
    let mut out = Vec::with_capacity(2 + rbsp.len());
    out.push(0x00);
    out.push((NAL_TYPE_SPS << 3) | 0x01);
    out.extend_from_slice(&crate::nal::rbsp_to_ebsp(&rbsp));
    Ok(out)
}

// ─────────────────────────── Tests ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::params::{
        VvcCpbSchedule, VvcDpbEntry, VvcOlsTimingHrdSublayer, VvcRplsEntry, VvcSublayerHrd,
    };
    use super::*;

    fn minimal_sps() -> VvcSps {
        VvcSps {
            sps_chroma_format_idc: 1,
            sps_log2_ctu_size_minus5: 2,
            sps_pic_width_max_in_luma_samples: 1920,
            sps_pic_height_max_in_luma_samples: 1080,
            sps_bitdepth_minus8: 2,
            sps_same_qp_table_for_chroma_flag: 1,
            chroma_qp_tables: vec![VvcChromaQpTable {
                sps_qp_table_start_minus26: 0,
                points: vec![(0, 0)],
            }],
            sps_chroma_horizontal_collocated_flag: 1,
            sps_chroma_vertical_collocated_flag: 1,
            ..Default::default()
        }
    }

    fn minimal_ptl() -> VvcProfileTierLevel {
        VvcProfileTierLevel {
            general_profile_idc: Some(1),
            general_tier_flag: Some(0),
            general_level_idc: 51,
            ptl_frame_only_constraint_flag: 1,
            ptl_multilayer_enabled_flag: 0,
            ptl_sublayer_level_present_flag: vec![],
            sublayer_level_idc: vec![],
            general_sub_profile_idc: vec![],
            gci_present_flag: false,
            gci_bits: vec![],
        }
    }

    /// write → parse → identical struct, and parse → write → identical
    /// bytes (the crate's byte-exact contract).
    fn assert_roundtrip(sps: &VvcSps) {
        let nal = write_sps_nal(sps).expect("SPS writes");
        let parsed = parse_sps(&nal).expect("written SPS parses");
        assert_eq!(&parsed, sps, "struct round-trip");
        let rewritten = write_sps_nal(&parsed).expect("re-write");
        assert_eq!(rewritten, nal, "byte round-trip");
    }

    #[test]
    fn minimal_1080p10_roundtrips() {
        let sps = minimal_sps();
        assert_roundtrip(&sps);
        let nal = write_sps_nal(&sps).unwrap();
        let parsed = parse_sps(&nal).unwrap();
        assert_eq!(parsed.sps_pic_width_max_in_luma_samples, 1920);
        assert_eq!(parsed.sps_pic_height_max_in_luma_samples, 1080);
        assert_eq!(parsed.bit_depth(), 10);
        assert_eq!(parsed.ctb_size_y(), 128);
        assert_eq!(parsed.poc_lsb_width(), 4);
        assert!(parsed.profile_tier_level.is_none());
        assert!(parsed.subpic_info.is_none());
    }

    #[test]
    fn ptl_dpb_and_conf_window_roundtrip() {
        let mut sps = minimal_sps();
        sps.profile_tier_level = Some(minimal_ptl());
        sps.dpb_parameters = Some(VvcDpbParameters {
            entries: vec![VvcDpbEntry {
                dpb_max_dec_pic_buffering_minus1: 7,
                dpb_max_num_reorder_pics: 3,
                dpb_max_latency_increase_plus1: 0,
            }],
        });
        sps.sps_conf_win_offsets = Some((0, 0, 0, 4));
        sps.sps_log2_max_pic_order_cnt_lsb_minus4 = 4;
        sps.sps_poc_msb_cycle_len_minus1 = Some(3);
        assert_roundtrip(&sps);
    }

    #[test]
    fn multi_sublayer_dpb_and_hrd_roundtrip() {
        let mut sps = minimal_sps();
        sps.sps_max_sublayers_minus1 = 2;
        let mut ptl = minimal_ptl();
        ptl.ptl_sublayer_level_present_flag = vec![0, 0];
        sps.profile_tier_level = Some(ptl);
        sps.sps_sublayer_dpb_params_flag = 1;
        sps.dpb_parameters = Some(VvcDpbParameters {
            entries: (0..3)
                .map(|i| VvcDpbEntry {
                    dpb_max_dec_pic_buffering_minus1: 4 + i,
                    dpb_max_num_reorder_pics: i,
                    dpb_max_latency_increase_plus1: 0,
                })
                .collect(),
        });
        // NAL HRD with one CPB schedule, DU disabled, all sublayers.
        let general = VvcGeneralTimingHrd {
            num_units_in_tick: 1001,
            time_scale: 60000,
            general_nal_hrd_params_present_flag: 1,
            general_vcl_hrd_params_present_flag: 0,
            general_same_pic_timing_in_all_ols_flag: 1,
            general_du_hrd_params_present_flag: 0,
            bit_rate_scale: 2,
            cpb_size_scale: 3,
            hrd_cpb_cnt_minus1: 0,
            ..Default::default()
        };
        let sublayer = VvcOlsTimingHrdSublayer {
            fixed_pic_rate_general_flag: 1,
            fixed_pic_rate_within_cvs_flag: 1,
            elemental_duration_in_tc_minus1: 0,
            low_delay_hrd_flag: 0,
            nal_hrd: Some(VvcSublayerHrd {
                schedules: vec![VvcCpbSchedule {
                    bit_rate_value_minus1: 49999,
                    cpb_size_value_minus1: 99999,
                    du_values_minus1: None,
                    cbr_flag: 1,
                }],
            }),
            vcl_hrd: None,
        };
        sps.timing_hrd = Some(VvcSpsTimingHrd {
            general,
            sps_sublayer_cpb_params_present_flag: 1,
            ols: VvcOlsTimingHrd {
                sublayers: vec![sublayer.clone(), sublayer.clone(), sublayer],
            },
        });
        assert_roundtrip(&sps);
    }

    #[test]
    fn subpic_2x2_explicit_geometry_roundtrips() {
        // 3840x2160 CTU-64 → 60x34 CTUs; 2x2 subpicture grid with
        // explicit per-subpic geometry and id mapping in the SPS.
        let mut sps = minimal_sps();
        sps.sps_log2_ctu_size_minus5 = 1; // CTU 64
        sps.sps_pic_width_max_in_luma_samples = 3840;
        sps.sps_pic_height_max_in_luma_samples = 2160;
        let entry = |x: u32, y: u32, w: u32, h: u32| VvcSubpicEntry {
            sps_subpic_ctu_top_left_x: x,
            sps_subpic_ctu_top_left_y: y,
            sps_subpic_width_minus1: w,
            sps_subpic_height_minus1: h,
            sps_subpic_treated_as_pic_flag: 1,
            sps_loop_filter_across_subpic_enabled_flag: 0,
        };
        sps.subpic_info = Some(VvcSubpicInfo {
            sps_num_subpics_minus1: 3,
            sps_independent_subpics_flag: 1,
            sps_subpic_same_size_flag: 0,
            entries: vec![
                entry(0, 0, 29, 16),
                entry(30, 0, 29, 16),
                entry(0, 17, 29, 16),
                entry(30, 17, 29, 16),
            ],
            sps_subpic_id_len_minus1: 3,
            sps_subpic_id_mapping_explicitly_signalled_flag: 1,
            sps_subpic_id_mapping_present_flag: 1,
            sps_subpic_ids: vec![9, 8, 7, 6],
        });
        assert_roundtrip(&sps);
    }

    #[test]
    fn subpic_same_size_grid_infers_geometry() {
        // 2x2 same-size grid on a 60x34-CTU picture is impossible (34
        // is not divisible by 17? it is: 34 / 17 = 2) — use 30x17 CTU
        // subpics so the grid tiles exactly and all geometry except
        // entry 0's width/height is inferred.
        let mut sps = minimal_sps();
        sps.sps_log2_ctu_size_minus5 = 1; // CTU 64
        sps.sps_pic_width_max_in_luma_samples = 3840; // 60 CTUs
        sps.sps_pic_height_max_in_luma_samples = 2176; // 34 CTUs
        let mut entries = Vec::new();
        for i in 0..4u32 {
            entries.push(VvcSubpicEntry {
                sps_subpic_ctu_top_left_x: (i % 2) * 30,
                sps_subpic_ctu_top_left_y: (i / 2) * 17,
                sps_subpic_width_minus1: 29,
                sps_subpic_height_minus1: 16,
                sps_subpic_treated_as_pic_flag: 1,
                sps_loop_filter_across_subpic_enabled_flag: 0,
            });
        }
        sps.subpic_info = Some(VvcSubpicInfo {
            sps_num_subpics_minus1: 3,
            sps_independent_subpics_flag: 1,
            sps_subpic_same_size_flag: 1,
            entries,
            sps_subpic_id_len_minus1: 1,
            sps_subpic_id_mapping_explicitly_signalled_flag: 0,
            sps_subpic_id_mapping_present_flag: 0,
            sps_subpic_ids: vec![],
        });
        assert_roundtrip(&sps);
    }

    #[test]
    fn rpl_templates_with_lt_and_st_roundtrip() {
        let mut sps = minimal_sps();
        sps.sps_long_term_ref_pics_flag = 1;
        sps.sps_log2_max_pic_order_cnt_lsb_minus4 = 4;
        let rpls = VvcRefPicListStruct {
            ltrp_in_header_flag: 0,
            entries: vec![
                VvcRplsEntry::ShortTerm {
                    abs_delta_poc_st: 1,
                    strp_entry_sign_flag: 0,
                },
                VvcRplsEntry::ShortTerm {
                    abs_delta_poc_st: 0,
                    strp_entry_sign_flag: 0,
                },
                VvcRplsEntry::LongTerm {
                    rpls_poc_lsb_lt: Some(0xa5),
                },
            ],
        };
        sps.sps_ref_pic_lists[0] = vec![rpls.clone()];
        sps.sps_rpl1_same_as_rpl0_flag = 0;
        sps.sps_ref_pic_lists[1] = vec![rpls];
        assert_roundtrip(&sps);

        // rpl1_same_as_rpl0: list 1 must be empty and uncoded.
        let mut sps2 = minimal_sps();
        sps2.sps_rpl1_same_as_rpl0_flag = 1;
        sps2.sps_ref_pic_lists[0] = vec![VvcRefPicListStruct {
            ltrp_in_header_flag: 1,
            entries: vec![VvcRplsEntry::ShortTerm {
                abs_delta_poc_st: 2,
                strp_entry_sign_flag: 1,
            }],
        }];
        assert_roundtrip(&sps2);
    }

    #[test]
    fn tool_flags_qp_tables_ladf_vbnd_roundtrip() {
        let mut sps = minimal_sps();
        sps.sps_transform_skip_enabled_flag = 1;
        sps.sps_log2_transform_skip_max_size_minus2 = 2;
        sps.sps_bdpcm_enabled_flag = 1;
        sps.sps_mts_enabled_flag = 1;
        sps.sps_explicit_mts_intra_enabled_flag = 1;
        sps.sps_lfnst_enabled_flag = 1;
        sps.sps_joint_cbcr_enabled_flag = 1;
        sps.sps_same_qp_table_for_chroma_flag = 0;
        sps.chroma_qp_tables = vec![
            VvcChromaQpTable {
                sps_qp_table_start_minus26: -9,
                points: vec![(3, 1), (2, 0)],
            },
            VvcChromaQpTable {
                sps_qp_table_start_minus26: 0,
                points: vec![(0, 0)],
            },
            VvcChromaQpTable {
                sps_qp_table_start_minus26: 5,
                points: vec![(1, 2)],
            },
        ];
        sps.sps_alf_enabled_flag = 1;
        sps.sps_ccalf_enabled_flag = 1;
        sps.sps_temporal_mvp_enabled_flag = 1;
        sps.sps_sbtmvp_enabled_flag = 1;
        sps.sps_amvr_enabled_flag = 1;
        sps.sps_bdof_enabled_flag = 1;
        sps.sps_bdof_control_present_in_ph_flag = 1;
        sps.sps_affine_enabled_flag = 1;
        sps.sps_five_minus_max_num_subblock_merge_cand = 2;
        sps.sps_6param_affine_enabled_flag = 1;
        sps.sps_affine_amvr_enabled_flag = 1;
        sps.sps_affine_prof_enabled_flag = 1;
        sps.sps_prof_control_present_in_ph_flag = 1;
        sps.sps_gpm_enabled_flag = 1; // MaxNumMergeCand = 6 >= 3
        sps.sps_max_num_merge_cand_minus_max_num_gpm_cand = 1;
        sps.sps_min_qp_prime_ts = 4; // transform skip enabled
        sps.sps_ibc_enabled_flag = 1;
        sps.sps_six_minus_max_num_ibc_merge_cand = 2;
        sps.ladf = Some(VvcLadf {
            sps_ladf_lowest_interval_qp_offset: -3,
            intervals: vec![(2, 9), (-2, 19)],
        });
        sps.sps_explicit_scaling_list_enabled_flag = 1;
        sps.sps_scaling_matrix_for_lfnst_disabled_flag = 1;
        sps.sps_virtual_boundaries_enabled_flag = 1;
        sps.sps_virtual_boundaries_present_flag = 1;
        sps.sps_virtual_boundary_pos_x_minus1 = vec![10, 50];
        sps.sps_virtual_boundary_pos_y_minus1 = vec![30];
        assert_roundtrip(&sps);
    }

    #[test]
    fn vui_payload_and_range_extension_roundtrip() {
        let mut sps = minimal_sps();
        sps.sps_field_seq_flag = 1;
        sps.vui_payload = Some(vec![0xde, 0xad, 0xbe, 0xef, 0x80]);
        sps.sps_transform_skip_enabled_flag = 1;
        sps.sps_log2_transform_skip_max_size_minus2 = 1;
        sps.sps_min_qp_prime_ts = 0;
        sps.sps_extension_flag = 1;
        sps.range_extension = Some(VvcSpsRangeExtension {
            sps_extended_precision_flag: 1,
            sps_ts_residual_coding_rice_present_in_sh_flag: 1,
            sps_rrc_rice_extension_flag: 0,
            sps_persistent_rice_adaptation_enabled_flag: 1,
            sps_reverse_last_sig_coeff_enabled_flag: 0,
        });
        assert_roundtrip(&sps);
    }

    #[test]
    fn extension_7bits_data_retained_verbatim() {
        let mut sps = minimal_sps();
        sps.sps_extension_flag = 1;
        sps.sps_extension_7bits = 0x40;
        sps.sps_extension_data = vec![1, 0, 0, 1, 1];
        assert_roundtrip(&sps);
        // A trailing 0 extension bit is unrepresentable: more_rbsp_data()
        // would fold it into the rbsp_trailing_bits padding on re-parse,
        // so the writer must refuse it rather than lose the bit.
        sps.sps_extension_data = vec![1, 0, 1, 1, 0];
        assert!(write_sps(&sps).is_err());
    }

    #[test]
    fn monochrome_no_qp_tables_roundtrips() {
        let mut sps = minimal_sps();
        sps.sps_chroma_format_idc = 0;
        sps.chroma_qp_tables = vec![];
        sps.sps_same_qp_table_for_chroma_flag = 1; // inferred value
        assert_roundtrip(&sps);
    }

    #[test]
    fn rejects_wrong_nal_type_and_truncation() {
        let mut nal = vec![0u8; 4];
        nal[1] = (super::super::NAL_TYPE_PPS << 3) | 1;
        assert!(matches!(
            parse_sps(&nal),
            Err(BitstreamError::InvalidData(_))
        ));
        assert!(matches!(
            parse_sps(&[0x00]),
            Err(BitstreamError::UnexpectedEnd(_))
        ));
        // A truncated but well-formed prefix must be caught by the
        // final rbsp_trailing_bits check, not silently zero-filled.
        let full = write_sps_nal(&minimal_sps()).unwrap();
        let cut = &full[..full.len() - 1];
        assert!(parse_sps(cut).is_err());
    }

    #[test]
    fn rejects_out_of_range_fields() {
        // sps_max_sublayers_minus1 = 7 (reserved).
        let mut sps = minimal_sps();
        sps.sps_max_sublayers_minus1 = 7;
        assert!(write_sps(&sps).is_err());
        // bitdepth > 8.
        let mut sps = minimal_sps();
        sps.sps_bitdepth_minus8 = 9;
        assert!(write_sps(&sps).is_err());
        // log2_max_poc out of envelope, via bytes: take a valid SPS
        // and set the u(4) field to 13 through a struct write attempt.
        let mut sps = minimal_sps();
        sps.sps_log2_max_pic_order_cnt_lsb_minus4 = 13;
        assert!(write_sps(&sps).is_err());
        // qp-table count mismatch.
        let mut sps = minimal_sps();
        sps.chroma_qp_tables = vec![];
        assert!(write_sps(&sps).is_err());
    }

    #[test]
    fn hand_written_full_rbsp_is_byte_exact() {
        // Build a complete no-PTL 1080p10 SPS RBSP with BitWriter,
        // field by field per §7.3.2.4, then confirm parse → write
        // reproduces it byte-exactly.
        let mut w = BitWriter::new();
        w.write_bits(3, 4); // sps_seq_parameter_set_id
        w.write_bits(0, 4); // sps_video_parameter_set_id
        w.write_bits(0, 3); // sps_max_sublayers_minus1
        w.write_bits(1, 2); // sps_chroma_format_idc
        w.write_bits(2, 2); // sps_log2_ctu_size_minus5
        w.write_bit(0); // sps_ptl_dpb_hrd_params_present_flag
        w.write_bit(0); // sps_gdr_enabled_flag
        w.write_bit(0); // sps_ref_pic_resampling_enabled_flag
        w.write_ue(1920).unwrap();
        w.write_ue(1080).unwrap();
        w.write_bit(0); // sps_conformance_window_flag
        w.write_bit(0); // sps_subpic_info_present_flag
        w.write_ue(2).unwrap(); // sps_bitdepth_minus8
        w.write_bit(1); // sps_entropy_coding_sync_enabled_flag
        w.write_bit(0); // sps_entry_point_offsets_present_flag
        w.write_bits(4, 4); // sps_log2_max_pic_order_cnt_lsb_minus4
        w.write_bit(0); // sps_poc_msb_cycle_flag
        w.write_bits(0, 2); // sps_num_extra_ph_bytes
        w.write_bits(0, 2); // sps_num_extra_sh_bytes
        w.write_ue(0).unwrap(); // sps_log2_min_luma_coding_block_size_minus2
        w.write_bit(0); // sps_partition_constraints_override_enabled_flag
        w.write_ue(0).unwrap(); // sps_log2_diff_min_qt_min_cb_intra_slice_luma
        w.write_ue(0).unwrap(); // sps_max_mtt_hierarchy_depth_intra_slice_luma
        w.write_bit(0); // sps_qtbtt_dual_tree_intra_flag
        w.write_ue(0).unwrap(); // sps_log2_diff_min_qt_min_cb_inter_slice
        w.write_ue(0).unwrap(); // sps_max_mtt_hierarchy_depth_inter_slice
        w.write_bit(0); // sps_max_luma_transform_size_64_flag (CTU 128 > 32)
        w.write_bit(0); // sps_transform_skip_enabled_flag
        w.write_bit(0); // sps_mts_enabled_flag
        w.write_bit(0); // sps_lfnst_enabled_flag
        w.write_bit(0); // sps_joint_cbcr_enabled_flag
        w.write_bit(1); // sps_same_qp_table_for_chroma_flag
        w.write_se(0).unwrap(); // sps_qp_table_start_minus26
        w.write_ue(0).unwrap(); // sps_num_points_in_qp_table_minus1
        w.write_ue(1).unwrap(); // sps_delta_qp_in_val_minus1[0][0]
        w.write_ue(0).unwrap(); // sps_delta_qp_diff_val[0][0]
        w.write_bit(1); // sps_sao_enabled_flag
        w.write_bit(0); // sps_alf_enabled_flag
        w.write_bit(0); // sps_lmcs_enabled_flag
        w.write_bit(0); // sps_weighted_pred_flag
        w.write_bit(0); // sps_weighted_bipred_flag
        w.write_bit(0); // sps_long_term_ref_pics_flag
        w.write_bit(0); // sps_idr_rpl_present_flag
        w.write_bit(0); // sps_rpl1_same_as_rpl0_flag
        w.write_ue(0).unwrap(); // sps_num_ref_pic_lists[0]
        w.write_ue(0).unwrap(); // sps_num_ref_pic_lists[1]
        w.write_bit(0); // sps_ref_wraparound_enabled_flag
        w.write_bit(0); // sps_temporal_mvp_enabled_flag
        w.write_bit(0); // sps_amvr_enabled_flag
        w.write_bit(0); // sps_bdof_enabled_flag
        w.write_bit(0); // sps_smvd_enabled_flag
        w.write_bit(0); // sps_dmvr_enabled_flag
        w.write_bit(0); // sps_mmvd_enabled_flag
        w.write_ue(0).unwrap(); // sps_six_minus_max_num_merge_cand → MaxNumMergeCand 6
        w.write_bit(0); // sps_sbt_enabled_flag
        w.write_bit(0); // sps_affine_enabled_flag
        w.write_bit(0); // sps_bcw_enabled_flag
        w.write_bit(0); // sps_ciip_enabled_flag
        w.write_bit(0); // sps_gpm_enabled_flag (MaxNumMergeCand >= 2)
        w.write_ue(0).unwrap(); // sps_log2_parallel_merge_level_minus2
        w.write_bit(0); // sps_isp_enabled_flag
        w.write_bit(0); // sps_mrl_enabled_flag
        w.write_bit(0); // sps_mip_enabled_flag
        w.write_bit(0); // sps_cclm_enabled_flag
        w.write_bit(1); // sps_chroma_horizontal_collocated_flag
        w.write_bit(1); // sps_chroma_vertical_collocated_flag
        w.write_bit(0); // sps_palette_enabled_flag
        w.write_bit(0); // sps_ibc_enabled_flag
        w.write_bit(0); // sps_ladf_enabled_flag
        w.write_bit(0); // sps_explicit_scaling_list_enabled_flag
        w.write_bit(0); // sps_dep_quant_enabled_flag
        w.write_bit(0); // sps_sign_data_hiding_enabled_flag
        w.write_bit(0); // sps_virtual_boundaries_enabled_flag
        w.write_bit(0); // sps_field_seq_flag
        w.write_bit(0); // sps_vui_parameters_present_flag
        w.write_bit(0); // sps_extension_flag
        w.write_rbsp_trailing_bits();
        let rbsp = w.finish();
        let mut nal = vec![0x00, (NAL_TYPE_SPS << 3) | 0x01];
        nal.extend_from_slice(&rbsp);
        let sps = parse_sps(&nal).expect("hand-written SPS parses");
        assert_eq!(sps.sps_seq_parameter_set_id, 3);
        assert_eq!(sps.sps_entropy_coding_sync_enabled_flag, 1);
        assert_eq!(sps.sps_sao_enabled_flag, 1);
        assert_eq!(sps.poc_lsb_width(), 8);
        assert_eq!(sps.max_num_merge_cand(), 6);
        assert_eq!(write_sps(&sps).expect("re-writes"), rbsp, "byte-exact");
    }
}
