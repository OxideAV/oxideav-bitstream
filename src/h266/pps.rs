//! H.266 / VVC picture parameter set (§7.3.2.5) — complete walk,
//! parse + byte-exact write.
//!
//! [`parse_pps`] walks every syntax element of
//! `pic_parameter_set_rbsp()` through `rbsp_trailing_bits()` —
//! including the rectangular-slice layout, whose per-slice presence
//! conditions depend on the §6.5.1 tile-scanning derivations
//! (`NumTileColumns` / `RowHeightVal` / `SliceTopLeftTileIdx` /
//! `NumSlicesInTile`) that this module replays as it parses.
//! [`write_pps`] is the byte-exact inverse on the same derivations.
//!
//! The PPS is parsed context-free (without its SPS): every presence
//! condition in §7.3.2.5 depends only on earlier PPS syntax, with the
//! picture-in-CTB geometry recovered from
//! `pps_pic_width/height_in_luma_samples` + `pps_log2_ctu_size_minus5`.
//!
//! Loop-driving counts are bounded by the tightest Table A.2 level
//! limits (level 6.3): `MaxTileCols ≤ 30`, `MaxTilesPerAu ≤ 990`,
//! `MaxSlicesPerAu ≤ 1000` — hostile counts cannot drive unbounded
//! loops or allocations.
//!
//! # Spec references
//!
//! ITU-T H.266 (V4) (01/2026): §7.3.2.5 / §7.4.3.5 (PPS RBSP),
//! §6.5.1 (CTB raster / tile scanning derivations, eqs. (14)–(22)),
//! Table A.2 (tier/level limits).

use super::{ebsp_to_rbsp, parse_nal_header, NAL_TYPE_PPS};
use crate::bit_reader::BitReader;
use crate::bit_writer::BitWriter;
use crate::BitstreamError;

/// Table A.2 level-6.3 limit: `MaxTileCols ≤ 30`.
pub const PPS_MAX_TILE_COLS: u64 = 30;
/// Table A.2 level-6.3 limit: `MaxTilesPerAu ≤ 990`.
pub const PPS_MAX_TILES_PER_AU: u64 = 990;
/// Table A.2 level-6.3 limit: `MaxSlicesPerAu ≤ 1000`, so
/// `pps_num_slices_in_pic_minus1 ≤ 999` (§7.4.3.5).
pub const PPS_NUM_SLICES_IN_PIC_MINUS1_MAX: u32 = 999;

// ─────────────────────────── Sub-blocks ──────────────────────────────────────

/// PPS-signalled subpicture ID mapping (§7.3.2.5, present iff
/// `pps_subpic_id_mapping_present_flag`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcPpsSubpicIdMapping {
    /// `pps_num_subpics_minus1` ue(v) — coded only when
    /// `!pps_no_pic_partition_flag`; inferred 0 otherwise. Must equal
    /// the SPS value (§7.4.3.5); bounded by Table A.2 (≤ 999).
    pub pps_num_subpics_minus1: u32,
    /// `pps_subpic_id_len_minus1` ue(v) — 0..=15, must equal the SPS
    /// value.
    pub pps_subpic_id_len_minus1: u32,
    /// `pps_subpic_id[i]` u(v) — `pps_num_subpics_minus1 + 1` ids.
    pub pps_subpic_ids: Vec<u32>,
}

/// One coded iteration of the §7.3.2.5 rectangular-slice loop.
///
/// Entries correspond to the loop's *coded* iterations, in order — a
/// tile that splits into `NumSlicesInTile > 1` slices consumes that
/// many picture-level slice indices but contributes exactly one entry
/// (the spec's `i += NumSlicesInTile − 1` advance), and the last
/// slice (`i == pps_num_slices_in_pic_minus1`) has no syntax at all.
/// Uncoded fields carry their §7.4.3.5 inferred values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcPpsRectSlice {
    /// `pps_slice_width_in_tiles_minus1[i]` ue(v) — coded only when
    /// the slice's top-left tile is not in the last tile column;
    /// inferred 0.
    pub pps_slice_width_in_tiles_minus1: u32,
    /// `pps_slice_height_in_tiles_minus1[i]` ue(v) — coded only when
    /// the top-left tile is not in the last tile row AND
    /// (`pps_tile_idx_delta_present_flag` or the tile is in column
    /// 0); inferred 0 (last row) or the previous slice's value.
    pub pps_slice_height_in_tiles_minus1: u32,
    /// `pps_exp_slice_height_in_ctus_minus1[i][j]` values — `Some`
    /// iff the `pps_num_exp_slices_in_tile[i]` field was coded (the
    /// slice covers exactly one tile whose row is taller than one
    /// CTU); the vec may be empty (`pps_num_exp_slices_in_tile = 0`,
    /// tile not split).
    pub exp_slice_heights_in_ctus_minus1: Option<Vec<u32>>,
    /// `pps_tile_idx_delta_val[i]` se(v) — `Some` iff coded
    /// (`pps_tile_idx_delta_present_flag` and not the last slice);
    /// nonzero, `|v| < NumTilesInPic`.
    pub pps_tile_idx_delta_val: Option<i32>,
}

/// The `!pps_no_pic_partition_flag` tile/slice partition block
/// (§7.3.2.5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcPpsPartition {
    /// `pps_log2_ctu_size_minus5` u(2) — 0..=2, must equal the SPS
    /// value.
    pub pps_log2_ctu_size_minus5: u8,
    /// `pps_tile_column_width_minus1[i]` ue(v) — the
    /// `pps_num_exp_tile_columns_minus1 + 1` explicit column widths.
    pub pps_tile_column_widths_minus1: Vec<u32>,
    /// `pps_tile_row_height_minus1[i]` ue(v) — explicit row heights.
    pub pps_tile_row_heights_minus1: Vec<u32>,
    /// `pps_loop_filter_across_tiles_enabled_flag` u(1) — coded only
    /// when `NumTilesInPic > 1`; inferred 0.
    pub pps_loop_filter_across_tiles_enabled_flag: u8,
    /// `pps_rect_slice_flag` u(1) — coded only when
    /// `NumTilesInPic > 1`; inferred 1.
    pub pps_rect_slice_flag: u8,
    /// `pps_single_slice_per_subpic_flag` u(1) — coded only when
    /// `pps_rect_slice_flag`; 0 otherwise.
    pub pps_single_slice_per_subpic_flag: u8,
    /// `pps_num_slices_in_pic_minus1` ue(v) — coded only for the
    /// explicit rectangular-slice layout; 0..=999 (Table A.2).
    pub pps_num_slices_in_pic_minus1: u32,
    /// `pps_tile_idx_delta_present_flag` u(1) — coded only when
    /// `pps_num_slices_in_pic_minus1 > 1`; inferred 0.
    pub pps_tile_idx_delta_present_flag: u8,
    /// The coded rectangular-slice loop iterations (see
    /// [`VvcPpsRectSlice`]).
    pub rect_slices: Vec<VvcPpsRectSlice>,
    /// `pps_loop_filter_across_slices_enabled_flag` u(1) — coded only
    /// when `!pps_rect_slice_flag`, `pps_single_slice_per_subpic_flag`
    /// or `pps_num_slices_in_pic_minus1 > 0`; inferred 0.
    pub pps_loop_filter_across_slices_enabled_flag: u8,
}

/// The `pps_chroma_tool_offsets_present_flag` block (§7.3.2.5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcPpsChromaToolOffsets {
    /// `pps_cb_qp_offset` se(v) — −12..=12.
    pub pps_cb_qp_offset: i32,
    /// `pps_cr_qp_offset` se(v) — −12..=12.
    pub pps_cr_qp_offset: i32,
    /// `pps_joint_cbcr_qp_offset_value` se(v) — `Some` iff
    /// `pps_joint_cbcr_qp_offset_present_flag`; −12..=12.
    pub pps_joint_cbcr_qp_offset_value: Option<i32>,
    /// `pps_slice_chroma_qp_offsets_present_flag` u(1).
    pub pps_slice_chroma_qp_offsets_present_flag: u8,
    /// The `pps_cu_chroma_qp_offset_list_enabled_flag` list — `Some`
    /// iff enabled; 1..=6 `(cb, cr, joint)` triples, `joint` present
    /// iff `pps_joint_cbcr_qp_offset_present_flag`. All offsets
    /// −12..=12.
    pub cu_chroma_qp_offset_list: Option<Vec<(i32, i32, Option<i32>)>>,
}

/// The `pps_deblocking_filter_control_present_flag` block (§7.3.2.5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcPpsDeblocking {
    /// `pps_deblocking_filter_override_enabled_flag` u(1).
    pub pps_deblocking_filter_override_enabled_flag: u8,
    /// `pps_deblocking_filter_disabled_flag` u(1).
    pub pps_deblocking_filter_disabled_flag: u8,
    /// `pps_dbf_info_in_ph_flag` u(1) — coded only when
    /// `!pps_no_pic_partition_flag` and override is enabled; inferred
    /// 0.
    pub pps_dbf_info_in_ph_flag: u8,
    /// `pps_luma_beta_offset_div2` se(v) — −12..=12; the four chroma
    /// offsets follow only when `pps_chroma_tool_offsets_present_flag`.
    pub pps_luma_beta_offset_div2: i32,
    /// `pps_luma_tc_offset_div2` se(v) — −12..=12.
    pub pps_luma_tc_offset_div2: i32,
    /// `(pps_cb_beta_offset_div2, pps_cb_tc_offset_div2)` — coded
    /// only with chroma tool offsets; inferred = luma values.
    pub pps_cb_offsets_div2: (i32, i32),
    /// `(pps_cr_beta_offset_div2, pps_cr_tc_offset_div2)` — ditto.
    pub pps_cr_offsets_div2: (i32, i32),
}

// ─────────────────────────── The PPS itself ──────────────────────────────────

/// A completely-walked VVC PPS (§7.3.2.5). Every syntax element is
/// retained (or spec-inferred when its presence condition failed), so
/// [`write_pps`] can re-emit the RBSP byte-exactly.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcPps {
    /// `pps_pic_parameter_set_id` u(6) — 0..=63.
    pub pps_pic_parameter_set_id: u8,
    /// `pps_seq_parameter_set_id` u(4) — 0..=15.
    pub pps_seq_parameter_set_id: u8,
    /// `pps_mixed_nalu_types_in_pic_flag` u(1).
    pub pps_mixed_nalu_types_in_pic_flag: u8,
    /// `pps_pic_width_in_luma_samples` ue(v) — must be > 0.
    pub pps_pic_width_in_luma_samples: u32,
    /// `pps_pic_height_in_luma_samples` ue(v) — must be > 0.
    pub pps_pic_height_in_luma_samples: u32,
    /// `(left, right, top, bottom)` `pps_conf_win_*_offset` values —
    /// present iff `pps_conformance_window_flag`.
    pub pps_conf_win_offsets: Option<(u32, u32, u32, u32)>,
    /// `(left, right, top, bottom)` `pps_scaling_win_*_offset` values
    /// (signed) — present iff
    /// `pps_scaling_window_explicit_signalling_flag`.
    pub pps_scaling_win_offsets: Option<(i32, i32, i32, i32)>,
    /// `pps_output_flag_present_flag` u(1).
    pub pps_output_flag_present_flag: u8,
    /// `pps_no_pic_partition_flag` u(1) — 1 means a single tile and a
    /// single slice span the picture and [`VvcPps::partition`] is
    /// `None`.
    pub pps_no_pic_partition_flag: u8,
    /// Subpicture ID mapping — present iff
    /// `pps_subpic_id_mapping_present_flag`.
    pub subpic_id_mapping: Option<VvcPpsSubpicIdMapping>,
    /// Tile/slice partition block — present iff
    /// `!pps_no_pic_partition_flag`.
    pub partition: Option<VvcPpsPartition>,
    /// `pps_cabac_init_present_flag` u(1).
    pub pps_cabac_init_present_flag: u8,
    /// `pps_num_ref_idx_default_active_minus1[i]` ue(v) — 0..=14 each.
    pub pps_num_ref_idx_default_active_minus1: [u32; 2],
    /// `pps_rpl1_idx_present_flag` u(1).
    pub pps_rpl1_idx_present_flag: u8,
    /// `pps_weighted_pred_flag` u(1).
    pub pps_weighted_pred_flag: u8,
    /// `pps_weighted_bipred_flag` u(1).
    pub pps_weighted_bipred_flag: u8,
    /// `pps_pic_width_minus_wraparound_offset` ue(v) — `Some` iff
    /// `pps_ref_wraparound_enabled_flag`.
    pub pps_pic_width_minus_wraparound_offset: Option<u32>,
    /// `pps_init_qp_minus26` se(v).
    pub pps_init_qp_minus26: i32,
    /// `pps_cu_qp_delta_enabled_flag` u(1).
    pub pps_cu_qp_delta_enabled_flag: u8,
    /// Chroma tool offsets block — present iff
    /// `pps_chroma_tool_offsets_present_flag`.
    pub chroma_tool_offsets: Option<VvcPpsChromaToolOffsets>,
    /// Deblocking control block — present iff
    /// `pps_deblocking_filter_control_present_flag`.
    pub deblocking: Option<VvcPpsDeblocking>,
    /// `pps_rpl_info_in_ph_flag` u(1) — coded only when
    /// `!pps_no_pic_partition_flag`; inferred 0.
    pub pps_rpl_info_in_ph_flag: u8,
    /// `pps_sao_info_in_ph_flag` u(1) — ditto.
    pub pps_sao_info_in_ph_flag: u8,
    /// `pps_alf_info_in_ph_flag` u(1) — ditto.
    pub pps_alf_info_in_ph_flag: u8,
    /// `pps_wp_info_in_ph_flag` u(1) — coded only when weighted
    /// prediction is on and `pps_rpl_info_in_ph_flag`; inferred 0.
    pub pps_wp_info_in_ph_flag: u8,
    /// `pps_qp_delta_info_in_ph_flag` u(1) — coded only when
    /// `!pps_no_pic_partition_flag`; inferred 0.
    pub pps_qp_delta_info_in_ph_flag: u8,
    /// `pps_picture_header_extension_present_flag` u(1).
    pub pps_picture_header_extension_present_flag: u8,
    /// `pps_slice_header_extension_present_flag` u(1).
    pub pps_slice_header_extension_present_flag: u8,
    /// `pps_extension_flag` u(1).
    pub pps_extension_flag: u8,
    /// `pps_extension_data_flag` bits (0/1 each) — retained verbatim;
    /// must end in a 1 bit (a trailing 0 is indistinguishable from
    /// `rbsp_trailing_bits` padding).
    pub pps_extension_data: Vec<u8>,
}

impl VvcPps {
    /// `PicWidthInCtbsY` from the PPS's own geometry (only meaningful
    /// when [`VvcPps::partition`] is present; §6.5.1).
    pub fn pic_width_in_ctbs(&self) -> u64 {
        let ctb = self
            .partition
            .as_ref()
            .map_or(5u32, |p| p.pps_log2_ctu_size_minus5 as u32)
            + 5;
        (self.pps_pic_width_in_luma_samples as u64).div_ceil(1u64 << ctb)
    }

    /// `PicHeightInCtbsY` (§6.5.1).
    pub fn pic_height_in_ctbs(&self) -> u64 {
        let ctb = self
            .partition
            .as_ref()
            .map_or(5u32, |p| p.pps_log2_ctu_size_minus5 as u32)
            + 5;
        (self.pps_pic_height_in_luma_samples as u64).div_ceil(1u64 << ctb)
    }
}

// ─────────────────────────── 6.5.1 derivations ───────────────────────────────

/// Derive the per-tile-column widths (or per-row heights) in CTBs
/// from the explicit `*_minus1` list per §6.5.1 eqs. (14)/(15):
/// explicit entries first, then uniform fill with the last explicit
/// size, then the remainder. Errors if the explicit entries overrun
/// the picture or the derived count exceeds `max_count`.
fn derive_tile_sizes(
    exp_minus1: &[u32],
    total_ctbs: u64,
    max_count: u64,
    axis: &str,
) -> Result<Vec<u64>, BitstreamError> {
    let mut sizes: Vec<u64> = Vec::new();
    let mut remaining = total_ctbs;
    for &e in exp_minus1 {
        let v = e as u64 + 1;
        if v > remaining {
            return Err(BitstreamError::invalid(format!(
                "explicit tile {axis} sizes exceed the picture ({v} CTBs > {remaining} remaining, 6.5.1)"
            )));
        }
        sizes.push(v);
        remaining -= v;
    }
    let uniform = *exp_minus1.last().expect("at least one explicit entry") as u64 + 1;
    let n_uniform = remaining / uniform;
    let tail = remaining % uniform;
    let count = sizes.len() as u64 + n_uniform + u64::from(tail > 0);
    if count > max_count {
        return Err(BitstreamError::invalid(format!(
            "derived tile {axis} count {count} exceeds the Table A.2 limit {max_count}"
        )));
    }
    for _ in 0..n_uniform {
        sizes.push(uniform);
    }
    if tail > 0 {
        sizes.push(tail);
    }
    Ok(sizes)
}

/// `NumSlicesInTile[i]` per §6.5.1 eq. (21): explicit slice heights,
/// then uniform fill with the last explicit height, then the
/// remainder. Returns the slice count; errors if the explicit heights
/// overrun the tile row.
fn num_slices_in_tile(
    exp_heights_minus1: &[u32],
    row_height_ctus: u64,
) -> Result<u64, BitstreamError> {
    if exp_heights_minus1.is_empty() {
        return Ok(1);
    }
    let mut remaining = row_height_ctus;
    for &e in exp_heights_minus1 {
        let h = e as u64 + 1;
        if h > remaining {
            return Err(BitstreamError::invalid(format!(
                "pps_exp_slice_height_in_ctus_minus1 overruns the tile row ({h} > {remaining}, 6.5.1)"
            )));
        }
        remaining -= h;
    }
    let uniform = *exp_heights_minus1.last().unwrap() as u64 + 1;
    Ok(exp_heights_minus1.len() as u64 + remaining / uniform + u64::from(remaining % uniform > 0))
}

/// Shared parse/write walk state for the rectangular-slice loop.
struct SliceLoopCtx {
    cols: u64,
    rows: u64,
    tiles: u64,
    row_heights: Vec<u64>,
    delta_present: bool,
    num_slices_minus1: u32,
}

impl SliceLoopCtx {
    /// The §7.3.2.5 presence condition for
    /// `pps_slice_width_in_tiles_minus1[i]`.
    fn width_coded(&self, tile_idx: u64) -> bool {
        tile_idx % self.cols != self.cols - 1
    }

    /// The §7.3.2.5 presence condition for
    /// `pps_slice_height_in_tiles_minus1[i]`.
    fn height_coded(&self, tile_idx: u64) -> bool {
        tile_idx / self.cols != self.rows - 1 && (self.delta_present || tile_idx % self.cols == 0)
    }

    /// The §7.3.2.5 condition for the `pps_num_exp_slices_in_tile[i]`
    /// block.
    fn exp_block(&self, tile_idx: u64, w_m1: u32, h_m1: u32) -> bool {
        w_m1 == 0 && h_m1 == 0 && self.row_heights[(tile_idx / self.cols) as usize] > 1
    }

    /// The default (`!pps_tile_idx_delta_present_flag`) §6.5.1 tile
    /// advance for the next slice.
    fn default_advance(&self, tile_idx: u64, w_m1: u32, h_m1: u32) -> u64 {
        let mut t = tile_idx + w_m1 as u64 + 1;
        if t % self.cols == 0 {
            t += h_m1 as u64 * self.cols;
        }
        t
    }

    /// Apply a coded `pps_tile_idx_delta_val[i]`, validating the
    /// §7.4.3.5 range and that the result stays inside the picture.
    fn apply_delta(&self, tile_idx: u64, delta: i32) -> Result<u64, BitstreamError> {
        if delta == 0 || delta.unsigned_abs() as u64 >= self.tiles {
            return Err(BitstreamError::invalid(format!(
                "pps_tile_idx_delta_val = {delta} outside ±(NumTilesInPic − 1) or zero (7.4.3.5)"
            )));
        }
        let t = tile_idx as i64 + delta as i64;
        if t < 0 || t as u64 >= self.tiles {
            return Err(BitstreamError::invalid(
                "pps_tile_idx_delta_val walks outside the picture's tiles (6.5.1)",
            ));
        }
        Ok(t as u64)
    }
}

// ─────────────────────────── parse_pps ───────────────────────────────────────

fn parse_partition(r: &mut BitReader<'_>, pps: &VvcPps) -> Result<VvcPpsPartition, BitstreamError> {
    let mut p = VvcPpsPartition {
        pps_log2_ctu_size_minus5: r.u(2) as u8,
        pps_rect_slice_flag: 1,
        ..Default::default()
    };
    if p.pps_log2_ctu_size_minus5 > 2 {
        return Err(BitstreamError::invalid(
            "pps_log2_ctu_size_minus5 > 2 (spec range 0..=2)",
        ));
    }
    let ctb = 1u64 << (p.pps_log2_ctu_size_minus5 as u32 + 5);
    let pic_w_ctbs = (pps.pps_pic_width_in_luma_samples as u64).div_ceil(ctb);
    let pic_h_ctbs = (pps.pps_pic_height_in_luma_samples as u64).div_ceil(ctb);
    let num_exp_cols = r.ue()?;
    let num_exp_rows = r.ue()?;
    if num_exp_cols as u64 >= PPS_MAX_TILE_COLS || num_exp_rows as u64 >= PPS_MAX_TILES_PER_AU {
        return Err(BitstreamError::invalid(
            "explicit tile column/row count exceeds the Table A.2 limits",
        ));
    }
    for _ in 0..=num_exp_cols {
        let v = r.ue()?;
        if v as u64 >= pic_w_ctbs {
            return Err(BitstreamError::invalid(
                "pps_tile_column_width_minus1 >= PicWidthInCtbsY (7.4.3.5)",
            ));
        }
        p.pps_tile_column_widths_minus1.push(v);
    }
    for _ in 0..=num_exp_rows {
        let v = r.ue()?;
        if v as u64 >= pic_h_ctbs {
            return Err(BitstreamError::invalid(
                "pps_tile_row_height_minus1 >= PicHeightInCtbsY (7.4.3.5)",
            ));
        }
        p.pps_tile_row_heights_minus1.push(v);
    }
    let col_widths = derive_tile_sizes(
        &p.pps_tile_column_widths_minus1,
        pic_w_ctbs,
        PPS_MAX_TILE_COLS,
        "column",
    )?;
    let row_heights = derive_tile_sizes(
        &p.pps_tile_row_heights_minus1,
        pic_h_ctbs,
        PPS_MAX_TILES_PER_AU / col_widths.len() as u64,
        "row",
    )?;
    let cols = col_widths.len() as u64;
    let rows = row_heights.len() as u64;
    let tiles = cols * rows;
    if tiles > 1 {
        p.pps_loop_filter_across_tiles_enabled_flag = r.u(1) as u8;
        p.pps_rect_slice_flag = r.u(1) as u8;
    }
    if p.pps_rect_slice_flag != 0 {
        p.pps_single_slice_per_subpic_flag = r.u(1) as u8;
    }
    if p.pps_rect_slice_flag != 0 && p.pps_single_slice_per_subpic_flag == 0 {
        p.pps_num_slices_in_pic_minus1 = r.ue()?;
        if p.pps_num_slices_in_pic_minus1 > PPS_NUM_SLICES_IN_PIC_MINUS1_MAX {
            return Err(BitstreamError::invalid(format!(
                "pps_num_slices_in_pic_minus1 = {} > {PPS_NUM_SLICES_IN_PIC_MINUS1_MAX} (Table A.2)",
                p.pps_num_slices_in_pic_minus1
            )));
        }
        if p.pps_num_slices_in_pic_minus1 > 1 {
            p.pps_tile_idx_delta_present_flag = r.u(1) as u8;
        }
        let ctx = SliceLoopCtx {
            cols,
            rows,
            tiles,
            row_heights,
            delta_present: p.pps_tile_idx_delta_present_flag != 0,
            num_slices_minus1: p.pps_num_slices_in_pic_minus1,
        };
        let mut tile_idx = 0u64;
        let mut heights_m1 = vec![0u32; ctx.num_slices_minus1 as usize + 1];
        let mut i = 0u32;
        while i < ctx.num_slices_minus1 {
            let mut e = VvcPpsRectSlice::default();
            let tile_x = tile_idx % ctx.cols;
            let tile_y = tile_idx / ctx.cols;
            e.pps_slice_width_in_tiles_minus1 = if ctx.width_coded(tile_idx) {
                r.ue()?
            } else {
                0
            };
            if e.pps_slice_width_in_tiles_minus1 as u64 >= ctx.cols - tile_x {
                return Err(BitstreamError::invalid(
                    "pps_slice_width_in_tiles_minus1 overruns the tile grid (7.4.3.5)",
                ));
            }
            e.pps_slice_height_in_tiles_minus1 = if ctx.height_coded(tile_idx) {
                r.ue()?
            } else if tile_y == ctx.rows - 1 {
                0
            } else {
                // i > 0 whenever this branch is reached: at i == 0
                // tile_idx == 0, so tile_x == 0 makes height_coded
                // true unless we're already in the last tile row.
                heights_m1[i as usize - 1]
            };
            if e.pps_slice_height_in_tiles_minus1 as u64 >= ctx.rows - tile_y {
                return Err(BitstreamError::invalid(
                    "pps_slice_height_in_tiles_minus1 overruns the tile grid (7.4.3.5)",
                ));
            }
            heights_m1[i as usize] = e.pps_slice_height_in_tiles_minus1;
            if ctx.exp_block(
                tile_idx,
                e.pps_slice_width_in_tiles_minus1,
                e.pps_slice_height_in_tiles_minus1,
            ) {
                let row_h = ctx.row_heights[tile_y as usize];
                let num_exp = r.ue()?;
                if num_exp as u64 >= row_h {
                    return Err(BitstreamError::invalid(
                        "pps_num_exp_slices_in_tile >= RowHeightVal (7.4.3.5)",
                    ));
                }
                let mut exp = Vec::with_capacity(num_exp as usize);
                for _ in 0..num_exp {
                    let v = r.ue()?;
                    if v as u64 >= row_h {
                        return Err(BitstreamError::invalid(
                            "pps_exp_slice_height_in_ctus_minus1 >= RowHeightVal (7.4.3.5)",
                        ));
                    }
                    exp.push(v);
                }
                let n = num_slices_in_tile(&exp, row_h)?;
                if i as u64 + n - 1 > ctx.num_slices_minus1 as u64 {
                    return Err(BitstreamError::invalid(
                        "tile splits into more slices than pps_num_slices_in_pic_minus1 allows (6.5.1)",
                    ));
                }
                e.exp_slice_heights_in_ctus_minus1 = Some(exp);
                // Slices i..i+n-1 all have sliceHeightInTiles = 1
                // (§6.5.1) — their inherited height_minus1 is 0, which
                // heights_m1 already holds.
                i += n as u32 - 1;
            }
            if ctx.delta_present && i < ctx.num_slices_minus1 {
                let delta = r.se()?;
                tile_idx = ctx.apply_delta(tile_idx, delta)?;
                e.pps_tile_idx_delta_val = Some(delta);
            } else if i < ctx.num_slices_minus1 {
                tile_idx = ctx.default_advance(
                    tile_idx,
                    e.pps_slice_width_in_tiles_minus1,
                    e.pps_slice_height_in_tiles_minus1,
                );
                if tile_idx >= ctx.tiles {
                    return Err(BitstreamError::invalid(
                        "rectangular-slice walk runs off the tile grid (6.5.1)",
                    ));
                }
            }
            p.rect_slices.push(e);
            i += 1;
        }
    }
    if p.pps_rect_slice_flag == 0
        || p.pps_single_slice_per_subpic_flag != 0
        || p.pps_num_slices_in_pic_minus1 > 0
    {
        p.pps_loop_filter_across_slices_enabled_flag = r.u(1) as u8;
    }
    Ok(p)
}

/// Parse a complete VVC PPS NAL (two-byte NAL header at index 0..1)
/// per §7.3.2.5, through `rbsp_trailing_bits()`.
///
/// The input slice MUST point at the start of the NAL body (i.e.
/// after [`super::split_annex_b`]). Emulation-prevention bytes are
/// stripped via [`ebsp_to_rbsp`] before bit-level parsing. Every
/// syntax element is retained (or spec-inferred when absent) and the
/// declared §7.4 / Table A.2 ranges are enforced, so [`write_pps`]
/// round-trips the RBSP byte-exactly.
pub fn parse_pps(nal_body: &[u8]) -> Result<VvcPps, BitstreamError> {
    if nal_body.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "H.266 PPS NAL needs at least the 2-byte header",
        ));
    }
    let header = parse_nal_header(nal_body)?;
    if header.nal_unit_type != NAL_TYPE_PPS {
        return Err(BitstreamError::invalid(format!(
            "expected PPS NAL (type {}), got {}",
            NAL_TYPE_PPS, header.nal_unit_type
        )));
    }
    let rbsp = ebsp_to_rbsp(&nal_body[2..]);
    let mut r = BitReader::new(&rbsp);
    let mut p = VvcPps {
        pps_pic_parameter_set_id: r.u(6) as u8,
        pps_seq_parameter_set_id: r.u(4) as u8,
        pps_mixed_nalu_types_in_pic_flag: r.u(1) as u8,
        pps_pic_width_in_luma_samples: r.ue()?,
        pps_pic_height_in_luma_samples: r.ue()?,
        ..Default::default()
    };
    if p.pps_pic_width_in_luma_samples == 0 || p.pps_pic_height_in_luma_samples == 0 {
        return Err(BitstreamError::invalid(
            "pps_pic_width/height_in_luma_samples must be > 0 (7.4.3.5)",
        ));
    }
    if r.u(1) != 0 {
        let l = r.ue()?;
        let rt = r.ue()?;
        let t = r.ue()?;
        let b = r.ue()?;
        p.pps_conf_win_offsets = Some((l, rt, t, b));
    }
    if r.u(1) != 0 {
        let l = r.se()?;
        let rt = r.se()?;
        let t = r.se()?;
        let b = r.se()?;
        p.pps_scaling_win_offsets = Some((l, rt, t, b));
    }
    p.pps_output_flag_present_flag = r.u(1) as u8;
    p.pps_no_pic_partition_flag = r.u(1) as u8;
    if r.u(1) != 0 {
        // pps_subpic_id_mapping_present_flag
        let mut m = VvcPpsSubpicIdMapping::default();
        if p.pps_no_pic_partition_flag == 0 {
            m.pps_num_subpics_minus1 = r.ue()?;
            if m.pps_num_subpics_minus1 > PPS_NUM_SLICES_IN_PIC_MINUS1_MAX {
                return Err(BitstreamError::invalid(
                    "pps_num_subpics_minus1 exceeds MaxSlicesPerAu - 1 (Table A.2)",
                ));
            }
        }
        m.pps_subpic_id_len_minus1 = r.ue()?;
        if m.pps_subpic_id_len_minus1 > 15 {
            return Err(BitstreamError::invalid(
                "pps_subpic_id_len_minus1 > 15 (7.4.3.5)",
            ));
        }
        let bits = m.pps_subpic_id_len_minus1 + 1;
        m.pps_subpic_ids = (0..=m.pps_num_subpics_minus1).map(|_| r.u(bits)).collect();
        p.subpic_id_mapping = Some(m);
    }
    if p.pps_no_pic_partition_flag == 0 {
        p.partition = Some(parse_partition(&mut r, &p)?);
    }
    p.pps_cabac_init_present_flag = r.u(1) as u8;
    for i in 0..2 {
        p.pps_num_ref_idx_default_active_minus1[i] = r.ue()?;
        if p.pps_num_ref_idx_default_active_minus1[i] > 14 {
            return Err(BitstreamError::invalid(
                "pps_num_ref_idx_default_active_minus1 > 14 (7.4.3.5)",
            ));
        }
    }
    p.pps_rpl1_idx_present_flag = r.u(1) as u8;
    p.pps_weighted_pred_flag = r.u(1) as u8;
    p.pps_weighted_bipred_flag = r.u(1) as u8;
    if r.u(1) != 0 {
        // pps_ref_wraparound_enabled_flag
        p.pps_pic_width_minus_wraparound_offset = Some(r.ue()?);
    }
    p.pps_init_qp_minus26 = r.se()?;
    p.pps_cu_qp_delta_enabled_flag = r.u(1) as u8;
    if r.u(1) != 0 {
        // pps_chroma_tool_offsets_present_flag
        let mut c = VvcPpsChromaToolOffsets {
            pps_cb_qp_offset: check_qp_offset(r.se()?, "pps_cb_qp_offset")?,
            pps_cr_qp_offset: check_qp_offset(r.se()?, "pps_cr_qp_offset")?,
            ..Default::default()
        };
        let joint_present = r.u(1) != 0;
        if joint_present {
            c.pps_joint_cbcr_qp_offset_value =
                Some(check_qp_offset(r.se()?, "pps_joint_cbcr_qp_offset_value")?);
        }
        c.pps_slice_chroma_qp_offsets_present_flag = r.u(1) as u8;
        if r.u(1) != 0 {
            // pps_cu_chroma_qp_offset_list_enabled_flag
            let len_minus1 = r.ue()?;
            if len_minus1 > 5 {
                return Err(BitstreamError::invalid(
                    "pps_chroma_qp_offset_list_len_minus1 > 5 (7.4.3.5)",
                ));
            }
            let mut list = Vec::with_capacity(len_minus1 as usize + 1);
            for _ in 0..=len_minus1 {
                let cb = check_qp_offset(r.se()?, "pps_cb_qp_offset_list")?;
                let cr = check_qp_offset(r.se()?, "pps_cr_qp_offset_list")?;
                let joint = if joint_present {
                    Some(check_qp_offset(r.se()?, "pps_joint_cbcr_qp_offset_list")?)
                } else {
                    None
                };
                list.push((cb, cr, joint));
            }
            c.cu_chroma_qp_offset_list = Some(list);
        }
        p.chroma_tool_offsets = Some(c);
    }
    if r.u(1) != 0 {
        // pps_deblocking_filter_control_present_flag
        let mut d = VvcPpsDeblocking {
            pps_deblocking_filter_override_enabled_flag: r.u(1) as u8,
            pps_deblocking_filter_disabled_flag: r.u(1) as u8,
            ..Default::default()
        };
        if p.pps_no_pic_partition_flag == 0 && d.pps_deblocking_filter_override_enabled_flag != 0 {
            d.pps_dbf_info_in_ph_flag = r.u(1) as u8;
        }
        if d.pps_deblocking_filter_disabled_flag == 0 {
            d.pps_luma_beta_offset_div2 = check_dbf_offset(r.se()?)?;
            d.pps_luma_tc_offset_div2 = check_dbf_offset(r.se()?)?;
            if p.chroma_tool_offsets.is_some() {
                d.pps_cb_offsets_div2 = (check_dbf_offset(r.se()?)?, check_dbf_offset(r.se()?)?);
                d.pps_cr_offsets_div2 = (check_dbf_offset(r.se()?)?, check_dbf_offset(r.se()?)?);
            } else {
                // Inferred = luma values (§7.4.3.5).
                d.pps_cb_offsets_div2 = (d.pps_luma_beta_offset_div2, d.pps_luma_tc_offset_div2);
                d.pps_cr_offsets_div2 = d.pps_cb_offsets_div2;
            }
        }
        p.deblocking = Some(d);
    }
    if p.pps_no_pic_partition_flag == 0 {
        p.pps_rpl_info_in_ph_flag = r.u(1) as u8;
        p.pps_sao_info_in_ph_flag = r.u(1) as u8;
        p.pps_alf_info_in_ph_flag = r.u(1) as u8;
        if (p.pps_weighted_pred_flag != 0 || p.pps_weighted_bipred_flag != 0)
            && p.pps_rpl_info_in_ph_flag != 0
        {
            p.pps_wp_info_in_ph_flag = r.u(1) as u8;
        }
        p.pps_qp_delta_info_in_ph_flag = r.u(1) as u8;
    }
    p.pps_picture_header_extension_present_flag = r.u(1) as u8;
    p.pps_slice_header_extension_present_flag = r.u(1) as u8;
    p.pps_extension_flag = r.u(1) as u8;
    if p.pps_extension_flag != 0 {
        while r.more_rbsp_data() {
            p.pps_extension_data.push(r.u(1) as u8);
        }
    }
    r.read_rbsp_trailing_bits()?;
    Ok(p)
}

fn check_qp_offset(v: i32, name: &str) -> Result<i32, BitstreamError> {
    if !(-12..=12).contains(&v) {
        return Err(BitstreamError::invalid(format!(
            "{name} = {v} outside -12..=12 (7.4.3.5)"
        )));
    }
    Ok(v)
}

fn check_dbf_offset(v: i32) -> Result<i32, BitstreamError> {
    if !(-12..=12).contains(&v) {
        return Err(BitstreamError::invalid(format!(
            "deblocking offset {v} outside -12..=12 (7.4.3.5)"
        )));
    }
    Ok(v)
}

// ─────────────────────────── write_pps ───────────────────────────────────────

fn write_partition(
    w: &mut BitWriter,
    p: &VvcPpsPartition,
    pps: &VvcPps,
) -> Result<(), BitstreamError> {
    if p.pps_log2_ctu_size_minus5 > 2 {
        return Err(BitstreamError::invalid(
            "pps_log2_ctu_size_minus5 > 2 (spec range 0..=2)",
        ));
    }
    w.write_bits(p.pps_log2_ctu_size_minus5 as u32, 2);
    let ctb = 1u64 << (p.pps_log2_ctu_size_minus5 as u32 + 5);
    let pic_w_ctbs = (pps.pps_pic_width_in_luma_samples as u64).div_ceil(ctb);
    let pic_h_ctbs = (pps.pps_pic_height_in_luma_samples as u64).div_ceil(ctb);
    if p.pps_tile_column_widths_minus1.is_empty() || p.pps_tile_row_heights_minus1.is_empty() {
        return Err(BitstreamError::invalid(
            "partition block needs at least one explicit tile column width and row height",
        ));
    }
    w.write_ue(p.pps_tile_column_widths_minus1.len() as u32 - 1)?;
    w.write_ue(p.pps_tile_row_heights_minus1.len() as u32 - 1)?;
    for &v in &p.pps_tile_column_widths_minus1 {
        if v as u64 >= pic_w_ctbs {
            return Err(BitstreamError::invalid(
                "pps_tile_column_width_minus1 >= PicWidthInCtbsY (7.4.3.5)",
            ));
        }
        w.write_ue(v)?;
    }
    for &v in &p.pps_tile_row_heights_minus1 {
        if v as u64 >= pic_h_ctbs {
            return Err(BitstreamError::invalid(
                "pps_tile_row_height_minus1 >= PicHeightInCtbsY (7.4.3.5)",
            ));
        }
        w.write_ue(v)?;
    }
    let col_widths = derive_tile_sizes(
        &p.pps_tile_column_widths_minus1,
        pic_w_ctbs,
        PPS_MAX_TILE_COLS,
        "column",
    )?;
    let row_heights = derive_tile_sizes(
        &p.pps_tile_row_heights_minus1,
        pic_h_ctbs,
        PPS_MAX_TILES_PER_AU / col_widths.len() as u64,
        "row",
    )?;
    let cols = col_widths.len() as u64;
    let rows = row_heights.len() as u64;
    let tiles = cols * rows;
    if tiles > 1 {
        w.write_bit(u32::from(p.pps_loop_filter_across_tiles_enabled_flag != 0));
        w.write_bit(u32::from(p.pps_rect_slice_flag != 0));
    } else if p.pps_rect_slice_flag != 1 {
        return Err(BitstreamError::invalid(
            "pps_rect_slice_flag must carry its inferred value 1 for a single-tile picture",
        ));
    }
    if p.pps_rect_slice_flag != 0 {
        w.write_bit(u32::from(p.pps_single_slice_per_subpic_flag != 0));
    }
    if p.pps_rect_slice_flag != 0 && p.pps_single_slice_per_subpic_flag == 0 {
        if p.pps_num_slices_in_pic_minus1 > PPS_NUM_SLICES_IN_PIC_MINUS1_MAX {
            return Err(BitstreamError::invalid(
                "pps_num_slices_in_pic_minus1 exceeds MaxSlicesPerAu - 1 (Table A.2)",
            ));
        }
        w.write_ue(p.pps_num_slices_in_pic_minus1)?;
        if p.pps_num_slices_in_pic_minus1 > 1 {
            w.write_bit(u32::from(p.pps_tile_idx_delta_present_flag != 0));
        }
        let ctx = SliceLoopCtx {
            cols,
            rows,
            tiles,
            row_heights,
            delta_present: p.pps_tile_idx_delta_present_flag != 0,
            num_slices_minus1: p.pps_num_slices_in_pic_minus1,
        };
        let mut entries = p.rect_slices.iter();
        let mut tile_idx = 0u64;
        let mut i = 0u32;
        while i < ctx.num_slices_minus1 {
            let e = entries.next().ok_or_else(|| {
                BitstreamError::invalid(
                    "rect_slices has fewer entries than the slice-loop walk requires",
                )
            })?;
            let tile_x = tile_idx % ctx.cols;
            let tile_y = tile_idx / ctx.cols;
            if e.pps_slice_width_in_tiles_minus1 as u64 >= ctx.cols - tile_x
                || e.pps_slice_height_in_tiles_minus1 as u64 >= ctx.rows - tile_y
            {
                return Err(BitstreamError::invalid(
                    "rect slice overruns the tile grid (7.4.3.5)",
                ));
            }
            if ctx.width_coded(tile_idx) {
                w.write_ue(e.pps_slice_width_in_tiles_minus1)?;
            }
            if ctx.height_coded(tile_idx) {
                w.write_ue(e.pps_slice_height_in_tiles_minus1)?;
            }
            let exp_condition = ctx.exp_block(
                tile_idx,
                e.pps_slice_width_in_tiles_minus1,
                e.pps_slice_height_in_tiles_minus1,
            );
            match (&e.exp_slice_heights_in_ctus_minus1, exp_condition) {
                (Some(exp), true) => {
                    let row_h = ctx.row_heights[tile_y as usize];
                    if exp.len() as u64 >= row_h {
                        return Err(BitstreamError::invalid(
                            "pps_num_exp_slices_in_tile >= RowHeightVal (7.4.3.5)",
                        ));
                    }
                    w.write_ue(exp.len() as u32)?;
                    for &v in exp {
                        if v as u64 >= row_h {
                            return Err(BitstreamError::invalid(
                                "pps_exp_slice_height_in_ctus_minus1 >= RowHeightVal (7.4.3.5)",
                            ));
                        }
                        w.write_ue(v)?;
                    }
                    let n = num_slices_in_tile(exp, row_h)?;
                    if i as u64 + n - 1 > ctx.num_slices_minus1 as u64 {
                        return Err(BitstreamError::invalid(
                            "tile splits into more slices than pps_num_slices_in_pic_minus1 allows (6.5.1)",
                        ));
                    }
                    i += n as u32 - 1;
                }
                (None, false) => {}
                _ => {
                    return Err(BitstreamError::invalid(
                        "exp_slice_heights_in_ctus_minus1 presence contradicts the \
                         one-tile-slice condition (7.3.2.5)",
                    ));
                }
            }
            match (e.pps_tile_idx_delta_val, ctx.delta_present) {
                (Some(delta), true) => {
                    if i >= ctx.num_slices_minus1 {
                        return Err(BitstreamError::invalid(
                            "pps_tile_idx_delta_val present on the final coded slice (7.3.2.5)",
                        ));
                    }
                    w.write_se(delta)?;
                    tile_idx = ctx.apply_delta(tile_idx, delta)?;
                }
                (None, true) if i >= ctx.num_slices_minus1 => {}
                (None, false) => {
                    if i < ctx.num_slices_minus1 {
                        tile_idx = ctx.default_advance(
                            tile_idx,
                            e.pps_slice_width_in_tiles_minus1,
                            e.pps_slice_height_in_tiles_minus1,
                        );
                        if tile_idx >= ctx.tiles {
                            return Err(BitstreamError::invalid(
                                "rectangular-slice walk runs off the tile grid (6.5.1)",
                            ));
                        }
                    }
                }
                _ => {
                    return Err(BitstreamError::invalid(
                        "pps_tile_idx_delta_val presence contradicts \
                         pps_tile_idx_delta_present_flag (7.3.2.5)",
                    ));
                }
            }
            i += 1;
        }
        if entries.next().is_some() {
            return Err(BitstreamError::invalid(
                "rect_slices has more entries than the slice-loop walk consumes",
            ));
        }
    } else if !p.rect_slices.is_empty() {
        return Err(BitstreamError::invalid(
            "rect_slices must be empty outside the explicit rectangular-slice layout",
        ));
    }
    if p.pps_rect_slice_flag == 0
        || p.pps_single_slice_per_subpic_flag != 0
        || p.pps_num_slices_in_pic_minus1 > 0
    {
        w.write_bit(u32::from(p.pps_loop_filter_across_slices_enabled_flag != 0));
    }
    Ok(())
}

/// Emit a `pic_parameter_set_rbsp()` (§7.3.2.5 including
/// `rbsp_trailing_bits()`) — the byte-exact inverse of [`parse_pps`]'s
/// RBSP walk: `write_pps(&parse_pps(nal)?)` reproduces the NAL's RBSP
/// bytes exactly for every input the parser accepts.
pub fn write_pps(p: &VvcPps) -> Result<Vec<u8>, BitstreamError> {
    let mut w = BitWriter::new();
    if p.pps_pic_parameter_set_id > 63 || p.pps_seq_parameter_set_id > 15 {
        return Err(BitstreamError::invalid("PPS/SPS id out of range"));
    }
    w.write_bits(p.pps_pic_parameter_set_id as u32, 6);
    w.write_bits(p.pps_seq_parameter_set_id as u32, 4);
    w.write_bit(u32::from(p.pps_mixed_nalu_types_in_pic_flag != 0));
    if p.pps_pic_width_in_luma_samples == 0 || p.pps_pic_height_in_luma_samples == 0 {
        return Err(BitstreamError::invalid(
            "pps_pic_width/height_in_luma_samples must be > 0 (7.4.3.5)",
        ));
    }
    w.write_ue(p.pps_pic_width_in_luma_samples)?;
    w.write_ue(p.pps_pic_height_in_luma_samples)?;
    w.write_bit(u32::from(p.pps_conf_win_offsets.is_some()));
    if let Some((l, r_, t, b)) = p.pps_conf_win_offsets {
        w.write_ue(l)?;
        w.write_ue(r_)?;
        w.write_ue(t)?;
        w.write_ue(b)?;
    }
    w.write_bit(u32::from(p.pps_scaling_win_offsets.is_some()));
    if let Some((l, r_, t, b)) = p.pps_scaling_win_offsets {
        w.write_se(l)?;
        w.write_se(r_)?;
        w.write_se(t)?;
        w.write_se(b)?;
    }
    w.write_bit(u32::from(p.pps_output_flag_present_flag != 0));
    w.write_bit(u32::from(p.pps_no_pic_partition_flag != 0));
    w.write_bit(u32::from(p.subpic_id_mapping.is_some()));
    if let Some(m) = &p.subpic_id_mapping {
        if p.pps_no_pic_partition_flag == 0 {
            if m.pps_num_subpics_minus1 > PPS_NUM_SLICES_IN_PIC_MINUS1_MAX {
                return Err(BitstreamError::invalid(
                    "pps_num_subpics_minus1 exceeds MaxSlicesPerAu - 1 (Table A.2)",
                ));
            }
            w.write_ue(m.pps_num_subpics_minus1)?;
        } else if m.pps_num_subpics_minus1 != 0 {
            return Err(BitstreamError::invalid(
                "pps_num_subpics_minus1 must carry its inferred value 0 when \
                 pps_no_pic_partition_flag (7.4.3.5)",
            ));
        }
        if m.pps_subpic_id_len_minus1 > 15 {
            return Err(BitstreamError::invalid(
                "pps_subpic_id_len_minus1 > 15 (7.4.3.5)",
            ));
        }
        w.write_ue(m.pps_subpic_id_len_minus1)?;
        if m.pps_subpic_ids.len() != m.pps_num_subpics_minus1 as usize + 1 {
            return Err(BitstreamError::invalid(
                "pps_subpic_id count != pps_num_subpics_minus1 + 1 (7.3.2.5)",
            ));
        }
        let bits = m.pps_subpic_id_len_minus1 + 1;
        for &id in &m.pps_subpic_ids {
            if bits < 32 && id >= (1u32 << bits) {
                return Err(BitstreamError::invalid(format!(
                    "pps_subpic_id = {id} does not fit u({bits})"
                )));
            }
            w.write_bits(id, bits);
        }
    }
    match (&p.partition, p.pps_no_pic_partition_flag == 0) {
        (Some(part), true) => write_partition(&mut w, part, p)?,
        (None, false) => {}
        _ => {
            return Err(BitstreamError::invalid(
                "partition block must be present iff !pps_no_pic_partition_flag (7.3.2.5)",
            ));
        }
    }
    w.write_bit(u32::from(p.pps_cabac_init_present_flag != 0));
    for i in 0..2 {
        if p.pps_num_ref_idx_default_active_minus1[i] > 14 {
            return Err(BitstreamError::invalid(
                "pps_num_ref_idx_default_active_minus1 > 14 (7.4.3.5)",
            ));
        }
        w.write_ue(p.pps_num_ref_idx_default_active_minus1[i])?;
    }
    w.write_bit(u32::from(p.pps_rpl1_idx_present_flag != 0));
    w.write_bit(u32::from(p.pps_weighted_pred_flag != 0));
    w.write_bit(u32::from(p.pps_weighted_bipred_flag != 0));
    w.write_bit(u32::from(p.pps_pic_width_minus_wraparound_offset.is_some()));
    if let Some(off) = p.pps_pic_width_minus_wraparound_offset {
        w.write_ue(off)?;
    }
    w.write_se(p.pps_init_qp_minus26)?;
    w.write_bit(u32::from(p.pps_cu_qp_delta_enabled_flag != 0));
    w.write_bit(u32::from(p.chroma_tool_offsets.is_some()));
    if let Some(c) = &p.chroma_tool_offsets {
        w.write_se(check_qp_offset(c.pps_cb_qp_offset, "pps_cb_qp_offset")?)?;
        w.write_se(check_qp_offset(c.pps_cr_qp_offset, "pps_cr_qp_offset")?)?;
        let joint_present = c.pps_joint_cbcr_qp_offset_value.is_some();
        w.write_bit(u32::from(joint_present));
        if let Some(v) = c.pps_joint_cbcr_qp_offset_value {
            w.write_se(check_qp_offset(v, "pps_joint_cbcr_qp_offset_value")?)?;
        }
        w.write_bit(u32::from(c.pps_slice_chroma_qp_offsets_present_flag != 0));
        w.write_bit(u32::from(c.cu_chroma_qp_offset_list.is_some()));
        if let Some(list) = &c.cu_chroma_qp_offset_list {
            if list.is_empty() || list.len() > 6 {
                return Err(BitstreamError::invalid(
                    "pps_chroma_qp_offset_list_len_minus1 outside 0..=5 (7.4.3.5)",
                ));
            }
            w.write_ue(list.len() as u32 - 1)?;
            for &(cb, cr, joint) in list {
                w.write_se(check_qp_offset(cb, "pps_cb_qp_offset_list")?)?;
                w.write_se(check_qp_offset(cr, "pps_cr_qp_offset_list")?)?;
                match (joint, joint_present) {
                    (Some(v), true) => {
                        w.write_se(check_qp_offset(v, "pps_joint_cbcr_qp_offset_list")?)?
                    }
                    (None, false) => {}
                    _ => {
                        return Err(BitstreamError::invalid(
                            "joint offset presence contradicts \
                             pps_joint_cbcr_qp_offset_present_flag (7.3.2.5)",
                        ));
                    }
                }
            }
        }
    }
    w.write_bit(u32::from(p.deblocking.is_some()));
    if let Some(d) = &p.deblocking {
        w.write_bit(u32::from(
            d.pps_deblocking_filter_override_enabled_flag != 0,
        ));
        w.write_bit(u32::from(d.pps_deblocking_filter_disabled_flag != 0));
        if p.pps_no_pic_partition_flag == 0 && d.pps_deblocking_filter_override_enabled_flag != 0 {
            w.write_bit(u32::from(d.pps_dbf_info_in_ph_flag != 0));
        }
        if d.pps_deblocking_filter_disabled_flag == 0 {
            w.write_se(check_dbf_offset(d.pps_luma_beta_offset_div2)?)?;
            w.write_se(check_dbf_offset(d.pps_luma_tc_offset_div2)?)?;
            if p.chroma_tool_offsets.is_some() {
                w.write_se(check_dbf_offset(d.pps_cb_offsets_div2.0)?)?;
                w.write_se(check_dbf_offset(d.pps_cb_offsets_div2.1)?)?;
                w.write_se(check_dbf_offset(d.pps_cr_offsets_div2.0)?)?;
                w.write_se(check_dbf_offset(d.pps_cr_offsets_div2.1)?)?;
            }
        }
    }
    if p.pps_no_pic_partition_flag == 0 {
        w.write_bit(u32::from(p.pps_rpl_info_in_ph_flag != 0));
        w.write_bit(u32::from(p.pps_sao_info_in_ph_flag != 0));
        w.write_bit(u32::from(p.pps_alf_info_in_ph_flag != 0));
        if (p.pps_weighted_pred_flag != 0 || p.pps_weighted_bipred_flag != 0)
            && p.pps_rpl_info_in_ph_flag != 0
        {
            w.write_bit(u32::from(p.pps_wp_info_in_ph_flag != 0));
        }
        w.write_bit(u32::from(p.pps_qp_delta_info_in_ph_flag != 0));
    }
    w.write_bit(u32::from(p.pps_picture_header_extension_present_flag != 0));
    w.write_bit(u32::from(p.pps_slice_header_extension_present_flag != 0));
    w.write_bit(u32::from(p.pps_extension_flag != 0));
    if p.pps_extension_flag != 0 {
        if p.pps_extension_data.last() == Some(&0) {
            return Err(BitstreamError::invalid(
                "pps_extension_data must end in a 1 bit — a trailing 0 is indistinguishable \
                 from rbsp_trailing_bits padding under more_rbsp_data() (7.2)",
            ));
        }
        for &bit in &p.pps_extension_data {
            w.write_bit(u32::from(bit != 0));
        }
    } else if !p.pps_extension_data.is_empty() {
        return Err(BitstreamError::invalid(
            "pps_extension_data requires pps_extension_flag (7.3.2.5)",
        ));
    }
    w.write_rbsp_trailing_bits();
    Ok(w.finish())
}

/// Emit a complete PPS NAL (canonical header: layer 0, TID 0),
/// emulation-prevention framed.
pub fn write_pps_nal(p: &VvcPps) -> Result<Vec<u8>, BitstreamError> {
    let rbsp = write_pps(p)?;
    let mut out = Vec::with_capacity(2 + rbsp.len());
    out.push(0x00);
    out.push((NAL_TYPE_PPS << 3) | 0x01);
    out.extend_from_slice(&crate::nal::rbsp_to_ebsp(&rbsp));
    Ok(out)
}

// ─────────────────────────── Tests ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pps() -> VvcPps {
        VvcPps {
            pps_pic_width_in_luma_samples: 1920,
            pps_pic_height_in_luma_samples: 1080,
            pps_no_pic_partition_flag: 1,
            ..Default::default()
        }
    }

    fn assert_roundtrip(pps: &VvcPps) {
        let nal = write_pps_nal(pps).expect("PPS writes");
        let parsed = parse_pps(&nal).expect("written PPS parses");
        assert_eq!(&parsed, pps, "struct round-trip");
        assert_eq!(write_pps_nal(&parsed).unwrap(), nal, "byte round-trip");
    }

    #[test]
    fn minimal_no_partition_roundtrips() {
        let pps = minimal_pps();
        assert_roundtrip(&pps);
        let parsed = parse_pps(&write_pps_nal(&pps).unwrap()).unwrap();
        assert!(parsed.partition.is_none());
        assert_eq!(parsed.pps_pic_width_in_luma_samples, 1920);
    }

    #[test]
    fn windows_and_scalar_blocks_roundtrip() {
        let mut pps = minimal_pps();
        pps.pps_conf_win_offsets = Some((0, 2, 0, 4));
        pps.pps_scaling_win_offsets = Some((1, -2, 3, -4));
        pps.pps_output_flag_present_flag = 1;
        pps.pps_cabac_init_present_flag = 1;
        pps.pps_num_ref_idx_default_active_minus1 = [3, 1];
        pps.pps_weighted_pred_flag = 1;
        pps.pps_pic_width_minus_wraparound_offset = Some(7);
        pps.pps_init_qp_minus26 = -5;
        pps.pps_cu_qp_delta_enabled_flag = 1;
        pps.chroma_tool_offsets = Some(VvcPpsChromaToolOffsets {
            pps_cb_qp_offset: -2,
            pps_cr_qp_offset: 3,
            pps_joint_cbcr_qp_offset_value: Some(-1),
            pps_slice_chroma_qp_offsets_present_flag: 1,
            cu_chroma_qp_offset_list: Some(vec![(1, -1, Some(2)), (0, 0, Some(0))]),
        });
        pps.deblocking = Some(VvcPpsDeblocking {
            pps_deblocking_filter_override_enabled_flag: 1,
            pps_deblocking_filter_disabled_flag: 0,
            pps_dbf_info_in_ph_flag: 0, // no_pic_partition → not coded
            pps_luma_beta_offset_div2: 2,
            pps_luma_tc_offset_div2: -2,
            pps_cb_offsets_div2: (1, 1),
            pps_cr_offsets_div2: (-1, -1),
        });
        pps.pps_picture_header_extension_present_flag = 1;
        assert_roundtrip(&pps);
    }

    #[test]
    fn deblocking_disabled_skips_offsets() {
        let mut pps = minimal_pps();
        pps.deblocking = Some(VvcPpsDeblocking {
            pps_deblocking_filter_disabled_flag: 1,
            ..Default::default()
        });
        assert_roundtrip(&pps);
    }

    /// A 2x2-tile partition with one rectangular slice per tile,
    /// raster order (no tile_idx_delta).
    #[test]
    fn tiles_2x2_four_slices_roundtrip() {
        let mut pps = minimal_pps();
        pps.pps_no_pic_partition_flag = 0;
        // 1920x1080 CTU-64 → 30x17 CTBs; explicit 15-wide column and
        // 9-high row, uniform fill gives 2 columns (15+15) and rows
        // 9+8.
        pps.partition = Some(VvcPpsPartition {
            pps_log2_ctu_size_minus5: 1,
            pps_tile_column_widths_minus1: vec![14],
            pps_tile_row_heights_minus1: vec![8],
            pps_loop_filter_across_tiles_enabled_flag: 1,
            pps_rect_slice_flag: 1,
            pps_single_slice_per_subpic_flag: 0,
            pps_num_slices_in_pic_minus1: 3,
            pps_tile_idx_delta_present_flag: 0,
            rect_slices: vec![
                VvcPpsRectSlice::default(), // (0,0): 1x1 tile, RowHeight 9 > 1 → exp block
                VvcPpsRectSlice::default(),
                VvcPpsRectSlice::default(),
            ],
            pps_loop_filter_across_slices_enabled_flag: 1,
        });
        // Each slice is one tile: width_minus1 = 0 / height_minus1 = 0,
        // and every tile row is > 1 CTU high, so the exp block IS
        // coded with num_exp = 0 for slices 0..=2 (the last slice has
        // no syntax). Fix up the entries accordingly.
        let part = pps.partition.as_mut().unwrap();
        for e in &mut part.rect_slices {
            e.exp_slice_heights_in_ctus_minus1 = Some(vec![]);
        }
        assert_roundtrip(&pps);
    }

    /// A tile split into multiple slices by explicit CTU-row heights,
    /// exercising the §6.5.1 NumSlicesInTile advance.
    #[test]
    fn tile_split_into_ctu_row_slices_roundtrip() {
        let mut pps = minimal_pps();
        pps.pps_no_pic_partition_flag = 0;
        // Single tile column (full 30-CTB width), single 17-CTB-high
        // tile row. The tile splits into 3 slices: heights 8, 8, 1
        // (explicit 8,8 + remainder 1). Slice count = 3 → num_minus1
        // = 2; the exp block consumes slices 0..=1... actually all 3
        // (i += NumSlicesInTile - 1 = 2), so the loop runs once.
        pps.partition = Some(VvcPpsPartition {
            pps_log2_ctu_size_minus5: 1,
            pps_tile_column_widths_minus1: vec![29],
            pps_tile_row_heights_minus1: vec![16],
            pps_loop_filter_across_tiles_enabled_flag: 0, // single tile → not coded
            pps_rect_slice_flag: 1,                       // inferred
            pps_single_slice_per_subpic_flag: 0,
            pps_num_slices_in_pic_minus1: 2,
            pps_tile_idx_delta_present_flag: 0,
            rect_slices: vec![VvcPpsRectSlice {
                pps_slice_width_in_tiles_minus1: 0,
                pps_slice_height_in_tiles_minus1: 0,
                exp_slice_heights_in_ctus_minus1: Some(vec![7, 7]),
                pps_tile_idx_delta_val: None,
            }],
            pps_loop_filter_across_slices_enabled_flag: 1,
        });
        assert_roundtrip(&pps);
    }

    /// Explicit tile-index deltas walking the slices out of raster
    /// order.
    #[test]
    fn tile_idx_delta_walk_roundtrips() {
        let mut pps = minimal_pps();
        pps.pps_no_pic_partition_flag = 0;
        // 2x2 tiles of 15x9(8) CTBs; 4 slices in order tile 0 → 3 →
        // 2 → 1 via deltas +3, -1, -1.
        pps.partition = Some(VvcPpsPartition {
            pps_log2_ctu_size_minus5: 1,
            pps_tile_column_widths_minus1: vec![14],
            pps_tile_row_heights_minus1: vec![8],
            pps_loop_filter_across_tiles_enabled_flag: 0,
            pps_rect_slice_flag: 1,
            pps_single_slice_per_subpic_flag: 0,
            pps_num_slices_in_pic_minus1: 3,
            pps_tile_idx_delta_present_flag: 1,
            rect_slices: vec![
                VvcPpsRectSlice {
                    exp_slice_heights_in_ctus_minus1: Some(vec![]),
                    pps_tile_idx_delta_val: Some(3),
                    ..Default::default()
                },
                VvcPpsRectSlice {
                    exp_slice_heights_in_ctus_minus1: Some(vec![]),
                    pps_tile_idx_delta_val: Some(-1),
                    ..Default::default()
                },
                VvcPpsRectSlice {
                    exp_slice_heights_in_ctus_minus1: Some(vec![]),
                    pps_tile_idx_delta_val: Some(-1),
                    ..Default::default()
                },
            ],
            pps_loop_filter_across_slices_enabled_flag: 0,
        });
        assert_roundtrip(&pps);
    }

    #[test]
    fn raster_scan_slice_mode_roundtrips() {
        let mut pps = minimal_pps();
        pps.pps_no_pic_partition_flag = 0;
        pps.partition = Some(VvcPpsPartition {
            pps_log2_ctu_size_minus5: 1,
            pps_tile_column_widths_minus1: vec![14],
            pps_tile_row_heights_minus1: vec![8],
            pps_loop_filter_across_tiles_enabled_flag: 1,
            pps_rect_slice_flag: 0, // raster-scan mode: no slice layout in PPS
            pps_single_slice_per_subpic_flag: 0,
            pps_num_slices_in_pic_minus1: 0,
            pps_tile_idx_delta_present_flag: 0,
            rect_slices: vec![],
            pps_loop_filter_across_slices_enabled_flag: 1,
        });
        assert_roundtrip(&pps);
    }

    #[test]
    fn single_slice_per_subpic_roundtrips() {
        let mut pps = minimal_pps();
        pps.pps_no_pic_partition_flag = 0;
        pps.subpic_id_mapping = Some(VvcPpsSubpicIdMapping {
            pps_num_subpics_minus1: 3,
            pps_subpic_id_len_minus1: 7,
            pps_subpic_ids: vec![10, 20, 30, 40],
        });
        pps.partition = Some(VvcPpsPartition {
            pps_log2_ctu_size_minus5: 1,
            pps_tile_column_widths_minus1: vec![14],
            pps_tile_row_heights_minus1: vec![8],
            pps_loop_filter_across_tiles_enabled_flag: 0,
            pps_rect_slice_flag: 1,
            pps_single_slice_per_subpic_flag: 1,
            pps_num_slices_in_pic_minus1: 0,
            pps_tile_idx_delta_present_flag: 0,
            rect_slices: vec![],
            pps_loop_filter_across_slices_enabled_flag: 1,
        });
        assert_roundtrip(&pps);
    }

    #[test]
    fn extension_data_retained_and_guarded() {
        let mut pps = minimal_pps();
        pps.pps_extension_flag = 1;
        pps.pps_extension_data = vec![0, 1, 1];
        assert_roundtrip(&pps);
        pps.pps_extension_data = vec![1, 0];
        assert!(write_pps(&pps).is_err());
    }

    #[test]
    fn rejects_wrong_nal_truncation_and_ranges() {
        let mut nal = vec![0u8; 4];
        nal[1] = (super::super::NAL_TYPE_SPS << 3) | 1;
        assert!(matches!(
            parse_pps(&nal),
            Err(BitstreamError::InvalidData(_))
        ));
        assert!(matches!(
            parse_pps(&[0x00]),
            Err(BitstreamError::UnexpectedEnd(_))
        ));
        let full = write_pps_nal(&minimal_pps()).unwrap();
        assert!(parse_pps(&full[..full.len() - 1]).is_err());

        // QP offset out of range.
        let mut pps = minimal_pps();
        pps.chroma_tool_offsets = Some(VvcPpsChromaToolOffsets {
            pps_cb_qp_offset: 13,
            ..Default::default()
        });
        assert!(write_pps(&pps).is_err());
        // Slice count over the Table A.2 envelope.
        let mut pps = minimal_pps();
        pps.pps_no_pic_partition_flag = 0;
        pps.partition = Some(VvcPpsPartition {
            pps_log2_ctu_size_minus5: 1,
            pps_tile_column_widths_minus1: vec![14],
            pps_tile_row_heights_minus1: vec![8],
            pps_rect_slice_flag: 1,
            pps_num_slices_in_pic_minus1: 1000,
            ..Default::default()
        });
        assert!(write_pps(&pps).is_err());
    }

    /// Uniform-fill tile derivation: a 1-CTB explicit column on a
    /// wide picture must be rejected once the derived column count
    /// exceeds MaxTileCols, instead of allocating unboundedly.
    #[test]
    fn uniform_tile_fill_is_bounded() {
        let mut pps = minimal_pps();
        pps.pps_no_pic_partition_flag = 0;
        pps.pps_pic_width_in_luma_samples = 8192; // 256 CTB-32 columns
        pps.partition = Some(VvcPpsPartition {
            pps_log2_ctu_size_minus5: 0,
            pps_tile_column_widths_minus1: vec![0], // 1-CTB uniform fill → 256 cols
            pps_tile_row_heights_minus1: vec![33],
            pps_rect_slice_flag: 1,
            ..Default::default()
        });
        assert!(write_pps(&pps).is_err());
    }
}
