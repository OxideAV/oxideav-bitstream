//! H.266 / VVC adaptation parameter set (§7.3.2.6) — parse + write.
//!
//! The APS carries the three slice-shared coding-tool data families:
//!
//! - ALF (§7.3.2.18 `alf_data()`) — luma / chroma adaptive-loop-filter
//!   coefficient sets plus the two cross-component filter banks,
//! - LMCS (§7.3.2.19 `lmcs_data()`) — luma mapping with chroma
//!   scaling piecewise-linear model,
//! - scaling lists (§7.3.2.20 `scaling_list_data()`) — the 28
//!   quantization matrices in up-right-diagonal delta coding.
//!
//! All three payloads parse completely and re-emit byte-exactly via
//! [`write_aps`] / [`write_aps_nal`]. Reserved `aps_params_type`
//! values (3..=7) and `aps_extension_flag == 1` payloads (whose
//! `aps_extension_data_flag` bits this parser does not retain) are
//! refused as [`BitstreamError::Unsupported`].
//!
//! # Spec references
//!
//! ITU-T H.266 (V4) (01/2026): §7.3.2.6 / §7.4.3.6 (APS RBSP),
//! §7.3.2.18 / §7.4.3.18 (ALF), §7.3.2.19 / §7.4.3.19 (LMCS),
//! §7.3.2.20 / §7.4.3.20 (scaling list data), §6.5.2 (up-right
//! diagonal scan order), Table 5 (PREFIX_APS_NUT / SUFFIX_APS_NUT),
//! Table 6 (`aps_params_type` codes).

use super::{ebsp_to_rbsp, parse_nal_header, NAL_TYPE_PREFIX_APS, NAL_TYPE_SUFFIX_APS};
use crate::bit_reader::BitReader;
use crate::bit_writer::BitWriter;
use crate::BitstreamError;

// ─────────────────────────── Constants ───────────────────────────────────────

/// Table 6 — `aps_params_type == 0`: ALF parameters.
pub const APS_PARAMS_TYPE_ALF: u8 = 0;
/// Table 6 — `aps_params_type == 1`: LMCS parameters.
pub const APS_PARAMS_TYPE_LMCS: u8 = 1;
/// Table 6 — `aps_params_type == 2`: scaling list parameters.
pub const APS_PARAMS_TYPE_SCALING: u8 = 2;

/// §7.4.3.18 — `NumAlfFilters`, the fixed number of luma filter
/// classes.
pub const NUM_ALF_FILTERS: usize = 25;

/// §7.3.2.20 — number of scaling-list matrix ids.
pub const NUM_SCALING_LIST_IDS: usize = 28;

// ─────────────────────────── Diagonal scan (§6.5.2) ─────────────────────────

/// The 8×8 up-right diagonal scan order `DiagScanOrder[3][3]`
/// (§6.5.2), as `(x, y)` pairs. `scaling_list_data()` indexes this
/// scan for every matrix size (only the first
/// `matrixSize * matrixSize` positions are used) and skips the
/// bottom-right 4×4 quadrant for the two 64×64 ids.
fn diag_scan_8x8() -> [(u8, u8); 64] {
    // §6.5.2 pseudo-code with blkWidth = blkHeight = 8.
    let mut out = [(0u8, 0u8); 64];
    let mut i = 0usize;
    let mut x: i32 = 0;
    let mut y: i32 = 0;
    while i < 64 {
        while y >= 0 {
            if x < 8 && y < 8 {
                out[i] = (x as u8, y as u8);
                i += 1;
            }
            y -= 1;
            x += 1;
        }
        y = x;
        x = 0;
    }
    out
}

// ─────────────────────────── ALF (§7.3.2.18) ─────────────────────────────────

/// Signalled luma ALF block — present iff
/// `alf_luma_filter_signal_flag`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcAlfLuma {
    pub alf_luma_clip_flag: bool,
    /// 0..=`NumAlfFilters − 1` (§7.4.3.18).
    pub alf_luma_num_filters_signalled_minus1: u32,
    /// `alf_luma_coeff_delta_idx[filtIdx]` — coded as
    /// `u(Ceil(Log2(alf_luma_num_filters_signalled_minus1 + 1)))`
    /// only when `alf_luma_num_filters_signalled_minus1 > 0`;
    /// inferred all-zero otherwise. Each value is bounded by
    /// `alf_luma_num_filters_signalled_minus1`.
    pub alf_luma_coeff_delta_idx: [u8; NUM_ALF_FILTERS],
    /// `alf_luma_coeff_abs[sfIdx][j]` — one row per signalled filter,
    /// each value 0..=128 (§7.4.3.18).
    pub coeff_abs: Vec<[u32; 12]>,
    /// `alf_luma_coeff_sign[sfIdx][j]` — coded iff the matching
    /// `coeff_abs` is non-zero; inferred `false` otherwise.
    pub coeff_sign: Vec<[bool; 12]>,
    /// `alf_luma_clip_idx[sfIdx][j]` u(2) — one row per signalled
    /// filter iff `alf_luma_clip_flag`; empty otherwise.
    pub clip_idx: Vec<[u8; 12]>,
}

/// Signalled chroma ALF block — present iff
/// `alf_chroma_filter_signal_flag`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcAlfChroma {
    pub alf_chroma_clip_flag: bool,
    /// 0..=7 (§7.4.3.18).
    pub alf_chroma_num_alt_filters_minus1: u32,
    /// One row per alternative filter, each value 0..=128.
    pub coeff_abs: Vec<[u32; 6]>,
    pub coeff_sign: Vec<[bool; 6]>,
    /// One row per alternative filter iff `alf_chroma_clip_flag`.
    pub clip_idx: Vec<[u8; 6]>,
}

/// One cross-component ALF filter bank (Cb or Cr) — present iff the
/// matching `alf_cc_c{b,r}_filter_signal_flag`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcAlfCcFilters {
    /// 0..=3 (§7.4.3.18).
    pub filters_signalled_minus1: u32,
    /// `alf_cc_*_mapped_coeff_abs[k][j]` u(3).
    pub mapped_coeff_abs: Vec<[u8; 7]>,
    /// Coded iff the matching mapped coefficient is non-zero.
    pub coeff_sign: Vec<[bool; 7]>,
}

/// `alf_data()` (§7.3.2.18).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcAlfData {
    pub alf_luma_filter_signal_flag: bool,
    /// Only coded when `aps_chroma_present_flag`; inferred `false`
    /// otherwise.
    pub alf_chroma_filter_signal_flag: bool,
    pub alf_cc_cb_filter_signal_flag: bool,
    pub alf_cc_cr_filter_signal_flag: bool,
    pub luma: Option<VvcAlfLuma>,
    pub chroma: Option<VvcAlfChroma>,
    pub cc_cb: Option<VvcAlfCcFilters>,
    pub cc_cr: Option<VvcAlfCcFilters>,
}

/// Ceil(Log2(x)) for x ≥ 1.
fn ceil_log2(x: u32) -> u32 {
    debug_assert!(x >= 1);
    32 - (x - 1).leading_zeros().min(32)
}

fn parse_alf_data(
    r: &mut BitReader<'_>,
    chroma_present: bool,
) -> Result<VvcAlfData, BitstreamError> {
    let mut d = VvcAlfData {
        alf_luma_filter_signal_flag: r.u(1) != 0,
        ..VvcAlfData::default()
    };
    if chroma_present {
        d.alf_chroma_filter_signal_flag = r.u(1) != 0;
        d.alf_cc_cb_filter_signal_flag = r.u(1) != 0;
        d.alf_cc_cr_filter_signal_flag = r.u(1) != 0;
    }
    if d.alf_luma_filter_signal_flag {
        let mut luma = VvcAlfLuma {
            alf_luma_clip_flag: r.u(1) != 0,
            alf_luma_num_filters_signalled_minus1: r.ue()?,
            ..VvcAlfLuma::default()
        };
        // §7.4.3.18: 0..=NumAlfFilters − 1 — also bounds the loops.
        if luma.alf_luma_num_filters_signalled_minus1 > (NUM_ALF_FILTERS - 1) as u32 {
            return Err(BitstreamError::invalid(format!(
                "alf_luma_num_filters_signalled_minus1={} (must be 0..=24, §7.4.3.18)",
                luma.alf_luma_num_filters_signalled_minus1
            )));
        }
        if luma.alf_luma_num_filters_signalled_minus1 > 0 {
            let bits = ceil_log2(luma.alf_luma_num_filters_signalled_minus1 + 1);
            for filt_idx in 0..NUM_ALF_FILTERS {
                let idx = r.u(bits);
                if idx > luma.alf_luma_num_filters_signalled_minus1 {
                    return Err(BitstreamError::invalid(format!(
                        "alf_luma_coeff_delta_idx[{filt_idx}]={idx} exceeds \
                         alf_luma_num_filters_signalled_minus1 (§7.4.3.18)"
                    )));
                }
                luma.alf_luma_coeff_delta_idx[filt_idx] = idx as u8;
            }
        }
        for _ in 0..=luma.alf_luma_num_filters_signalled_minus1 {
            let mut abs = [0u32; 12];
            let mut sign = [false; 12];
            for j in 0..12 {
                abs[j] = r.ue()?;
                // §7.4.3.18: 0..=128.
                if abs[j] > 128 {
                    return Err(BitstreamError::invalid(format!(
                        "alf_luma_coeff_abs={} (must be 0..=128, §7.4.3.18)",
                        abs[j]
                    )));
                }
                if abs[j] != 0 {
                    sign[j] = r.u(1) != 0;
                }
            }
            luma.coeff_abs.push(abs);
            luma.coeff_sign.push(sign);
        }
        if luma.alf_luma_clip_flag {
            for _ in 0..=luma.alf_luma_num_filters_signalled_minus1 {
                let mut clip = [0u8; 12];
                for c in clip.iter_mut() {
                    *c = r.u(2) as u8;
                }
                luma.clip_idx.push(clip);
            }
        }
        d.luma = Some(luma);
    }
    if d.alf_chroma_filter_signal_flag {
        let mut chroma = VvcAlfChroma {
            alf_chroma_clip_flag: r.u(1) != 0,
            alf_chroma_num_alt_filters_minus1: r.ue()?,
            ..VvcAlfChroma::default()
        };
        // §7.4.3.18: 0..=7.
        if chroma.alf_chroma_num_alt_filters_minus1 > 7 {
            return Err(BitstreamError::invalid(format!(
                "alf_chroma_num_alt_filters_minus1={} (must be 0..=7, §7.4.3.18)",
                chroma.alf_chroma_num_alt_filters_minus1
            )));
        }
        for _ in 0..=chroma.alf_chroma_num_alt_filters_minus1 {
            let mut abs = [0u32; 6];
            let mut sign = [false; 6];
            for j in 0..6 {
                abs[j] = r.ue()?;
                if abs[j] > 128 {
                    return Err(BitstreamError::invalid(format!(
                        "alf_chroma_coeff_abs={} (must be 0..=128, §7.4.3.18)",
                        abs[j]
                    )));
                }
                if abs[j] != 0 {
                    sign[j] = r.u(1) != 0;
                }
            }
            chroma.coeff_abs.push(abs);
            chroma.coeff_sign.push(sign);
            if chroma.alf_chroma_clip_flag {
                let mut clip = [0u8; 6];
                for c in clip.iter_mut() {
                    *c = r.u(2) as u8;
                }
                chroma.clip_idx.push(clip);
            }
        }
        d.chroma = Some(chroma);
    }
    for (signal, slot) in [
        (d.alf_cc_cb_filter_signal_flag, &mut d.cc_cb),
        (d.alf_cc_cr_filter_signal_flag, &mut d.cc_cr),
    ] {
        if !signal {
            continue;
        }
        let mut cc = VvcAlfCcFilters {
            filters_signalled_minus1: r.ue()?,
            ..VvcAlfCcFilters::default()
        };
        // §7.4.3.18: 0..=3.
        if cc.filters_signalled_minus1 > 3 {
            return Err(BitstreamError::invalid(format!(
                "alf_cc_*_filters_signalled_minus1={} (must be 0..=3, §7.4.3.18)",
                cc.filters_signalled_minus1
            )));
        }
        for _ in 0..=cc.filters_signalled_minus1 {
            let mut abs = [0u8; 7];
            let mut sign = [false; 7];
            for j in 0..7 {
                abs[j] = r.u(3) as u8;
                if abs[j] != 0 {
                    sign[j] = r.u(1) != 0;
                }
            }
            cc.mapped_coeff_abs.push(abs);
            cc.coeff_sign.push(sign);
        }
        *slot = Some(cc);
    }
    Ok(d)
}

fn write_alf_data(
    w: &mut BitWriter,
    d: &VvcAlfData,
    chroma_present: bool,
) -> Result<(), BitstreamError> {
    w.write_bit(u32::from(d.alf_luma_filter_signal_flag));
    if chroma_present {
        w.write_bit(u32::from(d.alf_chroma_filter_signal_flag));
        w.write_bit(u32::from(d.alf_cc_cb_filter_signal_flag));
        w.write_bit(u32::from(d.alf_cc_cr_filter_signal_flag));
    } else if d.alf_chroma_filter_signal_flag
        || d.alf_cc_cb_filter_signal_flag
        || d.alf_cc_cr_filter_signal_flag
    {
        return Err(BitstreamError::invalid(
            "ALF chroma / cross-component signal flags require aps_chroma_present_flag \
             (§7.3.2.18)",
        ));
    }
    if d.alf_luma_filter_signal_flag {
        let Some(luma) = &d.luma else {
            return Err(BitstreamError::invalid(
                "alf_luma_filter_signal_flag set without luma content",
            ));
        };
        if luma.alf_luma_num_filters_signalled_minus1 > (NUM_ALF_FILTERS - 1) as u32 {
            return Err(BitstreamError::invalid(
                "alf_luma_num_filters_signalled_minus1 must be 0..=24 (§7.4.3.18)",
            ));
        }
        let signalled = luma.alf_luma_num_filters_signalled_minus1 as usize + 1;
        if luma.coeff_abs.len() != signalled || luma.coeff_sign.len() != signalled {
            return Err(BitstreamError::invalid(
                "ALF luma coefficient rows must match the signalled filter count",
            ));
        }
        if luma.clip_idx.len()
            != if luma.alf_luma_clip_flag {
                signalled
            } else {
                0
            }
        {
            return Err(BitstreamError::invalid(
                "ALF luma clip_idx rows must match the clip flag and filter count",
            ));
        }
        w.write_bit(u32::from(luma.alf_luma_clip_flag));
        w.write_ue(luma.alf_luma_num_filters_signalled_minus1)?;
        if luma.alf_luma_num_filters_signalled_minus1 > 0 {
            let bits = ceil_log2(luma.alf_luma_num_filters_signalled_minus1 + 1);
            for filt_idx in 0..NUM_ALF_FILTERS {
                let idx = luma.alf_luma_coeff_delta_idx[filt_idx] as u32;
                if idx > luma.alf_luma_num_filters_signalled_minus1 {
                    return Err(BitstreamError::invalid(format!(
                        "alf_luma_coeff_delta_idx[{filt_idx}] exceeds \
                         alf_luma_num_filters_signalled_minus1 (§7.4.3.18)"
                    )));
                }
                w.write_bits(idx, bits);
            }
        } else if luma.alf_luma_coeff_delta_idx.iter().any(|&v| v != 0) {
            return Err(BitstreamError::invalid(
                "alf_luma_coeff_delta_idx entries are inferred 0 when only one filter \
                 is signalled (§7.4.3.18)",
            ));
        }
        for (abs, sign) in luma.coeff_abs.iter().zip(&luma.coeff_sign) {
            for j in 0..12 {
                if abs[j] > 128 {
                    return Err(BitstreamError::invalid(
                        "alf_luma_coeff_abs must be 0..=128 (§7.4.3.18)",
                    ));
                }
                w.write_ue(abs[j])?;
                if abs[j] != 0 {
                    w.write_bit(u32::from(sign[j]));
                } else if sign[j] {
                    return Err(BitstreamError::invalid(
                        "alf_luma_coeff_sign is inferred 0 for a zero coefficient (§7.4.3.18)",
                    ));
                }
            }
        }
        for clip in &luma.clip_idx {
            for &c in clip {
                if c > 3 {
                    return Err(BitstreamError::invalid(
                        "alf_luma_clip_idx does not fit u(2)",
                    ));
                }
                w.write_bits(c as u32, 2);
            }
        }
    } else if d.luma.is_some() {
        return Err(BitstreamError::invalid(
            "ALF luma content without alf_luma_filter_signal_flag",
        ));
    }
    if d.alf_chroma_filter_signal_flag {
        let Some(chroma) = &d.chroma else {
            return Err(BitstreamError::invalid(
                "alf_chroma_filter_signal_flag set without chroma content",
            ));
        };
        if chroma.alf_chroma_num_alt_filters_minus1 > 7 {
            return Err(BitstreamError::invalid(
                "alf_chroma_num_alt_filters_minus1 must be 0..=7 (§7.4.3.18)",
            ));
        }
        let alts = chroma.alf_chroma_num_alt_filters_minus1 as usize + 1;
        if chroma.coeff_abs.len() != alts || chroma.coeff_sign.len() != alts {
            return Err(BitstreamError::invalid(
                "ALF chroma coefficient rows must match the alternative-filter count",
            ));
        }
        if chroma.clip_idx.len() != if chroma.alf_chroma_clip_flag { alts } else { 0 } {
            return Err(BitstreamError::invalid(
                "ALF chroma clip_idx rows must match the clip flag and filter count",
            ));
        }
        w.write_bit(u32::from(chroma.alf_chroma_clip_flag));
        w.write_ue(chroma.alf_chroma_num_alt_filters_minus1)?;
        for alt in 0..alts {
            let abs = &chroma.coeff_abs[alt];
            let sign = &chroma.coeff_sign[alt];
            for j in 0..6 {
                if abs[j] > 128 {
                    return Err(BitstreamError::invalid(
                        "alf_chroma_coeff_abs must be 0..=128 (§7.4.3.18)",
                    ));
                }
                w.write_ue(abs[j])?;
                if abs[j] != 0 {
                    w.write_bit(u32::from(sign[j]));
                } else if sign[j] {
                    return Err(BitstreamError::invalid(
                        "alf_chroma_coeff_sign is inferred 0 for a zero coefficient (§7.4.3.18)",
                    ));
                }
            }
            if chroma.alf_chroma_clip_flag {
                for &c in &chroma.clip_idx[alt] {
                    if c > 3 {
                        return Err(BitstreamError::invalid(
                            "alf_chroma_clip_idx does not fit u(2)",
                        ));
                    }
                    w.write_bits(c as u32, 2);
                }
            }
        }
    } else if d.chroma.is_some() {
        return Err(BitstreamError::invalid(
            "ALF chroma content without alf_chroma_filter_signal_flag",
        ));
    }
    for (signal, slot, what) in [
        (d.alf_cc_cb_filter_signal_flag, &d.cc_cb, "Cb"),
        (d.alf_cc_cr_filter_signal_flag, &d.cc_cr, "Cr"),
    ] {
        if !signal {
            if slot.is_some() {
                return Err(BitstreamError::invalid(format!(
                    "ALF cross-component {what} content without its signal flag"
                )));
            }
            continue;
        }
        let Some(cc) = slot else {
            return Err(BitstreamError::invalid(format!(
                "ALF cross-component {what} signal flag set without content"
            )));
        };
        if cc.filters_signalled_minus1 > 3 {
            return Err(BitstreamError::invalid(
                "alf_cc_*_filters_signalled_minus1 must be 0..=3 (§7.4.3.18)",
            ));
        }
        let count = cc.filters_signalled_minus1 as usize + 1;
        if cc.mapped_coeff_abs.len() != count || cc.coeff_sign.len() != count {
            return Err(BitstreamError::invalid(
                "ALF cross-component coefficient rows must match the signalled count",
            ));
        }
        w.write_ue(cc.filters_signalled_minus1)?;
        for (abs, sign) in cc.mapped_coeff_abs.iter().zip(&cc.coeff_sign) {
            for j in 0..7 {
                if abs[j] > 7 {
                    return Err(BitstreamError::invalid(
                        "alf_cc_*_mapped_coeff_abs does not fit u(3)",
                    ));
                }
                w.write_bits(abs[j] as u32, 3);
                if abs[j] != 0 {
                    w.write_bit(u32::from(sign[j]));
                } else if sign[j] {
                    return Err(BitstreamError::invalid(
                        "alf_cc_*_coeff_sign is inferred 0 for a zero coefficient (§7.4.3.18)",
                    ));
                }
            }
        }
    }
    Ok(())
}

// ─────────────────────────── LMCS (§7.3.2.19) ────────────────────────────────

/// `lmcs_data()` (§7.3.2.19). The 16-entry codeword arrays hold
/// coded values at indices `lmcs_min_bin_idx..=LmcsMaxBinIdx` and the
/// inferred zeros elsewhere.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcLmcsData {
    /// 0..=15 (§7.4.3.19).
    pub lmcs_min_bin_idx: u32,
    /// 0..=15; `LmcsMaxBinIdx = 15 − lmcs_delta_max_bin_idx` must be
    /// ≥ `lmcs_min_bin_idx` (§7.4.3.19).
    pub lmcs_delta_max_bin_idx: u32,
    /// 0..=14 — `lmcs_delta_abs_cw` entries are coded as
    /// `u(lmcs_delta_cw_prec_minus1 + 1)`.
    pub lmcs_delta_cw_prec_minus1: u32,
    pub lmcs_delta_abs_cw: [u32; 16],
    pub lmcs_delta_sign_cw_flag: [bool; 16],
    /// u(3) — coded only when `aps_chroma_present_flag`.
    pub lmcs_delta_abs_crs: u8,
    /// Coded iff `lmcs_delta_abs_crs > 0`.
    pub lmcs_delta_sign_crs_flag: bool,
}

impl VvcLmcsData {
    /// `LmcsMaxBinIdx` (§7.4.3.19).
    pub fn lmcs_max_bin_idx(&self) -> u32 {
        15 - self.lmcs_delta_max_bin_idx.min(15)
    }
}

fn parse_lmcs_data(
    r: &mut BitReader<'_>,
    chroma_present: bool,
) -> Result<VvcLmcsData, BitstreamError> {
    let mut d = VvcLmcsData {
        lmcs_min_bin_idx: r.ue()?,
        lmcs_delta_max_bin_idx: r.ue()?,
        lmcs_delta_cw_prec_minus1: r.ue()?,
        ..VvcLmcsData::default()
    };
    // §7.4.3.19 ranges; the max-bin constraint also bounds the loop.
    if d.lmcs_min_bin_idx > 15 {
        return Err(BitstreamError::invalid(format!(
            "lmcs_min_bin_idx={} (must be 0..=15, §7.4.3.19)",
            d.lmcs_min_bin_idx
        )));
    }
    if d.lmcs_delta_max_bin_idx > 15 || 15 - d.lmcs_delta_max_bin_idx < d.lmcs_min_bin_idx {
        return Err(BitstreamError::invalid(format!(
            "lmcs_delta_max_bin_idx={} (LmcsMaxBinIdx must be lmcs_min_bin_idx..=15, §7.4.3.19)",
            d.lmcs_delta_max_bin_idx
        )));
    }
    if d.lmcs_delta_cw_prec_minus1 > 14 {
        return Err(BitstreamError::invalid(format!(
            "lmcs_delta_cw_prec_minus1={} (must be 0..=14, §7.4.3.19)",
            d.lmcs_delta_cw_prec_minus1
        )));
    }
    let bits = d.lmcs_delta_cw_prec_minus1 + 1;
    for i in d.lmcs_min_bin_idx as usize..=(15 - d.lmcs_delta_max_bin_idx) as usize {
        d.lmcs_delta_abs_cw[i] = r.u(bits);
        if d.lmcs_delta_abs_cw[i] > 0 {
            d.lmcs_delta_sign_cw_flag[i] = r.u(1) != 0;
        }
    }
    if chroma_present {
        d.lmcs_delta_abs_crs = r.u(3) as u8;
        if d.lmcs_delta_abs_crs > 0 {
            d.lmcs_delta_sign_crs_flag = r.u(1) != 0;
        }
    }
    Ok(d)
}

fn write_lmcs_data(
    w: &mut BitWriter,
    d: &VvcLmcsData,
    chroma_present: bool,
) -> Result<(), BitstreamError> {
    if d.lmcs_min_bin_idx > 15
        || d.lmcs_delta_max_bin_idx > 15
        || 15 - d.lmcs_delta_max_bin_idx < d.lmcs_min_bin_idx
    {
        return Err(BitstreamError::invalid(
            "LMCS bin indices out of range (§7.4.3.19)",
        ));
    }
    if d.lmcs_delta_cw_prec_minus1 > 14 {
        return Err(BitstreamError::invalid(
            "lmcs_delta_cw_prec_minus1 must be 0..=14 (§7.4.3.19)",
        ));
    }
    w.write_ue(d.lmcs_min_bin_idx)?;
    w.write_ue(d.lmcs_delta_max_bin_idx)?;
    w.write_ue(d.lmcs_delta_cw_prec_minus1)?;
    let bits = d.lmcs_delta_cw_prec_minus1 + 1;
    for i in 0..16usize {
        let coded =
            (d.lmcs_min_bin_idx as usize..=(15 - d.lmcs_delta_max_bin_idx) as usize).contains(&i);
        if coded {
            if u64::from(d.lmcs_delta_abs_cw[i]) >> bits != 0 {
                return Err(BitstreamError::invalid(format!(
                    "lmcs_delta_abs_cw[{i}] does not fit u({bits})"
                )));
            }
            w.write_bits(d.lmcs_delta_abs_cw[i], bits);
            if d.lmcs_delta_abs_cw[i] > 0 {
                w.write_bit(u32::from(d.lmcs_delta_sign_cw_flag[i]));
            } else if d.lmcs_delta_sign_cw_flag[i] {
                return Err(BitstreamError::invalid(
                    "lmcs_delta_sign_cw_flag is inferred 0 for a zero codeword (§7.4.3.19)",
                ));
            }
        } else if d.lmcs_delta_abs_cw[i] != 0 || d.lmcs_delta_sign_cw_flag[i] {
            return Err(BitstreamError::invalid(
                "LMCS codeword entries outside lmcs_min_bin_idx..=LmcsMaxBinIdx are \
                 inferred 0 (§7.4.3.19)",
            ));
        }
    }
    if chroma_present {
        if d.lmcs_delta_abs_crs > 7 {
            return Err(BitstreamError::invalid(
                "lmcs_delta_abs_crs does not fit u(3)",
            ));
        }
        w.write_bits(d.lmcs_delta_abs_crs as u32, 3);
        if d.lmcs_delta_abs_crs > 0 {
            w.write_bit(u32::from(d.lmcs_delta_sign_crs_flag));
        } else if d.lmcs_delta_sign_crs_flag {
            return Err(BitstreamError::invalid(
                "lmcs_delta_sign_crs_flag is inferred 0 for a zero crs delta (§7.4.3.19)",
            ));
        }
    } else if d.lmcs_delta_abs_crs != 0 || d.lmcs_delta_sign_crs_flag {
        return Err(BitstreamError::invalid(
            "LMCS chroma residual scaling fields require aps_chroma_present_flag (§7.3.2.19)",
        ));
    }
    Ok(())
}

// ─────────────────────────── Scaling lists (§7.3.2.20) ──────────────────────

/// `scaling_list_data()` (§7.3.2.20). For each of the 28 matrix ids
/// the resolved `ScalingList[id][i]` delta-accumulator values are
/// stored (only the first `matrixSize²` entries of each row are
/// meaningful; the byte-exact writer re-derives the coded
/// `scaling_list_delta_coef` differences from them). Ids that are not
/// coded (chroma ids without `aps_chroma_present_flag`) keep
/// `scaling_list_copy_mode_flag == true` per the §7.4.3.20 inference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VvcScalingListData {
    pub copy_mode_flag: [bool; NUM_SCALING_LIST_IDS],
    pub pred_mode_flag: [bool; NUM_SCALING_LIST_IDS],
    /// Bounded by `maxIdDelta` (101): `id`, `id − 2` or `id − 8`
    /// depending on the size class.
    pub pred_id_delta: [u32; NUM_SCALING_LIST_IDS],
    /// `scaling_list_dc_coef[id − 14]` for ids 14..=27, −128..=127.
    pub dc_coef: [i32; 14],
    /// `ScalingList[id][i]` accumulator values (105).
    pub scaling_list: [[i32; 64]; NUM_SCALING_LIST_IDS],
}

impl Default for VvcScalingListData {
    fn default() -> Self {
        VvcScalingListData {
            copy_mode_flag: [false; NUM_SCALING_LIST_IDS],
            pred_mode_flag: [false; NUM_SCALING_LIST_IDS],
            pred_id_delta: [0; NUM_SCALING_LIST_IDS],
            dc_coef: [0; 14],
            scaling_list: [[0; 64]; NUM_SCALING_LIST_IDS],
        }
    }
}

/// `matrixSize` for a scaling-list id (§7.3.2.20).
fn matrix_size(id: usize) -> usize {
    if id < 2 {
        2
    } else if id < 8 {
        4
    } else {
        8
    }
}

/// `maxIdDelta` (101).
fn max_id_delta(id: usize) -> u32 {
    (if id < 2 {
        id
    } else if id < 8 {
        id - 2
    } else {
        id - 8
    }) as u32
}

/// True when the syntax codes matrix `id` for this
/// `aps_chroma_present_flag` (§7.3.2.20).
fn scaling_id_coded(id: usize, chroma_present: bool) -> bool {
    chroma_present || id % 3 == 2 || id == 27
}

fn parse_scaling_list_data(
    r: &mut BitReader<'_>,
    chroma_present: bool,
) -> Result<VvcScalingListData, BitstreamError> {
    let scan = diag_scan_8x8();
    let mut d = VvcScalingListData::default();
    for id in 0..NUM_SCALING_LIST_IDS {
        if !scaling_id_coded(id, chroma_present) {
            // §7.4.3.20: scaling_list_copy_mode_flag inferred to 1.
            d.copy_mode_flag[id] = true;
            continue;
        }
        d.copy_mode_flag[id] = r.u(1) != 0;
        if !d.copy_mode_flag[id] {
            d.pred_mode_flag[id] = r.u(1) != 0;
        }
        if (d.copy_mode_flag[id] || d.pred_mode_flag[id]) && id != 0 && id != 2 && id != 8 {
            d.pred_id_delta[id] = r.ue()?;
            // §7.4.3.20 (101): 0..=maxIdDelta.
            if d.pred_id_delta[id] > max_id_delta(id) {
                return Err(BitstreamError::invalid(format!(
                    "scaling_list_pred_id_delta[{id}]={} exceeds maxIdDelta={} (§7.4.3.20)",
                    d.pred_id_delta[id],
                    max_id_delta(id)
                )));
            }
        }
        if !d.copy_mode_flag[id] {
            let mut next_coef: i32 = 0;
            if id > 13 {
                let dc = r.se()?;
                // §7.4.3.20: −128..=127.
                if !(-128..=127).contains(&dc) {
                    return Err(BitstreamError::invalid(format!(
                        "scaling_list_dc_coef[{}]={dc} out of -128..=127 (§7.4.3.20)",
                        id - 14
                    )));
                }
                d.dc_coef[id - 14] = dc;
                next_coef += dc;
            }
            let n = matrix_size(id);
            for (i, &(x, y)) in scan.iter().enumerate().take(n * n) {
                if !(id > 25 && x >= 4 && y >= 4) {
                    let delta = r.se()?;
                    if !(-128..=127).contains(&delta) {
                        return Err(BitstreamError::invalid(format!(
                            "scaling_list_delta_coef[{id}][{i}]={delta} out of -128..=127 \
                             (§7.4.3.20)"
                        )));
                    }
                    next_coef += delta;
                }
                d.scaling_list[id][i] = next_coef;
            }
        }
    }
    Ok(d)
}

fn write_scaling_list_data(
    w: &mut BitWriter,
    d: &VvcScalingListData,
    chroma_present: bool,
) -> Result<(), BitstreamError> {
    let scan = diag_scan_8x8();
    for id in 0..NUM_SCALING_LIST_IDS {
        if !scaling_id_coded(id, chroma_present) {
            continue;
        }
        w.write_bit(u32::from(d.copy_mode_flag[id]));
        if !d.copy_mode_flag[id] {
            w.write_bit(u32::from(d.pred_mode_flag[id]));
        } else if d.pred_mode_flag[id] {
            return Err(BitstreamError::invalid(
                "scaling_list_pred_mode_flag is only coded when copy mode is off (§7.3.2.20)",
            ));
        }
        if (d.copy_mode_flag[id] || d.pred_mode_flag[id]) && id != 0 && id != 2 && id != 8 {
            if d.pred_id_delta[id] > max_id_delta(id) {
                return Err(BitstreamError::invalid(format!(
                    "scaling_list_pred_id_delta[{id}] exceeds maxIdDelta (§7.4.3.20)"
                )));
            }
            w.write_ue(d.pred_id_delta[id])?;
        } else if d.pred_id_delta[id] != 0 {
            return Err(BitstreamError::invalid(format!(
                "scaling_list_pred_id_delta[{id}] is inferred 0 and cannot be coded here \
                 (§7.4.3.20)"
            )));
        }
        if !d.copy_mode_flag[id] {
            let mut prev: i32 = 0;
            if id > 13 {
                let dc = d.dc_coef[id - 14];
                if !(-128..=127).contains(&dc) {
                    return Err(BitstreamError::invalid(
                        "scaling_list_dc_coef out of -128..=127 (§7.4.3.20)",
                    ));
                }
                w.write_se(dc)?;
                prev += dc;
            }
            let n = matrix_size(id);
            for (i, &(x, y)) in scan.iter().enumerate().take(n * n) {
                if !(id > 25 && x >= 4 && y >= 4) {
                    let delta = d.scaling_list[id][i] - prev;
                    if !(-128..=127).contains(&delta) {
                        return Err(BitstreamError::invalid(format!(
                            "ScalingList[{id}][{i}] step out of the -128..=127 \
                             scaling_list_delta_coef range (§7.4.3.20)"
                        )));
                    }
                    w.write_se(delta)?;
                    prev = d.scaling_list[id][i];
                } else if d.scaling_list[id][i] != prev {
                    return Err(BitstreamError::invalid(format!(
                        "ScalingList[{id}][{i}] must repeat the accumulator in the skipped \
                         64×64 quadrant (§7.3.2.20)"
                    )));
                }
            }
        }
    }
    Ok(())
}

// ─────────────────────────── APS wrapper (§7.3.2.6) ─────────────────────────

/// Decoded `adaptation_parameter_set_rbsp()` (§7.3.2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VvcAps {
    /// One of [`APS_PARAMS_TYPE_ALF`] / [`APS_PARAMS_TYPE_LMCS`] /
    /// [`APS_PARAMS_TYPE_SCALING`]. Reserved values are refused at
    /// parse time (their payload syntax is undefined).
    pub aps_params_type: u8,
    /// u(5); 0..=7 for ALF/scaling APSs, 0..=3 for LMCS (§7.4.3.6).
    pub aps_adaptation_parameter_set_id: u8,
    pub aps_chroma_present_flag: bool,
    pub payload: VvcApsPayload,
    /// Retained; the extension payload itself is not, so the writer
    /// refuses `true`.
    pub aps_extension_flag: bool,
}

/// The type-discriminated APS payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VvcApsPayload {
    Alf(Box<VvcAlfData>),
    Lmcs(VvcLmcsData),
    ScalingList(Box<VvcScalingListData>),
}

/// Parse an `adaptation_parameter_set_rbsp()` from an RBSP (already
/// emulation-prevention-stripped, no NAL header).
pub fn parse_aps_rbsp(rbsp: &[u8]) -> Result<VvcAps, BitstreamError> {
    let mut r = BitReader::new(rbsp);
    let aps_params_type = r.u(3) as u8;
    let aps_adaptation_parameter_set_id = r.u(5) as u8;
    let aps_chroma_present_flag = r.u(1) != 0;
    // §7.4.3.6 id ranges per type; also rejects the reserved types
    // 3..=7 whose payload syntax is undefined in this edition.
    let payload = match aps_params_type {
        APS_PARAMS_TYPE_ALF => {
            VvcApsPayload::Alf(Box::new(parse_alf_data(&mut r, aps_chroma_present_flag)?))
        }
        APS_PARAMS_TYPE_LMCS => {
            if aps_adaptation_parameter_set_id > 3 {
                return Err(BitstreamError::invalid(format!(
                    "LMCS aps_adaptation_parameter_set_id={aps_adaptation_parameter_set_id} \
                     (must be 0..=3, §7.4.3.6)"
                )));
            }
            VvcApsPayload::Lmcs(parse_lmcs_data(&mut r, aps_chroma_present_flag)?)
        }
        APS_PARAMS_TYPE_SCALING => VvcApsPayload::ScalingList(Box::new(parse_scaling_list_data(
            &mut r,
            aps_chroma_present_flag,
        )?)),
        other => {
            return Err(BitstreamError::unsupported(format!(
                "reserved aps_params_type={other} (Table 6; decoders shall ignore such APSs)"
            )));
        }
    };
    if aps_params_type != APS_PARAMS_TYPE_LMCS && aps_adaptation_parameter_set_id > 7 {
        return Err(BitstreamError::invalid(format!(
            "aps_adaptation_parameter_set_id={aps_adaptation_parameter_set_id} \
             (must be 0..=7, §7.4.3.6)"
        )));
    }
    let aps_extension_flag = r.u(1) != 0;
    // aps_extension_data_flag bits (if any) are not retained; the
    // remaining bits are extension data + rbsp_trailing_bits.
    if !aps_extension_flag {
        r.read_rbsp_trailing_bits()?;
    }
    Ok(VvcAps {
        aps_params_type,
        aps_adaptation_parameter_set_id,
        aps_chroma_present_flag,
        payload,
        aps_extension_flag,
    })
}

/// Parse an APS NAL — two-byte NAL header (type 17 PREFIX_APS or 18
/// SUFFIX_APS) followed by the EBSP body.
pub fn parse_aps(nal_body: &[u8]) -> Result<VvcAps, BitstreamError> {
    if nal_body.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "H.266 APS NAL needs at least the 2-byte header",
        ));
    }
    let header = parse_nal_header(nal_body)?;
    if header.nal_unit_type != NAL_TYPE_PREFIX_APS && header.nal_unit_type != NAL_TYPE_SUFFIX_APS {
        return Err(BitstreamError::invalid(format!(
            "expected APS NAL (type {NAL_TYPE_PREFIX_APS} or {NAL_TYPE_SUFFIX_APS}), got {}",
            header.nal_unit_type
        )));
    }
    let rbsp = ebsp_to_rbsp(&nal_body[2..]);
    parse_aps_rbsp(&rbsp)
}

/// Emit an `adaptation_parameter_set_rbsp()` (§7.3.2.6 including
/// `rbsp_trailing_bits()`) — the byte-exact inverse of
/// [`parse_aps_rbsp`] for every input that parser accepts, except
/// `aps_extension_flag == 1` (unretained extension payload), which is
/// refused as [`BitstreamError::Unsupported`].
pub fn write_aps(aps: &VvcAps) -> Result<Vec<u8>, BitstreamError> {
    if aps.aps_extension_flag {
        return Err(BitstreamError::unsupported(
            "H.266 APS aps_extension_flag == 1 (unretained aps_extension_data_flag bits)",
        ));
    }
    let expected_type = match &aps.payload {
        VvcApsPayload::Alf(_) => APS_PARAMS_TYPE_ALF,
        VvcApsPayload::Lmcs(_) => APS_PARAMS_TYPE_LMCS,
        VvcApsPayload::ScalingList(_) => APS_PARAMS_TYPE_SCALING,
    };
    if aps.aps_params_type != expected_type {
        return Err(BitstreamError::invalid(format!(
            "aps_params_type={} does not match the payload variant (expected {expected_type})",
            aps.aps_params_type
        )));
    }
    let id_max = if aps.aps_params_type == APS_PARAMS_TYPE_LMCS {
        3
    } else {
        7
    };
    if aps.aps_adaptation_parameter_set_id > id_max {
        return Err(BitstreamError::invalid(format!(
            "aps_adaptation_parameter_set_id={} (must be 0..={id_max}, §7.4.3.6)",
            aps.aps_adaptation_parameter_set_id
        )));
    }
    let mut w = BitWriter::new();
    w.write_bits(aps.aps_params_type as u32, 3);
    w.write_bits(aps.aps_adaptation_parameter_set_id as u32, 5);
    w.write_bit(u32::from(aps.aps_chroma_present_flag));
    match &aps.payload {
        VvcApsPayload::Alf(d) => write_alf_data(&mut w, d, aps.aps_chroma_present_flag)?,
        VvcApsPayload::Lmcs(d) => write_lmcs_data(&mut w, d, aps.aps_chroma_present_flag)?,
        VvcApsPayload::ScalingList(d) => {
            write_scaling_list_data(&mut w, d, aps.aps_chroma_present_flag)?
        }
    }
    w.write_bit(0); // aps_extension_flag (refused above when set)
    w.write_rbsp_trailing_bits();
    Ok(w.finish())
}

/// Emit a complete APS NAL: two-byte NAL header (`nal_unit_type` must
/// be [`NAL_TYPE_PREFIX_APS`] or [`NAL_TYPE_SUFFIX_APS`]; layer 0,
/// TID 0) + emulation-prevention-encoded RBSP.
pub fn write_aps_nal(aps: &VvcAps, nal_unit_type: u8) -> Result<Vec<u8>, BitstreamError> {
    if nal_unit_type != NAL_TYPE_PREFIX_APS && nal_unit_type != NAL_TYPE_SUFFIX_APS {
        return Err(BitstreamError::invalid(format!(
            "APS NAL type must be {NAL_TYPE_PREFIX_APS} (prefix) or {NAL_TYPE_SUFFIX_APS} \
             (suffix), got {nal_unit_type}"
        )));
    }
    let rbsp = write_aps(aps)?;
    let mut out = Vec::with_capacity(2 + rbsp.len());
    out.push(0x00); // forbidden 0, reserved 0, layer 0
    out.push((nal_unit_type << 3) | 0x01); // type + tid_plus1 = 1
    out.extend_from_slice(&crate::nal::rbsp_to_ebsp(&rbsp));
    Ok(out)
}

// ─────────────────────────── Tests ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn aps_nal_from(w: BitWriter, nal_unit_type: u8) -> Vec<u8> {
        let mut nal = vec![0x00, (nal_unit_type << 3) | 0x01];
        nal.extend_from_slice(&crate::nal::rbsp_to_ebsp(&w.finish()));
        nal
    }

    #[test]
    fn diag_scan_first_positions_match_spec_order() {
        // §6.5.2 with an 8×8 block starts (0,0), (0,1), (1,0), (0,2),
        // (1,1), (2,0), … — up-right diagonals bottom-left to
        // top-right.
        let scan = diag_scan_8x8();
        assert_eq!(
            &scan[..6],
            &[(0, 0), (0, 1), (1, 0), (0, 2), (1, 1), (2, 0)]
        );
        assert_eq!(scan[63], (7, 7));
        // Every position visited exactly once.
        let mut seen = [[false; 8]; 8];
        for &(x, y) in &scan {
            assert!(!seen[y as usize][x as usize]);
            seen[y as usize][x as usize] = true;
        }
    }

    #[test]
    fn alf_aps_parses_and_roundtrips_byte_exact() {
        let mut w = BitWriter::new();
        w.write_bits(APS_PARAMS_TYPE_ALF as u32, 3);
        w.write_bits(2, 5); // aps_adaptation_parameter_set_id
        w.write_bit(1); // aps_chroma_present_flag
        w.write_bit(1); // alf_luma_filter_signal_flag
        w.write_bit(1); // alf_chroma_filter_signal_flag
        w.write_bit(1); // alf_cc_cb_filter_signal_flag
        w.write_bit(0); // alf_cc_cr_filter_signal_flag
                        // luma:
        w.write_bit(1); // alf_luma_clip_flag
        w.write_ue(1).unwrap(); // alf_luma_num_filters_signalled_minus1 = 1
        for filt_idx in 0..NUM_ALF_FILTERS {
            // u(ceil(log2(2))) = u(1)
            w.write_bits((filt_idx % 2) as u32, 1);
        }
        for sf in 0..2 {
            for j in 0..12 {
                let abs = if j == sf { 3 } else { 0 };
                w.write_ue(abs).unwrap();
                if abs != 0 {
                    w.write_bit(1); // sign
                }
            }
        }
        for _ in 0..2 {
            for j in 0..12 {
                w.write_bits((j % 4) as u32, 2); // clip_idx
            }
        }
        // chroma:
        w.write_bit(0); // alf_chroma_clip_flag
        w.write_ue(0).unwrap(); // alf_chroma_num_alt_filters_minus1
        for j in 0..6 {
            let abs = if j == 0 { 128 } else { 0 };
            w.write_ue(abs).unwrap();
            if abs != 0 {
                w.write_bit(0);
            }
        }
        // cc_cb:
        w.write_ue(1).unwrap(); // filters_signalled_minus1 = 1
        for _ in 0..2 {
            for j in 0..7 {
                let abs = if j < 2 { 5 } else { 0 };
                w.write_bits(abs, 3);
                if abs != 0 {
                    w.write_bit(1);
                }
            }
        }
        w.write_bit(0); // aps_extension_flag
        w.write_rbsp_trailing_bits();

        let nal = aps_nal_from(w, NAL_TYPE_PREFIX_APS);
        let aps = parse_aps(&nal).expect("ALF APS parses");
        assert_eq!(aps.aps_params_type, APS_PARAMS_TYPE_ALF);
        assert_eq!(aps.aps_adaptation_parameter_set_id, 2);
        assert!(aps.aps_chroma_present_flag);
        let VvcApsPayload::Alf(alf) = &aps.payload else {
            panic!("expected ALF payload");
        };
        let luma = alf.luma.as_ref().expect("luma signalled");
        assert_eq!(luma.alf_luma_num_filters_signalled_minus1, 1);
        assert_eq!(luma.alf_luma_coeff_delta_idx[0], 0);
        assert_eq!(luma.alf_luma_coeff_delta_idx[1], 1);
        assert_eq!(luma.coeff_abs[0][0], 3);
        assert!(luma.coeff_sign[0][0]);
        assert_eq!(luma.clip_idx.len(), 2);
        let chroma = alf.chroma.as_ref().expect("chroma signalled");
        assert_eq!(chroma.coeff_abs[0][0], 128);
        assert!(alf.cc_cb.is_some());
        assert!(alf.cc_cr.is_none());
        assert_eq!(
            write_aps_nal(&aps, NAL_TYPE_PREFIX_APS).expect("APS writes"),
            nal,
            "ALF APS parse→write must be byte-exact"
        );
    }

    #[test]
    fn lmcs_aps_parses_and_roundtrips_byte_exact() {
        let mut w = BitWriter::new();
        w.write_bits(APS_PARAMS_TYPE_LMCS as u32, 3);
        w.write_bits(3, 5); // id = 3 (LMCS max)
        w.write_bit(1); // chroma present
        w.write_ue(2).unwrap(); // lmcs_min_bin_idx
        w.write_ue(1).unwrap(); // lmcs_delta_max_bin_idx → LmcsMaxBinIdx = 14
        w.write_ue(3).unwrap(); // lmcs_delta_cw_prec_minus1 → u(4)
        for i in 2..=14u32 {
            let v = i % 5;
            w.write_bits(v, 4);
            if v > 0 {
                w.write_bit(i % 2);
            }
        }
        w.write_bits(5, 3); // lmcs_delta_abs_crs
        w.write_bit(1); // lmcs_delta_sign_crs_flag
        w.write_bit(0); // aps_extension_flag
        w.write_rbsp_trailing_bits();

        let nal = aps_nal_from(w, NAL_TYPE_SUFFIX_APS);
        let aps = parse_aps(&nal).expect("LMCS APS parses");
        let VvcApsPayload::Lmcs(lmcs) = &aps.payload else {
            panic!("expected LMCS payload");
        };
        assert_eq!(lmcs.lmcs_min_bin_idx, 2);
        assert_eq!(lmcs.lmcs_max_bin_idx(), 14);
        assert_eq!(lmcs.lmcs_delta_abs_cw[0], 0, "below min bin — inferred");
        assert_eq!(lmcs.lmcs_delta_abs_cw[2], 2);
        assert_eq!(lmcs.lmcs_delta_abs_crs, 5);
        assert!(lmcs.lmcs_delta_sign_crs_flag);
        assert_eq!(
            write_aps_nal(&aps, NAL_TYPE_SUFFIX_APS).expect("APS writes"),
            nal,
            "LMCS APS parse→write must be byte-exact"
        );
    }

    #[test]
    fn scaling_aps_parses_and_roundtrips_byte_exact() {
        // chroma_present = 0 codes only ids 2, 5, 8, 11, 14, 17, 20,
        // 23, 26, 27 (id % 3 == 2 or id == 27).
        let mut w = BitWriter::new();
        w.write_bits(APS_PARAMS_TYPE_SCALING as u32, 3);
        w.write_bits(0, 5);
        w.write_bit(0); // aps_chroma_present_flag = 0
        for id in 0..NUM_SCALING_LIST_IDS {
            if !(id % 3 == 2 || id == 27) {
                continue;
            }
            match id {
                2 => {
                    w.write_bit(0); // copy_mode
                    w.write_bit(0); // pred_mode → explicit from the flat-8 base
                                    // (id == 2 codes no pred_id_delta)
                    for i in 0..16 {
                        w.write_se(if i == 0 { 5 } else { 1 }).unwrap();
                    }
                }
                26 => {
                    w.write_bit(0); // copy_mode
                    w.write_bit(1); // pred_mode
                    w.write_ue(3).unwrap(); // pred_id_delta
                    w.write_se(-4).unwrap(); // dc_coef (id > 13)
                                             // 64×64 id: bottom-right 4×4 quadrant skipped → 48 coded
                    for i in 0..48 {
                        w.write_se(if i % 7 == 0 { 2 } else { 0 }).unwrap();
                    }
                }
                27 => {
                    w.write_bit(1); // copy_mode
                    w.write_ue(2).unwrap(); // pred_id_delta
                }
                _ => {
                    w.write_bit(1); // copy_mode
                    if id != 8 {
                        w.write_ue(0).unwrap(); // pred_id_delta
                    }
                }
            }
        }
        w.write_bit(0); // aps_extension_flag
        w.write_rbsp_trailing_bits();

        let nal = aps_nal_from(w, NAL_TYPE_PREFIX_APS);
        let aps = parse_aps(&nal).expect("scaling APS parses");
        let VvcApsPayload::ScalingList(sl) = &aps.payload else {
            panic!("expected scaling-list payload");
        };
        // Uncoded ids inherit the copy-mode inference.
        assert!(sl.copy_mode_flag[0]);
        assert!(sl.copy_mode_flag[1]);
        // id 2: explicit ramp 5, 6, 7, …
        assert!(!sl.copy_mode_flag[2] && !sl.pred_mode_flag[2]);
        assert_eq!(sl.scaling_list[2][0], 5);
        assert_eq!(sl.scaling_list[2][15], 20);
        // id 26: predicted with dc and the skipped quadrant repeating
        // the accumulator.
        assert!(sl.pred_mode_flag[26]);
        assert_eq!(sl.pred_id_delta[26], 3);
        assert_eq!(sl.dc_coef[26 - 14], -4);
        // id 27: copy mode with reference two ids back.
        assert!(sl.copy_mode_flag[27]);
        assert_eq!(sl.pred_id_delta[27], 2);
        assert_eq!(
            write_aps_nal(&aps, NAL_TYPE_PREFIX_APS).expect("APS writes"),
            nal,
            "scaling APS parse→write must be byte-exact"
        );
    }

    #[test]
    fn aps_rejects_reserved_type_and_out_of_range_ids() {
        // Reserved aps_params_type = 3.
        let mut w = BitWriter::new();
        w.write_bits(3, 3);
        w.write_bits(0, 5);
        w.write_bit(0);
        w.write_rbsp_trailing_bits();
        let nal = aps_nal_from(w, NAL_TYPE_PREFIX_APS);
        assert!(matches!(
            parse_aps(&nal).unwrap_err(),
            BitstreamError::Unsupported(_)
        ));

        // LMCS id = 4 exceeds the 0..=3 range (§7.4.3.6).
        let mut w = BitWriter::new();
        w.write_bits(APS_PARAMS_TYPE_LMCS as u32, 3);
        w.write_bits(4, 5);
        w.write_bit(0);
        let nal = aps_nal_from(w, NAL_TYPE_PREFIX_APS);
        assert!(matches!(
            parse_aps(&nal).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));

        // Wrong NAL type.
        let nal = vec![0x00, (super::super::NAL_TYPE_SPS << 3) | 0x01, 0x00];
        assert!(matches!(
            parse_aps(&nal).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));
    }

    #[test]
    fn aps_writer_rejects_extension_flag_and_mismatched_type() {
        let aps = VvcAps {
            aps_params_type: APS_PARAMS_TYPE_LMCS,
            aps_adaptation_parameter_set_id: 0,
            aps_chroma_present_flag: false,
            payload: VvcApsPayload::Lmcs(VvcLmcsData::default()),
            aps_extension_flag: true,
        };
        assert!(matches!(
            write_aps(&aps).unwrap_err(),
            BitstreamError::Unsupported(_)
        ));

        let aps = VvcAps {
            aps_params_type: APS_PARAMS_TYPE_ALF, // payload says LMCS
            aps_adaptation_parameter_set_id: 0,
            aps_chroma_present_flag: false,
            payload: VvcApsPayload::Lmcs(VvcLmcsData::default()),
            aps_extension_flag: false,
        };
        assert!(matches!(
            write_aps(&aps).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));
    }

    #[test]
    fn alf_luma_rejects_out_of_range_counts_and_coeffs() {
        // alf_luma_num_filters_signalled_minus1 = 25 (> 24).
        let mut w = BitWriter::new();
        w.write_bits(APS_PARAMS_TYPE_ALF as u32, 3);
        w.write_bits(0, 5);
        w.write_bit(0); // no chroma
        w.write_bit(1); // luma signal
        w.write_bit(0); // clip
        w.write_ue(25).unwrap();
        let nal = aps_nal_from(w, NAL_TYPE_PREFIX_APS);
        assert!(matches!(
            parse_aps(&nal).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));

        // alf_luma_coeff_abs = 129 (> 128).
        let mut w = BitWriter::new();
        w.write_bits(APS_PARAMS_TYPE_ALF as u32, 3);
        w.write_bits(0, 5);
        w.write_bit(0);
        w.write_bit(1); // luma signal
        w.write_bit(0); // clip
        w.write_ue(0).unwrap(); // one filter
        w.write_ue(129).unwrap(); // coeff_abs[0][0]
        let nal = aps_nal_from(w, NAL_TYPE_PREFIX_APS);
        assert!(matches!(
            parse_aps(&nal).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));
    }

    #[test]
    fn lmcs_rejects_inverted_bin_range() {
        // min_bin 10 with delta_max 8 → LmcsMaxBinIdx 7 < 10.
        let mut w = BitWriter::new();
        w.write_bits(APS_PARAMS_TYPE_LMCS as u32, 3);
        w.write_bits(0, 5);
        w.write_bit(0);
        w.write_ue(10).unwrap();
        w.write_ue(8).unwrap();
        w.write_ue(0).unwrap();
        let nal = aps_nal_from(w, NAL_TYPE_PREFIX_APS);
        assert!(matches!(
            parse_aps(&nal).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));
    }
}
