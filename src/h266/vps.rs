//! H.266 / VVC video parameter set (§7.3.2.3) — complete walk,
//! parse + byte-exact write.
//!
//! [`parse_vps`] walks every syntax element of
//! `video_parameter_set_rbsp()` through `rbsp_trailing_bits()`,
//! including the multi-layer machinery: the inter-layer dependency
//! block, OLS configuration for every `vps_ols_mode_idc` (with the
//! §7.4.3.3 `TotalNumOlss` / `NumLayersInOls` / `NumMultiLayerOlss`
//! derivations — for mode 2 that means the transitive
//! reference-layer closure), the PTL list, the per-multi-layer-OLS
//! DPB blocks and the OLS timing/HRD list. [`write_vps`] replays the
//! same derivations and is the byte-exact inverse.
//!
//! # Spec references
//!
//! ITU-T H.266 (V4) (01/2026): §7.3.2.3 / §7.4.3.3 (VPS RBSP +
//! OLS derivations, eqs. (28)–(33)), §7.3.3.1 (profile / tier /
//! level), §7.3.4 (DPB), §7.3.5 (timing + HRD).

use super::params::{
    parse_dpb_parameters, parse_general_timing_hrd, parse_ols_timing_hrd, write_dpb_parameters,
    write_general_timing_hrd, write_ols_timing_hrd, VvcDpbParameters, VvcGeneralTimingHrd,
    VvcOlsTimingHrd,
};
use super::{
    ebsp_to_rbsp, parse_nal_header, parse_profile_tier_level, write_profile_tier_level,
    VvcProfileTierLevel, NAL_TYPE_VPS,
};
use crate::bit_reader::BitReader;
use crate::bit_writer::BitWriter;
use crate::BitstreamError;

// ─────────────────────────── Sub-structures ─────────────────────────────────

/// One layer's entry in the VPS layer loop (§7.3.2.3). Uncoded fields
/// carry their §7.4.3.3 inferred values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcVpsLayer {
    /// `vps_layer_id[i]` u(6) — strictly increasing across layers.
    pub vps_layer_id: u8,
    /// `vps_independent_layer_flag[i]` u(1) — coded only for `i > 0`
    /// when `!vps_all_independent_layers_flag`; inferred 1.
    pub vps_independent_layer_flag: u8,
    /// `vps_max_tid_ref_present_flag[i]` u(1) — coded only for
    /// dependent layers; inferred 0.
    pub vps_max_tid_ref_present_flag: u8,
    /// `vps_direct_ref_layer_flag[i][j]` for `j < i` — empty (all
    /// inferred 0) for independent layers.
    pub vps_direct_ref_layer_flag: Vec<u8>,
    /// `vps_max_tid_il_ref_pics_plus1[i][j]` for `j < i` — parallel
    /// to the direct-ref flags; coded only where the max-tid-ref
    /// present flag and the direct-ref flag are both set, inferred
    /// `vps_max_sublayers_minus1 + 1` otherwise. Empty for
    /// independent layers.
    pub vps_max_tid_il_ref_pics_plus1: Vec<u8>,
}

/// One `profile_tier_level()` slot in the VPS (§7.3.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VvcVpsPtl {
    /// `vps_pt_present_flag[i]` u(1) — coded only for `i > 0`;
    /// inferred 1 for `i == 0`.
    pub vps_pt_present_flag: u8,
    /// `vps_ptl_max_tid[i]` u(3) — coded only when
    /// `!vps_default_ptl_dpb_hrd_max_tid_flag`; inferred
    /// `vps_max_sublayers_minus1`. Range 0..=`vps_max_sublayers_minus1`.
    pub vps_ptl_max_tid: u8,
    /// The `profile_tier_level(vps_pt_present_flag[i],
    /// vps_ptl_max_tid[i])` structure.
    pub ptl: VvcProfileTierLevel,
}

/// One `dpb_parameters()` slot in the VPS (§7.3.2.3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcVpsDpb {
    /// `vps_dpb_max_tid[i]` u(3) — coded only when
    /// `!vps_default_ptl_dpb_hrd_max_tid_flag`; inferred
    /// `vps_max_sublayers_minus1`.
    pub vps_dpb_max_tid: u8,
    /// `dpb_parameters(vps_dpb_max_tid[i],
    /// vps_sublayer_dpb_params_present_flag)`.
    pub dpb: VvcDpbParameters,
}

/// Per-multi-layer-OLS DPB sizing (§7.3.2.3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcVpsOlsDpb {
    /// `vps_ols_dpb_pic_width[i]` ue(v).
    pub vps_ols_dpb_pic_width: u32,
    /// `vps_ols_dpb_pic_height[i]` ue(v).
    pub vps_ols_dpb_pic_height: u32,
    /// `vps_ols_dpb_chroma_format[i]` u(2).
    pub vps_ols_dpb_chroma_format: u8,
    /// `vps_ols_dpb_bitdepth_minus8[i]` ue(v) — 0..=8.
    pub vps_ols_dpb_bitdepth_minus8: u32,
    /// `vps_ols_dpb_params_idx[i]` ue(v) — coded only when
    /// `VpsNumDpbParams > 1` and `!= NumMultiLayerOlss`; inferred 0
    /// (one DPB set) or `i` (one per OLS). Range
    /// 0..`VpsNumDpbParams`.
    pub vps_ols_dpb_params_idx: u32,
}

/// One `ols_timing_hrd_parameters()` slot in the VPS timing block.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcVpsOlsHrd {
    /// `vps_hrd_max_tid[i]` u(3) — coded only when
    /// `!vps_default_ptl_dpb_hrd_max_tid_flag`; inferred
    /// `vps_max_sublayers_minus1`.
    pub vps_hrd_max_tid: u8,
    /// `ols_timing_hrd_parameters(firstSubLayer, vps_hrd_max_tid[i])`.
    pub ols: VvcOlsTimingHrd,
}

/// The VPS timing/HRD block (§7.3.2.3, present iff
/// `vps_timing_hrd_params_present_flag`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcVpsTimingHrd {
    /// `general_timing_hrd_parameters()` (§7.3.5.1).
    pub general: VvcGeneralTimingHrd,
    /// `vps_sublayer_cpb_params_present_flag` u(1) — coded only when
    /// `vps_max_sublayers_minus1 > 0`; inferred 0.
    pub vps_sublayer_cpb_params_present_flag: u8,
    /// `vps_num_ols_timing_hrd_params_minus1 + 1` entries.
    pub entries: Vec<VvcVpsOlsHrd>,
    /// `vps_ols_timing_hrd_idx[i]` per multi-layer OLS — coded only
    /// when the entry count is > 1 and != `NumMultiLayerOlss`;
    /// otherwise carries the inferred values (all 0, or `i`).
    pub vps_ols_timing_hrd_idx: Vec<u32>,
}

// ─────────────────────────── The VPS itself ──────────────────────────────────

/// A completely-walked VVC VPS (§7.3.2.3). Every syntax element is
/// retained (or spec-inferred when absent) so [`write_vps`] can
/// re-emit the RBSP byte-exactly.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VvcVps {
    /// `vps_video_parameter_set_id` u(4) — the spec requires > 0;
    /// surfaced rather than rejected so callers can decide.
    pub vps_video_parameter_set_id: u8,
    /// `vps_max_sublayers_minus1` u(3) — 0..=6.
    pub vps_max_sublayers_minus1: u8,
    /// `vps_default_ptl_dpb_hrd_max_tid_flag` u(1) — coded only when
    /// both layer and sublayer counts exceed 1; inferred 1.
    pub vps_default_ptl_dpb_hrd_max_tid_flag: u8,
    /// `vps_all_independent_layers_flag` u(1) — coded only for
    /// multi-layer VPSs; inferred 1.
    pub vps_all_independent_layers_flag: u8,
    /// The `vps_max_layers_minus1 + 1` layer entries.
    pub layers: Vec<VvcVpsLayer>,
    /// `vps_each_layer_is_an_ols_flag` u(1) — coded only for
    /// all-independent multi-layer VPSs; inferred 1 (single layer) or
    /// 0 (dependent layers).
    pub vps_each_layer_is_an_ols_flag: u8,
    /// `vps_ols_mode_idc` u(2) — 0..=2 (3 reserved); coded only when
    /// `!vps_each_layer_is_an_ols_flag` and
    /// `!vps_all_independent_layers_flag`; inferred 2 otherwise
    /// (meaningless when each layer is an OLS).
    pub vps_ols_mode_idc: u8,
    /// `vps_ols_output_layer_flag[i][j]` rows for OLS `i` in
    /// 1..`TotalNumOlss` (mode 2 only) — each row has one flag per
    /// layer.
    pub vps_ols_output_layer_flags: Vec<Vec<u8>>,
    /// The `vps_num_ptls_minus1 + 1` PTL slots.
    pub ptls: Vec<VvcVpsPtl>,
    /// `vps_ols_ptl_idx[i]` for every OLS — carries the §7.4.3.3
    /// inferred values when the field is not coded.
    pub vps_ols_ptl_idx: Vec<u32>,
    /// `vps_sublayer_dpb_params_present_flag` u(1) — coded only when
    /// the DPB block is present and `vps_max_sublayers_minus1 > 0`;
    /// inferred 0.
    pub vps_sublayer_dpb_params_present_flag: u8,
    /// The `VpsNumDpbParams` DPB slots (empty when each layer is an
    /// OLS).
    pub dpb_params: Vec<VvcVpsDpb>,
    /// Per-multi-layer-OLS DPB sizing entries (`NumMultiLayerOlss` of
    /// them).
    pub ols_dpbs: Vec<VvcVpsOlsDpb>,
    /// Timing/HRD block — present iff
    /// `vps_timing_hrd_params_present_flag` (only coded when the DPB
    /// block is).
    pub timing_hrd: Option<VvcVpsTimingHrd>,
    /// `vps_extension_flag` u(1).
    pub vps_extension_flag: u8,
    /// `vps_extension_data_flag` bits — retained verbatim; must end
    /// in a 1 bit.
    pub vps_extension_data: Vec<u8>,
}

impl VvcVps {
    /// `vps_max_layers_minus1` (u(6)) — one less than the layer count.
    pub fn vps_max_layers_minus1(&self) -> u8 {
        (self.layers.len().max(1) - 1) as u8
    }

    /// The per-layer `nuh_layer_id` values.
    pub fn layer_ids(&self) -> Vec<u8> {
        self.layers.iter().map(|l| l.vps_layer_id).collect()
    }
}

// ─────────────────────────── OLS derivations (7.4.3.3) ───────────────────────

/// The derived OLS counts the parse/write conditions need.
struct OlsInfo {
    /// `TotalNumOlss` (eq. (31)).
    total: usize,
    /// `NumMultiLayerOlss` (eq. (33)).
    multi: usize,
}

/// Replay eqs. (28)–(33) far enough to know `TotalNumOlss` and
/// `NumMultiLayerOlss`. For mode 2 this includes the transitive
/// dependency closure of the explicitly-signalled output layers.
fn derive_ols_info(vps: &VvcVps) -> Result<OlsInfo, BitstreamError> {
    let n = vps.layers.len();
    if vps.vps_each_layer_is_an_ols_flag != 0 {
        return Ok(OlsInfo { total: n, multi: 0 });
    }
    match vps.vps_ols_mode_idc {
        0 | 1 => Ok(OlsInfo {
            total: n,
            multi: n - 1,
        }),
        2 => {
            let total = vps.vps_ols_output_layer_flags.len() + 1;
            // dependencyFlag transitive closure (eq. (28)).
            let mut dep = vec![vec![false; n]; n];
            for i in 0..n {
                for j in 0..i {
                    dep[i][j] = *vps.layers[i].vps_direct_ref_layer_flag.get(j).unwrap_or(&0) != 0;
                }
                for k in 0..i {
                    if *vps.layers[i].vps_direct_ref_layer_flag.get(k).unwrap_or(&0) != 0 {
                        for j in 0..n {
                            if dep[k][j] {
                                dep[i][j] = true;
                            }
                        }
                    }
                }
            }
            let mut multi = 0usize;
            for row in &vps.vps_ols_output_layer_flags {
                if row.len() != n {
                    return Err(BitstreamError::invalid(
                        "vps_ols_output_layer_flag row length != layer count (7.3.2.3)",
                    ));
                }
                let mut included = vec![false; n];
                let mut any_output = false;
                for (k, &f) in row.iter().enumerate() {
                    if f != 0 {
                        included[k] = true;
                        any_output = true;
                        for (j, inc) in included.iter_mut().enumerate() {
                            if dep[k][j] {
                                *inc = true;
                            }
                        }
                    }
                }
                if !any_output {
                    return Err(BitstreamError::invalid(
                        "every OLS needs at least one output layer (7.4.3.3)",
                    ));
                }
                if included.iter().filter(|&&x| x).count() > 1 {
                    multi += 1;
                }
            }
            Ok(OlsInfo { total, multi })
        }
        _ => Err(BitstreamError::invalid(
            "vps_ols_mode_idc = 3 is reserved (7.4.3.3)",
        )),
    }
}

// ─────────────────────────── parse_vps ───────────────────────────────────────

/// Parse a complete VVC VPS NAL (two-byte NAL header at index 0..1)
/// per §7.3.2.3, through `rbsp_trailing_bits()`.
///
/// The input slice MUST point at the start of the NAL body (i.e.
/// after [`super::split_annex_b`]). Emulation-prevention bytes are
/// stripped via [`ebsp_to_rbsp`] before bit-level parsing. Every
/// syntax element is retained (or spec-inferred when absent) and the
/// §7.4.3.3 value ranges are enforced, so [`write_vps`] round-trips
/// the RBSP byte-exactly.
pub fn parse_vps(nal_body: &[u8]) -> Result<VvcVps, BitstreamError> {
    if nal_body.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "H.266 VPS NAL needs at least the 2-byte header",
        ));
    }
    let header = parse_nal_header(nal_body)?;
    if header.nal_unit_type != NAL_TYPE_VPS {
        return Err(BitstreamError::invalid(format!(
            "expected VPS NAL (type {}), got {}",
            NAL_TYPE_VPS, header.nal_unit_type
        )));
    }
    let rbsp = ebsp_to_rbsp(&nal_body[2..]);
    let mut r = BitReader::new(&rbsp);
    let mut v = VvcVps {
        vps_video_parameter_set_id: r.u(4) as u8,
        vps_default_ptl_dpb_hrd_max_tid_flag: 1,
        vps_all_independent_layers_flag: 1,
        vps_each_layer_is_an_ols_flag: 1,
        vps_ols_mode_idc: 2,
        ..Default::default()
    };
    let max_layers_minus1 = r.u(6) as usize;
    v.vps_max_sublayers_minus1 = r.u(3) as u8;
    if v.vps_max_sublayers_minus1 > 6 {
        return Err(BitstreamError::invalid(format!(
            "vps_max_sublayers_minus1 = {} > 6 (spec range 0..=6)",
            v.vps_max_sublayers_minus1
        )));
    }
    if max_layers_minus1 > 0 && v.vps_max_sublayers_minus1 > 0 {
        v.vps_default_ptl_dpb_hrd_max_tid_flag = r.u(1) as u8;
    }
    if max_layers_minus1 > 0 {
        v.vps_all_independent_layers_flag = r.u(1) as u8;
    }
    let max_tid_il_default = v.vps_max_sublayers_minus1 + 1;
    for i in 0..=max_layers_minus1 {
        let mut l = VvcVpsLayer {
            vps_layer_id: r.u(6) as u8,
            vps_independent_layer_flag: 1,
            ..Default::default()
        };
        if let Some(prev) = v.layers.last() {
            if l.vps_layer_id <= prev.vps_layer_id {
                return Err(BitstreamError::invalid(
                    "vps_layer_id values must be strictly increasing (7.4.3.3)",
                ));
            }
        }
        if i > 0 && v.vps_all_independent_layers_flag == 0 {
            l.vps_independent_layer_flag = r.u(1) as u8;
            if l.vps_independent_layer_flag == 0 {
                l.vps_max_tid_ref_present_flag = r.u(1) as u8;
                for _ in 0..i {
                    let direct = r.u(1) as u8;
                    let max_tid = if l.vps_max_tid_ref_present_flag != 0 && direct != 0 {
                        r.u(3) as u8
                    } else {
                        max_tid_il_default
                    };
                    l.vps_direct_ref_layer_flag.push(direct);
                    l.vps_max_tid_il_ref_pics_plus1.push(max_tid);
                }
                if !l.vps_direct_ref_layer_flag.contains(&1) {
                    return Err(BitstreamError::invalid(
                        "a dependent layer needs at least one direct reference layer (7.4.3.3)",
                    ));
                }
            }
        }
        v.layers.push(l);
    }
    let mut num_ptls_minus1 = 0usize;
    if max_layers_minus1 > 0 {
        if v.vps_all_independent_layers_flag != 0 {
            v.vps_each_layer_is_an_ols_flag = r.u(1) as u8;
        } else {
            v.vps_each_layer_is_an_ols_flag = 0;
        }
        if v.vps_each_layer_is_an_ols_flag == 0 {
            if v.vps_all_independent_layers_flag == 0 {
                v.vps_ols_mode_idc = r.u(2) as u8;
                if v.vps_ols_mode_idc == 3 {
                    return Err(BitstreamError::invalid(
                        "vps_ols_mode_idc = 3 is reserved (7.4.3.3)",
                    ));
                }
            }
            if v.vps_ols_mode_idc == 2 {
                let num_olss_minus2 = r.u(8) as usize;
                for _ in 1..=num_olss_minus2 + 1 {
                    let row: Vec<u8> = (0..=max_layers_minus1).map(|_| r.u(1) as u8).collect();
                    v.vps_ols_output_layer_flags.push(row);
                }
            }
        }
        num_ptls_minus1 = r.u(8) as usize;
    }
    let ols = derive_ols_info(&v)?;
    if num_ptls_minus1 >= ols.total {
        return Err(BitstreamError::invalid(
            "vps_num_ptls_minus1 must be less than TotalNumOlss (7.4.3.3)",
        ));
    }
    // PTL slot headers, then alignment, then the PTL bodies.
    let mut slot_flags = Vec::with_capacity(num_ptls_minus1 + 1);
    for i in 0..=num_ptls_minus1 {
        let pt_present = if i > 0 { r.u(1) as u8 } else { 1 };
        let max_tid = if v.vps_default_ptl_dpb_hrd_max_tid_flag == 0 {
            let t = r.u(3) as u8;
            if t > v.vps_max_sublayers_minus1 {
                return Err(BitstreamError::invalid(
                    "vps_ptl_max_tid exceeds vps_max_sublayers_minus1 (7.4.3.3)",
                ));
            }
            t
        } else {
            v.vps_max_sublayers_minus1
        };
        slot_flags.push((pt_present, max_tid));
    }
    while !r.byte_aligned() {
        if r.u(1) != 0 {
            return Err(BitstreamError::invalid(
                "vps_ptl_alignment_zero_bit must be 0 (7.3.2.3)",
            ));
        }
    }
    for (pt_present, max_tid) in slot_flags {
        let ptl = parse_profile_tier_level(&mut r, pt_present != 0, max_tid as u32)?;
        v.ptls.push(VvcVpsPtl {
            vps_pt_present_flag: pt_present,
            vps_ptl_max_tid: max_tid,
            ptl,
        });
    }
    for i in 0..ols.total {
        let idx = if num_ptls_minus1 > 0 && num_ptls_minus1 + 1 != ols.total {
            let idx = r.ue()?;
            if idx as usize > num_ptls_minus1 {
                return Err(BitstreamError::invalid(
                    "vps_ols_ptl_idx exceeds vps_num_ptls_minus1 (7.4.3.3)",
                ));
            }
            idx
        } else if num_ptls_minus1 == 0 {
            0
        } else {
            i as u32
        };
        v.vps_ols_ptl_idx.push(idx);
    }
    if v.vps_each_layer_is_an_ols_flag == 0 {
        let num_dpb_minus1 = r.ue()? as usize;
        if num_dpb_minus1 + 1 > ols.multi {
            return Err(BitstreamError::invalid(
                "vps_num_dpb_params_minus1 must be < NumMultiLayerOlss (7.4.3.3)",
            ));
        }
        if v.vps_max_sublayers_minus1 > 0 {
            v.vps_sublayer_dpb_params_present_flag = r.u(1) as u8;
        }
        for _ in 0..=num_dpb_minus1 {
            let max_tid = if v.vps_default_ptl_dpb_hrd_max_tid_flag == 0 {
                let t = r.u(3) as u8;
                if t > v.vps_max_sublayers_minus1 {
                    return Err(BitstreamError::invalid(
                        "vps_dpb_max_tid exceeds vps_max_sublayers_minus1 (7.4.3.3)",
                    ));
                }
                t
            } else {
                v.vps_max_sublayers_minus1
            };
            let dpb = parse_dpb_parameters(
                &mut r,
                max_tid as u32,
                v.vps_sublayer_dpb_params_present_flag != 0,
            )?;
            v.dpb_params.push(VvcVpsDpb {
                vps_dpb_max_tid: max_tid,
                dpb,
            });
        }
        let num_dpb = num_dpb_minus1 + 1;
        for i in 0..ols.multi {
            let mut d = VvcVpsOlsDpb {
                vps_ols_dpb_pic_width: r.ue()?,
                vps_ols_dpb_pic_height: r.ue()?,
                vps_ols_dpb_chroma_format: r.u(2) as u8,
                vps_ols_dpb_bitdepth_minus8: r.ue()?,
                ..Default::default()
            };
            if d.vps_ols_dpb_bitdepth_minus8 > 8 {
                return Err(BitstreamError::invalid(
                    "vps_ols_dpb_bitdepth_minus8 > 8 (BitDepth ≤ 16)",
                ));
            }
            d.vps_ols_dpb_params_idx = if num_dpb > 1 && num_dpb != ols.multi {
                let idx = r.ue()?;
                if idx as usize >= num_dpb {
                    return Err(BitstreamError::invalid(
                        "vps_ols_dpb_params_idx exceeds VpsNumDpbParams - 1 (7.4.3.3)",
                    ));
                }
                idx
            } else if num_dpb == 1 {
                0
            } else {
                i as u32
            };
            v.ols_dpbs.push(d);
        }
        if r.u(1) != 0 {
            // vps_timing_hrd_params_present_flag
            let general = parse_general_timing_hrd(&mut r)?;
            let mut th = VvcVpsTimingHrd {
                general,
                ..Default::default()
            };
            if v.vps_max_sublayers_minus1 > 0 {
                th.vps_sublayer_cpb_params_present_flag = r.u(1) as u8;
            }
            let num_hrd_minus1 = r.ue()? as usize;
            if num_hrd_minus1 + 1 > ols.multi {
                return Err(BitstreamError::invalid(
                    "vps_num_ols_timing_hrd_params_minus1 must be < NumMultiLayerOlss (7.4.3.3)",
                ));
            }
            for _ in 0..=num_hrd_minus1 {
                let max_tid = if v.vps_default_ptl_dpb_hrd_max_tid_flag == 0 {
                    let t = r.u(3) as u8;
                    if t > v.vps_max_sublayers_minus1 {
                        return Err(BitstreamError::invalid(
                            "vps_hrd_max_tid exceeds vps_max_sublayers_minus1 (7.4.3.3)",
                        ));
                    }
                    t
                } else {
                    v.vps_max_sublayers_minus1
                };
                let first = if th.vps_sublayer_cpb_params_present_flag != 0 {
                    0
                } else {
                    max_tid as u32
                };
                let ols_hrd = parse_ols_timing_hrd(&mut r, first, max_tid as u32, &th.general)?;
                th.entries.push(VvcVpsOlsHrd {
                    vps_hrd_max_tid: max_tid,
                    ols: ols_hrd,
                });
            }
            for i in 0..ols.multi {
                let idx = if num_hrd_minus1 > 0 && num_hrd_minus1 + 1 != ols.multi {
                    let idx = r.ue()?;
                    if idx as usize > num_hrd_minus1 {
                        return Err(BitstreamError::invalid(
                            "vps_ols_timing_hrd_idx exceeds the entry count (7.4.3.3)",
                        ));
                    }
                    idx
                } else if num_hrd_minus1 == 0 {
                    0
                } else {
                    i as u32
                };
                th.vps_ols_timing_hrd_idx.push(idx);
            }
            v.timing_hrd = Some(th);
        }
    }
    v.vps_extension_flag = r.u(1) as u8;
    if v.vps_extension_flag != 0 {
        while r.more_rbsp_data() {
            v.vps_extension_data.push(r.u(1) as u8);
        }
    }
    r.read_rbsp_trailing_bits()?;
    Ok(v)
}

// ─────────────────────────── write_vps ───────────────────────────────────────

/// Emit a `video_parameter_set_rbsp()` (§7.3.2.3 including
/// `rbsp_trailing_bits()`) — the byte-exact inverse of
/// [`parse_vps`]'s RBSP walk.
pub fn write_vps(v: &VvcVps) -> Result<Vec<u8>, BitstreamError> {
    let mut w = BitWriter::new();
    if v.layers.is_empty() || v.layers.len() > 64 {
        return Err(BitstreamError::invalid(
            "VPS must describe 1..=64 layers (vps_max_layers_minus1 is u(6))",
        ));
    }
    if v.vps_video_parameter_set_id > 15 || v.vps_max_sublayers_minus1 > 6 {
        return Err(BitstreamError::invalid(
            "vps_video_parameter_set_id / vps_max_sublayers_minus1 out of range",
        ));
    }
    let max_layers_minus1 = v.layers.len() - 1;
    w.write_bits(v.vps_video_parameter_set_id as u32, 4);
    w.write_bits(max_layers_minus1 as u32, 6);
    w.write_bits(v.vps_max_sublayers_minus1 as u32, 3);
    if max_layers_minus1 > 0 && v.vps_max_sublayers_minus1 > 0 {
        w.write_bit(u32::from(v.vps_default_ptl_dpb_hrd_max_tid_flag != 0));
    } else if v.vps_default_ptl_dpb_hrd_max_tid_flag != 1 {
        return Err(BitstreamError::invalid(
            "vps_default_ptl_dpb_hrd_max_tid_flag must carry its inferred value 1 (7.4.3.3)",
        ));
    }
    if max_layers_minus1 > 0 {
        w.write_bit(u32::from(v.vps_all_independent_layers_flag != 0));
    } else if v.vps_all_independent_layers_flag != 1 {
        return Err(BitstreamError::invalid(
            "vps_all_independent_layers_flag must carry its inferred value 1 (7.4.3.3)",
        ));
    }
    let max_tid_il_default = v.vps_max_sublayers_minus1 + 1;
    for (i, l) in v.layers.iter().enumerate() {
        if l.vps_layer_id > 63 {
            return Err(BitstreamError::invalid("vps_layer_id does not fit u(6)"));
        }
        if i > 0 && l.vps_layer_id <= v.layers[i - 1].vps_layer_id {
            return Err(BitstreamError::invalid(
                "vps_layer_id values must be strictly increasing (7.4.3.3)",
            ));
        }
        w.write_bits(l.vps_layer_id as u32, 6);
        if i > 0 && v.vps_all_independent_layers_flag == 0 {
            w.write_bit(u32::from(l.vps_independent_layer_flag != 0));
            if l.vps_independent_layer_flag == 0 {
                if l.vps_direct_ref_layer_flag.len() != i
                    || l.vps_max_tid_il_ref_pics_plus1.len() != i
                {
                    return Err(BitstreamError::invalid(
                        "dependent layer needs exactly i direct-ref / max-tid entries (7.3.2.3)",
                    ));
                }
                w.write_bit(u32::from(l.vps_max_tid_ref_present_flag != 0));
                for j in 0..i {
                    let direct = l.vps_direct_ref_layer_flag[j];
                    w.write_bit(u32::from(direct != 0));
                    let coded = l.vps_max_tid_ref_present_flag != 0 && direct != 0;
                    let max_tid = l.vps_max_tid_il_ref_pics_plus1[j];
                    if coded {
                        if max_tid > 7 {
                            return Err(BitstreamError::invalid(
                                "vps_max_tid_il_ref_pics_plus1 does not fit u(3)",
                            ));
                        }
                        w.write_bits(max_tid as u32, 3);
                    } else if max_tid != max_tid_il_default {
                        return Err(BitstreamError::invalid(
                            "uncoded vps_max_tid_il_ref_pics_plus1 must carry its inferred \
                             value (7.4.3.3)",
                        ));
                    }
                }
            } else if !l.vps_direct_ref_layer_flag.is_empty() {
                return Err(BitstreamError::invalid(
                    "independent layers carry no direct-ref flags (7.3.2.3)",
                ));
            }
        } else if l.vps_independent_layer_flag != 1 || !l.vps_direct_ref_layer_flag.is_empty() {
            return Err(BitstreamError::invalid(
                "layer 0 / all-independent layers must carry the inferred independent \
                 flag and no direct-ref flags (7.4.3.3)",
            ));
        }
    }
    let ols = derive_ols_info(v)?;
    let num_ptls_minus1 = match v.ptls.len() {
        0 => {
            return Err(BitstreamError::invalid(
                "VPS needs at least one profile_tier_level() slot (7.3.2.3)",
            ));
        }
        n if n > 256 || n > ols.total => {
            return Err(BitstreamError::invalid(
                "vps_num_ptls_minus1 must fit u(8) and be < TotalNumOlss (7.4.3.3)",
            ));
        }
        n => n - 1,
    };
    if max_layers_minus1 > 0 {
        if v.vps_all_independent_layers_flag != 0 {
            w.write_bit(u32::from(v.vps_each_layer_is_an_ols_flag != 0));
        } else if v.vps_each_layer_is_an_ols_flag != 0 {
            return Err(BitstreamError::invalid(
                "vps_each_layer_is_an_ols_flag must carry its inferred value 0 (7.4.3.3)",
            ));
        }
        if v.vps_each_layer_is_an_ols_flag == 0 {
            if v.vps_all_independent_layers_flag == 0 {
                if v.vps_ols_mode_idc > 2 {
                    return Err(BitstreamError::invalid(
                        "vps_ols_mode_idc = 3 is reserved (7.4.3.3)",
                    ));
                }
                w.write_bits(v.vps_ols_mode_idc as u32, 2);
            } else if v.vps_ols_mode_idc != 2 {
                return Err(BitstreamError::invalid(
                    "vps_ols_mode_idc must carry its inferred value 2 (7.4.3.3)",
                ));
            }
            if v.vps_ols_mode_idc == 2 {
                if v.vps_ols_output_layer_flags.is_empty()
                    || v.vps_ols_output_layer_flags.len() > 256
                {
                    return Err(BitstreamError::invalid(
                        "mode-2 VPS needs 1..=256 explicit OLS rows (u(8) count)",
                    ));
                }
                w.write_bits(v.vps_ols_output_layer_flags.len() as u32 - 1, 8);
                for row in &v.vps_ols_output_layer_flags {
                    for &f in row {
                        w.write_bit(u32::from(f != 0));
                    }
                }
            } else if !v.vps_ols_output_layer_flags.is_empty() {
                return Err(BitstreamError::invalid(
                    "explicit OLS rows are mode-2 only (7.3.2.3)",
                ));
            }
        } else if !v.vps_ols_output_layer_flags.is_empty() {
            return Err(BitstreamError::invalid(
                "explicit OLS rows are mode-2 only (7.3.2.3)",
            ));
        }
        w.write_bits(num_ptls_minus1 as u32, 8);
    } else if num_ptls_minus1 != 0 || !v.vps_ols_output_layer_flags.is_empty() {
        return Err(BitstreamError::invalid(
            "single-layer VPS carries exactly one inferred PTL slot (7.4.3.3)",
        ));
    }
    for (i, slot) in v.ptls.iter().enumerate() {
        if i > 0 {
            w.write_bit(u32::from(slot.vps_pt_present_flag != 0));
        } else if slot.vps_pt_present_flag != 1 {
            return Err(BitstreamError::invalid(
                "vps_pt_present_flag[0] must carry its inferred value 1 (7.4.3.3)",
            ));
        }
        if v.vps_default_ptl_dpb_hrd_max_tid_flag == 0 {
            if slot.vps_ptl_max_tid > v.vps_max_sublayers_minus1 {
                return Err(BitstreamError::invalid(
                    "vps_ptl_max_tid exceeds vps_max_sublayers_minus1 (7.4.3.3)",
                ));
            }
            w.write_bits(slot.vps_ptl_max_tid as u32, 3);
        } else if slot.vps_ptl_max_tid != v.vps_max_sublayers_minus1 {
            return Err(BitstreamError::invalid(
                "uncoded vps_ptl_max_tid must carry its inferred value (7.4.3.3)",
            ));
        }
    }
    while !w.byte_aligned() {
        w.write_bit(0); // vps_ptl_alignment_zero_bit
    }
    for slot in &v.ptls {
        write_profile_tier_level(
            &mut w,
            &slot.ptl,
            slot.vps_pt_present_flag != 0,
            slot.vps_ptl_max_tid as u32,
        )?;
    }
    if v.vps_ols_ptl_idx.len() != ols.total {
        return Err(BitstreamError::invalid(
            "vps_ols_ptl_idx must carry one entry per OLS (7.3.2.3)",
        ));
    }
    for (i, &idx) in v.vps_ols_ptl_idx.iter().enumerate() {
        if num_ptls_minus1 > 0 && num_ptls_minus1 + 1 != ols.total {
            if idx as usize > num_ptls_minus1 {
                return Err(BitstreamError::invalid(
                    "vps_ols_ptl_idx exceeds vps_num_ptls_minus1 (7.4.3.3)",
                ));
            }
            w.write_ue(idx)?;
        } else {
            let inferred = if num_ptls_minus1 == 0 { 0 } else { i as u32 };
            if idx != inferred {
                return Err(BitstreamError::invalid(
                    "uncoded vps_ols_ptl_idx must carry its inferred value (7.4.3.3)",
                ));
            }
        }
    }
    if v.vps_each_layer_is_an_ols_flag == 0 {
        let num_dpb = v.dpb_params.len();
        if num_dpb == 0 || num_dpb > ols.multi {
            return Err(BitstreamError::invalid(
                "VpsNumDpbParams must be 1..=NumMultiLayerOlss (7.4.3.3)",
            ));
        }
        w.write_ue(num_dpb as u32 - 1)?;
        if v.vps_max_sublayers_minus1 > 0 {
            w.write_bit(u32::from(v.vps_sublayer_dpb_params_present_flag != 0));
        }
        for slot in &v.dpb_params {
            if v.vps_default_ptl_dpb_hrd_max_tid_flag == 0 {
                if slot.vps_dpb_max_tid > v.vps_max_sublayers_minus1 {
                    return Err(BitstreamError::invalid(
                        "vps_dpb_max_tid exceeds vps_max_sublayers_minus1 (7.4.3.3)",
                    ));
                }
                w.write_bits(slot.vps_dpb_max_tid as u32, 3);
            } else if slot.vps_dpb_max_tid != v.vps_max_sublayers_minus1 {
                return Err(BitstreamError::invalid(
                    "uncoded vps_dpb_max_tid must carry its inferred value (7.4.3.3)",
                ));
            }
            write_dpb_parameters(
                &mut w,
                &slot.dpb,
                slot.vps_dpb_max_tid as u32,
                v.vps_sublayer_dpb_params_present_flag != 0,
            )?;
        }
        if v.ols_dpbs.len() != ols.multi {
            return Err(BitstreamError::invalid(
                "one vps_ols_dpb entry per multi-layer OLS required (7.3.2.3)",
            ));
        }
        for (i, d) in v.ols_dpbs.iter().enumerate() {
            w.write_ue(d.vps_ols_dpb_pic_width)?;
            w.write_ue(d.vps_ols_dpb_pic_height)?;
            w.write_bits((d.vps_ols_dpb_chroma_format & 3) as u32, 2);
            if d.vps_ols_dpb_bitdepth_minus8 > 8 {
                return Err(BitstreamError::invalid(
                    "vps_ols_dpb_bitdepth_minus8 > 8 (BitDepth ≤ 16)",
                ));
            }
            w.write_ue(d.vps_ols_dpb_bitdepth_minus8)?;
            if num_dpb > 1 && num_dpb != ols.multi {
                if d.vps_ols_dpb_params_idx as usize >= num_dpb {
                    return Err(BitstreamError::invalid(
                        "vps_ols_dpb_params_idx exceeds VpsNumDpbParams - 1 (7.4.3.3)",
                    ));
                }
                w.write_ue(d.vps_ols_dpb_params_idx)?;
            } else {
                let inferred = if num_dpb == 1 { 0 } else { i as u32 };
                if d.vps_ols_dpb_params_idx != inferred {
                    return Err(BitstreamError::invalid(
                        "uncoded vps_ols_dpb_params_idx must carry its inferred value (7.4.3.3)",
                    ));
                }
            }
        }
        w.write_bit(u32::from(v.timing_hrd.is_some()));
        if let Some(th) = &v.timing_hrd {
            write_general_timing_hrd(&mut w, &th.general)?;
            if v.vps_max_sublayers_minus1 > 0 {
                w.write_bit(u32::from(th.vps_sublayer_cpb_params_present_flag != 0));
            }
            let num_hrd = th.entries.len();
            if num_hrd == 0 || num_hrd > ols.multi {
                return Err(BitstreamError::invalid(
                    "vps_num_ols_timing_hrd_params_minus1 must be < NumMultiLayerOlss (7.4.3.3)",
                ));
            }
            w.write_ue(num_hrd as u32 - 1)?;
            for e in &th.entries {
                if v.vps_default_ptl_dpb_hrd_max_tid_flag == 0 {
                    if e.vps_hrd_max_tid > v.vps_max_sublayers_minus1 {
                        return Err(BitstreamError::invalid(
                            "vps_hrd_max_tid exceeds vps_max_sublayers_minus1 (7.4.3.3)",
                        ));
                    }
                    w.write_bits(e.vps_hrd_max_tid as u32, 3);
                } else if e.vps_hrd_max_tid != v.vps_max_sublayers_minus1 {
                    return Err(BitstreamError::invalid(
                        "uncoded vps_hrd_max_tid must carry its inferred value (7.4.3.3)",
                    ));
                }
                let first = if th.vps_sublayer_cpb_params_present_flag != 0 {
                    0
                } else {
                    e.vps_hrd_max_tid as u32
                };
                write_ols_timing_hrd(&mut w, &e.ols, first, e.vps_hrd_max_tid as u32, &th.general)?;
            }
            if th.vps_ols_timing_hrd_idx.len() != ols.multi {
                return Err(BitstreamError::invalid(
                    "vps_ols_timing_hrd_idx must carry one entry per multi-layer OLS",
                ));
            }
            for (i, &idx) in th.vps_ols_timing_hrd_idx.iter().enumerate() {
                if num_hrd > 1 && num_hrd != ols.multi {
                    if idx as usize >= num_hrd {
                        return Err(BitstreamError::invalid(
                            "vps_ols_timing_hrd_idx exceeds the entry count (7.4.3.3)",
                        ));
                    }
                    w.write_ue(idx)?;
                } else {
                    let inferred = if num_hrd == 1 { 0 } else { i as u32 };
                    if idx != inferred {
                        return Err(BitstreamError::invalid(
                            "uncoded vps_ols_timing_hrd_idx must carry its inferred value",
                        ));
                    }
                }
            }
        }
    } else if !v.dpb_params.is_empty() || !v.ols_dpbs.is_empty() || v.timing_hrd.is_some() {
        return Err(BitstreamError::invalid(
            "DPB / timing-HRD blocks require a multi-layer OLS configuration (7.3.2.3)",
        ));
    }
    w.write_bit(u32::from(v.vps_extension_flag != 0));
    if v.vps_extension_flag != 0 {
        if v.vps_extension_data.last() == Some(&0) {
            return Err(BitstreamError::invalid(
                "vps_extension_data must end in a 1 bit — a trailing 0 is indistinguishable \
                 from rbsp_trailing_bits padding under more_rbsp_data() (7.2)",
            ));
        }
        for &bit in &v.vps_extension_data {
            w.write_bit(u32::from(bit != 0));
        }
    } else if !v.vps_extension_data.is_empty() {
        return Err(BitstreamError::invalid(
            "vps_extension_data requires vps_extension_flag (7.3.2.3)",
        ));
    }
    w.write_rbsp_trailing_bits();
    Ok(w.finish())
}

/// Emit a complete VPS NAL (canonical header: layer 0, TID 0),
/// emulation-prevention framed.
pub fn write_vps_nal(v: &VvcVps) -> Result<Vec<u8>, BitstreamError> {
    let rbsp = write_vps(v)?;
    let mut out = Vec::with_capacity(2 + rbsp.len());
    out.push(0x00);
    out.push((NAL_TYPE_VPS << 3) | 0x01);
    out.extend_from_slice(&crate::nal::rbsp_to_ebsp(&rbsp));
    Ok(out)
}

// ─────────────────────────── Tests ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::params::{VvcDpbEntry, VvcOlsTimingHrdSublayer};
    use super::*;

    fn ptl(max_tid: u8, present: bool) -> VvcVpsPtl {
        VvcVpsPtl {
            vps_pt_present_flag: u8::from(present),
            vps_ptl_max_tid: max_tid,
            ptl: VvcProfileTierLevel {
                general_profile_idc: if present { Some(1) } else { None },
                general_tier_flag: if present { Some(0) } else { None },
                general_level_idc: 51,
                ptl_frame_only_constraint_flag: 1,
                ptl_multilayer_enabled_flag: 0,
                ptl_sublayer_level_present_flag: vec![0; max_tid as usize],
                sublayer_level_idc: vec![],
                general_sub_profile_idc: vec![],
                gci_present_flag: false,
                gci_bits: vec![],
            },
        }
    }

    fn single_layer_vps() -> VvcVps {
        VvcVps {
            vps_video_parameter_set_id: 1,
            vps_max_sublayers_minus1: 0,
            vps_default_ptl_dpb_hrd_max_tid_flag: 1,
            vps_all_independent_layers_flag: 1,
            layers: vec![VvcVpsLayer {
                vps_layer_id: 0,
                vps_independent_layer_flag: 1,
                ..Default::default()
            }],
            vps_each_layer_is_an_ols_flag: 1,
            vps_ols_mode_idc: 2,
            ptls: vec![ptl(0, true)],
            vps_ols_ptl_idx: vec![0],
            ..Default::default()
        }
    }

    fn assert_roundtrip(vps: &VvcVps) {
        let nal = write_vps_nal(vps).expect("VPS writes");
        let parsed = parse_vps(&nal).expect("written VPS parses");
        assert_eq!(&parsed, vps, "struct round-trip");
        assert_eq!(write_vps_nal(&parsed).unwrap(), nal, "byte round-trip");
    }

    #[test]
    fn single_layer_roundtrips() {
        let vps = single_layer_vps();
        assert_roundtrip(&vps);
        let parsed = parse_vps(&write_vps_nal(&vps).unwrap()).unwrap();
        assert_eq!(parsed.vps_max_layers_minus1(), 0);
        assert_eq!(parsed.layer_ids(), vec![0]);
        assert_eq!(parsed.vps_each_layer_is_an_ols_flag, 1);
    }

    #[test]
    fn all_independent_each_layer_ols_roundtrips() {
        // Two independent layers, each its own OLS: no DPB/HRD block.
        let mut vps = single_layer_vps();
        vps.vps_max_sublayers_minus1 = 2;
        vps.layers = vec![
            VvcVpsLayer {
                vps_layer_id: 0,
                vps_independent_layer_flag: 1,
                ..Default::default()
            },
            VvcVpsLayer {
                vps_layer_id: 4,
                vps_independent_layer_flag: 1,
                ..Default::default()
            },
        ];
        vps.vps_each_layer_is_an_ols_flag = 1;
        vps.ptls = vec![ptl(2, true), ptl(2, false)];
        vps.vps_ols_ptl_idx = vec![0, 1]; // num_ptls+1 == TotalNumOlss → inferred i
        assert_roundtrip(&vps);
    }

    #[test]
    fn mode1_dependent_layers_with_dpb_and_hrd_roundtrip() {
        // Two layers, layer 1 depends on layer 0, ols_mode_idc 1
        // (all layers output) → one multi-layer OLS with DPB + HRD.
        let general = VvcGeneralTimingHrd {
            num_units_in_tick: 1,
            time_scale: 50,
            ..Default::default()
        };
        let vps = VvcVps {
            vps_video_parameter_set_id: 2,
            vps_max_sublayers_minus1: 0,
            vps_default_ptl_dpb_hrd_max_tid_flag: 1,
            vps_all_independent_layers_flag: 0,
            layers: vec![
                VvcVpsLayer {
                    vps_layer_id: 0,
                    vps_independent_layer_flag: 1,
                    ..Default::default()
                },
                VvcVpsLayer {
                    vps_layer_id: 1,
                    vps_independent_layer_flag: 0,
                    vps_max_tid_ref_present_flag: 1,
                    vps_direct_ref_layer_flag: vec![1],
                    vps_max_tid_il_ref_pics_plus1: vec![3],
                },
            ],
            vps_each_layer_is_an_ols_flag: 0,
            vps_ols_mode_idc: 1,
            ptls: vec![ptl(0, true)],
            vps_ols_ptl_idx: vec![0, 0],
            dpb_params: vec![VvcVpsDpb {
                vps_dpb_max_tid: 0,
                dpb: VvcDpbParameters {
                    entries: vec![VvcDpbEntry {
                        dpb_max_dec_pic_buffering_minus1: 3,
                        dpb_max_num_reorder_pics: 1,
                        dpb_max_latency_increase_plus1: 0,
                    }],
                },
            }],
            ols_dpbs: vec![VvcVpsOlsDpb {
                vps_ols_dpb_pic_width: 1920,
                vps_ols_dpb_pic_height: 1080,
                vps_ols_dpb_chroma_format: 1,
                vps_ols_dpb_bitdepth_minus8: 2,
                vps_ols_dpb_params_idx: 0,
            }],
            timing_hrd: Some(VvcVpsTimingHrd {
                general,
                vps_sublayer_cpb_params_present_flag: 0,
                entries: vec![VvcVpsOlsHrd {
                    vps_hrd_max_tid: 0,
                    ols: VvcOlsTimingHrd {
                        sublayers: vec![VvcOlsTimingHrdSublayer {
                            fixed_pic_rate_general_flag: 1,
                            fixed_pic_rate_within_cvs_flag: 1,
                            elemental_duration_in_tc_minus1: 0,
                            ..Default::default()
                        }],
                    },
                }],
                vps_ols_timing_hrd_idx: vec![0],
            }),
            ..Default::default()
        };
        assert_roundtrip(&vps);
    }

    #[test]
    fn mode2_explicit_ols_with_dependency_closure_roundtrips() {
        // Three layers: 2 depends on 1, 1 depends on 0. Two explicit
        // OLS rows: OLS 1 outputs layer 2 (pulls in 1 and 0 through
        // the closure → 3 layers), OLS 2 outputs layer 0 only
        // (single layer). NumMultiLayerOlss = 1.
        let dep = |refs: Vec<u8>, tids: Vec<u8>, present: u8| VvcVpsLayer {
            vps_layer_id: 0, // fixed up below
            vps_independent_layer_flag: 0,
            vps_max_tid_ref_present_flag: present,
            vps_direct_ref_layer_flag: refs,
            vps_max_tid_il_ref_pics_plus1: tids,
        };
        let mut l1 = dep(vec![1], vec![2], 1);
        l1.vps_layer_id = 1;
        let mut l2 = dep(vec![0, 1], vec![2, 2], 0);
        l2.vps_layer_id = 2;
        // With max_tid_ref_present = 0 the tids must carry the
        // inferred value (max_sublayers + 1 = 2).
        let vps = VvcVps {
            vps_video_parameter_set_id: 3,
            vps_max_sublayers_minus1: 1,
            vps_default_ptl_dpb_hrd_max_tid_flag: 0,
            vps_all_independent_layers_flag: 0,
            layers: vec![
                VvcVpsLayer {
                    vps_layer_id: 0,
                    vps_independent_layer_flag: 1,
                    ..Default::default()
                },
                l1,
                l2,
            ],
            vps_each_layer_is_an_ols_flag: 0,
            vps_ols_mode_idc: 2,
            vps_ols_output_layer_flags: vec![vec![0, 0, 1], vec![1, 0, 0]],
            ptls: vec![ptl(1, true)],
            vps_ols_ptl_idx: vec![0, 0, 0],
            dpb_params: vec![VvcVpsDpb {
                vps_dpb_max_tid: 1,
                dpb: VvcDpbParameters {
                    entries: vec![VvcDpbEntry {
                        dpb_max_dec_pic_buffering_minus1: 5,
                        dpb_max_num_reorder_pics: 2,
                        dpb_max_latency_increase_plus1: 0,
                    }],
                },
            }],
            ols_dpbs: vec![VvcVpsOlsDpb {
                vps_ols_dpb_pic_width: 640,
                vps_ols_dpb_pic_height: 360,
                vps_ols_dpb_chroma_format: 1,
                vps_ols_dpb_bitdepth_minus8: 0,
                vps_ols_dpb_params_idx: 0,
            }],
            timing_hrd: None,
            ..Default::default()
        };
        assert_roundtrip(&vps);
    }

    #[test]
    fn extension_data_retained_and_guarded() {
        let mut vps = single_layer_vps();
        vps.vps_extension_flag = 1;
        vps.vps_extension_data = vec![1, 1, 0, 1];
        assert_roundtrip(&vps);
        vps.vps_extension_data = vec![1, 0];
        assert!(write_vps(&vps).is_err());
    }

    #[test]
    fn rejects_wrong_nal_truncation_and_ranges() {
        let mut nal = vec![0u8; 4];
        nal[1] = (super::super::NAL_TYPE_SPS << 3) | 1;
        assert!(matches!(
            parse_vps(&nal),
            Err(BitstreamError::InvalidData(_))
        ));
        assert!(matches!(
            parse_vps(&[0x00]),
            Err(BitstreamError::UnexpectedEnd(_))
        ));
        let full = write_vps_nal(&single_layer_vps()).unwrap();
        assert!(parse_vps(&full[..full.len() - 1]).is_err());
        // Reserved sublayer count via the writer guard.
        let mut vps = single_layer_vps();
        vps.vps_max_sublayers_minus1 = 7;
        assert!(write_vps(&vps).is_err());
        // Non-increasing layer ids.
        let mut vps = single_layer_vps();
        vps.layers = vec![
            VvcVpsLayer {
                vps_layer_id: 5,
                vps_independent_layer_flag: 1,
                ..Default::default()
            },
            VvcVpsLayer {
                vps_layer_id: 5,
                vps_independent_layer_flag: 1,
                ..Default::default()
            },
        ];
        vps.ptls = vec![ptl(0, true), ptl(0, false)];
        vps.vps_ols_ptl_idx = vec![0, 1];
        assert!(write_vps(&vps).is_err());
    }
}
