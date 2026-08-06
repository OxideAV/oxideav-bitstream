//! H.266 / VVC minimal NAL-walker layer.
//!
//! This module is the byte-aligned framing layer for VVC: Annex-B
//! start-code splitter, emulation-prevention stripper, two-byte NAL
//! header decoder, plus the NAL-type constants and IRAP / VCL
//! classifiers. Full SPS / PPS / picture-header parsing is **out of
//! scope for this round** — they will land in later rounds as the
//! oxideav HW-accel bridge crates grow VVC support
//! (`VkVideoDecodeH266PictureInfoKHR` and friends).
//!
//! Until then this module gives the bridge crates a single, shared
//! place to:
//!
//! - Walk an Annex-B VVC stream and obtain per-NAL byte slices.
//! - Inspect each NAL header to identify VPS / SPS / PPS / PH /
//!   IDR_W_RADL / IDR_N_LP / CRA / GDR / TRAIL etc.
//! - Filter to IRAP NALs for random-access entry-point detection.
//! - Convert an EBSP body to RBSP by stripping `0x03`
//!   emulation-prevention bytes (identical convention to H.264 /
//!   HEVC, but defined for H.266 in 7.3.1.1).
//!
//! # Bit ordering
//!
//! Same as H.264 / HEVC: bits inside each byte are read MSB-first.
//! The NAL header in particular is laid out as:
//!
//! ```text
//! byte 0: forbidden_zero_bit (1) | nuh_reserved_zero_bit (1) |
//!         nuh_layer_id (6)
//! byte 1: nal_unit_type (5) | nuh_temporal_id_plus1 (3)
//! ```
//!
//! # Spec references
//!
//! ITU-T H.266 (V4) (01/2026), a.k.a. ISO/IEC 23090-3 — VVC. Sections
//! used here:
//!
//! - 7.3.1.1 — General NAL unit syntax (`emulation_prevention_three_byte`).
//! - 7.3.1.2 — NAL unit header syntax (`nal_unit_header()`).
//! - 7.4.2.2 — NAL unit header semantics + Table 5 (NAL unit type codes
//!   and NAL unit type classes).
//! - 7.3.2.3 — Video parameter set RBSP syntax.
//! - 7.3.2.4 — Sequence parameter set RBSP syntax.
//! - 7.3.2.5 — Picture parameter set RBSP syntax.
//! - 7.3.3.1 — General profile, tier, and level syntax.
//! - 7.3.3.2 — General constraints information syntax.

use crate::bit_reader::BitReader;
use crate::BitstreamError;

pub mod aps;
pub mod sei;

// ─────────────────────────── NAL unit types (Table 5) ───────────────────────

/// 7.4.2.2 Table 5 — Coded slice of a trailing picture/subpicture (VCL).
pub const NAL_TYPE_TRAIL: u8 = 0;
/// 7.4.2.2 Table 5 — Coded slice of an STSA picture/subpicture (VCL).
pub const NAL_TYPE_STSA: u8 = 1;
/// 7.4.2.2 Table 5 — Coded slice of a RADL picture/subpicture (VCL).
pub const NAL_TYPE_RADL: u8 = 2;
/// 7.4.2.2 Table 5 — Coded slice of a RASL picture/subpicture (VCL).
pub const NAL_TYPE_RASL: u8 = 3;
/// 7.4.2.2 Table 5 — Reserved non-IRAP VCL (4..6).
pub const NAL_TYPE_RSV_VCL_4: u8 = 4;
/// 7.4.2.2 Table 5 — Reserved non-IRAP VCL (4..6).
pub const NAL_TYPE_RSV_VCL_5: u8 = 5;
/// 7.4.2.2 Table 5 — Reserved non-IRAP VCL (4..6).
pub const NAL_TYPE_RSV_VCL_6: u8 = 6;
/// 7.4.2.2 Table 5 — IDR picture/subpicture, with associated RADL
/// pictures permitted (VCL, IRAP).
pub const NAL_TYPE_IDR_W_RADL: u8 = 7;
/// 7.4.2.2 Table 5 — IDR picture/subpicture, no leading pictures
/// (VCL, IRAP).
pub const NAL_TYPE_IDR_N_LP: u8 = 8;
/// 7.4.2.2 Table 5 — Clean random access picture/subpicture
/// (VCL, IRAP).
pub const NAL_TYPE_CRA: u8 = 9;
/// 7.4.2.2 Table 5 — Gradual decoding refresh picture/subpicture (VCL).
pub const NAL_TYPE_GDR: u8 = 10;
/// 7.4.2.2 Table 5 — Reserved IRAP VCL (11).
pub const NAL_TYPE_RSV_IRAP_11: u8 = 11;
/// 7.4.2.2 Table 5 — Operating point information (non-VCL).
pub const NAL_TYPE_OPI: u8 = 12;
/// 7.4.2.2 Table 5 — Decoding capability information (non-VCL).
pub const NAL_TYPE_DCI: u8 = 13;
/// 7.4.2.2 Table 5 — Video parameter set (non-VCL).
pub const NAL_TYPE_VPS: u8 = 14;
/// 7.4.2.2 Table 5 — Sequence parameter set (non-VCL).
pub const NAL_TYPE_SPS: u8 = 15;
/// 7.4.2.2 Table 5 — Picture parameter set (non-VCL).
pub const NAL_TYPE_PPS: u8 = 16;
/// 7.4.2.2 Table 5 — Prefix adaptation parameter set (non-VCL).
pub const NAL_TYPE_PREFIX_APS: u8 = 17;
/// 7.4.2.2 Table 5 — Suffix adaptation parameter set (non-VCL).
pub const NAL_TYPE_SUFFIX_APS: u8 = 18;
/// 7.4.2.2 Table 5 — Picture header (non-VCL).
pub const NAL_TYPE_PH: u8 = 19;
/// 7.4.2.2 Table 5 — Access unit delimiter (non-VCL).
pub const NAL_TYPE_AUD: u8 = 20;
/// 7.4.2.2 Table 5 — End of sequence (non-VCL).
pub const NAL_TYPE_EOS: u8 = 21;
/// 7.4.2.2 Table 5 — End of bitstream (non-VCL).
pub const NAL_TYPE_EOB: u8 = 22;
/// 7.4.2.2 Table 5 — Prefix SEI (non-VCL).
pub const NAL_TYPE_PREFIX_SEI: u8 = 23;
/// 7.4.2.2 Table 5 — Suffix SEI (non-VCL).
pub const NAL_TYPE_SUFFIX_SEI: u8 = 24;
/// 7.4.2.2 Table 5 — Filler data (non-VCL).
pub const NAL_TYPE_FD: u8 = 25;
/// 7.4.2.2 Table 5 — Reserved non-VCL (26..27).
pub const NAL_TYPE_RSV_NVCL_26: u8 = 26;
/// 7.4.2.2 Table 5 — Reserved non-VCL (26..27).
pub const NAL_TYPE_RSV_NVCL_27: u8 = 27;

// ─────────────────────────── Annex-B framing ─────────────────────────────────

/// Locate every NAL unit in an Annex-B VVC bitstream and return slices
/// pointing at the NAL body (start code stripped, the two-byte NAL
/// header is at index 0..1, emulation-prevention bytes still in
/// place — strip those with [`ebsp_to_rbsp`] before any bit-level
/// parsing).
///
/// Both the four-byte (`00 00 00 01`) and the three-byte
/// (`00 00 01`) start-code forms from Annex-B are recognised. The
/// implementation mirrors the H.264 / HEVC walkers in this crate.
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

/// Strip H.266 emulation-prevention `0x03` bytes from an EBSP to
/// produce an RBSP (7.3.1.1). Inserted by the encoder after `00 00 0x`
/// (with `x < 4`) inside the NAL body so a start-code prefix can never
/// appear inside payload data.
///
/// H.264, HEVC and H.266 all express the rule identically, so this
/// module re-exports the shared helper from [`crate::nal::ebsp_to_rbsp`]
/// rather than carrying a private copy.
pub use crate::nal::ebsp_to_rbsp;

// ─────────────────────────── NAL header ──────────────────────────────────────

/// Decoded H.266 NAL unit header (7.3.1.2 / 7.4.2.2).
///
/// Two bytes on the wire:
/// `forbidden_zero_bit f(1) | nuh_reserved_zero_bit u(1) |
/// nuh_layer_id u(6) | nal_unit_type u(5) | nuh_temporal_id_plus1 u(3)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VvcNalHeader {
    /// `forbidden_zero_bit` (7.4.2.2): shall be 0 on a well-formed
    /// bitstream. Surfaced rather than checked so callers can decide
    /// what to do with malformed streams.
    pub forbidden_zero_bit: u8,
    /// `nuh_reserved_zero_bit` (7.4.2.2): shall be 0.
    pub nuh_reserved_zero_bit: u8,
    /// `nuh_layer_id` (7.4.2.2): 6 bits, identifies the layer this
    /// NAL belongs to. 0 in single-layer streams.
    pub nuh_layer_id: u8,
    /// `nal_unit_type` (7.4.2.2 Table 5): 5 bits, one of the
    /// `NAL_TYPE_*` constants in this module.
    pub nal_unit_type: u8,
    /// `nuh_temporal_id_plus1` (7.4.2.2): 3 bits, one more than the
    /// `TemporalId` of the NAL. `TemporalId = nuh_temporal_id_plus1 -
    /// 1`. Value 0 is forbidden by the spec (so `TemporalId >= 0`
    /// always).
    pub nuh_temporal_id_plus1: u8,
}

impl VvcNalHeader {
    /// `TemporalId` as defined in 7.4.2.2 (`nuh_temporal_id_plus1 -
    /// 1`). Saturates at 0 if a malformed input encoded
    /// `nuh_temporal_id_plus1` as 0.
    pub fn temporal_id(&self) -> u8 {
        self.nuh_temporal_id_plus1.saturating_sub(1)
    }
}

/// Decode the two-byte NAL header at the start of an Annex-B NAL
/// body (i.e. after `split_annex_b` has stripped the start code).
///
/// Returns `UnexpectedEnd` if the body is shorter than two bytes.
/// Does **not** reject `forbidden_zero_bit = 1` or
/// `nuh_temporal_id_plus1 = 0` — those validations are deferred to
/// the consumer.
pub fn parse_nal_header(nal_body: &[u8]) -> Result<VvcNalHeader, BitstreamError> {
    if nal_body.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "H.266 NAL header needs at least 2 bytes",
        ));
    }
    let b0 = nal_body[0];
    let b1 = nal_body[1];
    Ok(VvcNalHeader {
        forbidden_zero_bit: (b0 >> 7) & 1,
        nuh_reserved_zero_bit: (b0 >> 6) & 1,
        nuh_layer_id: b0 & 0x3f,
        nal_unit_type: (b1 >> 3) & 0x1f,
        nuh_temporal_id_plus1: b1 & 0x7,
    })
}

// ─────────────────────────── Classifiers ─────────────────────────────────────

/// True if `nal_unit_type` is in the VCL range (0..=11 per Table 5).
/// VCL NALs carry slice data; everything else is parameter-set,
/// delimiter or metadata.
pub fn is_vcl(nal_unit_type: u8) -> bool {
    nal_unit_type <= NAL_TYPE_RSV_IRAP_11
}

/// True if `nal_unit_type` is one of the IRAP slice types treated by
/// this crate as a random-access entry point (IDR_W_RADL, IDR_N_LP,
/// CRA). `RSV_IRAP_11` is reserved-IRAP so it's a *future* IRAP but
/// callers can't decode it without an updated profile — we return
/// `false` here on purpose (mirrors the HEVC module's stance on
/// reserved IRAP slots).
pub fn is_irap(nal_unit_type: u8) -> bool {
    matches!(
        nal_unit_type,
        NAL_TYPE_IDR_W_RADL | NAL_TYPE_IDR_N_LP | NAL_TYPE_CRA
    )
}

/// True if `nal_unit_type` is one of the parameter-set carriers
/// (VPS, SPS, PPS, prefix/suffix APS, or DCI / OPI). Useful for
/// pre-scan passes that want to extract every parameter-set NAL
/// from a stream before locating the first VCL NAL.
pub fn is_parameter_set(nal_unit_type: u8) -> bool {
    matches!(
        nal_unit_type,
        NAL_TYPE_VPS
            | NAL_TYPE_SPS
            | NAL_TYPE_PPS
            | NAL_TYPE_PREFIX_APS
            | NAL_TYPE_SUFFIX_APS
            | NAL_TYPE_DCI
            | NAL_TYPE_OPI
    )
}

// ─────────────────────────── Profile/Tier/Level (7.3.3) ─────────────────────

/// Profile / tier / level syntax structure (7.3.3.1).
///
/// This carries the subset of `profile_tier_level()` fields a HW
/// bridge actually inspects: profile / tier / level codes and any
/// signalled 32-bit sub-profile identifiers. The `general_constraints_info()`
/// block (7.3.3.2) is **walked but not surfaced** — bridges that need
/// it can pull it from the raw NAL body. Per-sublayer level codes are
/// kept verbatim for any sublayer that signalled them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VvcProfileTierLevel {
    /// `general_profile_idc` u(7) (7.4.4.1). Only present when the
    /// caller passed `profileTierPresentFlag = 1`; `None` otherwise.
    pub general_profile_idc: Option<u8>,
    /// `general_tier_flag` u(1). Mirrors `general_profile_idc`'s
    /// presence: `None` when `profileTierPresentFlag = 0`.
    pub general_tier_flag: Option<u8>,
    /// `general_level_idc` u(8) (7.4.4.1). Always present.
    pub general_level_idc: u8,
    /// `ptl_frame_only_constraint_flag` u(1).
    pub ptl_frame_only_constraint_flag: u8,
    /// `ptl_multilayer_enabled_flag` u(1).
    pub ptl_multilayer_enabled_flag: u8,
    /// `ptl_sublayer_level_present_flag[i]` for i in 0..=MaxNumSubLayersMinus1-1
    /// (the spec walks i high-to-low, but we store low-to-high for
    /// natural indexing).
    pub ptl_sublayer_level_present_flag: Vec<u8>,
    /// `sublayer_level_idc[i]` for sublayers with the corresponding
    /// `ptl_sublayer_level_present_flag` set (low-to-high).
    pub sublayer_level_idc: Vec<u8>,
    /// `general_sub_profile_idc[i]` u(32). Empty when
    /// `profileTierPresentFlag = 0`. Length equals
    /// `ptl_num_sub_profiles` (7.3.3.1).
    pub general_sub_profile_idc: Vec<u32>,
    /// `gci_present_flag` (7.3.3.2) — only meaningful when
    /// `profileTierPresentFlag = 1`.
    pub gci_present_flag: bool,
    /// The raw `general_constraints_info()` content bits following
    /// `gci_present_flag`, in coded order (69 fixed fields +
    /// `gci_num_additional_bits` u(8) + the additional/reserved run;
    /// empty when `gci_present_flag = 0`). Retained verbatim so
    /// [`write_profile_tier_level`] can reproduce the structure
    /// byte-exactly without modelling each of the 70+ constraint
    /// flags individually.
    pub gci_bits: Vec<bool>,
}

/// Parse a `profile_tier_level()` structure (7.3.3.1) at the reader's
/// current bit position. The `profile_tier_present_flag` argument
/// gates the `general_profile_idc` / `general_tier_flag` /
/// `general_constraints_info()` / sub-profile parts (matching
/// `profileTierPresentFlag` in the syntax tables). `max_sublayers_minus1`
/// controls the number of `ptl_sublayer_level_present_flag` bits and
/// the number of `sublayer_level_idc` codes that may follow.
///
/// The full `general_constraints_info()` (7.3.3.2) is walked so the
/// reader ends byte-aligned at the structure's terminating
/// `ptl_num_sub_profiles` / sub-profile loop, exactly as required by
/// 7.3.2.4 to continue reading the SPS — but its fields are not
/// surfaced (see [`VvcProfileTierLevel`]).
pub fn parse_profile_tier_level(
    r: &mut BitReader<'_>,
    profile_tier_present_flag: bool,
    max_sublayers_minus1: u32,
) -> Result<VvcProfileTierLevel, BitstreamError> {
    let (general_profile_idc, general_tier_flag) = if profile_tier_present_flag {
        (Some(r.u(7) as u8), Some(r.u(1) as u8))
    } else {
        (None, None)
    };
    let general_level_idc = r.u(8) as u8;
    let ptl_frame_only_constraint_flag = r.u(1) as u8;
    let ptl_multilayer_enabled_flag = r.u(1) as u8;
    let (gci_present_flag, gci_bits) = if profile_tier_present_flag {
        // 7.3.3.2 — general_constraints_info(). The bridge does not
        // need the individual fields, but we must walk them so the
        // reader is positioned correctly to continue with the
        // per-sublayer level flags — and the raw bits are retained so
        // the writer can reproduce them. The structure self-aligns to
        // a byte boundary at the end (final `gci_alignment_zero_bit`
        // while-loop).
        walk_general_constraints_info(r)?
    } else {
        (false, Vec::new())
    };
    // Spec walks i from MaxNumSubLayersMinus1 - 1 down to 0; we
    // collect the bits in that order then reverse so the storage is
    // indexed low-to-high. That's purely cosmetic — the *bit-pattern*
    // remains correct.
    let n_sub = max_sublayers_minus1 as usize;
    let mut ptl_sublayer_level_present_flag = vec![0u8; n_sub];
    for i in (0..n_sub).rev() {
        ptl_sublayer_level_present_flag[i] = r.u(1) as u8;
    }
    // Padding zero bits up to the next byte boundary (the spec's
    // `while( !byte_aligned() ) ptl_reserved_zero_bit`).
    r.align_to_byte();
    let mut sublayer_level_idc = Vec::with_capacity(n_sub);
    for i in (0..n_sub).rev() {
        if ptl_sublayer_level_present_flag[i] != 0 {
            sublayer_level_idc.push(r.u(8) as u8);
        }
    }
    // Restore low-to-high ordering on the sublayer_level_idc vec so
    // the i-th entry matches the i-th entry in
    // `ptl_sublayer_level_present_flag` (after filtering out the
    // not-present sublayers in order).
    sublayer_level_idc.reverse();
    let mut general_sub_profile_idc = Vec::new();
    if profile_tier_present_flag {
        let ptl_num_sub_profiles = r.u(8) as usize;
        for _ in 0..ptl_num_sub_profiles {
            general_sub_profile_idc.push(r.u(32));
        }
    }
    Ok(VvcProfileTierLevel {
        general_profile_idc,
        general_tier_flag,
        general_level_idc,
        ptl_frame_only_constraint_flag,
        ptl_multilayer_enabled_flag,
        ptl_sublayer_level_present_flag,
        sublayer_level_idc,
        general_sub_profile_idc,
        gci_present_flag,
        gci_bits,
    })
}

/// Walk 7.3.3.2 `general_constraints_info()` consuming bits until the
/// structure's terminating `gci_alignment_zero_bit` byte-aligns the
/// reader. Returns `(gci_present_flag, raw content bits)` — the
/// content is retained verbatim rather than decoded field-by-field;
/// the only caller is `parse_profile_tier_level`.
fn walk_general_constraints_info(
    r: &mut BitReader<'_>,
) -> Result<(bool, Vec<bool>), BitstreamError> {
    let gci_present_flag = r.u(1) != 0;
    let mut bits = Vec::new();
    let take = |r: &mut BitReader<'_>, n: u32, bits: &mut Vec<bool>| -> u32 {
        let mut v = 0u32;
        for _ in 0..n {
            let b = r.read_bit();
            bits.push(b != 0);
            v = (v << 1) | b;
        }
        v
    };
    if gci_present_flag {
        // 71 single-bit / multi-bit fields up to and including
        // `gci_no_virtual_boundaries_constraint_flag`, then 8 bits of
        // `gci_num_additional_bits`:
        //
        // /* general */                3 × u(1)                 = 3
        // /* picture format */         u(4) + u(2)              = 6
        // /* NAL unit type related */ 10 × u(1)                 = 10
        // /* tile/slice/subpic */      6 × u(1)                 = 6
        // /* CTU and block part. */    u(2) + 3 × u(1)          = 5
        // /* intra */                  6 × u(1)                 = 6
        // /* inter */                 14 × u(1)                 = 14
        // /* transform/quant/resid */ 13 × u(1)                 = 13
        // /* loop filter */            6 × u(1)                 = 6
        //                              ---
        //                              69 bits to here
        // plus gci_num_additional_bits u(8)                     = 8
        // total fixed prefix                                    = 77 bits
        take(r, 69, &mut bits);
        let gci_num_additional_bits = take(r, 8, &mut bits);
        let num_additional_bits_used = if gci_num_additional_bits > 5 {
            // 6 named "additional" bits.
            take(r, 6, &mut bits);
            6
        } else {
            0
        };
        // gci_reserved_bit[i] for the remainder.
        if gci_num_additional_bits > num_additional_bits_used {
            take(
                r,
                gci_num_additional_bits - num_additional_bits_used,
                &mut bits,
            );
        }
    }
    // Final while(!byte_aligned()) gci_alignment_zero_bit.
    r.align_to_byte();
    Ok((gci_present_flag, bits))
}

/// Emit a `profile_tier_level( profileTierPresentFlag,
/// maxNumSubLayersMinus1 )` structure (7.3.3.1) — the byte-exact
/// inverse of [`parse_profile_tier_level`] for conforming inputs (the
/// spec's reserved/alignment zero bits are re-emitted as zeros).
pub fn write_profile_tier_level(
    w: &mut crate::bit_writer::BitWriter,
    ptl: &VvcProfileTierLevel,
    profile_tier_present_flag: bool,
    max_sublayers_minus1: u32,
) -> Result<(), BitstreamError> {
    if profile_tier_present_flag {
        let (Some(profile_idc), Some(tier_flag)) = (ptl.general_profile_idc, ptl.general_tier_flag)
        else {
            return Err(BitstreamError::invalid(
                "profile_tier_level: profile/tier fields required when \
                 profileTierPresentFlag is set (7.3.3.1)",
            ));
        };
        if profile_idc > 0x7f {
            return Err(BitstreamError::invalid(
                "general_profile_idc does not fit u(7)",
            ));
        }
        w.write_bits(profile_idc as u32, 7);
        w.write_bit(tier_flag as u32 & 1);
    } else if ptl.general_profile_idc.is_some()
        || ptl.general_tier_flag.is_some()
        || !ptl.general_sub_profile_idc.is_empty()
        || ptl.gci_present_flag
    {
        return Err(BitstreamError::invalid(
            "profile_tier_level: profile-gated fields present without \
             profileTierPresentFlag (7.3.3.1)",
        ));
    }
    w.write_bits(ptl.general_level_idc as u32, 8);
    w.write_bit(ptl.ptl_frame_only_constraint_flag as u32 & 1);
    w.write_bit(ptl.ptl_multilayer_enabled_flag as u32 & 1);
    if profile_tier_present_flag {
        // general_constraints_info() — presence flag + retained raw
        // content bits + gci_alignment_zero_bit run.
        w.write_bit(u32::from(ptl.gci_present_flag));
        if ptl.gci_present_flag {
            if ptl.gci_bits.len() < 77 {
                return Err(BitstreamError::invalid(
                    "general_constraints_info content must cover the 77-bit fixed \
                     prefix (7.3.3.2)",
                ));
            }
            for &b in &ptl.gci_bits {
                w.write_bit(u32::from(b));
            }
        } else if !ptl.gci_bits.is_empty() {
            return Err(BitstreamError::invalid(
                "general_constraints_info content bits without gci_present_flag",
            ));
        }
        w.align_to_byte();
    }
    let n_sub = max_sublayers_minus1 as usize;
    if ptl.ptl_sublayer_level_present_flag.len() != n_sub {
        return Err(BitstreamError::invalid(format!(
            "profile_tier_level sublayer flag entries ({}) != maxNumSubLayersMinus1 ({n_sub})",
            ptl.ptl_sublayer_level_present_flag.len()
        )));
    }
    for i in (0..n_sub).rev() {
        w.write_bit(ptl.ptl_sublayer_level_present_flag[i] as u32 & 1);
    }
    w.align_to_byte(); // ptl_reserved_zero_bit run
    let present_count = ptl
        .ptl_sublayer_level_present_flag
        .iter()
        .filter(|&&f| f != 0)
        .count();
    if ptl.sublayer_level_idc.len() != present_count {
        return Err(BitstreamError::invalid(
            "profile_tier_level sublayer_level_idc entries must match the present flags",
        ));
    }
    // The parser stores level idcs low-to-high; the wire order is
    // high-to-low over the present sublayers.
    let mut idc_iter = ptl.sublayer_level_idc.iter().rev();
    for i in (0..n_sub).rev() {
        if ptl.ptl_sublayer_level_present_flag[i] != 0 {
            let idc = idc_iter.next().expect("length validated above");
            w.write_bits(*idc as u32, 8);
        }
    }
    if profile_tier_present_flag {
        if ptl.general_sub_profile_idc.len() > 255 {
            return Err(BitstreamError::invalid(
                "ptl_num_sub_profiles does not fit u(8)",
            ));
        }
        w.write_bits(ptl.general_sub_profile_idc.len() as u32, 8);
        for &idc in &ptl.general_sub_profile_idc {
            w.write_bits(idc, 32);
        }
    }
    Ok(())
}

// ─────────────────────────── OPI RBSP (7.3.2.2) ─────────────────────────────

/// Operating point information RBSP (7.3.2.2 / 7.4.3.2). The OPI NAL
/// (type 12) tells the decoder which OLS and/or highest temporal
/// sublayer to operate on, overriding external means.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcOpi {
    /// `Some(opi_ols_idx)` iff `opi_ols_info_present_flag`.
    pub opi_ols_idx: Option<u32>,
    /// `Some(opi_htid_plus1)` (u(3)) iff `opi_htid_info_present_flag`.
    pub opi_htid_plus1: Option<u8>,
    /// Retained; the extension payload itself is not, so the writer
    /// refuses `true`.
    pub opi_extension_flag: bool,
}

/// Parse an OPI NAL (two-byte NAL header at index 0..1).
pub fn parse_opi(nal_body: &[u8]) -> Result<VvcOpi, BitstreamError> {
    if nal_body.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "H.266 OPI NAL needs at least the 2-byte header",
        ));
    }
    let header = parse_nal_header(nal_body)?;
    if header.nal_unit_type != NAL_TYPE_OPI {
        return Err(BitstreamError::invalid(format!(
            "expected OPI NAL (type {NAL_TYPE_OPI}), got {}",
            header.nal_unit_type
        )));
    }
    let rbsp = ebsp_to_rbsp(&nal_body[2..]);
    let mut r = BitReader::new(&rbsp);
    let ols_info_present = r.u(1) != 0;
    let htid_info_present = r.u(1) != 0;
    let mut opi = VvcOpi::default();
    if ols_info_present {
        opi.opi_ols_idx = Some(r.ue()?);
    }
    if htid_info_present {
        opi.opi_htid_plus1 = Some(r.u(3) as u8);
    }
    opi.opi_extension_flag = r.u(1) != 0;
    if !opi.opi_extension_flag {
        r.read_rbsp_trailing_bits()?;
    }
    Ok(opi)
}

/// Emit an `operating_point_information_rbsp()` (7.3.2.2 including
/// `rbsp_trailing_bits()`) — the byte-exact inverse of [`parse_opi`]'s
/// RBSP walk. `opi_extension_flag == 1` (unretained extension
/// payload) is refused as [`BitstreamError::Unsupported`].
pub fn write_opi(opi: &VvcOpi) -> Result<Vec<u8>, BitstreamError> {
    if opi.opi_extension_flag {
        return Err(BitstreamError::unsupported(
            "H.266 OPI opi_extension_flag == 1 (unretained opi_extension_data_flag bits)",
        ));
    }
    let mut w = crate::bit_writer::BitWriter::new();
    w.write_bit(u32::from(opi.opi_ols_idx.is_some()));
    w.write_bit(u32::from(opi.opi_htid_plus1.is_some()));
    if let Some(idx) = opi.opi_ols_idx {
        w.write_ue(idx)?;
    }
    if let Some(htid) = opi.opi_htid_plus1 {
        if htid > 7 {
            return Err(BitstreamError::invalid("opi_htid_plus1 does not fit u(3)"));
        }
        w.write_bits(htid as u32, 3);
    }
    w.write_bit(0); // opi_extension_flag (refused above when set)
    w.write_rbsp_trailing_bits();
    Ok(w.finish())
}

/// Emit a complete OPI NAL (canonical header: layer 0, TID 0).
pub fn write_opi_nal(opi: &VvcOpi) -> Result<Vec<u8>, BitstreamError> {
    let rbsp = write_opi(opi)?;
    let mut out = Vec::with_capacity(2 + rbsp.len());
    out.push(0x00);
    out.push((NAL_TYPE_OPI << 3) | 0x01);
    out.extend_from_slice(&crate::nal::rbsp_to_ebsp(&rbsp));
    Ok(out)
}

// ─────────────────────────── DCI RBSP (7.3.2.1) ─────────────────────────────

/// Decoding capability information RBSP (7.3.2.1 / 7.4.3.1). The DCI
/// NAL (type 13) carries a list of `profile_tier_level(1, 0)`
/// structures; a bitstream conforms if at least one of them is
/// satisfied for every CVS.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcDci {
    /// `dci_reserved_zero_4bits` — zero in conforming streams;
    /// retained verbatim (decoders shall ignore the value, 7.4.3.1).
    pub dci_reserved_zero_4bits: u8,
    /// 1..=16 entries (`dci_num_ptls_minus1` u(4)).
    pub profile_tier_levels: Vec<VvcProfileTierLevel>,
    /// Retained; the extension payload itself is not, so the writer
    /// refuses `true`.
    pub dci_extension_flag: bool,
}

/// Parse a DCI NAL (two-byte NAL header at index 0..1).
pub fn parse_dci(nal_body: &[u8]) -> Result<VvcDci, BitstreamError> {
    if nal_body.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "H.266 DCI NAL needs at least the 2-byte header",
        ));
    }
    let header = parse_nal_header(nal_body)?;
    if header.nal_unit_type != NAL_TYPE_DCI {
        return Err(BitstreamError::invalid(format!(
            "expected DCI NAL (type {NAL_TYPE_DCI}), got {}",
            header.nal_unit_type
        )));
    }
    let rbsp = ebsp_to_rbsp(&nal_body[2..]);
    let mut r = BitReader::new(&rbsp);
    let mut dci = VvcDci {
        dci_reserved_zero_4bits: r.u(4) as u8,
        ..VvcDci::default()
    };
    let num_ptls_minus1 = r.u(4);
    for _ in 0..=num_ptls_minus1 {
        dci.profile_tier_levels
            .push(parse_profile_tier_level(&mut r, true, 0)?);
    }
    dci.dci_extension_flag = r.u(1) != 0;
    if !dci.dci_extension_flag {
        r.read_rbsp_trailing_bits()?;
    }
    Ok(dci)
}

/// Emit a `decoding_capability_information_rbsp()` (7.3.2.1 including
/// `rbsp_trailing_bits()`) — the byte-exact inverse of [`parse_dci`]'s
/// RBSP walk for conforming inputs. `dci_extension_flag == 1`
/// (unretained extension payload) is refused as
/// [`BitstreamError::Unsupported`].
pub fn write_dci(dci: &VvcDci) -> Result<Vec<u8>, BitstreamError> {
    if dci.dci_extension_flag {
        return Err(BitstreamError::unsupported(
            "H.266 DCI dci_extension_flag == 1 (unretained dci_extension_data_flag bits)",
        ));
    }
    if dci.profile_tier_levels.is_empty() || dci.profile_tier_levels.len() > 16 {
        return Err(BitstreamError::invalid(
            "DCI must carry 1..=16 profile_tier_level structures (dci_num_ptls_minus1 u(4))",
        ));
    }
    if dci.dci_reserved_zero_4bits > 0x0f {
        return Err(BitstreamError::invalid(
            "dci_reserved_zero_4bits does not fit u(4)",
        ));
    }
    let mut w = crate::bit_writer::BitWriter::new();
    w.write_bits(dci.dci_reserved_zero_4bits as u32, 4);
    w.write_bits(dci.profile_tier_levels.len() as u32 - 1, 4);
    for ptl in &dci.profile_tier_levels {
        write_profile_tier_level(&mut w, ptl, true, 0)?;
    }
    w.write_bit(0); // dci_extension_flag (refused above when set)
    w.write_rbsp_trailing_bits();
    Ok(w.finish())
}

/// Emit a complete DCI NAL (canonical header: layer 0, TID 0).
pub fn write_dci_nal(dci: &VvcDci) -> Result<Vec<u8>, BitstreamError> {
    let rbsp = write_dci(dci)?;
    let mut out = Vec::with_capacity(2 + rbsp.len());
    out.push(0x00);
    out.push((NAL_TYPE_DCI << 3) | 0x01);
    out.extend_from_slice(&crate::nal::rbsp_to_ebsp(&rbsp));
    Ok(out)
}

// ─────────────────────────── VPS RBSP (7.3.2.3) ─────────────────────────────

/// Decoded VVC VPS structural fields (7.3.2.3).
///
/// Surfaces the fixed-prefix fields a HW-accel bridge inspects when it
/// receives a VPS NAL: VPS identifier, layer count, sublayer count, and
/// the per-layer `nuh_layer_id` array. The remaining inter-layer
/// dependency / OLS / PTL-array / DPB / HRD / extension blocks are
/// **out of scope for this round** — single-layer VVC streams
/// (`vps_max_layers_minus1 == 0`) are the only currently supported
/// configuration, and HW bridges fall back to a software path on
/// multi-layer fixtures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VvcVps {
    /// `vps_video_parameter_set_id` u(4) (7.4.3.3). 0..=15 selects which
    /// VPS in the active set this is. Per 7.4.3.3 the value shall be
    /// greater than 0 on a well-formed bitstream — surfaced rather than
    /// rejected so callers can decide what to do.
    pub vps_video_parameter_set_id: u8,
    /// `vps_max_layers_minus1` u(6) (7.4.3.3). One less than the number
    /// of layers specified by the VPS. 0 means single-layer.
    pub vps_max_layers_minus1: u8,
    /// `vps_max_sublayers_minus1` u(3) (7.4.3.3). One less than the
    /// maximum number of temporal sublayers that may be present in
    /// any layer specified by the VPS. Spec range 0..=6.
    pub vps_max_sublayers_minus1: u8,
    /// `vps_layer_id[i]` u(6) for i in 0..=`vps_max_layers_minus1`
    /// (7.4.3.3). For each layer described by the VPS this is the
    /// `nuh_layer_id` carried in the NAL header of NAL units belonging
    /// to that layer.
    pub vps_layer_id: Vec<u8>,
}

/// Strip the two-byte NAL header from a VPS NAL body and parse the
/// VPS RBSP structural prefix per 7.3.2.3.
///
/// The input slice MUST point at the start of the NAL body (i.e.
/// after [`split_annex_b`]). Emulation-prevention bytes are stripped
/// via [`ebsp_to_rbsp`] before bit-level parsing.
///
/// The current round surfaces `vps_video_parameter_set_id`,
/// `vps_max_layers_minus1`, `vps_max_sublayers_minus1` and the
/// per-layer `vps_layer_id[]` array. Parsing stops there: the
/// inter-layer dependency loop, OLS configuration, per-OLS PTL array,
/// DPB / HRD parameters and the extension flag are deferred to later
/// rounds.
///
/// Returns:
/// - [`BitstreamError::InvalidData`] if the NAL body's
///   `nal_unit_type` is not [`NAL_TYPE_VPS`], or if
///   `vps_max_sublayers_minus1 > 6` (out of spec range).
/// - [`BitstreamError::Unsupported`] when the VPS describes more than
///   one layer (`vps_max_layers_minus1 > 0`); multi-layer signalling
///   requires the full inter-layer dependency walk which is not in
///   scope for this round.
/// - [`BitstreamError::UnexpectedEnd`] if the NAL body is shorter than
///   the two-byte header.
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

    let vps_video_parameter_set_id = r.u(4) as u8;
    let vps_max_layers_minus1 = r.u(6) as u8;
    let vps_max_sublayers_minus1 = r.u(3) as u8;
    if vps_max_sublayers_minus1 > 6 {
        return Err(BitstreamError::invalid(format!(
            "vps_max_sublayers_minus1 = {vps_max_sublayers_minus1} > 6 (spec range 0..=6)"
        )));
    }
    if vps_max_layers_minus1 > 0 {
        // Multi-layer VPS — the inter-layer dependency block
        // (`vps_independent_layer_flag` /
        //  `vps_max_tid_ref_present_flag` /
        //  `vps_direct_ref_layer_flag` /
        //  `vps_max_tid_il_ref_pics_plus1`), OLS configuration
        // (`vps_each_layer_is_an_ols_flag` / `vps_ols_mode_idc` /
        //  `vps_num_output_layer_sets_minus2`), per-OLS PTL array, DPB
        // and HRD parameter blocks are deferred to a later round.
        return Err(BitstreamError::unsupported(
            "VVC VPS with vps_max_layers_minus1 > 0 (multi-layer) not parsed in this round",
        ));
    }
    // Single-layer path: the two conditional flags before the
    // `vps_layer_id` loop (`vps_default_ptl_dpb_hrd_max_tid_flag`,
    // `vps_all_independent_layers_flag`) are both gated on
    // `vps_max_layers_minus1 > 0` so neither is present here. The loop
    // executes exactly once for i = 0 and reads only `vps_layer_id[0]`
    // because the inter-layer block is also gated on `i > 0`.
    let vps_layer_id = vec![r.u(6) as u8];

    Ok(VvcVps {
        vps_video_parameter_set_id,
        vps_max_layers_minus1,
        vps_max_sublayers_minus1,
        vps_layer_id,
    })
}

// ──────────────────── SPS RBSP (7.3.2.4) — full walk ───────────────────────

pub mod params;
pub mod sps;

pub use params::{
    parse_dpb_parameters, parse_general_timing_hrd, parse_ols_timing_hrd,
    parse_ref_pic_list_struct, write_dpb_parameters, write_general_timing_hrd,
    write_ols_timing_hrd, write_ref_pic_list_struct, VvcCpbSchedule, VvcDpbEntry, VvcDpbParameters,
    VvcGeneralTimingHrd, VvcOlsTimingHrd, VvcOlsTimingHrdSublayer, VvcRefPicListStruct,
    VvcRplsContext, VvcRplsEntry, VvcSublayerHrd, VVC_NUM_REF_ENTRIES_MAX,
};
pub use sps::{
    parse_sps, write_sps, write_sps_nal, VvcChromaQpTable, VvcLadf, VvcSps, VvcSpsRangeExtension,
    VvcSpsTimingHrd, VvcSubpicEntry, VvcSubpicInfo, SPS_LOG2_MAX_PIC_ORDER_CNT_LSB_MINUS4_MAX,
    SPS_NUM_SUBPICS_MINUS1_MAX,
};

// ─────────────────────────── PPS RBSP (7.3.2.5) ─────────────────────────────

/// Decoded VVC PPS structural fields (7.3.2.5).
///
/// Surfaces the fixed-prefix fields a HW-accel bridge inspects when it
/// receives a PPS NAL: PPS / SPS identifiers, mixed-NAL-types flag,
/// per-picture luma dimensions, the conformance-window and
/// scaling-window offset blocks (with their presence flags), and the
/// three remaining presence / partition flags that this round walks
/// (`pps_output_flag_present_flag`, `pps_no_pic_partition_flag`,
/// `pps_subpic_id_mapping_present_flag`). All later PPS fields
/// (subpicture id mapping, tile/slice partitioning, deblocking,
/// chroma QP, etc.) are out of scope for this round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VvcPps {
    /// `pps_pic_parameter_set_id` u(6) (7.4.3.5). 0..=63 selects which
    /// PPS in the active set this is.
    pub pps_pic_parameter_set_id: u8,
    /// `pps_seq_parameter_set_id` u(4) (7.4.3.5). Identifies the
    /// active SPS this PPS refers to (0..=15).
    pub pps_seq_parameter_set_id: u8,
    /// `pps_mixed_nalu_types_in_pic_flag` u(1) (7.4.3.5). When 1, the
    /// pictures referring to the PPS may contain VCL NAL units of more
    /// than one `nal_unit_type`.
    pub pps_mixed_nalu_types_in_pic_flag: u8,
    /// `pps_pic_width_in_luma_samples` ue(v) (7.4.3.5). Width of each
    /// decoded picture referring to the PPS, in luma samples. Must be
    /// `<= sps_pic_width_max_in_luma_samples`.
    pub pps_pic_width_in_luma_samples: u32,
    /// `pps_pic_height_in_luma_samples` ue(v) (7.4.3.5). Height of each
    /// decoded picture referring to the PPS, in luma samples. Must be
    /// `<= sps_pic_height_max_in_luma_samples`.
    pub pps_pic_height_in_luma_samples: u32,
    /// `pps_conformance_window_flag` u(1) (7.4.3.5). When 1, the four
    /// `pps_conf_win_*_offset` ue(v) values follow and are surfaced in
    /// [`VvcPps::pps_conf_win_offsets`].
    pub pps_conformance_window_flag: u8,
    /// `(left, right, top, bottom)` conformance-window offsets in
    /// chroma samples (7.4.3.5). `None` when
    /// `pps_conformance_window_flag = 0`.
    pub pps_conf_win_offsets: Option<(u32, u32, u32, u32)>,
    /// `pps_scaling_window_explicit_signalling_flag` u(1) (7.4.3.5).
    /// When 1, the four `pps_scaling_win_*_offset` se(v) values follow.
    pub pps_scaling_window_explicit_signalling_flag: u8,
    /// `(left, right, top, bottom)` scaling-window offsets in luma
    /// samples (7.4.3.5). Signed because the spec allows negative
    /// offsets. `None` when
    /// `pps_scaling_window_explicit_signalling_flag = 0`.
    pub pps_scaling_win_offsets: Option<(i32, i32, i32, i32)>,
    /// `pps_output_flag_present_flag` u(1) (7.4.3.5). When 1, the
    /// `ph_pic_output_flag` syntax element is present in PHs referring
    /// to the PPS.
    pub pps_output_flag_present_flag: u8,
    /// `pps_no_pic_partition_flag` u(1) (7.4.3.5). When 1, no picture
    /// partitioning is applied to any picture referring to the PPS
    /// (single tile, single slice spanning the whole picture).
    pub pps_no_pic_partition_flag: u8,
    /// `pps_subpic_id_mapping_present_flag` u(1) (7.4.3.5). When 1,
    /// subpicture id mapping is signalled in the PPS. The subpicture
    /// id mapping body itself is NOT parsed in this round.
    pub pps_subpic_id_mapping_present_flag: u8,
}

/// Strip the two-byte NAL header from a PPS NAL body (the `0x_10_..`
/// header bytes that [`parse_nal_header`] decodes), then parse the
/// PPS RBSP structural prefix per 7.3.2.5.
///
/// The input slice MUST point at the start of the NAL body (i.e.
/// after [`split_annex_b`]). Emulation-prevention bytes are stripped
/// via [`ebsp_to_rbsp`] before bit-level parsing.
///
/// The current round surfaces the fixed-prefix fields a HW bridge
/// needs (PPS/SPS ids, mixed-NAL flag, per-picture luma dimensions,
/// conformance-window + scaling-window offset blocks, and the three
/// presence/partition flags up through
/// `pps_subpic_id_mapping_present_flag`). Parsing stops there: the
/// remaining tile / slice partitioning + cabac / weighted-pred /
/// deblocking blocks are deferred to later rounds.
///
/// Returns [`BitstreamError::InvalidData`] if the NAL body's
/// `nal_unit_type` is not [`NAL_TYPE_PPS`].
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

    let pps_pic_parameter_set_id = r.u(6) as u8;
    let pps_seq_parameter_set_id = r.u(4) as u8;
    let pps_mixed_nalu_types_in_pic_flag = r.u(1) as u8;
    let pps_pic_width_in_luma_samples = r.ue()?;
    let pps_pic_height_in_luma_samples = r.ue()?;
    let pps_conformance_window_flag = r.u(1) as u8;
    let pps_conf_win_offsets = if pps_conformance_window_flag != 0 {
        let l = r.ue()?;
        let rr = r.ue()?;
        let t = r.ue()?;
        let b = r.ue()?;
        Some((l, rr, t, b))
    } else {
        None
    };
    let pps_scaling_window_explicit_signalling_flag = r.u(1) as u8;
    let pps_scaling_win_offsets = if pps_scaling_window_explicit_signalling_flag != 0 {
        let l = r.se()?;
        let rr = r.se()?;
        let t = r.se()?;
        let b = r.se()?;
        Some((l, rr, t, b))
    } else {
        None
    };
    let pps_output_flag_present_flag = r.u(1) as u8;
    let pps_no_pic_partition_flag = r.u(1) as u8;
    let pps_subpic_id_mapping_present_flag = r.u(1) as u8;

    Ok(VvcPps {
        pps_pic_parameter_set_id,
        pps_seq_parameter_set_id,
        pps_mixed_nalu_types_in_pic_flag,
        pps_pic_width_in_luma_samples,
        pps_pic_height_in_luma_samples,
        pps_conformance_window_flag,
        pps_conf_win_offsets,
        pps_scaling_window_explicit_signalling_flag,
        pps_scaling_win_offsets,
        pps_output_flag_present_flag,
        pps_no_pic_partition_flag,
        pps_subpic_id_mapping_present_flag,
    })
}

// ─────────────────────────── Picture header ──────────────────────────────────

/// H.266 / VVC picture-header structural prefix (7.3.2.7 / 7.3.2.8).
///
/// In VVC the `picture_header_structure()` is carried by its own NAL
/// unit (`NAL_TYPE_PH`) and applies to every VCL slice of the access
/// unit that follows it. A HW bridge has to classify the picture
/// (IRAP / GDR / inter-allowed / intra-allowed / non-reference) and
/// recover the active PPS id before submitting the per-slice parameter
/// buffer to the GPU.
///
/// This struct surfaces the **fixed prefix** of the picture-header
/// structure — the fields that are always present without depending on
/// the active SPS / PPS. Parsing stops immediately after
/// `ph_pic_parameter_set_id`, because the very next field
/// (`ph_pic_order_cnt_lsb`) is `u(v)` with a width of
/// `sps_log2_max_pic_order_cnt_lsb_minus4 + 4` derived from the SPS the
/// PPS chains to (7.4.3.4 / 7.4.3.8) — and routing that context-sensitive
/// width through the parser is deferred to a later round. Everything
/// gated on `sps_*` / `pps_*` flags (ALF, LMCS, virtual boundaries, RPL,
/// partition constraints, deblocking offsets, QP delta, …) is therefore
/// out of scope for this round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VvcPictureHeader {
    /// `ph_gdr_or_irap_pic_flag` u(1) (7.4.3.8). When 1 the picture is
    /// either a GDR picture (`ph_gdr_pic_flag = 1`) or an IRAP picture
    /// (`ph_gdr_pic_flag = 0`); HW bridges use this for random-access
    /// entry-point selection.
    pub ph_gdr_or_irap_pic_flag: u8,
    /// `ph_non_ref_pic_flag` u(1) (7.4.3.8). When 1 the picture is not
    /// used as a reference picture; bridges may forward this to the
    /// DPB-management API for early eviction.
    pub ph_non_ref_pic_flag: u8,
    /// `ph_gdr_pic_flag` u(1) (7.4.3.8). Present when
    /// `ph_gdr_or_irap_pic_flag = 1`, `None` otherwise. Distinguishes a
    /// GDR picture from an IRAP picture inside the
    /// `ph_gdr_or_irap_pic_flag` set.
    pub ph_gdr_pic_flag: Option<u8>,
    /// `ph_inter_slice_allowed_flag` u(1) (7.4.3.8). When 1 the picture
    /// may contain at least one P or B slice; when 0 every slice is an
    /// I-slice (and `ph_intra_slice_allowed_flag` is inferred as 1).
    pub ph_inter_slice_allowed_flag: u8,
    /// `ph_intra_slice_allowed_flag` u(1) (7.4.3.8). Present when
    /// `ph_inter_slice_allowed_flag = 1`, `None` otherwise. When 0 the
    /// picture has only inter slices.
    pub ph_intra_slice_allowed_flag: Option<u8>,
    /// `ph_pic_parameter_set_id` ue(v) (7.4.3.8). Identifies the active
    /// PPS this picture refers to. Spec range is 0..=63 (matching
    /// `pps_pic_parameter_set_id` u(6) in 7.4.3.5); values outside that
    /// range are rejected as [`BitstreamError::InvalidData`].
    pub ph_pic_parameter_set_id: u8,
    /// `ph_pic_order_cnt_lsb` u(v) (7.4.3.8). Width is
    /// `sps_log2_max_pic_order_cnt_lsb_minus4 + 4` bits, derived from
    /// the active SPS — see [`VvcSps::poc_lsb_width`]. Always
    /// `Some(_)` when the picture header was decoded through
    /// [`parse_picture_header_with_sps`] (which threads the SPS
    /// context); `None` when decoded through the context-free
    /// [`parse_picture_header`] entry point that stops at
    /// `ph_pic_parameter_set_id`.
    pub ph_pic_order_cnt_lsb: Option<u32>,
    /// `ph_recovery_poc_cnt` ue(v) (7.4.3.8). Present only when
    /// `ph_gdr_pic_flag = 1`. `None` for IRAP / non-GDR pictures and
    /// for context-free decodes via [`parse_picture_header`]. Per the
    /// spec the value is signalled by the encoder; the parser surfaces
    /// it directly without further range checks (the field is
    /// constrained per profile but those tables are out of scope).
    pub ph_recovery_poc_cnt: Option<u32>,
}

impl VvcPictureHeader {
    /// Convenience: `ph_intra_slice_allowed_flag` resolved to its
    /// effective value (1 when `ph_inter_slice_allowed_flag = 0`, the
    /// stored flag otherwise). Per 7.4.3.8 the field is inferred to be
    /// 1 when not signalled (a picture that disallows inter must allow
    /// intra; otherwise it would have no slices at all).
    pub fn intra_slice_allowed(&self) -> u8 {
        match (
            self.ph_inter_slice_allowed_flag,
            self.ph_intra_slice_allowed_flag,
        ) {
            (0, _) => 1,
            (_, Some(v)) => v,
            // ph_inter_slice_allowed_flag = 1 always pairs with the
            // explicit `ph_intra_slice_allowed_flag` field per the spec
            // grammar; defensive fallback only.
            (_, None) => 1,
        }
    }

    /// True when the picture is an IRAP picture (`ph_gdr_or_irap_pic_flag
    /// = 1` and `ph_gdr_pic_flag = 0`). IRAP pictures are the
    /// random-access entry points HW bridges hand off to a clean DPB.
    pub fn is_irap(&self) -> bool {
        self.ph_gdr_or_irap_pic_flag == 1 && self.ph_gdr_pic_flag == Some(0)
    }

    /// True when the picture is a GDR picture (`ph_gdr_or_irap_pic_flag
    /// = 1` and `ph_gdr_pic_flag = 1`).
    pub fn is_gdr(&self) -> bool {
        self.ph_gdr_or_irap_pic_flag == 1 && self.ph_gdr_pic_flag == Some(1)
    }
}

/// `ph_pic_parameter_set_id` shares the spec-defined range of
/// `pps_pic_parameter_set_id` u(6) (7.4.3.5): 0..=63. Surfaced as a
/// constant so callers can validate against the same envelope the
/// parser enforces.
pub const PH_PIC_PARAMETER_SET_ID_MAX: u8 = 63;

/// Strip the two-byte NAL header from a PH NAL body, then parse the
/// `picture_header_structure()` (7.3.2.8) up to and including
/// `ph_pic_parameter_set_id`.
///
/// The input slice MUST point at the start of the NAL body (i.e. after
/// [`split_annex_b`]). Emulation-prevention bytes are stripped via
/// [`ebsp_to_rbsp`] before bit-level parsing.
///
/// Returns [`BitstreamError::InvalidData`] when the NAL is not
/// [`NAL_TYPE_PH`] or when `ph_pic_parameter_set_id` exceeds the spec
/// range (>63). All later picture-header bits are out of scope for
/// this round — the reader's cursor is left wherever the prefix
/// finished and no further state is touched.
pub fn parse_picture_header(nal_body: &[u8]) -> Result<VvcPictureHeader, BitstreamError> {
    if nal_body.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "H.266 PH NAL needs at least the 2-byte header",
        ));
    }
    let header = parse_nal_header(nal_body)?;
    if header.nal_unit_type != NAL_TYPE_PH {
        return Err(BitstreamError::invalid(format!(
            "expected PH NAL (type {}), got {}",
            NAL_TYPE_PH, header.nal_unit_type
        )));
    }
    let rbsp = ebsp_to_rbsp(&nal_body[2..]);
    let mut r = BitReader::new(&rbsp);

    let ph_gdr_or_irap_pic_flag = r.u(1) as u8;
    let ph_non_ref_pic_flag = r.u(1) as u8;
    let ph_gdr_pic_flag = if ph_gdr_or_irap_pic_flag != 0 {
        Some(r.u(1) as u8)
    } else {
        None
    };
    let ph_inter_slice_allowed_flag = r.u(1) as u8;
    let ph_intra_slice_allowed_flag = if ph_inter_slice_allowed_flag != 0 {
        Some(r.u(1) as u8)
    } else {
        None
    };
    let ph_pic_parameter_set_id_u32 = r.ue()?;
    if ph_pic_parameter_set_id_u32 > PH_PIC_PARAMETER_SET_ID_MAX as u32 {
        return Err(BitstreamError::invalid(format!(
            "ph_pic_parameter_set_id = {ph_pic_parameter_set_id_u32} > {PH_PIC_PARAMETER_SET_ID_MAX} (spec range 0..=63)"
        )));
    }
    let ph_pic_parameter_set_id = ph_pic_parameter_set_id_u32 as u8;

    Ok(VvcPictureHeader {
        ph_gdr_or_irap_pic_flag,
        ph_non_ref_pic_flag,
        ph_gdr_pic_flag,
        ph_inter_slice_allowed_flag,
        ph_intra_slice_allowed_flag,
        ph_pic_parameter_set_id,
        ph_pic_order_cnt_lsb: None,
        ph_recovery_poc_cnt: None,
    })
}

/// Strip the two-byte NAL header from a PH NAL body, then parse the
/// `picture_header_structure()` (7.3.2.8) through `ph_pic_order_cnt_lsb`
/// (and `ph_recovery_poc_cnt` when present), using the bit-width of the
/// POC LSB field supplied by the active SPS context.
///
/// This is the SPS-context-aware companion to [`parse_picture_header`].
/// The shorter variant stops at `ph_pic_parameter_set_id` because the
/// next field — `ph_pic_order_cnt_lsb` — is `u(v)` with a width derived
/// from `sps_log2_max_pic_order_cnt_lsb_minus4 + 4` (7.4.3.4 / 7.4.3.8).
/// A HW bridge that has already parsed the active SPS (via
/// [`parse_sps`]) can pass that SPS in here to recover the POC LSB —
/// the field every reference-picture-list management API consumes — and,
/// for GDR pictures, the `ph_recovery_poc_cnt` ue(v) that signals when
/// the GDR refresh completes.
///
/// Parsing stops immediately after those two fields. Every later
/// picture-header bit (the `ph_extra_bit[i]` array gated on
/// `NumExtraPhBits`, the `sps_poc_msb_cycle_flag` block, all the ALF /
/// LMCS / scaling-list / virtual-boundary / RPL / partition-constraint /
/// deblocking / QP-delta sub-blocks gated on `sps_*` and `pps_*` flags)
/// is out of scope for this round — they each carry their own
/// SPS / PPS-driven dependency chain and would multiply the parser's
/// surface several-fold for fields HW bridges don't read directly.
///
/// Returns [`BitstreamError::InvalidData`] when the NAL is not
/// [`NAL_TYPE_PH`] or when `ph_pic_parameter_set_id` exceeds the spec
/// range (>63). The SPS's `sps_log2_max_pic_order_cnt_lsb_minus4` is
/// trusted as already-validated by [`parse_sps`] (which enforces the
/// 0..=12 envelope).
pub fn parse_picture_header_with_sps(
    nal_body: &[u8],
    sps: &VvcSps,
) -> Result<VvcPictureHeader, BitstreamError> {
    if nal_body.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "H.266 PH NAL needs at least the 2-byte header",
        ));
    }
    let header = parse_nal_header(nal_body)?;
    if header.nal_unit_type != NAL_TYPE_PH {
        return Err(BitstreamError::invalid(format!(
            "expected PH NAL (type {}), got {}",
            NAL_TYPE_PH, header.nal_unit_type
        )));
    }
    let rbsp = ebsp_to_rbsp(&nal_body[2..]);
    let mut r = BitReader::new(&rbsp);

    let ph_gdr_or_irap_pic_flag = r.u(1) as u8;
    let ph_non_ref_pic_flag = r.u(1) as u8;
    let ph_gdr_pic_flag = if ph_gdr_or_irap_pic_flag != 0 {
        Some(r.u(1) as u8)
    } else {
        None
    };
    let ph_inter_slice_allowed_flag = r.u(1) as u8;
    let ph_intra_slice_allowed_flag = if ph_inter_slice_allowed_flag != 0 {
        Some(r.u(1) as u8)
    } else {
        None
    };
    let ph_pic_parameter_set_id_u32 = r.ue()?;
    if ph_pic_parameter_set_id_u32 > PH_PIC_PARAMETER_SET_ID_MAX as u32 {
        return Err(BitstreamError::invalid(format!(
            "ph_pic_parameter_set_id = {ph_pic_parameter_set_id_u32} > {PH_PIC_PARAMETER_SET_ID_MAX} (spec range 0..=63)"
        )));
    }
    let ph_pic_parameter_set_id = ph_pic_parameter_set_id_u32 as u8;
    let ph_pic_order_cnt_lsb = r.u(sps.poc_lsb_width());
    let ph_recovery_poc_cnt = if ph_gdr_pic_flag == Some(1) {
        Some(r.ue()?)
    } else {
        None
    };

    Ok(VvcPictureHeader {
        ph_gdr_or_irap_pic_flag,
        ph_non_ref_pic_flag,
        ph_gdr_pic_flag,
        ph_inter_slice_allowed_flag,
        ph_intra_slice_allowed_flag,
        ph_pic_parameter_set_id,
        ph_pic_order_cnt_lsb: Some(ph_pic_order_cnt_lsb),
        ph_recovery_poc_cnt,
    })
}

// ─────────────────────────── Access unit delimiter (7.3.2.10) ────────────────

/// Access unit delimiter RBSP — H.266 §7.3.2.10 / §7.4.3.10.
///
/// The AUD NAL (type 20) marks the boundary between access units in
/// non-multi-layer streams and is mandatory in multi-layer OLSs that
/// contain only IRAP / GDR pictures. Two fields are signalled:
///
/// - `aud_irap_or_gdr_flag` u(1): 1 when the access unit is an IRAP
///   or GDR access unit, 0 otherwise.
/// - `aud_pic_type` u(3): conformance-restricted to 0 (I-only), 1
///   (P+I) or 2 (B+P+I); 3..=7 are reserved-for-future-use and
///   decoders MUST accept them per the spec's
///   "Decoders … shall ignore reserved values" clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VvcAccessUnitDelimiter {
    /// `aud_irap_or_gdr_flag` u(1) (§7.4.3.10). When 1 the access unit
    /// contains only IRAP or GDR coded pictures.
    pub aud_irap_or_gdr_flag: u8,
    /// `aud_pic_type` u(3) (§7.4.3.10 / Table 7). Conforming
    /// bitstreams use 0..=2; the parser surfaces reserved values
    /// (3..=7) verbatim per the spec's must-accept-reserved contract.
    pub aud_pic_type: u8,
}

/// `aud_pic_type` is u(3) so the spec range is 0..=7 (§7.4.3.10).
pub const AUD_PIC_TYPE_MAX: u8 = 7;

/// `aud_pic_type` values defined by the current H.266 edition. The
/// writer accepts the full u(3) range so reserved values round-trip
/// against the parser's accept-reserved contract.
pub const AUD_PIC_TYPE_I_ONLY: u8 = 0;
pub const AUD_PIC_TYPE_P_OR_I: u8 = 1;
pub const AUD_PIC_TYPE_B_P_OR_I: u8 = 2;

/// Strip the two-byte NAL header from an AUD NAL body and parse the
/// `access_unit_delimiter_rbsp()` (§7.3.2.10) — `aud_irap_or_gdr_flag`
/// u(1) + `aud_pic_type` u(3) + `rbsp_trailing_bits()`.
///
/// Returns [`BitstreamError::InvalidData`] when the NAL is not
/// [`NAL_TYPE_AUD`] or when the trailing marker is malformed;
/// returns [`BitstreamError::UnexpectedEnd`] when the NAL is too
/// short for the two-byte header plus a payload byte. Reserved
/// `aud_pic_type` values (3..=7) are returned verbatim per the
/// "Decoders … shall ignore reserved values" clause.
pub fn parse_aud(nal_body: &[u8]) -> Result<VvcAccessUnitDelimiter, BitstreamError> {
    if nal_body.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "H.266 AUD NAL needs at least the 2-byte header",
        ));
    }
    let header = parse_nal_header(nal_body)?;
    if header.nal_unit_type != NAL_TYPE_AUD {
        return Err(BitstreamError::invalid(format!(
            "expected AUD NAL (type {}), got {}",
            NAL_TYPE_AUD, header.nal_unit_type
        )));
    }
    if nal_body.len() < 3 {
        return Err(BitstreamError::unexpected_end(
            "H.266 AUD NAL has no body after the 2-byte header",
        ));
    }
    let rbsp = ebsp_to_rbsp(&nal_body[2..]);
    let mut r = BitReader::new(&rbsp);
    let aud_irap_or_gdr_flag = r.u(1) as u8;
    let aud_pic_type = r.u(3) as u8;
    r.read_rbsp_trailing_bits()?;
    Ok(VvcAccessUnitDelimiter {
        aud_irap_or_gdr_flag,
        aud_pic_type,
    })
}

/// Emit an AUD NAL — two-byte NAL header followed by a 1-byte RBSP
/// that packs `aud_irap_or_gdr_flag` u(1), `aud_pic_type` u(3) and
/// the `rbsp_trailing_bits()` marker (§7.3.2.10).
///
/// The NAL header fixes `forbidden_zero_bit = 0`,
/// `nuh_reserved_zero_bit = 0`, `nuh_layer_id = 0` and
/// `nuh_temporal_id_plus1 = 1` — the canonical base-layer / TID-0
/// choice for AUD NALs. Reserved `aud_pic_type` values (3..=7) are
/// accepted so the writer round-trips against the parser's
/// accept-reserved contract.
///
/// Returns [`BitstreamError::InvalidData`] when `aud_irap_or_gdr_flag
/// > 1` or `aud_pic_type > 7` (the u(1) / u(3) envelopes).
pub fn write_aud(aud: &VvcAccessUnitDelimiter) -> Result<Vec<u8>, BitstreamError> {
    if aud.aud_irap_or_gdr_flag > 1 {
        return Err(BitstreamError::invalid(format!(
            "aud_irap_or_gdr_flag = {} > 1 (u(1) envelope)",
            aud.aud_irap_or_gdr_flag
        )));
    }
    if aud.aud_pic_type > AUD_PIC_TYPE_MAX {
        return Err(BitstreamError::invalid(format!(
            "aud_pic_type = {} > {} (u(3) envelope)",
            aud.aud_pic_type, AUD_PIC_TYPE_MAX
        )));
    }
    // forbidden_zero=0, reserved_zero=0, layer_id=0 -> byte 0 = 0x00.
    // nal_unit_type=20, tid_plus1=1 -> (20 << 3) | 1 = 0xA1.
    let b0: u8 = 0;
    let b1: u8 = (NAL_TYPE_AUD << 3) | 1;
    let mut bw = crate::bit_writer::BitWriter::new();
    bw.write_bits(aud.aud_irap_or_gdr_flag as u32, 1);
    bw.write_bits(aud.aud_pic_type as u32, 3);
    bw.write_rbsp_trailing_bits();
    let rbsp = bw.finish();
    // The 1-byte RBSP cannot contain the 0x00 0x00 0x0{0..3} triple
    // the encapsulation rule guards against, so the EBSP equals the
    // RBSP.
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
    fn opi_parses_and_roundtrips_byte_exact() {
        // Both info fields present.
        let mut w = crate::bit_writer::BitWriter::new();
        w.write_bit(1); // opi_ols_info_present_flag
        w.write_bit(1); // opi_htid_info_present_flag
        w.write_ue(5).unwrap(); // opi_ols_idx
        w.write_bits(3, 3); // opi_htid_plus1
        w.write_bit(0); // opi_extension_flag
        w.write_rbsp_trailing_bits();
        let mut nal = vec![0x00, (NAL_TYPE_OPI << 3) | 0x01];
        nal.extend_from_slice(&crate::nal::rbsp_to_ebsp(&w.finish()));

        let opi = parse_opi(&nal).expect("OPI parses");
        assert_eq!(opi.opi_ols_idx, Some(5));
        assert_eq!(opi.opi_htid_plus1, Some(3));
        assert!(!opi.opi_extension_flag);
        assert_eq!(
            write_opi_nal(&opi).expect("OPI writes"),
            nal,
            "OPI parse→write must be byte-exact"
        );

        // Neither present — the minimal OPI.
        let empty = VvcOpi::default();
        let nal2 = write_opi_nal(&empty).unwrap();
        assert_eq!(parse_opi(&nal2).unwrap(), empty);

        // Extension flag refused on write.
        let ext = VvcOpi {
            opi_extension_flag: true,
            ..VvcOpi::default()
        };
        assert!(matches!(
            write_opi(&ext).unwrap_err(),
            BitstreamError::Unsupported(_)
        ));
    }

    #[test]
    fn dci_parses_and_roundtrips_byte_exact() {
        // Two PTLs: one with GCI content + a sub-profile, one minimal.
        let mut w = crate::bit_writer::BitWriter::new();
        w.write_bits(0, 4); // dci_reserved_zero_4bits
        w.write_bits(1, 4); // dci_num_ptls_minus1 = 1
                            // PTL 0 — profile_tier_level(1, 0):
        w.write_bits(1, 7); // general_profile_idc
        w.write_bit(0); // general_tier_flag
        w.write_bits(51, 8); // general_level_idc
        w.write_bit(1); // ptl_frame_only_constraint_flag
        w.write_bit(0); // ptl_multilayer_enabled_flag
        w.write_bit(1); // gci_present_flag
        for i in 0..69u32 {
            w.write_bit(u32::from(i % 5 == 0)); // fixed constraint fields
        }
        w.write_bits(2, 8); // gci_num_additional_bits = 2
        w.write_bit(1); // gci_reserved_bit[0]
        w.write_bit(0); // gci_reserved_bit[1]
        w.align_to_byte(); // gci_alignment_zero_bit
                           // (max_sublayers_minus1 == 0: no sublayer flags)
        w.align_to_byte(); // ptl_reserved_zero_bit (no-op, already aligned)
        w.write_bits(1, 8); // ptl_num_sub_profiles = 1
        w.write_bits(0xDEAD_BEEF_u32, 32); // general_sub_profile_idc[0]
                                           // PTL 1 — minimal:
        w.write_bits(2, 7);
        w.write_bit(1);
        w.write_bits(83, 8);
        w.write_bit(0);
        w.write_bit(0);
        w.write_bit(0); // gci_present_flag = 0
        w.align_to_byte();
        w.write_bits(0, 8); // ptl_num_sub_profiles = 0
        w.write_bit(0); // dci_extension_flag
        w.write_rbsp_trailing_bits();
        let mut nal = vec![0x00, (NAL_TYPE_DCI << 3) | 0x01];
        nal.extend_from_slice(&crate::nal::rbsp_to_ebsp(&w.finish()));

        let dci = parse_dci(&nal).expect("DCI parses");
        assert_eq!(dci.profile_tier_levels.len(), 2);
        let p0 = &dci.profile_tier_levels[0];
        assert_eq!(p0.general_profile_idc, Some(1));
        assert_eq!(p0.general_level_idc, 51);
        assert!(p0.gci_present_flag);
        assert_eq!(p0.gci_bits.len(), 69 + 8 + 2);
        assert!(p0.gci_bits[0]); // i % 5 == 0
        assert_eq!(p0.general_sub_profile_idc, vec![0xDEAD_BEEF]);
        let p1 = &dci.profile_tier_levels[1];
        assert_eq!(p1.general_profile_idc, Some(2));
        assert_eq!(p1.general_tier_flag, Some(1));
        assert!(!p1.gci_present_flag);
        assert!(p1.gci_bits.is_empty());
        assert_eq!(
            write_dci_nal(&dci).expect("DCI writes"),
            nal,
            "DCI parse→write must be byte-exact"
        );

        // Writer refusals: extension flag, empty PTL list.
        let ext = VvcDci {
            dci_extension_flag: true,
            profile_tier_levels: dci.profile_tier_levels.clone(),
            ..VvcDci::default()
        };
        assert!(matches!(
            write_dci(&ext).unwrap_err(),
            BitstreamError::Unsupported(_)
        ));
        assert!(matches!(
            write_dci(&VvcDci::default()).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));
    }

    #[test]
    fn split_annex_b_three_byte_start_codes() {
        // Two NALs with three-byte start codes.
        let stream = [
            0x00, 0x00, 0x01, 0x40, 0x01, 0xaa, 0x00, 0x00, 0x01, 0x42, 0x01, 0xbb, 0xcc,
        ];
        let nals = split_annex_b(&stream);
        assert_eq!(nals.len(), 2);
        assert_eq!(nals[0], [0x40, 0x01, 0xaa]);
        assert_eq!(nals[1], [0x42, 0x01, 0xbb, 0xcc]);
    }

    #[test]
    fn split_annex_b_four_byte_start_codes() {
        let stream = [
            0x00, 0x00, 0x00, 0x01, 0x78, 0x01, 0x11, 0x22, 0x00, 0x00, 0x00, 0x01, 0x7a, 0x01,
            0x33,
        ];
        let nals = split_annex_b(&stream);
        assert_eq!(nals.len(), 2);
        assert_eq!(nals[0], [0x78, 0x01, 0x11, 0x22]);
        assert_eq!(nals[1], [0x7a, 0x01, 0x33]);
    }

    #[test]
    fn split_annex_b_mixed_start_codes() {
        let stream = [
            0x00, 0x00, 0x00, 0x01, 0x70, 0x01, 0xaa, 0x00, 0x00, 0x01, 0x72, 0x01, 0xbb,
        ];
        let nals = split_annex_b(&stream);
        assert_eq!(nals.len(), 2);
        assert_eq!(nals[0], [0x70, 0x01, 0xaa]);
        assert_eq!(nals[1], [0x72, 0x01, 0xbb]);
    }

    #[test]
    fn ebsp_to_rbsp_strips_emulation_byte() {
        // 0x00 0x00 0x03 0x00 -> 0x00 0x00 0x00
        let ebsp = [0x12, 0x00, 0x00, 0x03, 0x00, 0x34];
        let rbsp = ebsp_to_rbsp(&ebsp);
        assert_eq!(rbsp, [0x12, 0x00, 0x00, 0x00, 0x34]);
    }

    #[test]
    fn ebsp_to_rbsp_leaves_03_without_prefix_alone() {
        // 0x03 not preceded by 0x00 0x00 is kept verbatim.
        let ebsp = [0x12, 0x03, 0x34, 0x00, 0x03, 0x56];
        let rbsp = ebsp_to_rbsp(&ebsp);
        assert_eq!(rbsp, ebsp);
    }

    #[test]
    fn parse_nal_header_vps_layer0_tid0() {
        // VPS_NUT=14, layer_id=0, temporal_id_plus1=1.
        // byte 0: 0_0_000000 = 0x00
        // byte 1: 01110_001  = 0x71
        let body = [0x00, 0x71, 0xff];
        let h = parse_nal_header(&body).unwrap();
        assert_eq!(h.forbidden_zero_bit, 0);
        assert_eq!(h.nuh_reserved_zero_bit, 0);
        assert_eq!(h.nuh_layer_id, 0);
        assert_eq!(h.nal_unit_type, NAL_TYPE_VPS);
        assert_eq!(h.nuh_temporal_id_plus1, 1);
        assert_eq!(h.temporal_id(), 0);
    }

    #[test]
    fn parse_nal_header_idr_layer0_tid0() {
        // IDR_W_RADL=7, layer_id=0, temporal_id_plus1=1.
        // byte 0: 0_0_000000 = 0x00
        // byte 1: 00111_001  = 0x39
        let body = [0x00, 0x39, 0x00];
        let h = parse_nal_header(&body).unwrap();
        assert_eq!(h.nal_unit_type, NAL_TYPE_IDR_W_RADL);
        assert_eq!(h.nuh_layer_id, 0);
        assert_eq!(h.temporal_id(), 0);
        assert!(is_irap(h.nal_unit_type));
        assert!(is_vcl(h.nal_unit_type));
        assert!(!is_parameter_set(h.nal_unit_type));
    }

    #[test]
    fn parse_nal_header_layer_id_max() {
        // layer_id=63 (all six bits set), nal_unit_type=PPS_NUT=16,
        // temporal_id_plus1=7.
        // byte 0: 0_0_111111 = 0x3f
        // byte 1: 10000_111  = 0x87
        let body = [0x3f, 0x87];
        let h = parse_nal_header(&body).unwrap();
        assert_eq!(h.nuh_layer_id, 63);
        assert_eq!(h.nal_unit_type, NAL_TYPE_PPS);
        assert_eq!(h.nuh_temporal_id_plus1, 7);
        assert_eq!(h.temporal_id(), 6);
        assert!(is_parameter_set(h.nal_unit_type));
        assert!(!is_vcl(h.nal_unit_type));
        assert!(!is_irap(h.nal_unit_type));
    }

    #[test]
    fn parse_nal_header_truncated() {
        assert!(matches!(
            parse_nal_header(&[]),
            Err(BitstreamError::UnexpectedEnd(_))
        ));
        assert!(matches!(
            parse_nal_header(&[0x00]),
            Err(BitstreamError::UnexpectedEnd(_))
        ));
    }

    #[test]
    fn is_vcl_classifies_table5_correctly() {
        for t in 0u8..=11 {
            assert!(is_vcl(t), "{t} should be VCL");
        }
        for t in 12u8..=27 {
            assert!(!is_vcl(t), "{t} should be non-VCL");
        }
    }

    #[test]
    fn is_irap_only_idr_and_cra() {
        assert!(is_irap(NAL_TYPE_IDR_W_RADL));
        assert!(is_irap(NAL_TYPE_IDR_N_LP));
        assert!(is_irap(NAL_TYPE_CRA));
        // Trailing / leading / GDR / reserved are not IRAP.
        for t in [
            NAL_TYPE_TRAIL,
            NAL_TYPE_STSA,
            NAL_TYPE_RADL,
            NAL_TYPE_RASL,
            NAL_TYPE_GDR,
            NAL_TYPE_RSV_IRAP_11,
            NAL_TYPE_VPS,
            NAL_TYPE_SPS,
            NAL_TYPE_PPS,
            NAL_TYPE_PH,
            NAL_TYPE_AUD,
        ] {
            assert!(!is_irap(t), "{t} should not be IRAP");
        }
    }

    /// Build an Annex-B-style PPS NAL: 2-byte `nal_unit_header()`
    /// (PPS, layer 0, temporal_id 0) followed by `rbsp`.
    fn build_pps_nal(rbsp: &[u8]) -> Vec<u8> {
        let hdr_b0: u8 = 0; // forbidden=0, reserved=0, layer_id=0
        let hdr_b1: u8 = (NAL_TYPE_PPS << 3) | 1; // tid_plus1 = 1
        let mut out = Vec::with_capacity(2 + rbsp.len());
        out.push(hdr_b0);
        out.push(hdr_b1);
        out.extend_from_slice(rbsp);
        out
    }

    #[test]
    fn parse_pps_minimal_64x32_no_windows() {
        // Bit layout (40 bits + 1-bit stop + 7 zeros = 6 bytes):
        //   pps_pic_parameter_set_id      = 0       u(6)  = 000000
        //   pps_seq_parameter_set_id      = 0       u(4)  = 0000
        //   pps_mixed_nalu_types_in_pic_flag = 0    u(1)  = 0
        //   pps_pic_width_in_luma_samples    = 64   ue(v) = 0000001000001  (13b)
        //   pps_pic_height_in_luma_samples   = 32   ue(v) = 00000100001    (11b)
        //   pps_conformance_window_flag      = 0    u(1)  = 0
        //   pps_scaling_window_explicit_..  = 0    u(1)  = 0
        //   pps_output_flag_present_flag    = 1    u(1)  = 1
        //   pps_no_pic_partition_flag       = 1    u(1)  = 1
        //   pps_subpic_id_mapping_present   = 0    u(1)  = 0
        //   rbsp_trailing_bits()                          = 1 + 7×0
        let rbsp = [0x00, 0x00, 0x41, 0x04, 0x26, 0x80];
        let nal = build_pps_nal(&rbsp);
        let pps = parse_pps(&nal).expect("minimal PPS should parse");
        assert_eq!(pps.pps_pic_parameter_set_id, 0);
        assert_eq!(pps.pps_seq_parameter_set_id, 0);
        assert_eq!(pps.pps_mixed_nalu_types_in_pic_flag, 0);
        assert_eq!(pps.pps_pic_width_in_luma_samples, 64);
        assert_eq!(pps.pps_pic_height_in_luma_samples, 32);
        assert_eq!(pps.pps_conformance_window_flag, 0);
        assert!(pps.pps_conf_win_offsets.is_none());
        assert_eq!(pps.pps_scaling_window_explicit_signalling_flag, 0);
        assert!(pps.pps_scaling_win_offsets.is_none());
        assert_eq!(pps.pps_output_flag_present_flag, 1);
        assert_eq!(pps.pps_no_pic_partition_flag, 1);
        assert_eq!(pps.pps_subpic_id_mapping_present_flag, 0);
    }

    #[test]
    fn parse_pps_1920x1080_with_conf_and_scaling_windows_zero_offsets() {
        // Bit layout (66 bits + 1-bit stop + 5 zeros = 9 bytes):
        //   pps_pic_parameter_set_id  = 2      u(6)  = 000010
        //   pps_seq_parameter_set_id  = 3      u(4)  = 0011
        //   pps_mixed_nalu_types_in_pic_flag = 0  u(1) = 0
        //   pps_pic_width_in_luma_samples    = 1920 ue(v) (21b)
        //   pps_pic_height_in_luma_samples   = 1080 ue(v) (21b)
        //   pps_conformance_window_flag      = 1    u(1)  = 1
        //   4× pps_conf_win_*_offset = 0           ue(v) = '1' each
        //   pps_scaling_window_explicit_..   = 1    u(1)  = 1
        //   4× pps_scaling_win_*_offset = 0        se(v) = '1' each
        //   pps_output_flag_present_flag    = 1     u(1)  = 1
        //   pps_no_pic_partition_flag       = 1     u(1)  = 1
        //   pps_subpic_id_mapping_present   = 0     u(1)  = 0
        let rbsp = [0x08, 0xc0, 0x07, 0x81, 0x00, 0x21, 0xcf, 0xff, 0xa0];
        let nal = build_pps_nal(&rbsp);
        let pps = parse_pps(&nal).expect("1920x1080 PPS should parse");
        assert_eq!(pps.pps_pic_parameter_set_id, 2);
        assert_eq!(pps.pps_seq_parameter_set_id, 3);
        assert_eq!(pps.pps_mixed_nalu_types_in_pic_flag, 0);
        assert_eq!(pps.pps_pic_width_in_luma_samples, 1920);
        assert_eq!(pps.pps_pic_height_in_luma_samples, 1080);
        assert_eq!(pps.pps_conformance_window_flag, 1);
        assert_eq!(pps.pps_conf_win_offsets, Some((0, 0, 0, 0)));
        assert_eq!(pps.pps_scaling_window_explicit_signalling_flag, 1);
        assert_eq!(pps.pps_scaling_win_offsets, Some((0, 0, 0, 0)));
        assert_eq!(pps.pps_output_flag_present_flag, 1);
        assert_eq!(pps.pps_no_pic_partition_flag, 1);
        assert_eq!(pps.pps_subpic_id_mapping_present_flag, 0);
    }

    #[test]
    fn parse_pps_320x240_with_signed_scaling_offsets() {
        // 320×240, no conformance window, scaling window with signed
        // offsets (1, -2, 3, -4), subpic_id_mapping flipped on (the
        // mapping body itself is not parsed in this round so the flag
        // is the only thing the parser cares about).
        //
        // Bit layout (68 bits + 1-bit stop + 3 zeros = 9 bytes):
        //   pps_pic_parameter_set_id  = 1      u(6)  = 000001
        //   pps_seq_parameter_set_id  = 2      u(4)  = 0010
        //   pps_mixed_nalu_types_in_pic_flag = 0  u(1) = 0
        //   width  = 320 ue(v) (17b: 0^8 + 101000001)
        //   height = 240 ue(v) (15b: 0^7 + 11110001)
        //   pps_conformance_window_flag      = 0    u(1)  = 0
        //   pps_scaling_window_explicit_..   = 1    u(1)  = 1
        //     se(1)  = ue code 1 = '010' (3b)
        //     se(-2) = ue code 4 = '00101' (5b)
        //     se(3)  = ue code 5 = '00110' (5b)
        //     se(-4) = ue code 8 = '0001001' (7b)
        //   pps_output_flag_present_flag    = 0     u(1)
        //   pps_no_pic_partition_flag       = 0     u(1)
        //   pps_subpic_id_mapping_present   = 1     u(1)
        let rbsp = [0x04, 0x80, 0x14, 0x10, 0x1e, 0x2a, 0x29, 0x84, 0x98];
        let nal = build_pps_nal(&rbsp);
        let pps = parse_pps(&nal).expect("scaling-window PPS should parse");
        assert_eq!(pps.pps_pic_parameter_set_id, 1);
        assert_eq!(pps.pps_seq_parameter_set_id, 2);
        assert_eq!(pps.pps_pic_width_in_luma_samples, 320);
        assert_eq!(pps.pps_pic_height_in_luma_samples, 240);
        assert_eq!(pps.pps_conformance_window_flag, 0);
        assert!(pps.pps_conf_win_offsets.is_none());
        assert_eq!(pps.pps_scaling_window_explicit_signalling_flag, 1);
        assert_eq!(pps.pps_scaling_win_offsets, Some((1, -2, 3, -4)));
        assert_eq!(pps.pps_output_flag_present_flag, 0);
        assert_eq!(pps.pps_no_pic_partition_flag, 0);
        assert_eq!(pps.pps_subpic_id_mapping_present_flag, 1);
    }

    #[test]
    fn parse_pps_rejects_wrong_nal_type() {
        // Build an SPS NAL header instead of PPS.
        let mut nal = vec![0u8; 4];
        nal[0] = 0;
        nal[1] = (NAL_TYPE_SPS << 3) | 1;
        let err = parse_pps(&nal).expect_err("SPS NAL must be rejected");
        assert!(matches!(err, BitstreamError::InvalidData(_)));
    }

    #[test]
    fn parse_pps_rejects_truncated() {
        let err = parse_pps(&[0x00]).expect_err("1-byte input must error");
        assert!(matches!(err, BitstreamError::UnexpectedEnd(_)));
    }

    #[test]
    fn is_parameter_set_covers_vps_sps_pps_aps_dci_opi() {
        for t in [
            NAL_TYPE_VPS,
            NAL_TYPE_SPS,
            NAL_TYPE_PPS,
            NAL_TYPE_PREFIX_APS,
            NAL_TYPE_SUFFIX_APS,
            NAL_TYPE_DCI,
            NAL_TYPE_OPI,
        ] {
            assert!(is_parameter_set(t), "{t} should be a parameter set");
        }
        for t in [
            NAL_TYPE_TRAIL,
            NAL_TYPE_IDR_W_RADL,
            NAL_TYPE_CRA,
            NAL_TYPE_GDR,
            NAL_TYPE_PH,
            NAL_TYPE_AUD,
            NAL_TYPE_EOS,
            NAL_TYPE_EOB,
            NAL_TYPE_PREFIX_SEI,
            NAL_TYPE_SUFFIX_SEI,
            NAL_TYPE_FD,
        ] {
            assert!(!is_parameter_set(t), "{t} should not be a parameter set");
        }
    }

    /// Build an Annex-B-style VPS NAL: 2-byte `nal_unit_header()`
    /// (VPS, layer 0, temporal_id 0) followed by `rbsp`.
    fn build_vps_nal(rbsp: &[u8]) -> Vec<u8> {
        let hdr_b0: u8 = 0; // forbidden=0, reserved=0, layer_id=0
        let hdr_b1: u8 = (NAL_TYPE_VPS << 3) | 1; // tid_plus1 = 1
        let mut out = Vec::with_capacity(2 + rbsp.len());
        out.push(hdr_b0);
        out.push(hdr_b1);
        out.extend_from_slice(rbsp);
        out
    }

    #[test]
    fn parse_vps_minimal_single_layer() {
        // Bit layout (19 bits total, packed MSB-first):
        //   vps_video_parameter_set_id = 1     u(4) = 0001
        //   vps_max_layers_minus1      = 0     u(6) = 000000
        //   vps_max_sublayers_minus1   = 0     u(3) = 000
        //   vps_layer_id[0]            = 0     u(6) = 000000
        // Byte 0 = 0001 0000 = 0x10
        // Byte 1 = 0000 0000 = 0x00
        // Byte 2 = 000_ ____ = 0x00
        let rbsp = [0x10, 0x00, 0x00];
        let nal = build_vps_nal(&rbsp);
        let vps = parse_vps(&nal).expect("minimal single-layer VPS should parse");
        assert_eq!(vps.vps_video_parameter_set_id, 1);
        assert_eq!(vps.vps_max_layers_minus1, 0);
        assert_eq!(vps.vps_max_sublayers_minus1, 0);
        assert_eq!(vps.vps_layer_id, vec![0]);
    }

    #[test]
    fn parse_vps_single_layer_with_sublayers_and_nonzero_layer_id() {
        // Bit layout (19 bits total, packed MSB-first):
        //   vps_video_parameter_set_id = 2     u(4) = 0010
        //   vps_max_layers_minus1      = 0     u(6) = 000000
        //   vps_max_sublayers_minus1   = 5     u(3) = 101
        //   vps_layer_id[0]            = 7     u(6) = 000111
        // Byte 0 = 0010 0000 = 0x20
        // Byte 1 = 0010 1000 = 0x28
        // Byte 2 = 1110 0000 = 0xE0
        let rbsp = [0x20, 0x28, 0xE0];
        let nal = build_vps_nal(&rbsp);
        let vps = parse_vps(&nal).expect("VPS should parse");
        assert_eq!(vps.vps_video_parameter_set_id, 2);
        assert_eq!(vps.vps_max_layers_minus1, 0);
        assert_eq!(vps.vps_max_sublayers_minus1, 5);
        assert_eq!(vps.vps_layer_id, vec![7]);
    }

    #[test]
    fn parse_vps_rejects_multi_layer_for_now() {
        // vps_id = 0 (u(4) = 0000), vps_max_layers_minus1 = 1
        // (u(6) = 000001), vps_max_sublayers_minus1 = 0 (u(3) = 000).
        // Byte 0 = 0000 0000 = 0x00
        // Byte 1 = 0100 0000 = 0x40
        let rbsp = [0x00, 0x40];
        let nal = build_vps_nal(&rbsp);
        let err = parse_vps(&nal).expect_err("vps_max_layers_minus1 > 0 should be unsupported");
        assert!(matches!(err, BitstreamError::Unsupported(_)));
    }

    #[test]
    fn parse_vps_rejects_out_of_range_sublayers() {
        // vps_id = 0, vps_max_layers_minus1 = 0, vps_max_sublayers_minus1
        // = 7 (out of spec range 0..=6).
        // Byte 0 = 0000 0000 = 0x00
        // Byte 1 = 0011 1000 = 0x38
        let rbsp = [0x00, 0x38];
        let nal = build_vps_nal(&rbsp);
        let err = parse_vps(&nal).expect_err("vps_max_sublayers_minus1 = 7 is illegal");
        assert!(matches!(err, BitstreamError::InvalidData(_)));
    }

    #[test]
    fn parse_vps_rejects_wrong_nal_type() {
        // SPS NAL header (type 15) instead of VPS (14).
        let mut nal = vec![0u8; 4];
        nal[0] = 0;
        nal[1] = (NAL_TYPE_SPS << 3) | 1;
        let err = parse_vps(&nal).expect_err("SPS NAL must be rejected by parse_vps");
        assert!(matches!(err, BitstreamError::InvalidData(_)));
    }

    #[test]
    fn parse_vps_rejects_truncated() {
        let err = parse_vps(&[0x00]).expect_err("1-byte input must error");
        assert!(matches!(err, BitstreamError::UnexpectedEnd(_)));
    }

    #[test]
    fn parse_vps_via_bit_writer_round_trip() {
        // Independent fixture construction: build the same VPS RBSP via
        // `BitWriter` and confirm the parser recovers the same field
        // values as the hand-laid-out byte literal in
        // `parse_vps_single_layer_with_sublayers_and_nonzero_layer_id`.
        use crate::bit_writer::BitWriter;
        let mut w = BitWriter::new();
        w.write_bits(2, 4); // vps_video_parameter_set_id
        w.write_bits(0, 6); // vps_max_layers_minus1
        w.write_bits(5, 3); // vps_max_sublayers_minus1
        w.write_bits(7, 6); // vps_layer_id[0]
        let rbsp = w.finish();
        // 19 bits -> 3 bytes (last 5 bits zero-padded by the writer).
        assert_eq!(rbsp.len(), 3);
        let nal = build_vps_nal(&rbsp);
        let vps = parse_vps(&nal).expect("VPS round-trips through BitWriter");
        assert_eq!(vps.vps_video_parameter_set_id, 2);
        assert_eq!(vps.vps_max_sublayers_minus1, 5);
        assert_eq!(vps.vps_layer_id, vec![7]);
    }

    // ── picture-header structural-prefix tests ──────────────────────────────

    /// Build an Annex-B-style PH NAL: 2-byte `nal_unit_header()` (PH,
    /// layer 0, temporal_id 0) followed by `rbsp`.
    fn build_ph_nal(rbsp: &[u8]) -> Vec<u8> {
        let hdr_b0: u8 = 0; // forbidden=0, reserved=0, layer_id=0
        let hdr_b1: u8 = (NAL_TYPE_PH << 3) | 1; // tid_plus1 = 1
        let mut out = Vec::with_capacity(2 + rbsp.len());
        out.push(hdr_b0);
        out.push(hdr_b1);
        out.extend_from_slice(rbsp);
        out
    }

    /// Build a PH structural-prefix RBSP via `BitWriter` matching the
    /// `(gdr_or_irap, non_ref, gdr_pic, inter_allowed, intra_allowed,
    /// pps_id)` tuple. `gdr_pic` is honoured iff `gdr_or_irap = 1`;
    /// `intra_allowed` is honoured iff `inter_allowed = 1`.
    fn build_ph_rbsp(
        gdr_or_irap: u8,
        non_ref: u8,
        gdr_pic: u8,
        inter_allowed: u8,
        intra_allowed: u8,
        pps_id: u32,
    ) -> Vec<u8> {
        use crate::bit_writer::BitWriter;
        let mut w = BitWriter::new();
        w.write_bits(gdr_or_irap as u32, 1);
        w.write_bits(non_ref as u32, 1);
        if gdr_or_irap != 0 {
            w.write_bits(gdr_pic as u32, 1);
        }
        w.write_bits(inter_allowed as u32, 1);
        if inter_allowed != 0 {
            w.write_bits(intra_allowed as u32, 1);
        }
        w.write_ue(pps_id).expect("pps_id within ue range");
        w.finish()
    }

    #[test]
    fn parse_picture_header_irap_inter_allowed_pps0() {
        // gdr_or_irap=1 (IRAP), non_ref=0, gdr_pic=0 (IRAP not GDR),
        // inter_allowed=1, intra_allowed=1, ph_pic_parameter_set_id=0.
        // ue(0) is the single bit '1'.
        let rbsp = build_ph_rbsp(1, 0, 0, 1, 1, 0);
        let nal = build_ph_nal(&rbsp);
        let ph = parse_picture_header(&nal).expect("PH parses");
        assert_eq!(ph.ph_gdr_or_irap_pic_flag, 1);
        assert_eq!(ph.ph_non_ref_pic_flag, 0);
        assert_eq!(ph.ph_gdr_pic_flag, Some(0));
        assert_eq!(ph.ph_inter_slice_allowed_flag, 1);
        assert_eq!(ph.ph_intra_slice_allowed_flag, Some(1));
        assert_eq!(ph.ph_pic_parameter_set_id, 0);
        assert!(ph.is_irap());
        assert!(!ph.is_gdr());
        assert_eq!(ph.intra_slice_allowed(), 1);
    }

    #[test]
    fn parse_picture_header_gdr_non_ref_pps5() {
        // gdr_or_irap=1, non_ref=1, gdr_pic=1 (GDR), inter_allowed=1,
        // intra_allowed=1, pps_id=5 (ue('00110')).
        let rbsp = build_ph_rbsp(1, 1, 1, 1, 1, 5);
        let nal = build_ph_nal(&rbsp);
        let ph = parse_picture_header(&nal).expect("PH parses");
        assert_eq!(ph.ph_gdr_or_irap_pic_flag, 1);
        assert_eq!(ph.ph_non_ref_pic_flag, 1);
        assert_eq!(ph.ph_gdr_pic_flag, Some(1));
        assert_eq!(ph.ph_pic_parameter_set_id, 5);
        assert!(!ph.is_irap());
        assert!(ph.is_gdr());
    }

    #[test]
    fn parse_picture_header_non_irap_no_gdr_field() {
        // gdr_or_irap=0 → ph_gdr_pic_flag is absent. inter_allowed=1,
        // intra_allowed=0 (inter-only picture), pps_id=1.
        let rbsp = build_ph_rbsp(0, 0, /*ignored*/ 0, 1, 0, 1);
        let nal = build_ph_nal(&rbsp);
        let ph = parse_picture_header(&nal).expect("PH parses");
        assert_eq!(ph.ph_gdr_or_irap_pic_flag, 0);
        assert_eq!(ph.ph_gdr_pic_flag, None);
        assert_eq!(ph.ph_inter_slice_allowed_flag, 1);
        assert_eq!(ph.ph_intra_slice_allowed_flag, Some(0));
        assert_eq!(ph.ph_pic_parameter_set_id, 1);
        assert!(!ph.is_irap());
        assert!(!ph.is_gdr());
        assert_eq!(ph.intra_slice_allowed(), 0);
    }

    #[test]
    fn parse_picture_header_inter_disabled_intra_inferred() {
        // gdr_or_irap=0, non_ref=0, inter_allowed=0
        // → ph_intra_slice_allowed_flag is absent (intra inferred = 1),
        // pps_id=63 (the largest legal value).
        let rbsp = build_ph_rbsp(0, 0, /*ignored*/ 0, 0, /*ignored*/ 0, 63);
        let nal = build_ph_nal(&rbsp);
        let ph = parse_picture_header(&nal).expect("PH parses");
        assert_eq!(ph.ph_inter_slice_allowed_flag, 0);
        assert_eq!(ph.ph_intra_slice_allowed_flag, None);
        assert_eq!(ph.ph_pic_parameter_set_id, 63);
        assert_eq!(ph.intra_slice_allowed(), 1);
    }

    #[test]
    fn parse_picture_header_rejects_wrong_nal_type() {
        // Build an SPS NAL header followed by valid-looking PH bits;
        // the parser must refuse on NAL-type mismatch.
        let mut nal = vec![0u8; 4];
        nal[0] = 0;
        nal[1] = (NAL_TYPE_SPS << 3) | 1;
        nal[2] = 0xff;
        nal[3] = 0xff;
        let err = parse_picture_header(&nal).expect_err("SPS NAL must be rejected");
        assert!(matches!(err, BitstreamError::InvalidData(_)));
    }

    #[test]
    fn parse_picture_header_rejects_truncated() {
        let err = parse_picture_header(&[0x00]).expect_err("1-byte input must error");
        assert!(matches!(err, BitstreamError::UnexpectedEnd(_)));
    }

    #[test]
    fn parse_picture_header_rejects_oversized_pps_id() {
        // Build a PH RBSP that encodes ph_pic_parameter_set_id = 64,
        // one past the spec-allowed maximum. ue(64) = 13 bits of code
        // word — well within a small RBSP.
        let rbsp = build_ph_rbsp(0, 0, /*ignored*/ 0, 0, /*ignored*/ 0, 64);
        let nal = build_ph_nal(&rbsp);
        let err = parse_picture_header(&nal)
            .expect_err("oversized ph_pic_parameter_set_id must be rejected");
        assert!(matches!(err, BitstreamError::InvalidData(_)));
    }

    #[test]
    fn parse_picture_header_handles_emulation_prevention_byte() {
        // Verify the PH parser routes its body through `ebsp_to_rbsp`
        // by giving it an EBSP that contains a `00 00 03 …` sequence
        // the spec mandates the encoder inserted. After stripping, the
        // bit reader sees the canonical RBSP and the parser must
        // recover the encoded fields identically.
        //
        // Canonical RBSP for (gdr_or_irap=0, non_ref=0, inter=0,
        // pps_id=0) is the single byte 0x10. Pad it with a 0x10 RBSP
        // tail containing a 0x00 0x00 0x00 run so the encoder would
        // have inserted an 0x03 emulation byte mid-stream. Pre-strip
        // RBSP we want the parser to see is `[0x10, 0x00, 0x00, 0x00]`.
        // EBSP form (with 0x03 inserted after the first 00 00 pair):
        //   `[0x10, 0x00, 0x00, 0x03, 0x00]` — `ebsp_to_rbsp` strips
        // the 0x03 back out. The first byte's high four bits drive the
        // whole prefix so the parse result is identical to the
        // no-emulation-byte case.
        let mut ebsp = Vec::new();
        ebsp.push(0u8); // NAL hdr byte 0
        ebsp.push((NAL_TYPE_PH << 3) | 1); // NAL hdr byte 1
        ebsp.extend_from_slice(&[0x10, 0x00, 0x00, 0x03, 0x00]);

        // First sanity-check the stripping itself produces the
        // expected canonical RBSP.
        assert_eq!(ebsp_to_rbsp(&ebsp[2..]), vec![0x10, 0x00, 0x00, 0x00]);

        let ph = parse_picture_header(&ebsp).expect("PH parses past emulation byte");
        assert_eq!(ph.ph_gdr_or_irap_pic_flag, 0);
        assert_eq!(ph.ph_non_ref_pic_flag, 0);
        assert_eq!(ph.ph_inter_slice_allowed_flag, 0);
        assert_eq!(ph.ph_intra_slice_allowed_flag, None);
        assert_eq!(ph.ph_pic_parameter_set_id, 0);
    }

    #[test]
    fn parse_picture_header_full_field_combinations() {
        // Sweep the 2x2x2 product of (gdr_or_irap, inter_allowed) and
        // (non_ref) flags. Where a child flag is gated on its parent we
        // also vary the child. This exercises every signalled/inferred
        // branch in the parser.
        for gdr_or_irap in 0u8..=1 {
            for non_ref in 0u8..=1 {
                for inter in 0u8..=1 {
                    let gdr_pics: &[u8] = if gdr_or_irap != 0 { &[0, 1] } else { &[0] };
                    let intras: &[u8] = if inter != 0 { &[0, 1] } else { &[0] };
                    for &gdr_pic in gdr_pics {
                        for &intra in intras {
                            let rbsp = build_ph_rbsp(
                                gdr_or_irap,
                                non_ref,
                                gdr_pic,
                                inter,
                                intra,
                                7, // mid-range pps_id
                            );
                            let nal = build_ph_nal(&rbsp);
                            let ph = parse_picture_header(&nal).unwrap_or_else(|e| {
                                panic!(
                                    "PH should parse for ({gdr_or_irap},{non_ref},{gdr_pic},{inter},{intra}): {e:?}"
                                )
                            });
                            assert_eq!(ph.ph_gdr_or_irap_pic_flag, gdr_or_irap);
                            assert_eq!(ph.ph_non_ref_pic_flag, non_ref);
                            assert_eq!(
                                ph.ph_gdr_pic_flag,
                                if gdr_or_irap != 0 {
                                    Some(gdr_pic)
                                } else {
                                    None
                                }
                            );
                            assert_eq!(ph.ph_inter_slice_allowed_flag, inter);
                            assert_eq!(
                                ph.ph_intra_slice_allowed_flag,
                                if inter != 0 { Some(intra) } else { None }
                            );
                            assert_eq!(ph.ph_pic_parameter_set_id, 7);
                            // is_irap / is_gdr are mutually exclusive.
                            assert!(!(ph.is_irap() && ph.is_gdr()));
                            // The context-free parser stops at
                            // `ph_pic_parameter_set_id` — both POC
                            // fields stay `None` regardless of which
                            // flag branch the picture took.
                            assert!(ph.ph_pic_order_cnt_lsb.is_none());
                            assert!(ph.ph_recovery_poc_cnt.is_none());
                        }
                    }
                }
            }
        }
    }

    // ── picture-header SPS-context tests ─────────────────────────────────────

    /// Build a [`VvcSps`] stub carrying only the fields
    /// [`parse_picture_header_with_sps`] depends on
    /// (`sps_log2_max_pic_order_cnt_lsb_minus4`). Other fields are
    /// filled with arbitrary canonical values; the PH parser does not
    /// read them.
    fn sps_with_poc_width(log2_max_poc_lsb_minus4: u8) -> VvcSps {
        VvcSps {
            sps_chroma_format_idc: 1,
            sps_log2_ctu_size_minus5: 2,
            sps_pic_width_max_in_luma_samples: 1920,
            sps_pic_height_max_in_luma_samples: 1080,
            sps_bitdepth_minus8: 2,
            sps_log2_max_pic_order_cnt_lsb_minus4: log2_max_poc_lsb_minus4,
            ..Default::default()
        }
    }

    /// Build a PH RBSP that carries the structural prefix
    /// (`gdr_or_irap`, `non_ref`, `gdr_pic`, `inter_allowed`,
    /// `intra_allowed`, `pps_id`) plus a POC LSB field
    /// (`poc_lsb_value` `poc_lsb_width` bits wide) and — when
    /// `gdr_pic = 1` — a `recovery_poc_cnt` ue(v).
    #[allow(clippy::too_many_arguments)]
    fn build_ph_rbsp_with_poc(
        gdr_or_irap: u8,
        non_ref: u8,
        gdr_pic: u8,
        inter_allowed: u8,
        intra_allowed: u8,
        pps_id: u32,
        poc_lsb_value: u32,
        poc_lsb_width: u32,
        recovery_poc_cnt: Option<u32>,
    ) -> Vec<u8> {
        use crate::bit_writer::BitWriter;
        let mut w = BitWriter::new();
        w.write_bits(gdr_or_irap as u32, 1);
        w.write_bits(non_ref as u32, 1);
        if gdr_or_irap != 0 {
            w.write_bits(gdr_pic as u32, 1);
        }
        w.write_bits(inter_allowed as u32, 1);
        if inter_allowed != 0 {
            w.write_bits(intra_allowed as u32, 1);
        }
        w.write_ue(pps_id).expect("pps_id within ue range");
        w.write_bits(poc_lsb_value, poc_lsb_width);
        if let Some(rpc) = recovery_poc_cnt {
            w.write_ue(rpc).expect("recovery_poc_cnt within ue range");
        }
        w.finish()
    }

    #[test]
    fn parse_picture_header_with_sps_irap_4bit_poc() {
        // sps_log2_max_pic_order_cnt_lsb_minus4 = 0 → POC LSB is u(4).
        // gdr_or_irap=1, non_ref=0, gdr_pic=0 (IRAP), inter=1, intra=1,
        // pps_id=0, poc_lsb=5 — the smallest non-canonical value to
        // verify we're actually reading the field rather than zero-
        // padding.
        let sps = sps_with_poc_width(0);
        let rbsp = build_ph_rbsp_with_poc(1, 0, 0, 1, 1, 0, 5, sps.poc_lsb_width(), None);
        let nal = build_ph_nal(&rbsp);
        let ph = parse_picture_header_with_sps(&nal, &sps).expect("PH parses with SPS ctx");
        assert_eq!(ph.ph_gdr_or_irap_pic_flag, 1);
        assert_eq!(ph.ph_non_ref_pic_flag, 0);
        assert_eq!(ph.ph_gdr_pic_flag, Some(0));
        assert_eq!(ph.ph_inter_slice_allowed_flag, 1);
        assert_eq!(ph.ph_intra_slice_allowed_flag, Some(1));
        assert_eq!(ph.ph_pic_parameter_set_id, 0);
        assert_eq!(ph.ph_pic_order_cnt_lsb, Some(5));
        // ph_gdr_pic_flag = 0 → ph_recovery_poc_cnt is absent.
        assert_eq!(ph.ph_recovery_poc_cnt, None);
        assert!(ph.is_irap());
    }

    #[test]
    fn parse_picture_header_with_sps_gdr_carries_recovery_poc() {
        // sps_log2_max_pic_order_cnt_lsb_minus4 = 4 → POC LSB is u(8).
        // gdr_or_irap=1, gdr_pic=1 → GDR picture → ph_recovery_poc_cnt
        // is present (= 7 here, ue(v) code '0001000' = 7 bits).
        let sps = sps_with_poc_width(4);
        let rbsp = build_ph_rbsp_with_poc(1, 1, 1, 1, 1, 5, 0x7f, sps.poc_lsb_width(), Some(7));
        let nal = build_ph_nal(&rbsp);
        let ph = parse_picture_header_with_sps(&nal, &sps).expect("GDR PH parses with SPS ctx");
        assert_eq!(ph.ph_gdr_pic_flag, Some(1));
        assert_eq!(ph.ph_pic_parameter_set_id, 5);
        assert_eq!(ph.ph_pic_order_cnt_lsb, Some(0x7f));
        assert_eq!(ph.ph_recovery_poc_cnt, Some(7));
        assert!(!ph.is_irap());
        assert!(ph.is_gdr());
    }

    #[test]
    fn parse_picture_header_with_sps_non_irap_inferred_intra_no_recovery() {
        // gdr_or_irap=0 → ph_gdr_pic_flag absent → ph_recovery_poc_cnt
        // absent. inter_allowed=0 → ph_intra_slice_allowed_flag is
        // inferred (1). Verify the inferred-intra branch is preserved
        // when the SPS-context parser threads the POC field.
        let sps = sps_with_poc_width(0);
        let rbsp = build_ph_rbsp_with_poc(0, 0, 0, 0, 0, 1, 0xa, sps.poc_lsb_width(), None);
        let nal = build_ph_nal(&rbsp);
        let ph = parse_picture_header_with_sps(&nal, &sps).expect("non-IRAP PH parses");
        assert_eq!(ph.ph_gdr_or_irap_pic_flag, 0);
        assert_eq!(ph.ph_gdr_pic_flag, None);
        assert_eq!(ph.ph_inter_slice_allowed_flag, 0);
        assert_eq!(ph.ph_intra_slice_allowed_flag, None);
        assert_eq!(ph.intra_slice_allowed(), 1);
        assert_eq!(ph.ph_pic_parameter_set_id, 1);
        assert_eq!(ph.ph_pic_order_cnt_lsb, Some(0xa));
        assert_eq!(ph.ph_recovery_poc_cnt, None);
    }

    #[test]
    fn parse_picture_header_with_sps_max_width_16bit_poc() {
        // sps_log2_max_pic_order_cnt_lsb_minus4 = 12 (the spec maximum)
        // → POC LSB is u(16). Round-trip the largest legal POC LSB
        // value (0xffff) to confirm the parser handles the full 16-bit
        // envelope without truncation.
        let sps = sps_with_poc_width(SPS_LOG2_MAX_PIC_ORDER_CNT_LSB_MINUS4_MAX);
        assert_eq!(sps.poc_lsb_width(), 16);
        let rbsp = build_ph_rbsp_with_poc(0, 0, 0, 1, 0, 0, 0xffff, sps.poc_lsb_width(), None);
        let nal = build_ph_nal(&rbsp);
        let ph = parse_picture_header_with_sps(&nal, &sps).expect("16-bit POC PH parses");
        assert_eq!(ph.ph_pic_order_cnt_lsb, Some(0xffff));
        assert_eq!(ph.ph_recovery_poc_cnt, None);
    }

    #[test]
    fn parse_picture_header_with_sps_rejects_wrong_nal_type() {
        let sps = sps_with_poc_width(0);
        let mut nal = vec![0u8; 4];
        nal[0] = 0;
        nal[1] = (NAL_TYPE_SPS << 3) | 1;
        nal[2] = 0xff;
        nal[3] = 0xff;
        let err = parse_picture_header_with_sps(&nal, &sps)
            .expect_err("SPS NAL must be rejected by parse_picture_header_with_sps");
        assert!(matches!(err, BitstreamError::InvalidData(_)));
    }

    #[test]
    fn parse_picture_header_with_sps_rejects_truncated() {
        let sps = sps_with_poc_width(0);
        let err =
            parse_picture_header_with_sps(&[0x00], &sps).expect_err("1-byte input must error");
        assert!(matches!(err, BitstreamError::UnexpectedEnd(_)));
    }

    #[test]
    fn parse_picture_header_with_sps_rejects_oversized_pps_id() {
        // SPS-context parser must enforce the same
        // `ph_pic_parameter_set_id ≤ 63` envelope the context-free
        // variant does.
        let sps = sps_with_poc_width(0);
        let rbsp = build_ph_rbsp_with_poc(0, 0, 0, 0, 0, 64, 0, sps.poc_lsb_width(), None);
        let nal = build_ph_nal(&rbsp);
        let err = parse_picture_header_with_sps(&nal, &sps)
            .expect_err("oversized ph_pic_parameter_set_id must be rejected");
        assert!(matches!(err, BitstreamError::InvalidData(_)));
    }

    #[test]
    fn aud_write_then_parse_roundtrips_every_combo() {
        for irap in 0u8..=1 {
            for pt in 0u8..=AUD_PIC_TYPE_MAX {
                let in_ = VvcAccessUnitDelimiter {
                    aud_irap_or_gdr_flag: irap,
                    aud_pic_type: pt,
                };
                let bytes = write_aud(&in_).expect("AUD writes");
                let parsed = parse_aud(&bytes).expect("AUD parses");
                assert_eq!(parsed, in_, "round-trip irap={irap} pic_type={pt}");
            }
        }
    }

    #[test]
    fn aud_writer_canonical_layer0_tid0() {
        // header: 0x00 0xA1 (type=20 << 3 | tid_plus1=1).
        // RBSP: irap=0 (1b) + pic_type=0 (3b) + stop-one (1b) + 3
        // alignment zeros = 0b0000_1000 = 0x08.
        let bytes = write_aud(&VvcAccessUnitDelimiter {
            aud_irap_or_gdr_flag: 0,
            aud_pic_type: 0,
        })
        .unwrap();
        assert_eq!(bytes, vec![0x00, 0xA1, 0x08]);
    }

    #[test]
    fn aud_writer_irap_pic_type_2_canonical_bytes() {
        // irap=1 (1b) + pic_type=2 (010) + stop-one (1b) + 3 zeros =
        // 0b1010_1000 = 0xA8.
        let bytes = write_aud(&VvcAccessUnitDelimiter {
            aud_irap_or_gdr_flag: 1,
            aud_pic_type: AUD_PIC_TYPE_B_P_OR_I,
        })
        .unwrap();
        assert_eq!(bytes, vec![0x00, 0xA1, 0xA8]);
    }

    #[test]
    fn aud_parser_accepts_reserved_pic_type() {
        // Spec mandates decoders accept reserved (3..=7) aud_pic_type
        // values; round-trip both ends to confirm the value surfaces
        // unchanged.
        for pt in 3u8..=7 {
            let bytes = write_aud(&VvcAccessUnitDelimiter {
                aud_irap_or_gdr_flag: 0,
                aud_pic_type: pt,
            })
            .unwrap();
            let parsed = parse_aud(&bytes).unwrap();
            assert_eq!(parsed.aud_pic_type, pt);
        }
    }

    #[test]
    fn aud_writer_rejects_out_of_range_fields() {
        assert!(matches!(
            write_aud(&VvcAccessUnitDelimiter {
                aud_irap_or_gdr_flag: 2,
                aud_pic_type: 0
            }),
            Err(BitstreamError::InvalidData(_))
        ));
        assert!(matches!(
            write_aud(&VvcAccessUnitDelimiter {
                aud_irap_or_gdr_flag: 0,
                aud_pic_type: 8
            }),
            Err(BitstreamError::InvalidData(_))
        ));
    }

    #[test]
    fn aud_parser_rejects_wrong_nal_type() {
        // SPS NAL header (type=15 -> (15<<3)|1 = 0x79).
        let nal = [0x00u8, 0x79, 0x10];
        let err = parse_aud(&nal).expect_err("wrong nal type rejected");
        assert!(matches!(err, BitstreamError::InvalidData(_)));
    }

    #[test]
    fn aud_parser_rejects_truncated_input() {
        let err = parse_aud(&[0x00u8]).expect_err("1-byte input rejected");
        assert!(matches!(err, BitstreamError::UnexpectedEnd(_)));
    }

    #[test]
    fn aud_parser_rejects_header_only_nal() {
        // header byte for AUD but no body.
        let err = parse_aud(&[0x00u8, 0xA1]).expect_err("header-only NAL rejected");
        assert!(matches!(err, BitstreamError::UnexpectedEnd(_)));
    }

    #[test]
    fn aud_parser_rejects_missing_stop_bit() {
        // Header + an all-zero body byte: reader finds no stop-one
        // bit during rbsp_trailing_bits.
        let nal = [0x00u8, 0xA1, 0x00];
        let err = parse_aud(&nal).expect_err("missing stop bit rejected");
        assert!(
            matches!(
                err,
                BitstreamError::InvalidData(_) | BitstreamError::UnexpectedEnd(_)
            ),
            "got: {err:?}"
        );
    }
}
