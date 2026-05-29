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
    if profile_tier_present_flag {
        // 7.3.3.2 — general_constraints_info(). The bridge does not
        // need the individual fields, but we must walk them so the
        // reader is positioned correctly to continue with the
        // per-sublayer level flags. The structure self-aligns to a
        // byte boundary at the end (final `gci_alignment_zero_bit`
        // while-loop), so it is safe to skip its raw bit content and
        // then `align_to_byte`.
        walk_general_constraints_info(r)?;
    }
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
    })
}

/// Walk 7.3.3.2 `general_constraints_info()` consuming bits until the
/// structure's terminating `gci_alignment_zero_bit` byte-aligns the
/// reader. Returns no data; the only caller is
/// `parse_profile_tier_level`.
fn walk_general_constraints_info(r: &mut BitReader<'_>) -> Result<(), BitstreamError> {
    let gci_present_flag = r.u(1);
    if gci_present_flag != 0 {
        // 71 single-bit / multi-bit fields up to and including
        // `gci_no_virtual_boundaries_constraint_flag`, then 8 bits of
        // `gci_num_additional_bits`. The exact bit-by-bit decoding is
        // not needed by the bridge, so we just count the bits and
        // skip them in one go.
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
        r.skip(69);
        let gci_num_additional_bits = r.u(8);
        let num_additional_bits_used = if gci_num_additional_bits > 5 {
            // 6 named "additional" bits.
            r.skip(6);
            6
        } else {
            0
        };
        // gci_reserved_bit[i] for the remainder.
        if gci_num_additional_bits > num_additional_bits_used {
            r.skip((gci_num_additional_bits - num_additional_bits_used) as usize);
        }
    }
    // Final while(!byte_aligned()) gci_alignment_zero_bit.
    r.align_to_byte();
    Ok(())
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

// ─────────────────────────── SPS RBSP (7.3.2.4) ─────────────────────────────

/// Decoded VVC SPS structural fields (7.3.2.4).
///
/// Carries the subset of SPS fields a HW-accel bridge needs to size
/// CTU and frame buffers before submission. Fields between the
/// surfaced ones (e.g. the GDR / ref-pic-resampling flags, the
/// conformance-window offsets) are walked but not stored — they don't
/// alter the buffer geometry the bridge cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VvcSps {
    /// `sps_seq_parameter_set_id` u(4) (7.4.3.4). 0..=15 selects which
    /// SPS in the active set this is.
    pub sps_seq_parameter_set_id: u8,
    /// `sps_video_parameter_set_id` u(4) (7.4.3.4). Identifies the
    /// referenced VPS, or 0 when no VPS is active.
    pub sps_video_parameter_set_id: u8,
    /// `sps_max_sublayers_minus1` u(3) (7.4.3.4). One less than the
    /// maximum number of temporal sublayers that may be present in
    /// each CLVS referring to the SPS.
    pub sps_max_sublayers_minus1: u8,
    /// `sps_chroma_format_idc` u(2) (7.4.3.4). 0 = 4:0:0, 1 = 4:2:0,
    /// 2 = 4:2:2, 3 = 4:4:4.
    pub sps_chroma_format_idc: u8,
    /// `sps_log2_ctu_size_minus5` u(2) (7.4.3.4). `CtbLog2SizeY =
    /// sps_log2_ctu_size_minus5 + 5`. The legal range covers
    /// 32 / 64 / 128 CTU sizes.
    pub sps_log2_ctu_size_minus5: u8,
    /// `sps_ptl_dpb_hrd_params_present_flag` u(1). When 1, the SPS
    /// also carries a `profile_tier_level()` structure (decoded into
    /// [`VvcSps::profile_tier_level`]).
    pub sps_ptl_dpb_hrd_params_present_flag: u8,
    /// `profile_tier_level()` (7.3.3.1). Present when
    /// `sps_ptl_dpb_hrd_params_present_flag = 1`, absent otherwise.
    pub profile_tier_level: Option<VvcProfileTierLevel>,
    /// `sps_pic_width_max_in_luma_samples` ue(v) (7.4.3.4).
    pub sps_pic_width_max_in_luma_samples: u32,
    /// `sps_pic_height_max_in_luma_samples` ue(v) (7.4.3.4).
    pub sps_pic_height_max_in_luma_samples: u32,
    /// `sps_subpic_info_present_flag` u(1) (7.4.3.4). When 1 the SPS
    /// carries a subpicture sub-structure that this round does not
    /// surface — the parser returns
    /// `BitstreamError::Unsupported(_)` in that case so callers can
    /// fall back to a software path.
    pub sps_subpic_info_present_flag: u8,
    /// `sps_bitdepth_minus8` ue(v) (7.4.3.4). Sample bit depth is
    /// `8 + sps_bitdepth_minus8`. Range 0..=8 per the spec
    /// (`BitDepth ≤ 16`).
    pub sps_bitdepth_minus8: u32,
}

impl VvcSps {
    /// `CtbLog2SizeY = sps_log2_ctu_size_minus5 + 5` (eq. (35) /
    /// 7.4.3.4). Convenience accessor.
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
}

/// Strip the two-byte NAL header from an SPS NAL body (the `0x0_F_..`
/// header bytes that [`parse_nal_header`] decodes), then parse the
/// SPS RBSP per 7.3.2.4.
///
/// The input slice MUST point at the start of the NAL body (i.e.
/// after [`split_annex_b`]). Emulation-prevention bytes are stripped
/// via [`ebsp_to_rbsp`] before bit-level parsing.
///
/// The current round surfaces the structural fields a HW bridge
/// needs to size buffers: SPS / VPS IDs, sublayer count, chroma
/// format, CTU log2 size, optional `profile_tier_level()`, max
/// luma width/height, subpicture-info presence flag and bit depth.
/// All other SPS bits are skipped but walked so the reader ends in
/// a well-defined state.
///
/// Returns [`BitstreamError::Unsupported`] when the SPS uses
/// subpicture signalling (`sps_subpic_info_present_flag = 1`); the
/// subpicture sub-structure is deferred to a later round.
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

    let sps_seq_parameter_set_id = r.u(4) as u8;
    let sps_video_parameter_set_id = r.u(4) as u8;
    let sps_max_sublayers_minus1 = r.u(3) as u8;
    let sps_chroma_format_idc = r.u(2) as u8;
    let sps_log2_ctu_size_minus5 = r.u(2) as u8;
    if sps_log2_ctu_size_minus5 > 2 {
        return Err(BitstreamError::invalid(format!(
            "sps_log2_ctu_size_minus5 = {sps_log2_ctu_size_minus5} > 2 (spec range 0..=2)"
        )));
    }
    let sps_ptl_dpb_hrd_params_present_flag = r.u(1) as u8;
    let profile_tier_level = if sps_ptl_dpb_hrd_params_present_flag != 0 {
        Some(parse_profile_tier_level(
            &mut r,
            true,
            sps_max_sublayers_minus1 as u32,
        )?)
    } else {
        None
    };
    // sps_gdr_enabled_flag u(1) + sps_ref_pic_resampling_enabled_flag u(1)
    // + optional sps_res_change_in_clvs_allowed_flag u(1).
    let _sps_gdr_enabled_flag = r.u(1);
    let sps_ref_pic_resampling_enabled_flag = r.u(1);
    if sps_ref_pic_resampling_enabled_flag != 0 {
        let _sps_res_change_in_clvs_allowed_flag = r.u(1);
    }
    let sps_pic_width_max_in_luma_samples = r.ue()?;
    let sps_pic_height_max_in_luma_samples = r.ue()?;
    let sps_conformance_window_flag = r.u(1);
    if sps_conformance_window_flag != 0 {
        // Four ue(v) offsets — walked, not stored.
        let _l = r.ue()?;
        let _rr = r.ue()?;
        let _t = r.ue()?;
        let _b = r.ue()?;
    }
    let sps_subpic_info_present_flag = r.u(1) as u8;
    if sps_subpic_info_present_flag != 0 {
        // Subpicture sub-structure is deferred — its u(v) fields
        // depend on derived CTU geometry and would require the full
        // subpic walk (7.3.2.4). Bridges that hit this fixture should
        // fall back to a software path.
        return Err(BitstreamError::unsupported(
            "VVC SPS with sps_subpic_info_present_flag = 1 (subpicture signalling) \
             not parsed in this round",
        ));
    }
    let sps_bitdepth_minus8 = r.ue()?;
    if sps_bitdepth_minus8 > 8 {
        return Err(BitstreamError::invalid(format!(
            "sps_bitdepth_minus8 = {sps_bitdepth_minus8} > 8 (BitDepth ≤ 16)"
        )));
    }

    Ok(VvcSps {
        sps_seq_parameter_set_id,
        sps_video_parameter_set_id,
        sps_max_sublayers_minus1,
        sps_chroma_format_idc,
        sps_log2_ctu_size_minus5,
        sps_ptl_dpb_hrd_params_present_flag,
        profile_tier_level,
        sps_pic_width_max_in_luma_samples,
        sps_pic_height_max_in_luma_samples,
        sps_subpic_info_present_flag,
        sps_bitdepth_minus8,
    })
}

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

// ─────────────────────────── Tests ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Build an Annex-B-style SPS NAL: 2-byte `nal_unit_header()`
    /// (SPS, layer 0, temporal_id 0) followed by `rbsp`.
    fn build_sps_nal(rbsp: &[u8]) -> Vec<u8> {
        let hdr_b0: u8 = 0; // forbidden=0, reserved=0, layer_id=0
        let hdr_b1: u8 = (NAL_TYPE_SPS << 3) | 1; // tid_plus1 = 1
        let mut out = Vec::with_capacity(2 + rbsp.len());
        out.push(hdr_b0);
        out.push(hdr_b1);
        out.extend_from_slice(rbsp);
        out
    }

    #[test]
    fn parse_sps_minimal_no_ptl_1080p_10bit() {
        // RBSP bytes generated from the bit layout documented in the
        // test source (sps_seq_parameter_set_id = 0, vps_id = 0,
        // sublayers - 1 = 0, chroma 4:2:0, log2_ctu - 5 = 2 → CtbSize
        // 128, ptl_dpb_present = 0, gdr = 0, ref_pic_resampling = 0,
        // 1920×1080, no conformance window, no subpic, bit-depth = 10).
        let rbsp = [0x00, 0x0c, 0x00, 0x0f, 0x02, 0x00, 0x43, 0x91, 0x80];
        let nal = build_sps_nal(&rbsp);
        let sps = parse_sps(&nal).expect("SPS should parse");
        assert_eq!(sps.sps_seq_parameter_set_id, 0);
        assert_eq!(sps.sps_video_parameter_set_id, 0);
        assert_eq!(sps.sps_max_sublayers_minus1, 0);
        assert_eq!(sps.sps_chroma_format_idc, 1);
        assert_eq!(sps.sps_log2_ctu_size_minus5, 2);
        assert_eq!(sps.ctb_log2_size_y(), 7);
        assert_eq!(sps.ctb_size_y(), 128);
        assert_eq!(sps.sps_ptl_dpb_hrd_params_present_flag, 0);
        assert!(sps.profile_tier_level.is_none());
        assert_eq!(sps.sps_pic_width_max_in_luma_samples, 1920);
        assert_eq!(sps.sps_pic_height_max_in_luma_samples, 1080);
        assert_eq!(sps.sps_subpic_info_present_flag, 0);
        assert_eq!(sps.sps_bitdepth_minus8, 2);
        assert_eq!(sps.bit_depth(), 10);
    }

    #[test]
    fn parse_sps_with_profile_tier_level_4k_main10() {
        // Carries a full profile_tier_level(1, 2): general_profile_idc
        // = 33 (Main 10), tier = 0, level_idc = 51 (5.1), frame_only =
        // 1, multilayer = 0, gci_present_flag = 0 (zero-filled GCI
        // alignment), ptl_sublayer_level_present_flag = [0 → i=0
        // absent, 1 → i=1 present], sublayer_level_idc[1] = 35,
        // ptl_num_sub_profiles = 2, sub_profile = [0xCAFEBABE,
        // 0xDEADBEEF]. SPS continues with 3840×2160 max luma, a
        // zero-offset conformance window, no subpic, bit-depth = 10.
        let rbsp = [
            0x23, 0x49, 0x42, 0x33, 0x80, 0x80, 0x23, 0x02, 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad,
            0xbe, 0xef, 0xc0, 0x03, 0xc0, 0x40, 0x04, 0x38, 0xfc, 0xc0,
        ];
        let nal = build_sps_nal(&rbsp);
        let sps = parse_sps(&nal).expect("SPS+PTL should parse");
        assert_eq!(sps.sps_seq_parameter_set_id, 2);
        assert_eq!(sps.sps_video_parameter_set_id, 3);
        assert_eq!(sps.sps_max_sublayers_minus1, 2);
        assert_eq!(sps.sps_chroma_format_idc, 1);
        assert_eq!(sps.sps_log2_ctu_size_minus5, 0);
        assert_eq!(sps.ctb_size_y(), 32);
        assert_eq!(sps.sps_ptl_dpb_hrd_params_present_flag, 1);

        let ptl = sps.profile_tier_level.as_ref().expect("PTL present");
        assert_eq!(ptl.general_profile_idc, Some(33));
        assert_eq!(ptl.general_tier_flag, Some(0));
        assert_eq!(ptl.general_level_idc, 51);
        assert_eq!(ptl.ptl_frame_only_constraint_flag, 1);
        assert_eq!(ptl.ptl_multilayer_enabled_flag, 0);
        // We stored low-to-high (after reversing the descending walk).
        // i=0 not present, i=1 present.
        assert_eq!(ptl.ptl_sublayer_level_present_flag, vec![0, 1]);
        // Only i=1 present → exactly one sublayer_level_idc.
        assert_eq!(ptl.sublayer_level_idc, vec![35]);
        assert_eq!(
            ptl.general_sub_profile_idc,
            vec![0xCAFE_BABEu32, 0xDEAD_BEEFu32]
        );

        assert_eq!(sps.sps_pic_width_max_in_luma_samples, 3840);
        assert_eq!(sps.sps_pic_height_max_in_luma_samples, 2160);
        assert_eq!(sps.sps_subpic_info_present_flag, 0);
        assert_eq!(sps.sps_bitdepth_minus8, 2);
        assert_eq!(sps.bit_depth(), 10);
    }

    #[test]
    fn parse_sps_rejects_subpic_info_present_for_now() {
        // Same prefix as the no-PTL fixture but with
        // sps_subpic_info_present_flag flipped to 1.
        //
        // sps_seq_parameter_set_id = 0 / vps = 0 / sublayers-1 = 0 /
        // chroma 4:2:0 / log2_ctu - 5 = 2 / ptl_dpb_present = 0 / gdr
        // = 0 / ref_pic_resampling = 0 / 1920×1080 / conformance
        // window = 0 / subpic_info = 1 → parser must return
        // Unsupported. The flag lives at absolute bit 61 (byte index
        // 7, mask 0x04) — that's the `0x91 → 0x95` change vs the
        // no-PTL fixture.
        let rbsp = [0x00, 0x0c, 0x00, 0x0f, 0x02, 0x00, 0x43, 0x95, 0x80];
        let nal = build_sps_nal(&rbsp);
        let err = parse_sps(&nal).expect_err("subpic_info_present_flag=1 should be unsupported");
        assert!(matches!(err, BitstreamError::Unsupported(_)));
    }

    #[test]
    fn parse_sps_rejects_wrong_nal_type() {
        // Build a PPS NAL header instead of SPS.
        let mut nal = vec![0u8; 4];
        nal[0] = 0;
        nal[1] = (NAL_TYPE_PPS << 3) | 1;
        let err = parse_sps(&nal).expect_err("PPS NAL must be rejected");
        assert!(matches!(err, BitstreamError::InvalidData(_)));
    }

    #[test]
    fn parse_sps_rejects_truncated() {
        let err = parse_sps(&[0x00]).expect_err("1-byte input must error");
        assert!(matches!(err, BitstreamError::UnexpectedEnd(_)));
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
}
