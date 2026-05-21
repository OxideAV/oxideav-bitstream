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
}
