//! MPEG-2 / H.262 sequence-header, picture-header and extension
//! parser.
//!
//! Lifted from `oxideav-vdpau::mpeg2` (Round 4) under the workspace
//! clean-room policy: same author, same workspace, moving the
//! canonical home from the VDPAU glue crate into the shared
//! bitstream crate so the other backends can share it.
//!
//! # Scope
//!
//! Like the H.264 / HEVC / VP9 / VP8 siblings this is **not** a full
//! MPEG-2 decoder — only the parameter-buffer-shaped header bits the
//! HW backends need (`VAPictureParameterBufferMPEG2`,
//! `VdpPictureInfoMPEG1Or2`).
//!
//! MPEG-2 uses byte-aligned start codes `00 00 01 XX` (no Annex-B
//! emulation-prevention bytes — those are H.264/HEVC only). The
//! parser walks the bitstream looking for:
//!
//! - sequence_header (start_code 0xb3)
//! - sequence_extension (extension_start_code 0xb5 + extension_id 0x1)
//! - picture_header (start_code 0x00)
//! - picture_coding_extension (start_code 0xb5 + extension_id 0x8)
//!
//! # References
//!
//! ITU-T H.262 / ISO/IEC 13818-2, sections 6.2.2 (sequence header),
//! 6.2.2.3 (sequence extension), 6.2.3 (picture header), 6.2.3.1
//! (picture coding extension).

use crate::bit_reader::BitReader;
use crate::BitstreamError;

// ─────────────────────────── Start codes ────────────────────────────────────

/// `picture_start_code` — see ITU-T H.262 §6.2.3.
pub const START_CODE_PICTURE: u8 = 0x00;
/// First slice start code (slice codes occupy 0x01..=0xAF).
pub const START_CODE_SLICE_FIRST: u8 = 0x01;
/// Last slice start code (slice codes occupy 0x01..=0xAF).
pub const START_CODE_SLICE_LAST: u8 = 0xAF;
/// `sequence_header_code` — §6.2.2.
pub const START_CODE_SEQUENCE_HEADER: u8 = 0xB3;
/// `extension_start_code` — §6.2.2.3 / §6.2.3.1.
pub const START_CODE_EXTENSION: u8 = 0xB5;
/// `sequence_end_code`.
pub const START_CODE_SEQUENCE_END: u8 = 0xB7;
/// `group_start_code` — §6.2.2.6.
pub const START_CODE_GROUP_OF_PICTURES: u8 = 0xB8;

/// `extension_start_code_identifier` for sequence extension (§6.2.2.3).
pub const EXTENSION_ID_SEQUENCE: u8 = 0x1;
/// `extension_start_code_identifier` for picture coding extension
/// (§6.2.3.1).
pub const EXTENSION_ID_PICTURE_CODING: u8 = 0x8;

// ─────────────────────────── Default quantizer matrices ─────────────────────

/// Default intra-quantizer matrix (zig-zag scan order, ISO 13818-2
/// table 7-3).
pub const DEFAULT_INTRA_QUANT: [u8; 64] = [
    8, 16, 19, 22, 26, 27, 29, 34, 16, 16, 22, 24, 27, 29, 34, 37, 19, 22, 26, 27, 29, 34, 34, 38,
    22, 22, 26, 27, 29, 34, 37, 40, 22, 26, 27, 29, 32, 35, 40, 48, 26, 27, 29, 32, 35, 40, 48, 58,
    26, 27, 29, 34, 38, 46, 56, 69, 27, 29, 35, 38, 46, 56, 69, 83,
];

/// Default non-intra-quantizer matrix (uniform 16/16, ISO 13818-2
/// table 7-4).
pub const DEFAULT_NON_INTRA_QUANT: [u8; 64] = [16; 64];

/// Convert MPEG-2 zig-zag scan order to raster scan order (ISO 13818-2
/// figure 7-3).
const ZIGZAG_TO_RASTER: [u8; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// Convert a quantizer matrix from zig-zag to raster scan order. The
/// HW backends expect raster order in their parameter buffers.
pub fn zigzag_to_raster_quant(zz: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (zz_idx, &raster_idx) in ZIGZAG_TO_RASTER.iter().enumerate() {
        out[raster_idx as usize] = zz[zz_idx];
    }
    out
}

// ─────────────────────────── Start-code framing ─────────────────────────────

/// Locate every MPEG-2 start code in `buf`. Returns a vec of
/// `(start_code_byte, payload_start_index)` — `start_code_byte` is
/// the byte immediately after `00 00 01`, and `payload_start_index`
/// points at the byte after that.
pub fn find_start_codes(buf: &[u8]) -> Vec<(u8, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    let n = buf.len();
    while i + 3 < n {
        if buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 1 {
            out.push((buf[i + 3], i + 4));
            i += 4;
        } else {
            i += 1;
        }
    }
    out
}

/// Find the byte offset of the first MPEG-2 slice start code
/// (0x00000101 .. 0x000001AF). Returns the offset of the leading
/// `00 00 01` byte triplet so callers can pass `&buf[off..]` to the
/// HW backend's bitstream submit.
pub fn find_first_slice(buf: &[u8]) -> Option<usize> {
    let n = buf.len();
    let mut i = 0;
    while i + 3 < n {
        if buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 1 {
            let code = buf[i + 3];
            if (START_CODE_SLICE_FIRST..=START_CODE_SLICE_LAST).contains(&code) {
                return Some(i);
            }
            i += 4;
        } else {
            i += 1;
        }
    }
    None
}

// ─────────────────────────── Output structs ─────────────────────────────────

/// Sequence header (§6.2.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mpeg2SequenceHeader {
    pub horizontal_size: u32,
    pub vertical_size: u32,
    pub aspect_ratio_information: u8,
    pub frame_rate_code: u8,
    pub bit_rate: u32,
    pub vbv_buffer_size: u32,
    pub constrained_parameters_flag: bool,
    /// Present only if `load_intra_quantizer_matrix=1`. The matrix is
    /// given in zig-zag scan order — use [`zigzag_to_raster_quant`]
    /// before submitting to the HW backend.
    pub intra_quantiser_matrix: Option<[u8; 64]>,
    /// Same shape as `intra_quantiser_matrix`.
    pub non_intra_quantiser_matrix: Option<[u8; 64]>,
}

impl Mpeg2SequenceHeader {
    /// Effective intra-quantizer matrix in raster scan order (the
    /// custom matrix if present, otherwise the spec default).
    pub fn intra_quantizer_matrix_raster(&self) -> [u8; 64] {
        zigzag_to_raster_quant(
            self.intra_quantiser_matrix
                .as_ref()
                .unwrap_or(&DEFAULT_INTRA_QUANT),
        )
    }

    /// Effective non-intra-quantizer matrix in raster scan order.
    pub fn non_intra_quantizer_matrix_raster(&self) -> [u8; 64] {
        zigzag_to_raster_quant(
            self.non_intra_quantiser_matrix
                .as_ref()
                .unwrap_or(&DEFAULT_NON_INTRA_QUANT),
        )
    }
}

/// Picture header (§6.2.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mpeg2PictureHeader {
    pub temporal_reference: u32,
    /// 1=I, 2=P, 3=B (4=D for MPEG-1 only).
    pub picture_coding_type: u8,
    pub vbv_delay: u32,
    /// MPEG-1 only — kept for completeness.
    pub full_pel_forward_vector: u8,
    pub full_pel_backward_vector: u8,
    pub f_code: [[u8; 2]; 2],
}

/// Picture coding extension (§6.2.3.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mpeg2PictureCodingExtension {
    pub f_code: [[u8; 2]; 2],
    pub intra_dc_precision: u8,
    pub picture_structure: u8,
    pub top_field_first: u8,
    pub frame_pred_frame_dct: u8,
    pub concealment_motion_vectors: u8,
    pub q_scale_type: u8,
    pub intra_vlc_format: u8,
    pub alternate_scan: u8,
    pub repeat_first_field: u8,
    pub chroma_420_type: u8,
    pub progressive_frame: u8,
}

/// Sequence extension (§6.2.2.3). Carries the high-level profile /
/// chroma-format / progressive / colour-primaries flags that
/// MPEG-2 layered on top of MPEG-1's sequence header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mpeg2SequenceExtension {
    pub profile_and_level_indication: u8,
    pub progressive_sequence: bool,
    /// 1 = 4:2:0, 2 = 4:2:2, 3 = 4:4:4.
    pub chroma_format: u8,
    pub horizontal_size_extension: u8,
    pub vertical_size_extension: u8,
    pub bit_rate_extension: u32,
    pub vbv_buffer_size_extension: u8,
    pub low_delay: bool,
    pub frame_rate_extension_n: u8,
    pub frame_rate_extension_d: u8,
}

// ─────────────────────────── Parsers ────────────────────────────────────────

/// Parse a sequence header. `bytes` is the buffer starting **after**
/// the `00 00 01 B3` start code (i.e. at the first payload byte).
pub fn parse_sequence_header(bytes: &[u8]) -> Result<Mpeg2SequenceHeader, BitstreamError> {
    if bytes.len() < 8 {
        return Err(BitstreamError::unexpected_end(
            "MPEG-2 sequence_header shorter than 8 bytes",
        ));
    }
    let mut r = BitReader::new(bytes);
    let mut s = Mpeg2SequenceHeader {
        horizontal_size: r.u(12),
        vertical_size: r.u(12),
        aspect_ratio_information: r.u(4) as u8,
        frame_rate_code: r.u(4) as u8,
        bit_rate: r.u(18),
        ..Mpeg2SequenceHeader::default()
    };
    let _marker_bit = r.u(1);
    s.vbv_buffer_size = r.u(10);
    s.constrained_parameters_flag = r.u(1) != 0;
    let load_intra = r.u(1) != 0;
    if load_intra {
        let mut m = [0u8; 64];
        for q in m.iter_mut() {
            *q = r.u(8) as u8;
        }
        s.intra_quantiser_matrix = Some(m);
    }
    let load_non_intra = r.u(1) != 0;
    if load_non_intra {
        let mut m = [0u8; 64];
        for q in m.iter_mut() {
            *q = r.u(8) as u8;
        }
        s.non_intra_quantiser_matrix = Some(m);
    }
    Ok(s)
}

/// Parse a picture header. `bytes` is the buffer starting **after**
/// the `00 00 01 00` start code.
pub fn parse_picture_header(bytes: &[u8]) -> Result<Mpeg2PictureHeader, BitstreamError> {
    if bytes.len() < 4 {
        return Err(BitstreamError::unexpected_end(
            "MPEG-2 picture_header shorter than 4 bytes",
        ));
    }
    let mut r = BitReader::new(bytes);
    let mut p = Mpeg2PictureHeader {
        temporal_reference: r.u(10),
        picture_coding_type: r.u(3) as u8,
        vbv_delay: r.u(16),
        ..Mpeg2PictureHeader::default()
    };
    if p.picture_coding_type == 2 || p.picture_coding_type == 3 {
        // P or B: full_pel_forward_vector + forward_f_code.
        p.full_pel_forward_vector = r.u(1) as u8;
        let forward_f_code = r.u(3) as u8;
        p.f_code[0][0] = forward_f_code;
        p.f_code[0][1] = forward_f_code;
    }
    if p.picture_coding_type == 3 {
        // B: full_pel_backward_vector + backward_f_code.
        p.full_pel_backward_vector = r.u(1) as u8;
        let backward_f_code = r.u(3) as u8;
        p.f_code[1][0] = backward_f_code;
        p.f_code[1][1] = backward_f_code;
    }
    Ok(p)
}

/// Parse a picture coding extension (§6.2.3.1). `bytes` starts at the
/// first byte of the extension payload — the high 4 bits of which
/// must equal [`EXTENSION_ID_PICTURE_CODING`] (8).
pub fn parse_picture_coding_extension(
    bytes: &[u8],
) -> Result<Mpeg2PictureCodingExtension, BitstreamError> {
    if bytes.len() < 4 {
        return Err(BitstreamError::unexpected_end(
            "MPEG-2 picture_coding_extension shorter than 4 bytes",
        ));
    }
    let mut r = BitReader::new(bytes);
    let ext_id = r.u(4) as u8;
    if ext_id != EXTENSION_ID_PICTURE_CODING {
        return Err(BitstreamError::invalid(format!(
            "MPEG-2 picture_coding_extension: ext_id={ext_id} != 8"
        )));
    }
    let mut e = Mpeg2PictureCodingExtension::default();
    e.f_code[0][0] = r.u(4) as u8;
    e.f_code[0][1] = r.u(4) as u8;
    e.f_code[1][0] = r.u(4) as u8;
    e.f_code[1][1] = r.u(4) as u8;
    e.intra_dc_precision = r.u(2) as u8;
    e.picture_structure = r.u(2) as u8;
    e.top_field_first = r.u(1) as u8;
    e.frame_pred_frame_dct = r.u(1) as u8;
    e.concealment_motion_vectors = r.u(1) as u8;
    e.q_scale_type = r.u(1) as u8;
    e.intra_vlc_format = r.u(1) as u8;
    e.alternate_scan = r.u(1) as u8;
    e.repeat_first_field = r.u(1) as u8;
    e.chroma_420_type = r.u(1) as u8;
    e.progressive_frame = r.u(1) as u8;
    Ok(e)
}

/// Parse a sequence extension (§6.2.2.3). `bytes` starts at the first
/// byte of the extension payload — the high 4 bits of which must equal
/// [`EXTENSION_ID_SEQUENCE`] (1).
pub fn parse_sequence_extension(bytes: &[u8]) -> Result<Mpeg2SequenceExtension, BitstreamError> {
    if bytes.len() < 6 {
        return Err(BitstreamError::unexpected_end(
            "MPEG-2 sequence_extension shorter than 6 bytes",
        ));
    }
    let mut r = BitReader::new(bytes);
    let ext_id = r.u(4) as u8;
    if ext_id != EXTENSION_ID_SEQUENCE {
        return Err(BitstreamError::invalid(format!(
            "MPEG-2 sequence_extension: ext_id={ext_id} != 1"
        )));
    }
    let mut e = Mpeg2SequenceExtension {
        profile_and_level_indication: r.u(8) as u8,
        progressive_sequence: r.u(1) != 0,
        chroma_format: r.u(2) as u8,
        horizontal_size_extension: r.u(2) as u8,
        vertical_size_extension: r.u(2) as u8,
        bit_rate_extension: r.u(12),
        ..Mpeg2SequenceExtension::default()
    };
    let _marker_bit = r.u(1);
    e.vbv_buffer_size_extension = r.u(8) as u8;
    e.low_delay = r.u(1) != 0;
    e.frame_rate_extension_n = r.u(2) as u8;
    e.frame_rate_extension_d = r.u(5) as u8;
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_start_codes_locates_known_codes() {
        let buf = [
            0, 0, 1, 0xb3, 0xaa, 0xbb, // sequence header
            0, 0, 1, 0xb5, 0xcc, // extension
            0, 0, 1, 0x00, 0xdd, 0xee, // picture header
            0, 0, 1, 0x01, 0xff, // slice 1
        ];
        let codes = find_start_codes(&buf);
        assert_eq!(codes.len(), 4);
        assert_eq!(codes[0].0, 0xb3);
        assert_eq!(codes[1].0, 0xb5);
        assert_eq!(codes[2].0, 0x00);
        assert_eq!(codes[3].0, 0x01);
    }

    #[test]
    fn find_first_slice_returns_offset_of_leading_zeros() {
        let buf = [
            0, 0, 1, 0xb3, 0xaa, // sequence header
            0, 0, 1, 0x00, 0xbb, // picture header
            0, 0, 1, 0x01, 0xcc, // slice 1
        ];
        let off = find_first_slice(&buf).expect("slice present");
        assert_eq!(off, 10);
    }

    #[test]
    fn zigzag_inverse_roundtrip() {
        let zz: [u8; 64] = std::array::from_fn(|i| (i + 1) as u8);
        let raster = zigzag_to_raster_quant(&zz);
        assert_eq!(raster[0], 1); // DC
        assert_eq!(raster[1], 2);
        assert_eq!(raster[8], 3);
    }

    #[test]
    fn parse_sequence_header_too_short() {
        assert!(matches!(
            parse_sequence_header(&[0u8; 4]),
            Err(BitstreamError::UnexpectedEnd(_))
        ));
    }

    #[test]
    fn parse_picture_coding_extension_rejects_wrong_ext_id() {
        // extension id = 1 in the high 4 bits → not picture coding.
        let bytes = [0x10, 0x00, 0x00, 0x00];
        assert!(matches!(
            parse_picture_coding_extension(&bytes),
            Err(BitstreamError::InvalidData(_))
        ));
    }
}
