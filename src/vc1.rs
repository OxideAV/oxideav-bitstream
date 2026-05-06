//! VC-1 (SMPTE 421M) sequence-header / entry-point / picture-header
//! parser. Advanced profile (Annex G start codes) is the primary
//! target — that is what `VdpPictureInfoVC1` and
//! `VAPictureParameterBufferVC1` consume in any modern HW pipeline.
//!
//! # Scope
//!
//! Like the H.264 / HEVC / VP9 / VP8 / MPEG-2 siblings this is **not**
//! a full VC-1 decoder. Only the parameter-buffer-shaped header bits
//! the HW backends need to populate `VdpPictureInfoVC1` /
//! `VAPictureParameterBufferVC1`.
//!
//! - Advanced-profile sequence header (§6.1) — full parse.
//! - Entry-point header (§6.2) — full parse, including HRD fullness
//!   (skipped past) and optional coded-size override.
//! - Picture header (§7.1.1) — minimal: FCM + picture-type only
//!   (enough to identify intra frames).
//! - Simple/Main profiles are **not** supported (no Annex G start
//!   codes — they require the codec_data byte from the container).
//!
//! # Bit ordering
//!
//! Unlike VP8/VP9, VC-1 reads bits MSB-first inside each byte —
//! identical to H.264 / HEVC / MPEG-2. We can re-use the shared
//! [`crate::bit_reader::BitReader`].
//!
//! # Spec references
//!
//! SMPTE ST 421:2006 ("VC-1 Compressed Video Bitstream Format and
//! Decoding Process") sections 6.1 (sequence header), 6.2
//! (entry-point header), 7.1.1 (picture header for advanced profile).
//!
//! # Annex G start codes (advanced profile only)
//!
//! VC-1 BDU start codes are 4 bytes: `00 00 01 XX`. The XX byte
//! gives the BDU type:
//! - `0x0F`: sequence header
//! - `0x0E`: entry-point header
//! - `0x0D`: frame (picture) BDU
//! - `0x0C`: field (interlaced field picture) BDU
//! - `0x0B`: slice BDU (advanced profile only, when slices used)
//! - `0x1D`: user data, sequence level
//! - `0x1E`: user data, entry-point level
//! - `0x1F`: end-of-sequence

use crate::bit_reader::BitReader;
use crate::BitstreamError;

// ─────────────────────────── BDU type bytes ─────────────────────────────────

pub const BDU_SEQUENCE_HEADER: u8 = 0x0F;
pub const BDU_ENTRY_POINT: u8 = 0x0E;
pub const BDU_FRAME: u8 = 0x0D;
pub const BDU_FIELD: u8 = 0x0C;
pub const BDU_SLICE: u8 = 0x0B;
pub const BDU_END_OF_SEQUENCE: u8 = 0x1F;

// ─────────────────────────── Profile ID values ──────────────────────────────

pub const PROFILE_SIMPLE: u8 = 0;
pub const PROFILE_MAIN: u8 = 1;
pub const PROFILE_ADVANCED: u8 = 3;

// ─────────────────────────── BDU framing ────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct VcBdu<'a> {
    pub bdu_type: u8,
    pub payload: &'a [u8],
}

/// Walk the input stream and return the list of BDUs (start code
/// stripped — `payload` points at the first body byte after
/// `00 00 01 XX`). Empty BDUs (zero-byte payload) are returned too.
pub fn split_bdus(stream: &[u8]) -> Vec<VcBdu<'_>> {
    let mut out = Vec::new();
    let mut i = 0;
    let n = stream.len();
    let mut current: Option<(u8, usize)> = None; // (bdu_type, body_start)
    while i + 3 < n {
        if stream[i] == 0 && stream[i + 1] == 0 && stream[i + 2] == 1 {
            if let Some((t, body_start)) = current.take() {
                out.push(VcBdu {
                    bdu_type: t,
                    payload: &stream[body_start..i],
                });
            }
            let bdu_type = stream[i + 3];
            i += 4;
            current = Some((bdu_type, i));
            continue;
        }
        i += 1;
    }
    if let Some((t, body_start)) = current.take() {
        out.push(VcBdu {
            bdu_type: t,
            payload: &stream[body_start..n],
        });
    }
    out
}

// ─────────────────────────── Output structs ─────────────────────────────────

/// Sequence header (§6.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vc1SequenceHeader {
    /// 0=Simple, 1=Main, 3=Advanced. Only Advanced is parsed by this
    /// module — the parser errors on the others.
    pub profile: u8,
    pub level: u8,
    /// 1 = 4:2:0. Other values reserved.
    pub colordiff_format: u8,
    pub frmrtq_postproc: u8,
    pub bitrtq_postproc: u8,
    pub postprocflag: bool,
    /// `MAX_CODED_WIDTH+1` — the encoded coded width in luma samples
    /// (already +1).
    pub max_coded_width: u32,
    /// `MAX_CODED_HEIGHT+1` — encoded coded height (already +1).
    pub max_coded_height: u32,
    pub pulldown: bool,
    pub interlace: bool,
    pub tfcntrflag: bool,
    pub finterpflag: bool,
    /// "Progressive segmented frame" flag — see §6.1.13.
    pub psf: bool,
    /// Whether the display-extension block (display size, aspect
    /// ratio, framerate, color description) is present.
    pub display_ext: bool,
    /// `DISP_HORIZ_SIZE+1` if `display_ext`, else 0.
    pub display_horiz_size: u32,
    /// `DISP_VERT_SIZE+1` if `display_ext`, else 0.
    pub display_vert_size: u32,
    pub aspect_ratio_flag: bool,
    pub aspect_ratio: u8,
    pub aspect_horiz_size: u8,
    pub aspect_vert_size: u8,
    pub framerate_flag: bool,
    pub framerateind: u8,
    pub frameratenr: u32,
    pub frameratedr: u8,
    pub color_format_flag: bool,
    pub color_primaries: u8,
    pub transfer_char: u8,
    pub matrix_coef: u8,
    pub hrd_param_flag: bool,
    pub hrd_num_leaky_buckets: u8,
    pub hrd_bit_rate_exponent: u8,
    pub hrd_buffer_size_exponent: u8,
}

/// Entry-point header (§6.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vc1EntryPointHeader {
    pub broken_link: bool,
    pub closed_entry: bool,
    pub panscan_flag: bool,
    pub refdist_flag: bool,
    pub loopfilter: bool,
    pub fastuvmc: bool,
    pub extended_mv: bool,
    pub dquant: u8,
    pub vstransform: bool,
    pub overlap: bool,
    pub quantizer: u8,
    pub coded_size_flag: bool,
    /// `CODED_WIDTH+1` if `coded_size_flag`, else 0. The HW backend
    /// should fall back to the sequence header's `max_coded_width`
    /// when `coded_size_flag=0`.
    pub coded_width: u32,
    /// `CODED_HEIGHT+1` if `coded_size_flag`, else 0.
    pub coded_height: u32,
    pub extended_dmv: bool,
    pub range_mapy_flag: bool,
    pub range_mapy: u8,
    pub range_mapuv_flag: bool,
    pub range_mapuv: u8,
}

/// Minimal picture header (§7.1.1). Picture-type decode in VC-1 is
/// VLC-coded and depends on the entry-point's `interlace` flag, the
/// sequence header's `finterpflag`, etc. We surface only the FCM
/// (frame coding mode) and the picture type, which is what
/// `VdpPictureInfoVC1::picture_type` ultimately consumes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vc1PictureHeader {
    /// FCM — frame coding mode (§7.1.1.15). 0 = progressive frame,
    /// 2 = interlaced field, 3 = interlaced frame.
    pub fcm: u8,
    /// Picture type: 0=I, 1=P, 2=B, 3=BI, 4=skipped (for progressive
    /// pictures). For interlaced field pictures this is per-field
    /// and uses different VLC; the parser falls back to a 3-bit
    /// fixed-length read for those.
    pub picture_type: u8,
}

/// Convenience structure returned by [`parse_first_picture`].
#[derive(Debug)]
pub struct Vc1FirstPictureParse<'a> {
    pub sequence_header: Vc1SequenceHeader,
    pub entry_point: Vc1EntryPointHeader,
    pub picture_header: Vc1PictureHeader,
    pub frame_payload: &'a [u8],
}

// ─────────────────────────── Sequence header parser ─────────────────────────

/// Parse an Advanced-profile sequence header. `bytes` is the buffer
/// starting **after** the `00 00 01 0F` start code (i.e. at the
/// PROFILE field). The parser errors if PROFILE is not 3.
pub fn parse_sequence_header_advanced(bytes: &[u8]) -> Result<Vc1SequenceHeader, BitstreamError> {
    if bytes.len() < 6 {
        return Err(BitstreamError::unexpected_end(
            "VC-1 sequence header shorter than 6 bytes",
        ));
    }
    let mut r = BitReader::new(bytes);
    let mut s = Vc1SequenceHeader {
        profile: r.u(2) as u8,
        ..Vc1SequenceHeader::default()
    };
    if s.profile != PROFILE_ADVANCED {
        return Err(BitstreamError::unsupported(format!(
            "VC-1 profile {} not supported (only Advanced/3)",
            s.profile
        )));
    }
    s.level = r.u(3) as u8;
    s.colordiff_format = r.u(2) as u8;
    s.frmrtq_postproc = r.u(3) as u8;
    s.bitrtq_postproc = r.u(5) as u8;
    s.postprocflag = r.u(1) != 0;
    s.max_coded_width = r.u(12) + 1;
    s.max_coded_height = r.u(12) + 1;
    s.pulldown = r.u(1) != 0;
    s.interlace = r.u(1) != 0;
    s.tfcntrflag = r.u(1) != 0;
    s.finterpflag = r.u(1) != 0;
    let _reserved = r.u(1);
    s.psf = r.u(1) != 0;
    s.display_ext = r.u(1) != 0;
    if s.display_ext {
        s.display_horiz_size = r.u(14) + 1;
        s.display_vert_size = r.u(14) + 1;
        s.aspect_ratio_flag = r.u(1) != 0;
        if s.aspect_ratio_flag {
            s.aspect_ratio = r.u(4) as u8;
            if s.aspect_ratio == 15 {
                s.aspect_horiz_size = r.u(8) as u8;
                s.aspect_vert_size = r.u(8) as u8;
            }
        }
        s.framerate_flag = r.u(1) != 0;
        if s.framerate_flag {
            s.framerateind = r.u(1) as u8;
            if s.framerateind == 0 {
                s.frameratenr = r.u(8);
                s.frameratedr = r.u(4) as u8;
            } else {
                s.frameratenr = r.u(16);
            }
        }
        s.color_format_flag = r.u(1) != 0;
        if s.color_format_flag {
            s.color_primaries = r.u(8) as u8;
            s.transfer_char = r.u(8) as u8;
            s.matrix_coef = r.u(8) as u8;
        }
    }
    s.hrd_param_flag = r.u(1) != 0;
    if s.hrd_param_flag {
        s.hrd_num_leaky_buckets = r.u(5) as u8;
        s.hrd_bit_rate_exponent = r.u(4) as u8;
        s.hrd_buffer_size_exponent = r.u(4) as u8;
        // For each leaky bucket, 16-bit HRD_RATE + 16-bit HRD_BUFFER.
        // We don't surface the rate/buffer arrays; just consume the bits.
        for _ in 0..s.hrd_num_leaky_buckets {
            let _hrd_rate = r.u(16);
            let _hrd_buffer = r.u(16);
        }
    }
    Ok(s)
}

// ─────────────────────────── Entry-point header parser ──────────────────────

/// Parse an entry-point header. The parser needs the previously
/// decoded sequence header so it can know how many HRD_FULL bytes
/// to skip, plus whether `extended_mv` was already signalled.
pub fn parse_entry_point_header(
    bytes: &[u8],
    seq: &Vc1SequenceHeader,
) -> Result<Vc1EntryPointHeader, BitstreamError> {
    if bytes.is_empty() {
        return Err(BitstreamError::unexpected_end(
            "VC-1 entry-point header empty",
        ));
    }
    let mut r = BitReader::new(bytes);
    let mut e = Vc1EntryPointHeader {
        broken_link: r.u(1) != 0,
        closed_entry: r.u(1) != 0,
        panscan_flag: r.u(1) != 0,
        refdist_flag: r.u(1) != 0,
        loopfilter: r.u(1) != 0,
        fastuvmc: r.u(1) != 0,
        extended_mv: r.u(1) != 0,
        dquant: r.u(2) as u8,
        vstransform: r.u(1) != 0,
        overlap: r.u(1) != 0,
        quantizer: r.u(2) as u8,
        ..Vc1EntryPointHeader::default()
    };
    // HRD fullness: 8 bits per leaky bucket if HRD was signalled in
    // the sequence header.
    if seq.hrd_param_flag {
        for _ in 0..seq.hrd_num_leaky_buckets {
            let _hrd_full = r.u(8);
        }
    }
    e.coded_size_flag = r.u(1) != 0;
    if e.coded_size_flag {
        e.coded_width = r.u(12) + 1;
        e.coded_height = r.u(12) + 1;
    }
    if e.extended_mv {
        e.extended_dmv = r.u(1) != 0;
    }
    e.range_mapy_flag = r.u(1) != 0;
    if e.range_mapy_flag {
        e.range_mapy = r.u(3) as u8;
    }
    e.range_mapuv_flag = r.u(1) != 0;
    if e.range_mapuv_flag {
        e.range_mapuv = r.u(3) as u8;
    }
    Ok(e)
}

// ─────────────────────────── Picture header parser ──────────────────────────

/// Parse a minimal frame-BDU picture header (§7.1.1). Only the FCM
/// (frame coding mode) and the picture type are extracted — that
/// is enough for the HW backends to populate
/// `VdpPictureInfoVC1::picture_type` / `frame_coding_mode`.
pub fn parse_picture_header(
    bytes: &[u8],
    seq: &Vc1SequenceHeader,
) -> Result<Vc1PictureHeader, BitstreamError> {
    if bytes.is_empty() {
        return Err(BitstreamError::unexpected_end("VC-1 picture header empty"));
    }
    let mut r = BitReader::new(bytes);
    let mut h = Vc1PictureHeader::default();
    // FCM: only present when interlace=1. VLC-coded:
    //   0  → progressive frame (FCM=0)
    //   10 → interlaced field (FCM=2)
    //   11 → interlaced frame (FCM=3)
    if seq.interlace {
        let fcm0 = r.u(1);
        if fcm0 == 0 {
            h.fcm = 0;
        } else {
            let fcm1 = r.u(1);
            h.fcm = if fcm1 == 0 { 2 } else { 3 };
        }
    } else {
        h.fcm = 0;
    }
    // Picture type. The exact VLC depends on FCM and on
    // `MAXBFRAMES` (signalled at sequence/entry-point level —
    // omitted from this minimal parser). For FCM=0 the table is:
    //   110  → I
    //   0    → P
    //   10   → B
    //   1110 → BI
    //   1111 → skipped
    // For FCM=3 (interlaced frame) it's a 3-bit fixed length:
    //   000=I, 001=P, 010=B, 011=BI, 100=skipped (per §7.1.1.4).
    // For FCM=2 (interlaced field) it's a 3-bit fixed length code
    // identifying a pair of field types (see SMPTE 421M Table 88).
    //
    // For the workspace's IRAP-only HW path we only need to
    // distinguish I from non-I. We surface the raw VLC value so the
    // HW backend / caller can interpret it according to the FCM it
    // sees.
    if h.fcm == 0 {
        // Progressive: consume the variable-length code.
        let b0 = r.u(1);
        if b0 == 0 {
            h.picture_type = 1; // P
        } else {
            let b1 = r.u(1);
            if b1 == 0 {
                h.picture_type = 2; // B
            } else {
                let b2 = r.u(1);
                if b2 == 0 {
                    h.picture_type = 0; // I (110)
                } else {
                    let b3 = r.u(1);
                    h.picture_type = if b3 == 0 { 3 } else { 4 }; // BI / skipped
                }
            }
        }
    } else {
        // Interlaced field/frame: 3-bit fixed length.
        h.picture_type = r.u(3) as u8;
    }
    Ok(h)
}

// ─────────────────────────── End-to-end walker ──────────────────────────────

/// Walk an Annex-G start-code stream, find the first sequence
/// header, the first entry-point header that follows it, and the
/// first frame BDU after that — parse all three and return them
/// together with a slice covering the frame BDU's payload.
pub fn parse_first_picture(stream: &[u8]) -> Result<Vc1FirstPictureParse<'_>, BitstreamError> {
    let bdus = split_bdus(stream);
    let seq = bdus
        .iter()
        .find(|b| b.bdu_type == BDU_SEQUENCE_HEADER)
        .ok_or_else(|| BitstreamError::invalid("VC-1: no sequence header BDU in stream"))?;
    let sequence_header = parse_sequence_header_advanced(seq.payload)?;
    let entry = bdus
        .iter()
        .find(|b| b.bdu_type == BDU_ENTRY_POINT)
        .ok_or_else(|| BitstreamError::invalid("VC-1: no entry-point BDU in stream"))?;
    let entry_point = parse_entry_point_header(entry.payload, &sequence_header)?;
    let frame = bdus
        .iter()
        .find(|b| b.bdu_type == BDU_FRAME)
        .ok_or_else(|| BitstreamError::invalid("VC-1: no frame BDU in stream"))?;
    let picture_header = parse_picture_header(frame.payload, &sequence_header)?;
    Ok(Vc1FirstPictureParse {
        sequence_header,
        entry_point,
        picture_header,
        frame_payload: frame.payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_bdus_finds_seq_entry_frame() {
        let stream = [
            0,
            0,
            1,
            BDU_SEQUENCE_HEADER,
            0xaa,
            0,
            0,
            1,
            BDU_ENTRY_POINT,
            0xbb,
            0,
            0,
            1,
            BDU_FRAME,
            0xcc,
            0xdd,
        ];
        let bdus = split_bdus(&stream);
        assert_eq!(bdus.len(), 3);
        assert_eq!(bdus[0].bdu_type, BDU_SEQUENCE_HEADER);
        assert_eq!(bdus[0].payload, &[0xaa]);
        assert_eq!(bdus[1].bdu_type, BDU_ENTRY_POINT);
        assert_eq!(bdus[1].payload, &[0xbb]);
        assert_eq!(bdus[2].bdu_type, BDU_FRAME);
        assert_eq!(bdus[2].payload, &[0xcc, 0xdd]);
    }

    #[test]
    fn parse_sequence_header_rejects_simple_profile() {
        // A 6-byte buffer where the top 2 bits = 0 (PROFILE = SIMPLE).
        let buf = [0u8; 6];
        assert!(matches!(
            parse_sequence_header_advanced(&buf),
            Err(BitstreamError::Unsupported(_))
        ));
    }

    #[test]
    fn parse_sequence_header_rejects_short_input() {
        assert!(matches!(
            parse_sequence_header_advanced(&[0u8; 2]),
            Err(BitstreamError::UnexpectedEnd(_))
        ));
    }
}
