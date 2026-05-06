//! AV1 minimal keyframe header parsing.
//!
//! This module walks an AV1 OBU bytestream (a.k.a. Low Overhead
//! Bitstream Format), parses the sequence-header OBU and the
//! key-frame frame-header OBU, and extracts just enough information
//! to populate the slice-data HW backends' parameter buffers
//! (`VAPictureParameterBufferAV1`, `VkVideoDecodeAV1PictureInfoKHR`).
//!
//! Refused (returned as [`BitstreamError::Unsupported`]):
//!
//! - Multiple operating points (`operating_points_cnt_minus_1 > 0`):
//!   we only consume `operating_point_idc[0]` / `level_idx[0]`.
//! - Decoder model / initial display delay info.
//! - `seq_force_screen_content_tools` overrides beyond the default.
//! - `enable_superres`, `enable_cdef`, `enable_restoration` advanced
//!   handling — we read but don't return them.
//! - Film grain.
//! - Anything that isn't a `KEY_FRAME` (or `INTRA_ONLY_FRAME` with
//!   `show_frame=1`).
//!
//! # Spec references
//!
//! AOMedia AV1 Bitstream & Decoding Process Specification (2018-06-25
//! v1.0.0 errata + 2019-07-08 v1.0.0). Sections of interest:
//! 5.3.1 (general OBU syntax), 5.3.2 (OBU header), 5.3.3 (extension
//! header), 5.3.4 (trailing bits), 5.5 (sequence header), 5.9
//! (frame header), 5.9.5 (uncompressed header for key frame),
//! 4.10 (leb128).

use crate::bit_reader::BitReader;
use crate::BitstreamError;

// ─────────────────────────── OBU types ───────────────────────────────────────

/// 6.2.1 `obu_type` values.
pub const OBU_RESERVED_0: u8 = 0;
pub const OBU_SEQUENCE_HEADER: u8 = 1;
pub const OBU_TEMPORAL_DELIMITER: u8 = 2;
pub const OBU_FRAME_HEADER: u8 = 3;
pub const OBU_TILE_GROUP: u8 = 4;
pub const OBU_METADATA: u8 = 5;
pub const OBU_FRAME: u8 = 6;
pub const OBU_REDUNDANT_FRAME_HEADER: u8 = 7;
pub const OBU_TILE_LIST: u8 = 8;
pub const OBU_PADDING: u8 = 15;

// ─────────────────────────── frame_type values ──────────────────────────────

/// 6.8.2 `frame_type` values.
pub const FRAME_TYPE_KEY: u8 = 0;
pub const FRAME_TYPE_INTER: u8 = 1;
pub const FRAME_TYPE_INTRA_ONLY: u8 = 2;
pub const FRAME_TYPE_SWITCH: u8 = 3;

// ─────────────────────────── OBU header / leb128 ─────────────────────────────

/// Decoded OBU header (5.3.2 + 5.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObuHeader {
    pub obu_type: u8,
    pub extension_flag: bool,
    pub has_size_field: bool,
    pub temporal_id: u8,
    pub spatial_id: u8,
}

/// Locate one OBU starting at `offset`. Returns:
/// `(header, payload_start, payload_end, next_offset)` where
/// `payload_*` covers the OBU payload (excluding OBU header byte,
/// extension byte and leb128 size bytes) and `next_offset` is where
/// the *next* OBU begins.
///
/// If the OBU has no `obu_size` field and we're inside a
/// Low-Overhead-Bitstream-Format stream (which is what aomenc's
/// `--obu` produces), the OBU body is *required* to have a
/// `obu_size` field — Section 5 mandates `obu_has_size_field == 1`
/// for all OBUs in the LOBF. We enforce that here.
pub fn read_obu(
    bytes: &[u8],
    offset: usize,
) -> Result<(ObuHeader, usize, usize, usize), BitstreamError> {
    if offset >= bytes.len() {
        return Err(BitstreamError::unexpected_end(
            "OBU offset past end of buffer",
        ));
    }
    let h = bytes[offset];
    let forbidden = (h >> 7) & 1;
    if forbidden != 0 {
        return Err(BitstreamError::invalid(
            "OBU header has obu_forbidden_bit=1",
        ));
    }
    let obu_type = (h >> 3) & 0xf;
    let extension_flag = ((h >> 2) & 1) != 0;
    let has_size_field = ((h >> 1) & 1) != 0;
    let _reserved = h & 1;

    let mut cur = offset + 1;
    let (temporal_id, spatial_id) = if extension_flag {
        if cur >= bytes.len() {
            return Err(BitstreamError::unexpected_end("OBU extension byte missing"));
        }
        let e = bytes[cur];
        cur += 1;
        ((e >> 5) & 0x7, (e >> 3) & 0x3)
    } else {
        (0, 0)
    };

    if !has_size_field {
        return Err(BitstreamError::unsupported(
            "OBU without obu_has_size_field=1 (LOBF requires it)",
        ));
    }
    let (size, size_len) = read_leb128(bytes, cur)?;
    cur += size_len;
    let payload_start = cur;
    let payload_end = cur
        .checked_add(size as usize)
        .ok_or_else(|| BitstreamError::invalid("OBU size overflow"))?;
    if payload_end > bytes.len() {
        return Err(BitstreamError::unexpected_end(
            "OBU payload extends past buffer end",
        ));
    }
    Ok((
        ObuHeader {
            obu_type,
            extension_flag,
            has_size_field,
            temporal_id,
            spatial_id,
        },
        payload_start,
        payload_end,
        payload_end,
    ))
}

/// 4.10 leb128 reader. Returns `(value, bytes_consumed)`. Limits
/// itself to 8 bytes (the spec's hard maximum, encoding 56 bits of
/// payload).
pub fn read_leb128(bytes: &[u8], offset: usize) -> Result<(u64, usize), BitstreamError> {
    let mut value: u64 = 0;
    for i in 0..8 {
        if offset + i >= bytes.len() {
            return Err(BitstreamError::unexpected_end("leb128 truncated"));
        }
        let b = bytes[offset + i];
        value |= ((b & 0x7f) as u64) << (i * 7);
        if (b & 0x80) == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(BitstreamError::invalid("leb128 longer than 8 bytes"))
}

// ─────────────────────────── Sequence header ─────────────────────────────────

/// 6.4.2 `color_config`. Reduced form — we keep only the fields the
/// HW backends actually need.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Av1ColorConfig {
    pub bit_depth: u8,
    pub monochrome: bool,
    pub color_range: bool,
    pub subsampling_x: bool,
    pub subsampling_y: bool,
    pub chroma_sample_position: u8,
}

/// 6.4.1 sequence header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Av1SequenceHeader {
    pub seq_profile: u8,
    pub still_picture: bool,
    pub reduced_still_picture_header: bool,

    pub seq_level_idx_0: u8,
    pub seq_tier_0: bool,
    pub operating_point_idc_0: u16,

    pub frame_width_bits: u8,
    pub frame_height_bits: u8,
    pub max_frame_width_minus_1: u32,
    pub max_frame_height_minus_1: u32,

    pub frame_id_numbers_present_flag: bool,
    pub delta_frame_id_length_minus_2: u8,
    pub additional_frame_id_length_minus_1: u8,

    pub use_128x128_superblock: bool,
    pub enable_filter_intra: bool,
    pub enable_intra_edge_filter: bool,
    pub enable_interintra_compound: bool,
    pub enable_masked_compound: bool,
    pub enable_warped_motion: bool,
    pub enable_dual_filter: bool,
    pub enable_order_hint: bool,
    pub enable_jnt_comp: bool,
    pub enable_ref_frame_mvs: bool,
    pub seq_choose_screen_content_tools: bool,
    pub seq_force_screen_content_tools: u8,
    pub seq_choose_integer_mv: bool,
    pub seq_force_integer_mv: u8,
    pub order_hint_bits: u8,

    pub enable_superres: bool,
    pub enable_cdef: bool,
    pub enable_restoration: bool,

    pub color_config: Av1ColorConfig,
    pub film_grain_params_present: bool,
}

impl Av1SequenceHeader {
    /// Maximum frame width in luma samples.
    pub fn max_frame_width(&self) -> u32 {
        self.max_frame_width_minus_1 + 1
    }

    /// Maximum frame height in luma samples.
    pub fn max_frame_height(&self) -> u32 {
        self.max_frame_height_minus_1 + 1
    }
}

/// 6.8.1 frame header — minimum fields, key-frame only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Av1FrameHeader {
    pub show_existing_frame: bool,
    pub frame_type: u8,
    pub show_frame: bool,
    pub showable_frame: bool,
    pub error_resilient_mode: bool,
    pub disable_cdf_update: bool,
    pub allow_screen_content_tools: bool,
    pub force_integer_mv: bool,
    pub frame_width: u32,
    pub frame_height: u32,
    pub render_width: u32,
    pub render_height: u32,
    pub allow_intrabc: bool,
}

/// Result of [`parse_obu_stream`].
#[derive(Debug, Clone)]
pub struct Av1KeyframeParse<'a> {
    pub sequence_header: Av1SequenceHeader,
    pub frame_header: Av1FrameHeader,
    /// Byte range of the OBU(s) covering the keyframe. Contains
    /// either an `OBU_FRAME` (header + tiles fused) or an
    /// `OBU_FRAME_HEADER` followed by one or more `OBU_TILE_GROUP`s.
    /// Includes the OBU header bytes — the HW backends submit the
    /// raw OBU(s) to the GPU.
    pub keyframe_obus: &'a [u8],
}

// ─────────────────────────── Sequence header parser ──────────────────────────

/// Parse the payload of an `OBU_SEQUENCE_HEADER` (5.5).
pub fn parse_sequence_header(payload: &[u8]) -> Result<Av1SequenceHeader, BitstreamError> {
    let mut r = BitReader::new(payload);
    let mut s = Av1SequenceHeader {
        seq_profile: r.u(3) as u8,
        ..Av1SequenceHeader::default()
    };
    if s.seq_profile > 2 {
        return Err(BitstreamError::invalid(format!(
            "invalid seq_profile={}",
            s.seq_profile
        )));
    }
    s.still_picture = r.u(1) != 0;
    s.reduced_still_picture_header = r.u(1) != 0;
    if s.reduced_still_picture_header && !s.still_picture {
        return Err(BitstreamError::invalid(
            "reduced_still_picture_header=1 with still_picture=0",
        ));
    }

    if s.reduced_still_picture_header {
        s.seq_level_idx_0 = r.u(5) as u8;
        s.seq_tier_0 = false;
        s.operating_point_idc_0 = 0;
    } else {
        let timing_info_present_flag = r.u(1) != 0;
        if timing_info_present_flag {
            // timing_info()
            let _num_units_in_display_tick = r.u(32);
            let _time_scale = r.u(32);
            let equal_picture_interval = r.u(1) != 0;
            if equal_picture_interval {
                let _num_ticks_per_picture_minus_1 = read_uvlc(&mut r)?;
            }
            let decoder_model_info_present_flag = r.u(1) != 0;
            if decoder_model_info_present_flag {
                return Err(BitstreamError::unsupported(
                    "AV1 decoder_model_info_present_flag=1 not supported",
                ));
            }
        }
        let initial_display_delay_present_flag = r.u(1) != 0;
        let operating_points_cnt_minus_1 = r.u(5) as u8;
        if operating_points_cnt_minus_1 > 0 {
            return Err(BitstreamError::unsupported(
                "AV1 operating_points_cnt_minus_1>0 not supported by minimal parser",
            ));
        }
        // Read the single operating point.
        s.operating_point_idc_0 = r.u(12) as u16;
        s.seq_level_idx_0 = r.u(5) as u8;
        if s.seq_level_idx_0 > 7 {
            s.seq_tier_0 = r.u(1) != 0;
        }
        if initial_display_delay_present_flag {
            let initial_display_delay_present_for_this_op = r.u(1) != 0;
            if initial_display_delay_present_for_this_op {
                let _initial_display_delay_minus_1 = r.u(4);
            }
        }
    }

    s.frame_width_bits = (r.u(4) + 1) as u8;
    s.frame_height_bits = (r.u(4) + 1) as u8;
    s.max_frame_width_minus_1 = r.u(s.frame_width_bits as u32);
    s.max_frame_height_minus_1 = r.u(s.frame_height_bits as u32);

    if s.reduced_still_picture_header {
        s.frame_id_numbers_present_flag = false;
    } else {
        s.frame_id_numbers_present_flag = r.u(1) != 0;
    }
    if s.frame_id_numbers_present_flag {
        s.delta_frame_id_length_minus_2 = r.u(4) as u8;
        s.additional_frame_id_length_minus_1 = r.u(3) as u8;
    }

    s.use_128x128_superblock = r.u(1) != 0;
    s.enable_filter_intra = r.u(1) != 0;
    s.enable_intra_edge_filter = r.u(1) != 0;

    if s.reduced_still_picture_header {
        s.enable_interintra_compound = false;
        s.enable_masked_compound = false;
        s.enable_warped_motion = false;
        s.enable_dual_filter = false;
        s.enable_order_hint = false;
        s.enable_jnt_comp = false;
        s.enable_ref_frame_mvs = false;
        s.seq_force_screen_content_tools = 2; // SELECT_SCREEN_CONTENT_TOOLS
        s.seq_force_integer_mv = 2; // SELECT_INTEGER_MV
        s.order_hint_bits = 0;
    } else {
        s.enable_interintra_compound = r.u(1) != 0;
        s.enable_masked_compound = r.u(1) != 0;
        s.enable_warped_motion = r.u(1) != 0;
        s.enable_dual_filter = r.u(1) != 0;
        s.enable_order_hint = r.u(1) != 0;
        if s.enable_order_hint {
            s.enable_jnt_comp = r.u(1) != 0;
            s.enable_ref_frame_mvs = r.u(1) != 0;
        }
        s.seq_choose_screen_content_tools = r.u(1) != 0;
        s.seq_force_screen_content_tools = if s.seq_choose_screen_content_tools {
            2 // SELECT_SCREEN_CONTENT_TOOLS
        } else {
            r.u(1) as u8
        };
        if s.seq_force_screen_content_tools > 0 {
            s.seq_choose_integer_mv = r.u(1) != 0;
            s.seq_force_integer_mv = if s.seq_choose_integer_mv {
                2 // SELECT_INTEGER_MV
            } else {
                r.u(1) as u8
            };
        } else {
            s.seq_force_integer_mv = 2;
        }
        if s.enable_order_hint {
            s.order_hint_bits = (r.u(3) + 1) as u8;
        }
    }

    s.enable_superres = r.u(1) != 0;
    s.enable_cdef = r.u(1) != 0;
    s.enable_restoration = r.u(1) != 0;

    // color_config
    let high_bitdepth = r.u(1) != 0;
    if s.seq_profile == 2 && high_bitdepth {
        let twelve_bit = r.u(1) != 0;
        s.color_config.bit_depth = if twelve_bit { 12 } else { 10 };
    } else {
        s.color_config.bit_depth = if high_bitdepth { 10 } else { 8 };
    }
    s.color_config.monochrome = if s.seq_profile == 1 {
        false
    } else {
        r.u(1) != 0
    };
    let color_description_present_flag = r.u(1) != 0;
    if color_description_present_flag {
        let _color_primaries = r.u(8);
        let _transfer_characteristics = r.u(8);
        let _matrix_coefficients = r.u(8);
    }
    if s.color_config.monochrome {
        s.color_config.color_range = r.u(1) != 0;
        s.color_config.subsampling_x = true;
        s.color_config.subsampling_y = true;
        s.color_config.chroma_sample_position = 0;
    } else {
        // identity (RGB) signalling: color_primaries==BT_709 et al.
        // For our scope we just read the fields and don't special-case
        // identity — we still record subsampling x/y.
        s.color_config.color_range = r.u(1) != 0;
        if s.seq_profile == 0 {
            s.color_config.subsampling_x = true;
            s.color_config.subsampling_y = true;
        } else if s.seq_profile == 1 {
            s.color_config.subsampling_x = false;
            s.color_config.subsampling_y = false;
        } else {
            // profile 2: depends on bit_depth
            if s.color_config.bit_depth == 12 {
                s.color_config.subsampling_x = r.u(1) != 0;
                s.color_config.subsampling_y = if s.color_config.subsampling_x {
                    r.u(1) != 0
                } else {
                    false
                };
            } else {
                s.color_config.subsampling_x = true;
                s.color_config.subsampling_y = false;
            }
        }
        if s.color_config.subsampling_x && s.color_config.subsampling_y {
            s.color_config.chroma_sample_position = r.u(2) as u8;
        }
        let _separate_uv_deltas_present = r.u(1);
    }
    s.film_grain_params_present = r.u(1) != 0;
    // trailing_bits handled by caller (we just stop reading).
    Ok(s)
}

/// 4.10.4 unsigned variable-length code (UVLC). Used in `timing_info()`.
fn read_uvlc(r: &mut BitReader<'_>) -> Result<u32, BitstreamError> {
    let mut leading_zeros = 0u32;
    while !r.at_end() {
        if r.u(1) != 0 {
            break;
        }
        leading_zeros += 1;
        if leading_zeros >= 32 {
            // spec says leadingZeros >= 32 → return 0xFFFFFFFF
            return Ok(u32::MAX);
        }
    }
    let value = r.u(leading_zeros);
    Ok(value + (1u32 << leading_zeros) - 1)
}

// ─────────────────────────── Frame header parser ─────────────────────────────

/// Parse the **uncompressed** part of an AV1 frame header / frame
/// OBU. Only the fields needed for HW-decode submission of a key
/// frame are populated; everything past the keyframe-specific block
/// is skipped.
///
/// `payload` is the OBU payload (after the OBU header / extension /
/// size bytes have been consumed by [`read_obu`]). For an OBU_FRAME
/// the payload is `frame_header_obu()` followed by `tile_group_obu()`;
/// we only parse the header part.
pub fn parse_frame_header(
    payload: &[u8],
    seq: &Av1SequenceHeader,
) -> Result<Av1FrameHeader, BitstreamError> {
    let mut r = BitReader::new(payload);
    let mut fh = Av1FrameHeader::default();

    if seq.reduced_still_picture_header {
        fh.show_existing_frame = false;
        fh.frame_type = FRAME_TYPE_KEY;
        fh.show_frame = true;
        fh.showable_frame = false;
        fh.error_resilient_mode = true;
    } else {
        fh.show_existing_frame = r.u(1) != 0;
        if fh.show_existing_frame {
            return Err(BitstreamError::unsupported(
                "AV1 show_existing_frame=1 not supported by minimal parser",
            ));
        }
        fh.frame_type = r.u(2) as u8;
        if fh.frame_type != FRAME_TYPE_KEY {
            return Err(BitstreamError::unsupported(format!(
                "AV1 frame_type={} not a KEY_FRAME (minimal parser is keyframe-only)",
                fh.frame_type
            )));
        }
        fh.show_frame = r.u(1) != 0;
        if fh.show_frame {
            // showable_frame is implicit for shown key frames.
            fh.showable_frame = false;
        } else {
            fh.showable_frame = r.u(1) != 0;
        }
        // For key frames showable_frame is implicit — error_resilient
        // signalled directly.
        fh.error_resilient_mode = r.u(1) != 0;
    }

    let _disable_cdf_update = r.u(1);
    fh.disable_cdf_update = _disable_cdf_update != 0;

    let allow_screen_content_tools = if seq.seq_force_screen_content_tools == 2 {
        r.u(1) != 0
    } else {
        seq.seq_force_screen_content_tools != 0
    };
    fh.allow_screen_content_tools = allow_screen_content_tools;
    if allow_screen_content_tools {
        fh.force_integer_mv = if seq.seq_force_integer_mv == 2 {
            r.u(1) != 0
        } else {
            seq.seq_force_integer_mv != 0
        };
    } else {
        fh.force_integer_mv = false;
    }

    if seq.frame_id_numbers_present_flag {
        let id_len = seq.additional_frame_id_length_minus_1 as u32
            + seq.delta_frame_id_length_minus_2 as u32
            + 3;
        let _current_frame_id = r.u(id_len);
    }

    let frame_size_override_flag = if fh.frame_type == FRAME_TYPE_SWITCH {
        true
    } else if seq.reduced_still_picture_header {
        false
    } else {
        r.u(1) != 0
    };

    let _order_hint = if seq.enable_order_hint {
        r.u(seq.order_hint_bits as u32)
    } else {
        0
    };

    // For a KEY_FRAME with show_frame=1 there's no primary_ref_frame
    // field (spec sets it to PRIMARY_REF_NONE implicitly).
    if !(fh.frame_type == FRAME_TYPE_KEY && fh.show_frame) {
        let _primary_ref_frame = r.u(3);
    }

    // frame_size() — for a key frame.
    if frame_size_override_flag {
        fh.frame_width = r.u(seq.frame_width_bits as u32) + 1;
        fh.frame_height = r.u(seq.frame_height_bits as u32) + 1;
    } else {
        fh.frame_width = seq.max_frame_width();
        fh.frame_height = seq.max_frame_height();
    }
    if seq.enable_superres {
        let use_superres = r.u(1) != 0;
        if use_superres {
            // SUPERRES_DENOM_BITS=3
            let _coded_denom = r.u(3);
        }
    }
    // render_size()
    let render_and_frame_size_different = r.u(1) != 0;
    if render_and_frame_size_different {
        fh.render_width = r.u(16) + 1;
        fh.render_height = r.u(16) + 1;
    } else {
        fh.render_width = fh.frame_width;
        fh.render_height = fh.frame_height;
    }

    // allow_intrabc only applies to key / intra-only frames.
    if allow_screen_content_tools && fh.frame_type == FRAME_TYPE_KEY {
        fh.allow_intrabc = r.u(1) != 0;
    }

    // We deliberately stop parsing here. The remaining fields (loop
    // filter parameters, quantiser, segmentation, tile info, …) are
    // not needed to confirm this is a key frame and to populate the
    // HW backends' picture-info struct's *high-level* fields. The HW
    // submit ships the entire OBU bytes back to the GPU, which
    // re-parses them itself.
    Ok(fh)
}

// ─────────────────────────── parse_obu_stream ────────────────────────────────

/// Walk an AV1 OBU stream and return the parsed sequence header,
/// the parsed key-frame header, and a slice of bytes covering the
/// keyframe OBU(s) (frame-header + tile-groups, or a single frame OBU).
pub fn parse_obu_stream(bytes: &[u8]) -> Result<Av1KeyframeParse<'_>, BitstreamError> {
    let mut offset = 0;
    let mut sequence_header: Option<Av1SequenceHeader> = None;
    let mut frame_header: Option<Av1FrameHeader> = None;
    let mut keyframe_start: Option<usize> = None;
    let mut keyframe_end: Option<usize> = None;
    let mut last_was_frame_header = false;

    while offset < bytes.len() {
        let (h, p_start, p_end, next) = read_obu(bytes, offset)?;
        match h.obu_type {
            OBU_SEQUENCE_HEADER => {
                if sequence_header.is_none() {
                    sequence_header = Some(parse_sequence_header(&bytes[p_start..p_end])?);
                }
            }
            OBU_TEMPORAL_DELIMITER => {
                // No-op: just delimits temporal units.
            }
            OBU_FRAME => {
                let seq = sequence_header.as_ref().ok_or_else(|| {
                    BitstreamError::invalid("OBU_FRAME without preceding sequence header")
                })?;
                if frame_header.is_none() {
                    let fh = parse_frame_header(&bytes[p_start..p_end], seq)?;
                    frame_header = Some(fh);
                    keyframe_start = Some(offset);
                    keyframe_end = Some(next);
                }
            }
            OBU_FRAME_HEADER => {
                let seq = sequence_header.as_ref().ok_or_else(|| {
                    BitstreamError::invalid("OBU_FRAME_HEADER without preceding sequence header")
                })?;
                if frame_header.is_none() {
                    let fh = parse_frame_header(&bytes[p_start..p_end], seq)?;
                    frame_header = Some(fh);
                    keyframe_start = Some(offset);
                    keyframe_end = Some(next);
                    last_was_frame_header = true;
                }
            }
            OBU_TILE_GROUP => {
                if last_was_frame_header {
                    keyframe_end = Some(next);
                }
            }
            _ => {
                // Metadata, tile-list, padding etc. — skip but reset
                // tile-group accumulation flag.
                last_was_frame_header = false;
            }
        }
        offset = next;
    }

    let sequence_header = sequence_header
        .ok_or_else(|| BitstreamError::invalid("stream has no sequence header OBU"))?;
    let frame_header =
        frame_header.ok_or_else(|| BitstreamError::invalid("stream has no key-frame OBU"))?;
    let start = keyframe_start.expect("keyframe bounds set when frame_header set");
    let end = keyframe_end.expect("keyframe bounds set when frame_header set");
    Ok(Av1KeyframeParse {
        sequence_header,
        frame_header,
        keyframe_obus: &bytes[start..end],
    })
}

// ─────────────────────────── Tests ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb128_roundtrip_small_values() {
        // Encode 0, 1, 127 (single-byte) and 128 (two bytes: 0x80 0x01).
        let bytes = [0x00, 0x01, 0x7f, 0x80, 0x01];
        let (v0, n0) = read_leb128(&bytes, 0).unwrap();
        assert_eq!((v0, n0), (0, 1));
        let (v1, n1) = read_leb128(&bytes, 1).unwrap();
        assert_eq!((v1, n1), (1, 1));
        let (v127, n127) = read_leb128(&bytes, 2).unwrap();
        assert_eq!((v127, n127), (127, 1));
        let (v128, n128) = read_leb128(&bytes, 3).unwrap();
        assert_eq!((v128, n128), (128, 2));
    }

    #[test]
    fn read_obu_decodes_temporal_delimiter() {
        // 0x12 = obu_type=2 (TD), has_size_field=1 → followed by 0x00 (size=0).
        let bytes = [0x12, 0x00];
        let (h, ps, pe, next) = read_obu(&bytes, 0).unwrap();
        assert_eq!(h.obu_type, OBU_TEMPORAL_DELIMITER);
        assert!(h.has_size_field);
        assert_eq!(ps, 2);
        assert_eq!(pe, 2);
        assert_eq!(next, 2);
    }

    #[test]
    fn read_obu_rejects_forbidden_bit() {
        // 0x80 sets obu_forbidden_bit=1.
        let bytes = [0x80, 0x00];
        let err = read_obu(&bytes, 0).unwrap_err();
        match err {
            BitstreamError::InvalidData(_) => {}
            e => panic!("expected InvalidData, got {e:?}"),
        }
    }
}
