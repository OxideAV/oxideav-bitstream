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

/// Largest `u64` representable as an AV1 §4.10 leb128 code. The spec
/// caps the encoding at 8 bytes, each contributing 7 payload bits, so
/// values up to `2^56 - 1` round-trip. [`write_leb128`] refuses any
/// value above this bound.
pub const LEB128_MAX: u64 = (1u64 << 56) - 1;

/// 4.10 leb128 writer — the inverse of [`read_leb128`].
///
/// Appends the minimal-length unsigned LEB128 encoding of `value` to
/// `out` and returns the number of bytes written. Round-trip contract:
/// the suffix `&out[start..start + n]` (where `start` is `out.len()`
/// before the call and `n` is the returned length) feeds back through
/// [`read_leb128`] as `(value, n)`.
///
/// AV1 caps a leb128 code at 8 bytes (56 bits of payload). Values
/// above [`LEB128_MAX`] are rejected with
/// [`BitstreamError::InvalidData`] rather than silently truncated, so
/// the round-trip contract holds for every accepted input.
pub fn write_leb128(out: &mut Vec<u8>, value: u64) -> Result<usize, BitstreamError> {
    if value > LEB128_MAX {
        return Err(BitstreamError::invalid(
            "write_leb128: value exceeds AV1 §4.10 56-bit leb128 limit",
        ));
    }
    let mut v = value;
    let mut n = 0usize;
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
            out.push(byte);
            n += 1;
        } else {
            out.push(byte);
            n += 1;
            return Ok(n);
        }
    }
}

/// 5.3.2 caps `obu_type` at 4 bits.
pub const OBU_TYPE_MAX: u8 = 0xf;
/// 5.3.3 caps `temporal_id` at 3 bits.
pub const OBU_TEMPORAL_ID_MAX: u8 = 0x7;
/// 5.3.3 caps `spatial_id` at 2 bits.
pub const OBU_SPATIAL_ID_MAX: u8 = 0x3;

/// 5.3.1 OBU emitter — the inverse of [`read_obu`].
///
/// Appends `obu_header [obu_extension_header] obu_size payload` to `out`,
/// returning `(start, end)` where the slice `&out[start..end]` is the
/// fully-framed OBU. Round-trip contract: feeding `start` back through
/// [`read_obu`] reproduces the same [`ObuHeader`], a payload range of
/// `(payload_start, payload_end)` covering exactly `payload.len()`
/// bytes, and `next_offset == end`.
///
/// Requirements (per the reader's contract and AV1 §5.3.1 LOBF):
///
/// * `header.has_size_field` must be `true`. The Low-Overhead-Bitstream
///   Format mandates `obu_has_size_field=1` for every OBU; [`read_obu`]
///   refuses anything else, so the writer mirrors that.
/// * `header.obu_type` must be ≤ [`OBU_TYPE_MAX`] (4 bits).
/// * `header.temporal_id` must be ≤ [`OBU_TEMPORAL_ID_MAX`] (3 bits) and
///   `header.spatial_id` ≤ [`OBU_SPATIAL_ID_MAX`] (2 bits). These checks
///   apply unconditionally — the reader zero-fills both fields when
///   `extension_flag` is clear, so out-of-range values silently lose
///   information without this guard.
/// * `payload.len()` must be ≤ [`LEB128_MAX`] so the size field fits in
///   the spec's eight-byte cap.
///
/// On any validation failure, `out` is left untouched (no partial OBU
/// header is appended) and the call returns [`BitstreamError::InvalidData`].
/// The forbidden bit and the trailing reserved bits in both header bytes
/// are always emitted as zero, matching §5.3.2 / §5.3.3.
pub fn write_obu(
    out: &mut Vec<u8>,
    header: ObuHeader,
    payload: &[u8],
) -> Result<(usize, usize), BitstreamError> {
    if !header.has_size_field {
        return Err(BitstreamError::invalid(
            "write_obu: LOBF requires obu_has_size_field=1",
        ));
    }
    if header.obu_type > OBU_TYPE_MAX {
        return Err(BitstreamError::invalid(
            "write_obu: obu_type exceeds 4-bit field",
        ));
    }
    if header.extension_flag {
        if header.temporal_id > OBU_TEMPORAL_ID_MAX {
            return Err(BitstreamError::invalid(
                "write_obu: temporal_id exceeds 3-bit field",
            ));
        }
        if header.spatial_id > OBU_SPATIAL_ID_MAX {
            return Err(BitstreamError::invalid(
                "write_obu: spatial_id exceeds 2-bit field",
            ));
        }
    } else if header.temporal_id != 0 || header.spatial_id != 0 {
        // The reader returns (0, 0) when extension_flag is clear; refuse
        // non-zero IDs paired with extension_flag=false so the round-trip
        // is total — the caller would otherwise silently lose the IDs.
        return Err(BitstreamError::invalid(
            "write_obu: temporal/spatial_id set with extension_flag=0",
        ));
    }
    if payload.len() as u64 > LEB128_MAX {
        return Err(BitstreamError::invalid(
            "write_obu: payload length exceeds AV1 §4.10 56-bit leb128 limit",
        ));
    }

    let start = out.len();
    // OBU header byte: obu_forbidden_bit (1) | obu_type (4) |
    // obu_extension_flag (1) | obu_has_size_field (1) | obu_reserved_1bit (1).
    let mut h = (header.obu_type & OBU_TYPE_MAX) << 3;
    if header.extension_flag {
        h |= 1 << 2;
    }
    // has_size_field is true by precondition above.
    h |= 1 << 1;
    out.push(h);
    if header.extension_flag {
        // Extension byte: temporal_id (3) | spatial_id (2) |
        // extension_header_reserved_3bits (3).
        let e = ((header.temporal_id & OBU_TEMPORAL_ID_MAX) << 5)
            | ((header.spatial_id & OBU_SPATIAL_ID_MAX) << 3);
        out.push(e);
    }
    // §4.10 leb128 encoding of obu_size. write_leb128 has already been
    // bounds-checked above so this cannot Err — but if it ever did
    // (e.g. the cap moved), truncate back to the original buffer length
    // so the "untouched on rejection" contract still holds.
    if let Err(e) = write_leb128(out, payload.len() as u64) {
        out.truncate(start);
        return Err(e);
    }
    out.extend_from_slice(payload);
    Ok((start, out.len()))
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
                // uvlc() per §4.10.3 — shared BitReader descriptor.
                let _num_ticks_per_picture_minus_1 = r.uvlc();
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
    fn write_leb128_encodes_minimal_known_values() {
        // 0 → 0x00 (1 byte), 1 → 0x01, 127 → 0x7f.
        let mut out = Vec::new();
        assert_eq!(write_leb128(&mut out, 0).unwrap(), 1);
        assert_eq!(out.as_slice(), &[0x00]);
        out.clear();
        assert_eq!(write_leb128(&mut out, 1).unwrap(), 1);
        assert_eq!(out.as_slice(), &[0x01]);
        out.clear();
        assert_eq!(write_leb128(&mut out, 127).unwrap(), 1);
        assert_eq!(out.as_slice(), &[0x7f]);
        // 128 → 0x80, 0x01 (2 bytes).
        out.clear();
        assert_eq!(write_leb128(&mut out, 128).unwrap(), 2);
        assert_eq!(out.as_slice(), &[0x80, 0x01]);
        // 16384 → 0x80, 0x80, 0x01 (3 bytes).
        out.clear();
        assert_eq!(write_leb128(&mut out, 16384).unwrap(), 3);
        assert_eq!(out.as_slice(), &[0x80, 0x80, 0x01]);
    }

    #[test]
    fn write_leb128_appends_without_clobbering() {
        // The writer is documented to append; pre-existing prefix bytes
        // must be preserved so the caller can frame an OBU header + size
        // pair into the same buffer.
        let mut out = vec![0xAA, 0xBB];
        let n = write_leb128(&mut out, 300).unwrap();
        assert_eq!(out[0..2], [0xAA, 0xBB]);
        let (val, consumed) = read_leb128(&out, 2).unwrap();
        assert_eq!(val, 300);
        assert_eq!(consumed, n);
        // 300 = 0x12C → 0xAC, 0x02 (two bytes).
        assert_eq!(out[2..], [0xAC, 0x02]);
    }

    #[test]
    fn write_leb128_at_maximum_value_emits_eight_bytes() {
        let mut out = Vec::new();
        let n = write_leb128(&mut out, LEB128_MAX).unwrap();
        assert_eq!(n, 8);
        assert_eq!(out.len(), 8);
        // All payload nibbles are 0x7f; continuation bits set on bytes
        // 0..6, cleared on byte 7.
        assert_eq!(out[0..7], [0xff; 7]);
        assert_eq!(out[7], 0x7f);
        let (val, consumed) = read_leb128(&out, 0).unwrap();
        assert_eq!(val, LEB128_MAX);
        assert_eq!(consumed, 8);
    }

    #[test]
    fn write_leb128_rejects_over_56_bits() {
        let mut out = Vec::new();
        // LEB128_MAX is the largest representable value; the next one up
        // would need a ninth byte, which read_leb128 refuses.
        let err = write_leb128(&mut out, LEB128_MAX + 1).unwrap_err();
        assert!(
            matches!(err, BitstreamError::InvalidData(_)),
            "expected InvalidData, got {err:?}"
        );
        // u64::MAX is also out of range.
        let err = write_leb128(&mut out, u64::MAX).unwrap_err();
        assert!(matches!(err, BitstreamError::InvalidData(_)));
        // Buffer is left untouched on rejection.
        assert!(out.is_empty());
    }

    #[test]
    fn write_leb128_round_trips_against_read() {
        // Spot-check a spread of values covering the 1-byte, 2-byte,
        // 3-byte, …, 8-byte size classes plus byte-boundary neighbours.
        let cases: &[u64] = &[
            0,
            1,
            127,
            128,
            16_383,
            16_384,
            2_097_151,
            2_097_152,
            268_435_455,
            268_435_456,
            34_359_738_367,
            34_359_738_368,
            4_398_046_511_103,
            4_398_046_511_104,
            562_949_953_421_311,
            LEB128_MAX,
        ];
        for &v in cases {
            let mut buf = Vec::new();
            let n = write_leb128(&mut buf, v).unwrap();
            assert_eq!(buf.len(), n, "writer length matches returned size");
            let (got, consumed) = read_leb128(&buf, 0).unwrap();
            assert_eq!(got, v, "round-trip value for {v}");
            assert_eq!(consumed, n, "round-trip byte count for {v}");
        }
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

    fn td_header() -> ObuHeader {
        ObuHeader {
            obu_type: OBU_TEMPORAL_DELIMITER,
            extension_flag: false,
            has_size_field: true,
            temporal_id: 0,
            spatial_id: 0,
        }
    }

    #[test]
    fn write_obu_emits_empty_temporal_delimiter_canonically() {
        // A TD OBU with no extension and zero payload is exactly two
        // bytes: 0x12 (type=2, has_size=1) and 0x00 (size=0). This
        // matches the canonical fixture used in `read_obu_decodes_*`.
        let mut out = Vec::new();
        let (start, end) = write_obu(&mut out, td_header(), &[]).unwrap();
        assert_eq!(start, 0);
        assert_eq!(end, 2);
        assert_eq!(out.as_slice(), &[0x12, 0x00]);
    }

    #[test]
    fn write_obu_round_trips_through_read_obu() {
        // Build a frame-shaped OBU with a payload of varying sizes and
        // confirm read_obu reproduces every header field plus the
        // payload range exactly.
        for &len in &[0usize, 1, 16, 127, 128, 1024] {
            let payload: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
            let header = ObuHeader {
                obu_type: OBU_FRAME,
                extension_flag: false,
                has_size_field: true,
                temporal_id: 0,
                spatial_id: 0,
            };
            let mut out = Vec::new();
            let (start, end) = write_obu(&mut out, header, &payload).unwrap();
            let (got, p_start, p_end, next) = read_obu(&out, start).unwrap();
            assert_eq!(got, header, "header round-trip for len={len}");
            assert_eq!(p_end - p_start, len);
            assert_eq!(&out[p_start..p_end], payload.as_slice());
            assert_eq!(next, end);
        }
    }

    #[test]
    fn write_obu_extension_byte_round_trips_ids() {
        // Sweep every legal (temporal_id, spatial_id) pair through
        // extension_flag=true and confirm the extension byte decodes
        // back to the same IDs.
        for t in 0..=OBU_TEMPORAL_ID_MAX {
            for s in 0..=OBU_SPATIAL_ID_MAX {
                let header = ObuHeader {
                    obu_type: OBU_FRAME_HEADER,
                    extension_flag: true,
                    has_size_field: true,
                    temporal_id: t,
                    spatial_id: s,
                };
                let payload = [0xaa, 0xbb, 0xcc];
                let mut out = Vec::new();
                let (start, _end) = write_obu(&mut out, header, &payload).unwrap();
                let (got, p_start, p_end, _next) = read_obu(&out, start).unwrap();
                assert_eq!(got.temporal_id, t, "t={t} s={s}");
                assert_eq!(got.spatial_id, s, "t={t} s={s}");
                assert!(got.extension_flag);
                assert_eq!(&out[p_start..p_end], &payload);
            }
        }
    }

    #[test]
    fn write_obu_appends_after_existing_prefix() {
        // The writer is documented to append: a pre-existing prefix in
        // `out` must be preserved so callers can concatenate multiple
        // OBUs into one temporal-unit buffer.
        let mut out = vec![0xde, 0xad, 0xbe, 0xef];
        let (start, end) = write_obu(&mut out, td_header(), &[]).unwrap();
        assert_eq!(start, 4);
        assert_eq!(end, 6);
        assert_eq!(&out[0..4], &[0xde, 0xad, 0xbe, 0xef]);
        let (got, _, _, next) = read_obu(&out, start).unwrap();
        assert_eq!(got.obu_type, OBU_TEMPORAL_DELIMITER);
        assert_eq!(next, end);
    }

    #[test]
    fn write_obu_rejects_no_size_field() {
        let mut h = td_header();
        h.has_size_field = false;
        let mut out = Vec::new();
        let err = write_obu(&mut out, h, &[]).unwrap_err();
        assert!(matches!(err, BitstreamError::InvalidData(_)));
        assert!(out.is_empty(), "rejected write must not append");
    }

    #[test]
    fn write_obu_rejects_oversized_obu_type() {
        let mut h = td_header();
        h.obu_type = 16; // 4-bit field max is 15
        let mut out = Vec::new();
        assert!(matches!(
            write_obu(&mut out, h, &[]),
            Err(BitstreamError::InvalidData(_))
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn write_obu_rejects_oversized_ids() {
        // temporal_id > 7 with extension_flag=true.
        let mut h = ObuHeader {
            obu_type: OBU_FRAME,
            extension_flag: true,
            has_size_field: true,
            temporal_id: 8,
            spatial_id: 0,
        };
        let mut out = Vec::new();
        assert!(matches!(
            write_obu(&mut out, h, &[]),
            Err(BitstreamError::InvalidData(_))
        ));
        assert!(out.is_empty());
        // spatial_id > 3 with extension_flag=true.
        h.temporal_id = 0;
        h.spatial_id = 4;
        assert!(matches!(
            write_obu(&mut out, h, &[]),
            Err(BitstreamError::InvalidData(_))
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn write_obu_rejects_nonzero_ids_without_extension_flag() {
        // The reader returns (0, 0) for both IDs when extension_flag is
        // clear; pairing non-zero IDs with extension_flag=false would
        // silently lose them, so the writer refuses it for round-trip
        // soundness.
        let mut h = td_header();
        h.temporal_id = 1;
        let mut out = Vec::new();
        assert!(matches!(
            write_obu(&mut out, h, &[]),
            Err(BitstreamError::InvalidData(_))
        ));
        assert!(out.is_empty());

        let mut h = td_header();
        h.spatial_id = 1;
        assert!(matches!(
            write_obu(&mut out, h, &[]),
            Err(BitstreamError::InvalidData(_))
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn write_obu_accepts_max_legal_ids() {
        let header = ObuHeader {
            obu_type: OBU_TYPE_MAX,
            extension_flag: true,
            has_size_field: true,
            temporal_id: OBU_TEMPORAL_ID_MAX,
            spatial_id: OBU_SPATIAL_ID_MAX,
        };
        let mut out = Vec::new();
        let (start, _) = write_obu(&mut out, header, &[]).unwrap();
        let (got, _, _, _) = read_obu(&out, start).unwrap();
        assert_eq!(got, header);
    }

    #[test]
    fn write_obu_emits_multi_byte_leb128_size() {
        // payload.len() = 128 needs a 2-byte leb128 size (0x80, 0x01).
        // Confirms the writer's size-field encoding is delegated to
        // write_leb128 correctly.
        let payload = vec![0u8; 128];
        let mut out = Vec::new();
        let (_start, end) = write_obu(&mut out, td_header(), &payload).unwrap();
        // header byte + 2-byte size + 128-byte payload = 131 bytes.
        assert_eq!(end, 1 + 2 + 128);
        assert_eq!(out[0], 0x12);
        assert_eq!(out[1], 0x80);
        assert_eq!(out[2], 0x01);
        assert_eq!(&out[3..], payload.as_slice());
    }

    #[test]
    fn write_obu_concatenates_into_obu_stream() {
        // Build a TD + SequenceHeader-shaped stream by appending two
        // OBUs to the same buffer, then walk the result with read_obu.
        let mut out = Vec::new();
        let (s1, e1) = write_obu(&mut out, td_header(), &[]).unwrap();
        let seq_header = ObuHeader {
            obu_type: OBU_SEQUENCE_HEADER,
            extension_flag: false,
            has_size_field: true,
            temporal_id: 0,
            spatial_id: 0,
        };
        let seq_payload = [0x11, 0x22, 0x33, 0x44];
        let (s2, e2) = write_obu(&mut out, seq_header, &seq_payload).unwrap();
        assert_eq!(s2, e1, "second OBU starts where the first ended");
        assert_eq!(e2, out.len());

        let (h1, _, _, n1) = read_obu(&out, s1).unwrap();
        assert_eq!(h1.obu_type, OBU_TEMPORAL_DELIMITER);
        assert_eq!(n1, s2);
        let (h2, ps2, pe2, n2) = read_obu(&out, n1).unwrap();
        assert_eq!(h2.obu_type, OBU_SEQUENCE_HEADER);
        assert_eq!(&out[ps2..pe2], &seq_payload);
        assert_eq!(n2, e2);
    }
}
