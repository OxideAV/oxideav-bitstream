//! Minimal IDR / keyframe header parsing for H.264, HEVC and AV1.
//!
//! This crate is the parser layer that the oxideav HW-accel bridge
//! crates (`oxideav-vaapi`, `oxideav-vdpau`, `oxideav-vulkan-video`)
//! call before submitting parameter buffers to the GPU. It is **not**
//! a full codec: there is no DCT, no entropy decode, no inverse
//! transform, no motion compensation. Just enough syntax parsing to
//! populate `VAPictureParameterBufferH264` / `VdpPictureInfoH264` /
//! `VkVideoDecodeH264PictureInfoKHR` and the equivalents for HEVC and
//! AV1.
//!
//! Each codec lives in its own module:
//!
//! - [`h264`] — Annex-B framing, SPS, PPS and minimal slice header.
//! - [`hevc`] — Annex-B framing, VPS, SPS, PPS and minimal slice
//!   segment header.
//! - [`h266`] — Annex-B framing, 2-byte NAL header decode, VCL /
//!   IRAP / parameter-set classifiers, structural VPS / SPS / PPS
//!   parsers, the picture-header structural prefix
//!   (7.3.2.8 through `ph_pic_parameter_set_id`) and an SPS-context
//!   PH variant (`parse_picture_header_with_sps`) that extends through
//!   `ph_pic_order_cnt_lsb` u(v) and `ph_recovery_poc_cnt` ue(v).
//! - [`av1`] — leb128 reader/writer, OBU walker + emitter, sequence
//!   header and key-frame OBU parsing.
//!
//! There is no shared cross-codec abstraction in v0 — each module
//! exposes its own `parse_*` entry points and result structs. The
//! shared [`bit_reader::BitReader`] type provides `u(n)`, `ue(v)`,
//! `se(v)`, `i(n)`, `te(v)` and `ns(n)` primitives;
//! [`bit_writer::BitWriter`] is its MSB-first inverse for emitting
//! the same fields back out. Byte-level NAL
//! framing helpers (the `emulation_prevention_three_byte` stripper
//! and its inverse inserter, shared identically across H.264, HEVC
//! and H.266) live in [`nal`].
//!
//! ## No `unsafe`
//!
//! This crate contains zero `unsafe` blocks. Bit reading is software,
//! no FFI involved.
//!
//! ## Workspace clean-room policy
//!
//! Bitstream syntax is taken from the relevant ITU-T / Khronos /
//! AOMedia spec PDFs only. We deliberately do not consult ffmpeg /
//! libavcodec, x264, x265, libde265, libaom, dav1d, rav1e or libgav1
//! source. ffmpeg / aomenc are used only as black-box CLI tools to
//! generate test fixtures.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod av1;
pub mod bit_reader;
pub mod bit_writer;
pub mod h264;
pub mod h266;
pub mod hevc;
pub mod ivf;
pub mod mpeg2;
pub mod nal;
pub mod vc1;
pub mod vp8;
pub mod vp9;

/// Errors produced by the parsers in this crate.
///
/// We deliberately do not depend on `oxideav_core::Error` — keeping
/// this crate dep-free means `oxideav-vdpau` / `oxideav-vaapi` /
/// `oxideav-vulkan-video` can pull it in without tugging on the rest
/// of the framework.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitstreamError {
    /// The byte stream ended in the middle of a header we expected
    /// to be complete (NAL too short, OBU truncated, etc.).
    UnexpectedEnd(String),

    /// Syntax error inside an otherwise well-framed header (an
    /// Exp-Golomb code with too many leading zeros, an out-of-range
    /// field value, a forbidden bit set, …).
    InvalidData(String),

    /// The input parses successfully but uses a feature this crate
    /// deliberately does not handle (scaling lists, FMO, AV1 film
    /// grain, …). HW backends should reject the fixture rather than
    /// submit a partial parameter buffer.
    Unsupported(String),
}

impl core::fmt::Display for BitstreamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BitstreamError::UnexpectedEnd(msg) => write!(f, "unexpected end of stream: {msg}"),
            BitstreamError::InvalidData(msg) => write!(f, "invalid bitstream data: {msg}"),
            BitstreamError::Unsupported(msg) => write!(f, "unsupported bitstream feature: {msg}"),
        }
    }
}

impl std::error::Error for BitstreamError {}

impl BitstreamError {
    pub fn invalid(msg: impl Into<String>) -> Self {
        BitstreamError::InvalidData(msg.into())
    }

    pub fn unsupported(msg: impl Into<String>) -> Self {
        BitstreamError::Unsupported(msg.into())
    }

    pub fn unexpected_end(msg: impl Into<String>) -> Self {
        BitstreamError::UnexpectedEnd(msg.into())
    }
}
