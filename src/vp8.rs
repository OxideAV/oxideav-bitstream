//! VP8 keyframe header parsing (RFC 6386).
//!
//! VP8 keyframes contain a 3-byte uncompressed bit-packed header
//! followed (for keyframes only) by a 7-byte uncompressed-data-chunk
//! that carries the start code and frame dimensions, followed by the
//! arithmetic-coded compressed bitstream. Decoding the compressed
//! bitstream requires a boolean entropy coder and several thousand
//! lines of decoder logic — that is the GPU's job, not ours.
//!
//! This module surfaces only the **uncompressed** parts. They are
//! enough to populate any of the slice-data HW backends' VP8
//! parameter buffers (`VAPictureParameterBufferVP8`, NVDEC's VP8
//! parameter struct, …).
//!
//! # Bit ordering
//!
//! VP8 is unusual: the first 3 bytes are read **byte-by-byte
//! little-endian, with each byte read least-significant-bit first**.
//! See RFC 6386 §9.1: the field order in the spec is
//!
//!   frame_type        (1 bit)  bit 0 of byte 0
//!   version           (3 bits) bits 1..3 of byte 0
//!   show_frame        (1 bit)  bit 4 of byte 0
//!   first_part_size  (19 bits) bits 5..23 (spans bytes 0, 1, 2)
//!
//! When this packing is interpreted as a single 24-bit
//! little-endian value, the field offsets are LSB-first and the
//! whole header decodes via shift-and-mask.
//!
//! For keyframes (`frame_type == 0`), the next 7 bytes are:
//!
//!   start code        (3 bytes, must be `0x9D 0x01 0x2A`)
//!   width + h-scale   (2 bytes, LE u16: low 14 bits = width,
//!                                top 2 bits = horizontal_scale)
//!   height + v-scale  (2 bytes, LE u16: same layout for height /
//!                                vertical_scale)
//!
//! After the uncompressed-data-chunk, the remaining bytes are the
//! arithmetic-coded compressed bitstream.

use crate::BitstreamError;

/// VP8 keyframe start code (RFC 6386 §9.1).
pub const VP8_KEYFRAME_START_CODE: [u8; 3] = [0x9D, 0x01, 0x2A];

/// Output of the VP8 uncompressed-header parsers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Vp8FrameHeader {
    /// 0 = keyframe (RFC 6386 calls this KEY_FRAME), 1 = interframe.
    pub frame_type: u8,
    /// Bitstream version (0..3). RFC 6386 §9.1 — only 0 is in
    /// widespread use; libvpx may emit 1, 2 or 3 to select the
    /// loop-filter / motion-comp tweaks.
    pub version: u8,
    /// `show_frame` bit. False here means the encoder emitted an
    /// alternate-reference frame that should not be rendered.
    pub show_frame: bool,
    /// `first_part_size` — length in bytes of the compressed
    /// "first partition" (the partition that holds the bool-coded
    /// frame header + per-MB modes, before the residual partitions).
    pub first_part_size: u32,
    /// Coded width in luma samples (keyframes only — 0 on
    /// interframes since RFC 6386 only re-transmits dimensions for
    /// keyframes).
    pub width: u32,
    /// Coded height in luma samples (keyframes only).
    pub height: u32,
    /// `horizontal_scale` — 0 means no horizontal upscale at display.
    pub horizontal_scale: u8,
    /// `vertical_scale` — 0 means no vertical upscale at display.
    pub vertical_scale: u8,
}

/// Parse the uncompressed parts of a VP8 frame header (keyframe or
/// interframe).
pub fn parse_frame_header(stream: &[u8]) -> Result<Vp8FrameHeader, BitstreamError> {
    if stream.len() < 3 {
        return Err(BitstreamError::unexpected_end("VP8 frame shorter than 3 bytes"));
    }
    // The 3-byte tag is interpreted as a 24-bit little-endian word
    // and the fields are extracted LSB-first per RFC 6386 §9.1.
    let tag = (stream[0] as u32) | ((stream[1] as u32) << 8) | ((stream[2] as u32) << 16);
    let frame_type = (tag & 0x1) as u8;
    let version = ((tag >> 1) & 0x7) as u8;
    let show_frame = ((tag >> 4) & 0x1) != 0;
    let first_part_size = (tag >> 5) & 0x7_FFFF;

    let mut hdr = Vp8FrameHeader {
        frame_type,
        version,
        show_frame,
        first_part_size,
        ..Vp8FrameHeader::default()
    };

    if frame_type == 0 {
        // Keyframe: 3-byte start code + 4-byte size word.
        if stream.len() < 10 {
            return Err(BitstreamError::unexpected_end(
                "VP8 keyframe shorter than 10-byte uncompressed-data-chunk",
            ));
        }
        if stream[3..6] != VP8_KEYFRAME_START_CODE {
            return Err(BitstreamError::invalid(format!(
                "VP8 keyframe start-code mismatch: {:02x?} != 9d 01 2a",
                &stream[3..6]
            )));
        }
        let w_word = u16::from_le_bytes([stream[6], stream[7]]) as u32;
        let h_word = u16::from_le_bytes([stream[8], stream[9]]) as u32;
        hdr.width = w_word & 0x3FFF;
        hdr.horizontal_scale = ((w_word >> 14) & 0x3) as u8;
        hdr.height = h_word & 0x3FFF;
        hdr.vertical_scale = ((h_word >> 14) & 0x3) as u8;
    }

    Ok(hdr)
}

/// Parse a keyframe header. Errors out if `frame_type != 0` (not a
/// keyframe) or any required byte is missing.
pub fn parse_keyframe(stream: &[u8]) -> Result<Vp8FrameHeader, BitstreamError> {
    let hdr = parse_frame_header(stream)?;
    if hdr.frame_type != 0 {
        return Err(BitstreamError::invalid(format!(
            "expected VP8 keyframe (frame_type=0), got frame_type={}",
            hdr.frame_type
        )));
    }
    Ok(hdr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_frame_header_decodes_synthetic_keyframe() {
        // Build a synthetic 3-byte tag: frame_type=0, version=0,
        // show_frame=1, first_part_size=42.
        let first_part_size: u32 = 42;
        let tag: u32 = 0 | (0 << 1) | (1 << 4) | (first_part_size << 5);
        let mut stream = vec![
            (tag & 0xff) as u8,
            ((tag >> 8) & 0xff) as u8,
            ((tag >> 16) & 0xff) as u8,
        ];
        // Keyframe extension: start code + width=8, h_scale=0, height=8, v_scale=0.
        stream.extend_from_slice(&VP8_KEYFRAME_START_CODE);
        stream.extend_from_slice(&8u16.to_le_bytes());
        stream.extend_from_slice(&8u16.to_le_bytes());

        let h = parse_frame_header(&stream).unwrap();
        assert_eq!(h.frame_type, 0);
        assert_eq!(h.version, 0);
        assert!(h.show_frame);
        assert_eq!(h.first_part_size, 42);
        assert_eq!(h.width, 8);
        assert_eq!(h.height, 8);
        assert_eq!(h.horizontal_scale, 0);
        assert_eq!(h.vertical_scale, 0);
    }

    #[test]
    fn parse_keyframe_rejects_interframe_tag() {
        // frame_type bit set → interframe.
        let stream = [0x01u8, 0x00, 0x00];
        assert!(matches!(
            parse_keyframe(&stream),
            Err(BitstreamError::InvalidData(_))
        ));
    }

    #[test]
    fn parse_keyframe_rejects_bad_start_code() {
        let mut stream = vec![0x10u8, 0x00, 0x00]; // tag: keyframe
        stream.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // bad start code
        stream.extend_from_slice(&8u16.to_le_bytes());
        stream.extend_from_slice(&8u16.to_le_bytes());
        assert!(matches!(
            parse_frame_header(&stream),
            Err(BitstreamError::InvalidData(_))
        ));
    }

    #[test]
    fn parse_frame_header_rejects_short_input() {
        let stream = [0u8, 0u8];
        assert!(matches!(
            parse_frame_header(&stream),
            Err(BitstreamError::UnexpectedEnd(_))
        ));
    }
}
