//! Tiny IVF demuxer shared by the VP8 and VP9 modules.
//!
//! IVF is the container ffmpeg / libvpx use for raw VP8 / VP9
//! elementary streams when no other container is needed:
//!
//! - 32-byte global header:
//!   - bytes 0..4   `DKIF` magic
//!   - bytes 4..6   version (LE u16, must be 0)
//!   - bytes 6..8   header length (LE u16, must be 32)
//!   - bytes 8..12  codec FourCC (e.g. `VP80`, `VP90`)
//!   - bytes 12..14 width (LE u16)
//!   - bytes 14..16 height (LE u16)
//!   - bytes 16..20 framerate numerator (LE u32, ignored here)
//!   - bytes 20..24 framerate denominator (LE u32, ignored here)
//!   - bytes 24..28 frame count (LE u32, ignored here)
//!   - bytes 28..32 reserved/unused
//! - per frame: 12-byte header (LE u32 size + LE u64 timestamp)
//!   followed by the frame payload bytes.
//!
//! There is no spec PDF for IVF — it is a libvpx-historical container
//! format whose layout is publicly documented in many places
//! (Wikipedia, Matroska wiki, etc.). This module is a clean
//! reimplementation.

use crate::BitstreamError;

/// FourCC for a VP8 IVF stream.
pub const IVF_FOURCC_VP80: [u8; 4] = *b"VP80";
/// FourCC for a VP9 IVF stream.
pub const IVF_FOURCC_VP90: [u8; 4] = *b"VP90";

/// Parsed IVF global header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IvfHeader {
    pub fourcc: [u8; 4],
    pub width: u16,
    pub height: u16,
    pub framerate_num: u32,
    pub framerate_den: u32,
    pub frame_count: u32,
}

/// Borrowed view of one IVF frame.
#[derive(Debug, Clone, Copy)]
pub struct IvfFrame<'a> {
    pub timestamp: u64,
    pub payload: &'a [u8],
}

/// Parse the 32-byte IVF global header and return it together with a
/// slice positioned at the first per-frame block.
pub fn parse_header(buf: &[u8]) -> Result<(IvfHeader, &[u8]), BitstreamError> {
    if buf.len() < 32 {
        return Err(BitstreamError::unexpected_end(
            "IVF file shorter than 32-byte header",
        ));
    }
    if &buf[0..4] != b"DKIF" {
        return Err(BitstreamError::invalid(format!(
            "IVF magic mismatch: {:?}",
            &buf[0..4]
        )));
    }
    let version = u16::from_le_bytes([buf[4], buf[5]]);
    if version != 0 {
        return Err(BitstreamError::invalid(format!(
            "IVF version {version} != 0"
        )));
    }
    let header_len = u16::from_le_bytes([buf[6], buf[7]]);
    if header_len != 32 {
        return Err(BitstreamError::invalid(format!(
            "IVF header_len {header_len} != 32"
        )));
    }
    let mut fourcc = [0u8; 4];
    fourcc.copy_from_slice(&buf[8..12]);
    let header = IvfHeader {
        fourcc,
        width: u16::from_le_bytes([buf[12], buf[13]]),
        height: u16::from_le_bytes([buf[14], buf[15]]),
        framerate_num: u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
        framerate_den: u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]),
        frame_count: u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
    };
    Ok((header, &buf[32..]))
}

/// Parse the next IVF frame. Returns `Ok(None)` on EOF, `Err` on
/// truncation.
pub fn parse_frame(buf: &[u8]) -> Result<Option<(IvfFrame<'_>, &[u8])>, BitstreamError> {
    if buf.is_empty() {
        return Ok(None);
    }
    if buf.len() < 12 {
        return Err(BitstreamError::unexpected_end("truncated IVF frame header"));
    }
    let size = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let timestamp = u64::from_le_bytes([
        buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
    ]);
    if buf.len() < 12 + size {
        return Err(BitstreamError::unexpected_end(
            "truncated IVF frame payload",
        ));
    }
    let payload = &buf[12..12 + size];
    let rest = &buf[12 + size..];
    Ok(Some((IvfFrame { timestamp, payload }, rest)))
}

/// Convenience: parse the entire IVF (header + every frame) into a
/// single [`IvfHeader`] plus a `Vec<IvfFrame>`.
pub fn parse_all(buf: &[u8]) -> Result<(IvfHeader, Vec<IvfFrame<'_>>), BitstreamError> {
    let (hdr, mut rest) = parse_header(buf)?;
    let mut frames = Vec::new();
    while let Some((frame, next)) = parse_frame(rest)? {
        frames.push(frame);
        rest = next;
    }
    Ok((hdr, frames))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_ivf(fourcc: &[u8; 4]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"DKIF");
        buf.extend_from_slice(&0u16.to_le_bytes()); // version
        buf.extend_from_slice(&32u16.to_le_bytes()); // header_len
        buf.extend_from_slice(fourcc);
        buf.extend_from_slice(&320u16.to_le_bytes()); // width
        buf.extend_from_slice(&240u16.to_le_bytes()); // height
        buf.extend_from_slice(&1u32.to_le_bytes()); // num
        buf.extend_from_slice(&1u32.to_le_bytes()); // den
        buf.extend_from_slice(&0u32.to_le_bytes()); // count
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
        buf
    }

    #[test]
    fn parse_header_extracts_basic_fields() {
        let buf = synth_ivf(&IVF_FOURCC_VP80);
        let (h, rest) = parse_header(&buf).unwrap();
        assert_eq!(&h.fourcc, &IVF_FOURCC_VP80);
        assert_eq!(h.width, 320);
        assert_eq!(h.height, 240);
        assert_eq!(rest.len(), 0);
    }

    #[test]
    fn parse_header_rejects_bad_magic() {
        let mut buf = synth_ivf(&IVF_FOURCC_VP80);
        buf[0] = b'X';
        assert!(matches!(
            parse_header(&buf),
            Err(BitstreamError::InvalidData(_))
        ));
    }

    #[test]
    fn parse_header_rejects_short_input() {
        let buf = vec![0u8; 16];
        assert!(matches!(
            parse_header(&buf),
            Err(BitstreamError::UnexpectedEnd(_))
        ));
    }

    #[test]
    fn parse_frame_reads_payload_and_advances() {
        let mut buf = synth_ivf(&IVF_FOURCC_VP90);
        // 5-byte payload, ts = 7.
        buf.extend_from_slice(&5u32.to_le_bytes());
        buf.extend_from_slice(&7u64.to_le_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4, 5]);
        let (_h, body) = parse_header(&buf).unwrap();
        let (frame, rest) = parse_frame(body).unwrap().unwrap();
        assert_eq!(frame.timestamp, 7);
        assert_eq!(frame.payload, &[1, 2, 3, 4, 5]);
        assert!(rest.is_empty());
        assert!(parse_frame(rest).unwrap().is_none());
    }

    #[test]
    fn parse_frame_rejects_truncated_payload() {
        let mut buf = synth_ivf(&IVF_FOURCC_VP90);
        buf.extend_from_slice(&5u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&[1, 2]); // less than declared 5 bytes
        let (_h, body) = parse_header(&buf).unwrap();
        assert!(matches!(
            parse_frame(body),
            Err(BitstreamError::UnexpectedEnd(_))
        ));
    }
}
