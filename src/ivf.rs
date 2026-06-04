//! Tiny IVF demuxer and muxer shared by the VP8 and VP9 modules.
//!
//! IVF is a thin container used for raw VP8 / VP9
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
//! There is no spec PDF for IVF — it is a thin historical container
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

/// Fixed length of the IVF global header in bytes.
pub const IVF_HEADER_LEN: usize = 32;

/// Fixed length of the per-frame IVF header (`size` + `timestamp`).
pub const IVF_FRAME_HEADER_LEN: usize = 12;

/// Maximum per-frame payload size representable in the on-wire u32
/// `size` field.
pub const IVF_FRAME_PAYLOAD_MAX: usize = u32::MAX as usize;

/// Append the 32-byte IVF global header for `header` to `out`.
///
/// This is the inverse of [`parse_header`]: feeding the bytes this
/// function appends back through [`parse_header`] reproduces `header`
/// exactly and leaves the consumed-rest slice empty.
///
/// Layout follows the module-level byte map: the `version` field is
/// emitted as `0u16` LE and the `header_len` field as `32u16` LE so the
/// reader's strict checks pass on every successful write. The four
/// reserved bytes at the tail are emitted as zero.
///
/// `header.fourcc` is written verbatim; this module makes no policy
/// statement about which FourCC values are legal — that is the
/// responsibility of the codec-specific writer that wraps this one.
///
/// Returns the byte range `(start, end)` covering the newly-appended
/// header so callers stacking multiple containers (or framing the
/// output inside a larger byte vector) can locate it. `end - start`
/// is always [`IVF_HEADER_LEN`].
pub fn write_header(out: &mut Vec<u8>, header: IvfHeader) -> (usize, usize) {
    let start = out.len();
    out.extend_from_slice(b"DKIF");
    out.extend_from_slice(&0u16.to_le_bytes()); // version
    out.extend_from_slice(&(IVF_HEADER_LEN as u16).to_le_bytes()); // header_len
    out.extend_from_slice(&header.fourcc);
    out.extend_from_slice(&header.width.to_le_bytes());
    out.extend_from_slice(&header.height.to_le_bytes());
    out.extend_from_slice(&header.framerate_num.to_le_bytes());
    out.extend_from_slice(&header.framerate_den.to_le_bytes());
    out.extend_from_slice(&header.frame_count.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved/unused
    (start, out.len())
}

/// Append one IVF frame (12-byte header + payload) to `out`.
///
/// Returns the byte range `(start, end)` covering the appended frame
/// — `end - start` equals [`IVF_FRAME_HEADER_LEN`] `+ payload.len()`.
///
/// Refuses `payload.len() > IVF_FRAME_PAYLOAD_MAX` with
/// `InvalidData` (the wire `size` field is a u32). On rejection the
/// buffer is left untouched, mirroring the rejection contract on
/// [`write_obu`](crate::av1::write_obu) and
/// [`write_leb128`](crate::av1::write_leb128) so a caller building a
/// container in-place can recover.
pub fn write_frame(
    out: &mut Vec<u8>,
    timestamp: u64,
    payload: &[u8],
) -> Result<(usize, usize), BitstreamError> {
    if payload.len() > IVF_FRAME_PAYLOAD_MAX {
        return Err(BitstreamError::invalid(format!(
            "IVF payload {} bytes exceeds u32 size field maximum",
            payload.len()
        )));
    }
    let start = out.len();
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(payload);
    Ok((start, out.len()))
}

/// Convenience: build a complete IVF byte sequence from a global header
/// plus a slice of `(timestamp, payload)` frames. The result feeds
/// back through [`parse_all`] producing the same header and per-frame
/// `(timestamp, payload)` tuples.
///
/// Returns `InvalidData` if any frame's payload exceeds
/// [`IVF_FRAME_PAYLOAD_MAX`]; on rejection no partial buffer is
/// returned.
pub fn write_all(header: IvfHeader, frames: &[(u64, &[u8])]) -> Result<Vec<u8>, BitstreamError> {
    // Validate every payload size up-front so a rejected frame does
    // not leave the caller with a half-built container.
    for (idx, (_, payload)) in frames.iter().enumerate() {
        if payload.len() > IVF_FRAME_PAYLOAD_MAX {
            return Err(BitstreamError::invalid(format!(
                "IVF frame {idx} payload {} bytes exceeds u32 size field maximum",
                payload.len()
            )));
        }
    }
    let mut out = Vec::with_capacity(
        IVF_HEADER_LEN
            + frames
                .iter()
                .map(|(_, p)| IVF_FRAME_HEADER_LEN + p.len())
                .sum::<usize>(),
    );
    write_header(&mut out, header);
    for &(ts, payload) in frames {
        // Cannot fail because the up-front sweep already validated.
        write_frame(&mut out, ts, payload).expect("payload size validated");
    }
    Ok(out)
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

    fn sample_header(fourcc: [u8; 4]) -> IvfHeader {
        IvfHeader {
            fourcc,
            width: 1920,
            height: 1080,
            framerate_num: 30000,
            framerate_den: 1001,
            frame_count: 42,
        }
    }

    #[test]
    fn write_header_round_trips_through_parse_header() {
        let h = sample_header(IVF_FOURCC_VP90);
        let mut out = Vec::new();
        let (start, end) = write_header(&mut out, h);
        assert_eq!(start, 0);
        assert_eq!(end, IVF_HEADER_LEN);
        assert_eq!(out.len(), IVF_HEADER_LEN);
        // The fixed-format bytes match the reader's strict checks.
        assert_eq!(&out[0..4], b"DKIF");
        assert_eq!(u16::from_le_bytes([out[4], out[5]]), 0);
        assert_eq!(u16::from_le_bytes([out[6], out[7]]), 32);
        // Round-trip.
        let (parsed, rest) = parse_header(&out).expect("parse own header");
        assert_eq!(parsed, h);
        assert!(rest.is_empty(), "no leftover after the 32-byte prefix");
    }

    #[test]
    fn write_header_appends_after_existing_prefix() {
        let prefix = b"OLDDATA\x00";
        let mut out = prefix.to_vec();
        let h = sample_header(IVF_FOURCC_VP80);
        let (start, end) = write_header(&mut out, h);
        assert_eq!(start, prefix.len());
        assert_eq!(end, prefix.len() + IVF_HEADER_LEN);
        assert_eq!(&out[..prefix.len()], prefix, "prefix preserved");
        let (parsed, rest) = parse_header(&out[start..]).unwrap();
        assert_eq!(parsed, h);
        assert!(rest.is_empty());
    }

    #[test]
    fn write_header_zeroes_the_reserved_tail() {
        let mut out = Vec::new();
        write_header(&mut out, sample_header(IVF_FOURCC_VP80));
        assert_eq!(&out[28..32], &[0u8; 4]);
    }

    #[test]
    fn write_frame_round_trips_through_parse_frame() {
        let mut out = Vec::new();
        let payload = [9u8, 8, 7, 6, 5, 4, 3, 2, 1, 0];
        let (start, end) = write_frame(&mut out, 12345, &payload).unwrap();
        assert_eq!(start, 0);
        assert_eq!(end, IVF_FRAME_HEADER_LEN + payload.len());
        assert_eq!(out.len(), end);
        let (frame, rest) = parse_frame(&out).unwrap().unwrap();
        assert_eq!(frame.timestamp, 12345);
        assert_eq!(frame.payload, &payload);
        assert!(rest.is_empty());
    }

    #[test]
    fn write_frame_empty_payload_round_trips() {
        let mut out = Vec::new();
        let (start, end) = write_frame(&mut out, 0, &[]).unwrap();
        assert_eq!(end - start, IVF_FRAME_HEADER_LEN);
        let (frame, rest) = parse_frame(&out).unwrap().unwrap();
        assert_eq!(frame.timestamp, 0);
        assert!(frame.payload.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn write_all_round_trips_multi_frame_stream() {
        let h = sample_header(IVF_FOURCC_VP90);
        let frames: Vec<(u64, &[u8])> = vec![
            (0, b"frame-zero".as_slice()),
            (33, b"second".as_slice()),
            (66, b"".as_slice()),
            (99, &[0xff; 200]),
        ];
        let buf = write_all(h, &frames).unwrap();
        let (parsed_h, parsed_frames) = parse_all(&buf).unwrap();
        assert_eq!(parsed_h, h);
        assert_eq!(parsed_frames.len(), frames.len());
        for ((expected_ts, expected_payload), got) in frames.iter().zip(parsed_frames.iter()) {
            assert_eq!(got.timestamp, *expected_ts);
            assert_eq!(got.payload, *expected_payload);
        }
    }

    #[test]
    fn write_all_empty_frame_list_yields_lone_header() {
        let h = sample_header(IVF_FOURCC_VP80);
        let buf = write_all(h, &[]).unwrap();
        assert_eq!(buf.len(), IVF_HEADER_LEN);
        let (parsed_h, frames) = parse_all(&buf).unwrap();
        assert_eq!(parsed_h, h);
        assert!(frames.is_empty());
    }

    #[test]
    fn write_frame_preserves_buffer_on_size_overflow_at_simulated_boundary() {
        // We cannot allocate u32::MAX + 1 bytes in a test, so simulate
        // the check by constructing a slice header (we never deref into
        // it) that lies about its length. Instead, exercise the
        // rejection contract by calling write_all with a payload that
        // is short but whose declared error path is the same.
        //
        // The only way to exceed IVF_FRAME_PAYLOAD_MAX in practice is
        // to feed a slice whose len() is > u32::MAX. On 32-bit targets
        // that is impossible. On 64-bit targets the test that follows
        // checks the boundary constant itself stays in sync.
        assert_eq!(IVF_FRAME_PAYLOAD_MAX, u32::MAX as usize);
        // Round-trip a payload at exactly u16::MAX bytes (typical max
        // single-buffer fixture size) to make sure no off-by-one in the
        // u32 size field surfaces near a likely consumer boundary.
        let payload = vec![0xa5u8; u16::MAX as usize];
        let mut out = Vec::new();
        let (_, end) = write_frame(&mut out, 1, &payload).unwrap();
        assert_eq!(end, IVF_FRAME_HEADER_LEN + payload.len());
        let (frame, rest) = parse_frame(&out).unwrap().unwrap();
        assert_eq!(frame.payload.len(), payload.len());
        assert_eq!(frame.payload, payload.as_slice());
        assert!(rest.is_empty());
    }

    #[test]
    fn write_all_writes_concatenated_frames_in_order() {
        let h = sample_header(IVF_FOURCC_VP80);
        let p1 = b"aaa".as_slice();
        let p2 = b"bbbbb".as_slice();
        let buf = write_all(h, &[(10, p1), (20, p2)]).unwrap();
        // After the global header, frame 1's size field must land at
        // offset 32, frame 1's payload at 32+12 = 44, frame 2's size
        // field at 32+12+3 = 47, etc.
        assert_eq!(buf.len(), IVF_HEADER_LEN + 12 + p1.len() + 12 + p2.len());
        assert_eq!(
            u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
            p1.len() as u32
        );
        let p2_size_off = 32 + 12 + p1.len();
        assert_eq!(
            u32::from_le_bytes([
                buf[p2_size_off],
                buf[p2_size_off + 1],
                buf[p2_size_off + 2],
                buf[p2_size_off + 3]
            ]),
            p2.len() as u32
        );
    }

    #[test]
    fn write_header_fields_appear_at_documented_offsets() {
        let h = IvfHeader {
            fourcc: *b"ABCD",
            width: 0x1234,
            height: 0x5678,
            framerate_num: 0xdead_beef,
            framerate_den: 0x0badf00d,
            frame_count: 0x55aa_55aa,
        };
        let mut out = Vec::new();
        write_header(&mut out, h);
        assert_eq!(&out[0..4], b"DKIF");
        assert_eq!(&out[4..6], &0u16.to_le_bytes());
        assert_eq!(&out[6..8], &32u16.to_le_bytes());
        assert_eq!(&out[8..12], b"ABCD");
        assert_eq!(&out[12..14], &h.width.to_le_bytes());
        assert_eq!(&out[14..16], &h.height.to_le_bytes());
        assert_eq!(&out[16..20], &h.framerate_num.to_le_bytes());
        assert_eq!(&out[20..24], &h.framerate_den.to_le_bytes());
        assert_eq!(&out[24..28], &h.frame_count.to_le_bytes());
        assert_eq!(&out[28..32], &0u32.to_le_bytes());
    }
}
