//! VP8 keyframe parser end-to-end test against an ffmpeg/libvpx-encoded
//! 320×240 single-frame IVF fixture.

use oxideav_bitstream::ivf::{parse_all, parse_header, IVF_FOURCC_VP80};
use oxideav_bitstream::vp8::{parse_frame_header, parse_keyframe, VP8_KEYFRAME_START_CODE};

const FIXTURE: &[u8] = include_bytes!("fixtures/vp8_320x240_1frame.ivf");

#[test]
fn vp8_ivf_header_is_vp80_320x240() {
    let (hdr, body) = parse_header(FIXTURE).expect("parse IVF header");
    assert_eq!(&hdr.fourcc, &IVF_FOURCC_VP80, "IVF fourcc must be VP80");
    assert_eq!(hdr.width, 320);
    assert_eq!(hdr.height, 240);
    assert!(!body.is_empty(), "IVF body must contain at least one frame");
}

#[test]
fn vp8_keyframe_parses_to_320x240_show_frame_first_part_size_896() {
    let (_hdr, frames) = parse_all(FIXTURE).expect("parse_all IVF");
    assert_eq!(frames.len(), 1, "fixture should hold a single frame");
    let payload = frames[0].payload;
    let h = parse_keyframe(payload).expect("parse_keyframe");
    assert_eq!(h.frame_type, 0, "must be a keyframe");
    assert_eq!(h.version, 0);
    assert!(h.show_frame);
    // libvpx's first_part_size for a 320×240 testsrc2 keyframe at the
    // default settings: 896 bytes (this is the size of the bool-coded
    // first partition, not including the 3-byte tag or the 7-byte
    // uncompressed-data-chunk).
    assert_eq!(h.first_part_size, 896);
    assert_eq!(h.width, 320);
    assert_eq!(h.height, 240);
    assert_eq!(h.horizontal_scale, 0);
    assert_eq!(h.vertical_scale, 0);
    // Sanity: the start code lives at bytes 3..6 of the payload.
    assert_eq!(payload[3..6], VP8_KEYFRAME_START_CODE);
}

#[test]
fn vp8_parse_frame_header_works_on_keyframe() {
    // Same fixture but via the lower-level entry point.
    let (_hdr, frames) = parse_all(FIXTURE).unwrap();
    let h = parse_frame_header(frames[0].payload).expect("parse_frame_header");
    assert_eq!(h.frame_type, 0);
    assert_eq!(h.width, 320);
    assert_eq!(h.height, 240);
}

#[test]
fn vp8_truncated_input_returns_unexpected_end() {
    assert!(parse_frame_header(&[0u8; 1]).is_err());
    // 3-byte tag but missing the keyframe extension.
    assert!(parse_keyframe(&[0x10u8, 0x00, 0x00]).is_err());
}
