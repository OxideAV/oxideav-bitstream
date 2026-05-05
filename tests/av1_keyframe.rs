//! AV1 minimal keyframe parser end-to-end test against an
//! aomenc-encoded 320×240 single-keyframe OBU fixture.

use oxideav_bitstream::av1::{parse_obu_stream, FRAME_TYPE_KEY};

const AV1: &[u8] = include_bytes!("fixtures/av1_320x240_1frame.obu");

#[test]
fn av1_parses_keyframe_obu_stream() {
    let parsed = parse_obu_stream(AV1).expect("parse_obu_stream");

    let s = &parsed.sequence_header;
    // aomenc default → seq_profile 0 (Main).
    assert_eq!(s.seq_profile, 0, "expected seq_profile=0 (Main)");
    // Single image — for our fixture aomenc may or may not set
    // still_picture, but max_frame_* must be 320×240.
    assert_eq!(s.max_frame_width(), 320);
    assert_eq!(s.max_frame_height(), 240);

    // Color config — 8 bit 4:2:0, monochrome=0.
    assert_eq!(s.color_config.bit_depth, 8);
    assert!(!s.color_config.monochrome);
    assert!(s.color_config.subsampling_x);
    assert!(s.color_config.subsampling_y);

    // Frame header — must be a key frame.
    assert_eq!(parsed.frame_header.frame_type, FRAME_TYPE_KEY);
    assert!(parsed.frame_header.show_frame);
    assert_eq!(parsed.frame_header.frame_width, 320);
    assert_eq!(parsed.frame_header.frame_height, 240);

    // Keyframe OBU range non-empty.
    assert!(
        !parsed.keyframe_obus.is_empty(),
        "expected non-empty keyframe OBU slab"
    );
}
