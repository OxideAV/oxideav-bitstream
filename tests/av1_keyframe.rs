//! AV1 minimal keyframe parser end-to-end test against an
//! reference-encoder-produced 320×240 single-keyframe OBU fixture.

use oxideav_bitstream::av1::{parse_obu_stream, FRAME_TYPE_KEY};

const AV1: &[u8] = include_bytes!("fixtures/av1_320x240_1frame.obu");

#[test]
fn av1_parses_keyframe_obu_stream() {
    let parsed = parse_obu_stream(AV1).expect("parse_obu_stream");

    let s = &parsed.sequence_header;
    // The reference encoder default → seq_profile 0 (Main).
    assert_eq!(s.seq_profile, 0, "expected seq_profile=0 (Main)");
    // Single image — for our fixture the reference encoder may or may not set
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

#[test]
fn av1_sequence_header_writer_is_byte_exact_on_fixture() {
    use oxideav_bitstream::av1::{
        parse_sequence_header, read_obu, write_sequence_header, OBU_SEQUENCE_HEADER,
    };
    // Walk the fixture's OBUs to the sequence header and prove the
    // writer reproduces its payload byte-exactly.
    let mut offset = 0usize;
    let mut checked = false;
    while offset < AV1.len() {
        let (hdr, payload_start, payload_end, next) =
            read_obu(AV1, offset).expect("fixture OBU walks");
        if hdr.obu_type == OBU_SEQUENCE_HEADER {
            let payload = &AV1[payload_start..payload_end];
            let parsed = parse_sequence_header(payload).expect("fixture seq header parses");
            let rewritten = write_sequence_header(&parsed).expect("seq header writes");
            assert_eq!(rewritten, payload, "byte-exact sequence-header round-trip");
            assert_eq!(
                parse_sequence_header(&rewritten).expect("rewritten parses"),
                parsed
            );
            checked = true;
        }
        offset = next;
    }
    assert!(checked, "fixture contains a sequence header OBU");
}
