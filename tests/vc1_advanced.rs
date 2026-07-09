//! VC-1 Advanced-profile parser end-to-end test against an excerpt
//! from a 1920×1080 sample (a conformance archive sample —
//! no black-box VC-1 encoder was available, so we cannot
//! synthesise a fresh fixture; the carved 8 KiB excerpt of the
//! upstream sample covers the seq+entry+first frame).

use oxideav_bitstream::vc1::{
    parse_entry_point_header, parse_first_picture, parse_picture_header,
    parse_sequence_header_advanced, split_bdus, BDU_ENTRY_POINT, BDU_FRAME, BDU_SEQUENCE_HEADER,
    PROFILE_ADVANCED,
};

const FIXTURE: &[u8] = include_bytes!("fixtures/vc1_advanced_1920x1080_1frame.vc1");

#[test]
fn vc1_split_bdus_finds_seq_entry_frame() {
    let bdus = split_bdus(FIXTURE);
    let kinds: Vec<u8> = bdus.iter().map(|b| b.bdu_type).collect();
    assert!(kinds.contains(&BDU_SEQUENCE_HEADER));
    assert!(kinds.contains(&BDU_ENTRY_POINT));
    assert!(kinds.contains(&BDU_FRAME));
}

#[test]
fn vc1_sequence_header_advanced_profile_960x540_max() {
    let bdus = split_bdus(FIXTURE);
    let seq = bdus
        .iter()
        .find(|b| b.bdu_type == BDU_SEQUENCE_HEADER)
        .expect("seq header BDU");
    let s = parse_sequence_header_advanced(seq.payload).expect("parse seq header");
    assert_eq!(s.profile, PROFILE_ADVANCED);
    // Level 3 at this resolution.
    assert_eq!(s.level, 3);
    // 4:2:0.
    assert_eq!(s.colordiff_format, 1);
    // The carved fixture's coded size is 960×540 (the upstream
    // encode used a half-resolution coded grid with display
    // upscale to 1920×1080).
    assert_eq!(s.max_coded_width, 960);
    assert_eq!(s.max_coded_height, 540);
    assert!(s.pulldown);
    assert!(s.interlace);
    assert!(!s.tfcntrflag);
    assert!(!s.finterpflag);
    assert!(!s.psf);
    assert!(s.display_ext);
    assert_eq!(s.display_horiz_size, 1920);
    assert_eq!(s.display_vert_size, 1080);
    assert!(s.aspect_ratio_flag);
    assert_eq!(s.aspect_ratio, 1);
    assert!(s.framerate_flag);
    assert_eq!(s.framerateind, 0);
    assert_eq!(s.frameratenr, 3);
    assert_eq!(s.frameratedr, 2);
    assert!(s.color_format_flag);
    assert_eq!(s.color_primaries, 1);
    assert_eq!(s.transfer_char, 1);
    assert_eq!(s.matrix_coef, 1);
    assert!(s.hrd_param_flag);
    assert_eq!(s.hrd_num_leaky_buckets, 1);
}

#[test]
fn vc1_entry_point_header_overrides_to_960x540() {
    let bdus = split_bdus(FIXTURE);
    let seq = parse_sequence_header_advanced(
        bdus.iter()
            .find(|b| b.bdu_type == BDU_SEQUENCE_HEADER)
            .unwrap()
            .payload,
    )
    .unwrap();
    let entry = bdus
        .iter()
        .find(|b| b.bdu_type == BDU_ENTRY_POINT)
        .expect("entry-point BDU");
    let e = parse_entry_point_header(entry.payload, &seq).expect("parse entry header");
    assert!(!e.broken_link);
    assert!(e.closed_entry);
    assert!(!e.panscan_flag);
    assert!(e.refdist_flag);
    assert!(e.loopfilter);
    assert!(!e.fastuvmc);
    assert!(e.extended_mv);
    assert_eq!(e.dquant, 1);
    assert!(e.vstransform);
    assert!(!e.overlap);
    assert_eq!(e.quantizer, 3);
    assert!(e.coded_size_flag);
    assert_eq!(e.coded_width, 960);
    assert_eq!(e.coded_height, 540);
    assert!(!e.extended_dmv);
    assert!(!e.range_mapy_flag);
    assert!(!e.range_mapuv_flag);
}

#[test]
fn vc1_first_picture_parses_into_frame_payload() {
    let parsed = parse_first_picture(FIXTURE).expect("parse_first_picture");
    assert_eq!(parsed.sequence_header.profile, PROFILE_ADVANCED);
    assert_eq!(parsed.sequence_header.max_coded_width, 960);
    assert_eq!(parsed.entry_point.coded_width, 960);
    // The frame BDU payload is non-empty.
    assert!(!parsed.frame_payload.is_empty());
}

#[test]
fn vc1_picture_header_parses_with_interlace_context() {
    let bdus = split_bdus(FIXTURE);
    let seq = parse_sequence_header_advanced(
        bdus.iter()
            .find(|b| b.bdu_type == BDU_SEQUENCE_HEADER)
            .unwrap()
            .payload,
    )
    .unwrap();
    let frame = bdus
        .iter()
        .find(|b| b.bdu_type == BDU_FRAME)
        .expect("frame BDU");
    let h = parse_picture_header(frame.payload, &seq).expect("parse picture");
    // Interlace=1 and the first byte is 0x6f → high bits 0110...
    // FCM VLC: first bit 0 → progressive frame (FCM=0). Picture type
    // VLC: next bit 1, then 1, then 0 → 110 → I-frame.
    assert_eq!(h.fcm, 0);
    assert_eq!(h.picture_type, 0, "first frame should decode as I");
}

#[test]
fn vc1_truncated_inputs_are_rejected() {
    assert!(parse_sequence_header_advanced(&[0u8; 2]).is_err());
    assert!(parse_first_picture(&[0u8; 2]).is_err());
}
