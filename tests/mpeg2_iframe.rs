//! MPEG-2 sequence/picture/extension parser end-to-end test against
//! an ffmpeg-encoded 320×240 single-I-frame fixture lifted from
//! oxideav-vdpau's Round 4 tests.

use oxideav_bitstream::mpeg2::{
    find_first_slice, find_start_codes, parse_picture_coding_extension, parse_picture_header,
    parse_sequence_extension, parse_sequence_header, EXTENSION_ID_PICTURE_CODING,
    EXTENSION_ID_SEQUENCE, START_CODE_EXTENSION, START_CODE_PICTURE, START_CODE_SEQUENCE_HEADER,
};

const FIXTURE: &[u8] = include_bytes!("fixtures/mpeg2_main_320x240_1frame.m2v");

#[test]
fn mpeg2_finds_sequence_picture_extensions() {
    let codes = find_start_codes(FIXTURE);
    let kinds: Vec<u8> = codes.iter().map(|c| c.0).collect();
    assert!(kinds.contains(&START_CODE_SEQUENCE_HEADER));
    assert!(kinds.contains(&START_CODE_EXTENSION));
    assert!(kinds.contains(&START_CODE_PICTURE));
}

#[test]
fn mpeg2_sequence_header_is_320x240() {
    let codes = find_start_codes(FIXTURE);
    let (_, seq_off) = codes
        .iter()
        .copied()
        .find(|(c, _)| *c == START_CODE_SEQUENCE_HEADER)
        .expect("sequence header present");
    let s = parse_sequence_header(&FIXTURE[seq_off..]).expect("parse sequence header");
    assert_eq!(s.horizontal_size, 320);
    assert_eq!(s.vertical_size, 240);
    assert_eq!(s.aspect_ratio_information, 2);
    assert_eq!(s.frame_rate_code, 2);
    // ffmpeg's mpeg2video encoder emits the maximal 18-bit value for an
    // unconstrained bitrate when the user did not pass -b:v.
    assert_eq!(s.bit_rate, 0x3FFFF);
    assert!(!s.constrained_parameters_flag);
    // No custom quantizer matrices in the fixture.
    assert!(s.intra_quantiser_matrix.is_none());
    assert!(s.non_intra_quantiser_matrix.is_none());
    // Default matrices match the spec.
    let intra_raster = s.intra_quantizer_matrix_raster();
    assert_eq!(intra_raster[0], 8); // DC = 8 in default intra matrix.
    let non_intra_raster = s.non_intra_quantizer_matrix_raster();
    assert!(non_intra_raster.iter().all(|&q| q == 16)); // uniform 16/16
}

#[test]
fn mpeg2_picture_header_is_iframe() {
    let codes = find_start_codes(FIXTURE);
    let (_, pic_off) = codes
        .iter()
        .copied()
        .find(|(c, _)| *c == START_CODE_PICTURE)
        .expect("picture header present");
    let p = parse_picture_header(&FIXTURE[pic_off..]).expect("parse picture header");
    assert_eq!(p.temporal_reference, 0);
    assert_eq!(p.picture_coding_type, 1, "I-frame");
    assert_eq!(p.vbv_delay, 0xFFFF);
}

#[test]
fn mpeg2_picture_coding_extension_progressive_frame_dct() {
    let codes = find_start_codes(FIXTURE);
    // Pick the extension whose first nibble is the picture-coding ID (8).
    let (_, ext_off) = codes
        .iter()
        .copied()
        .filter(|(c, _)| *c == START_CODE_EXTENSION)
        .find(|&(_, payload_start)| {
            FIXTURE
                .get(payload_start)
                .map(|b| (b >> 4) == EXTENSION_ID_PICTURE_CODING)
                .unwrap_or(false)
        })
        .expect("picture_coding_extension present");
    let e = parse_picture_coding_extension(&FIXTURE[ext_off..]).expect("parse pic ext");
    assert_eq!(e.f_code[0], [15, 15]);
    assert_eq!(e.f_code[1], [15, 15]);
    assert_eq!(e.intra_dc_precision, 0);
    assert_eq!(e.picture_structure, 3, "frame picture");
    assert_eq!(e.frame_pred_frame_dct, 1);
    assert_eq!(e.progressive_frame, 1);
    assert_eq!(e.chroma_420_type, 1);
}

#[test]
fn mpeg2_sequence_extension_main_profile_progressive_420() {
    let codes = find_start_codes(FIXTURE);
    let (_, ext_off) = codes
        .iter()
        .copied()
        .filter(|(c, _)| *c == START_CODE_EXTENSION)
        .find(|&(_, payload_start)| {
            FIXTURE
                .get(payload_start)
                .map(|b| (b >> 4) == EXTENSION_ID_SEQUENCE)
                .unwrap_or(false)
        })
        .expect("sequence_extension present");
    let e = parse_sequence_extension(&FIXTURE[ext_off..]).expect("parse seq ext");
    // ffmpeg's mpeg2video defaults emit Main@Main (PLI = 0x48).
    assert_eq!(e.profile_and_level_indication, 0x48);
    assert!(e.progressive_sequence);
    assert_eq!(e.chroma_format, 1, "4:2:0");
    assert_eq!(e.horizontal_size_extension, 0);
    assert_eq!(e.vertical_size_extension, 0);
}

#[test]
fn mpeg2_first_slice_is_locatable() {
    let off = find_first_slice(FIXTURE).expect("at least one slice");
    // The first slice must come AFTER the picture header / extension.
    let codes = find_start_codes(FIXTURE);
    let pic_off = codes.iter().find(|(c, _)| *c == START_CODE_PICTURE).unwrap().1 - 4;
    assert!(off > pic_off);
}

#[test]
fn mpeg2_truncated_inputs_are_rejected() {
    assert!(parse_sequence_header(&[0u8; 4]).is_err());
    assert!(parse_picture_header(&[0u8; 2]).is_err());
    assert!(parse_picture_coding_extension(&[0u8; 2]).is_err());
}
