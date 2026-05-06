//! HEVC minimal-IDR parser end-to-end test against an x265-encoded
//! 320×240 single-frame fixture.

use oxideav_bitstream::hevc::{
    is_irap, parse_idr_only, parse_pps_nal, parse_sps_nal, parse_vps_nal, split_annex_b,
    NAL_TYPE_IDR_N_LP, NAL_TYPE_IDR_W_RADL, NAL_TYPE_PPS, NAL_TYPE_SPS, NAL_TYPE_VPS,
};

const HEVC_MAIN: &[u8] = include_bytes!("fixtures/hevc_main_320x240_1frame.h265");

fn find_nal_of_type(stream: &[u8], t: u8) -> Option<&[u8]> {
    split_annex_b(stream).into_iter().find(|n| {
        if n.len() < 2 {
            return false;
        }
        ((n[0] >> 1) & 0x3f) == t
    })
}

#[test]
fn hevc_parses_via_idr_only_and_dimensions_match() {
    let parsed = parse_idr_only(HEVC_MAIN).expect("parse_idr_only HEVC");

    // x265 default Main profile = profile_idc 1.
    assert_eq!(parsed.sps.profile_tier_level.general_profile_idc, 1);

    // 320×240 → general_level_idc is 30 (Level 1) for x265 ultrafast at
    // this resolution; we don't pin the exact value here, just sanity-check.
    assert!(
        parsed.sps.profile_tier_level.general_level_idc > 0,
        "level_idc should be set"
    );

    assert_eq!(parsed.sps.pic_width_in_luma_samples, 320);
    assert_eq!(parsed.sps.pic_height_in_luma_samples, 240);
    assert_eq!(parsed.sps.chroma_format_idc, 1, "HEVC fixture is 4:2:0");
    assert_eq!(parsed.sps.bit_depth_luma_minus8, 0, "8-bit luma");
    assert_eq!(parsed.sps.bit_depth_chroma_minus8, 0, "8-bit chroma");
    assert_eq!(parsed.sps.coded_width(), 320);
    assert_eq!(parsed.sps.coded_height(), 240);

    // Restricted scope — none of these may be set in the fixture.
    assert!(!parsed.sps.scaling_list_enabled_flag);
    assert!(!parsed.sps.pcm_enabled_flag);
    assert_eq!(parsed.sps.num_short_term_ref_pic_sets, 0);
    assert!(!parsed.sps.long_term_ref_pics_present_flag);

    assert!(!parsed.pps.tiles_enabled_flag);
    assert!(!parsed.pps.entropy_coding_sync_enabled_flag);
    assert!(!parsed.pps.dependent_slice_segments_enabled_flag);

    // Slice header.
    assert!(parsed.slice_header.first_slice_segment_in_pic_flag);
    assert!(parsed.slice_header.is_irap);
    assert!(
        is_irap(parsed.nal_unit_type),
        "expected IDR/CRA NAL type, got {}",
        parsed.nal_unit_type
    );
    assert_eq!(
        parsed.slice_header.slice_type, 2,
        "IRAP slice must be I-slice (slice_type=2)"
    );
}

#[test]
fn hevc_split_annex_b_finds_vps_sps_pps_idr() {
    let nals = split_annex_b(HEVC_MAIN);
    let types: Vec<u8> = nals.iter().filter(|n| n.len() >= 2).map(|n| (n[0] >> 1) & 0x3f).collect();
    assert!(types.contains(&NAL_TYPE_VPS), "no VPS in HEVC fixture");
    assert!(types.contains(&NAL_TYPE_SPS), "no SPS in HEVC fixture");
    assert!(types.contains(&NAL_TYPE_PPS), "no PPS in HEVC fixture");
    assert!(
        types.contains(&NAL_TYPE_IDR_W_RADL) || types.contains(&NAL_TYPE_IDR_N_LP),
        "no IDR in HEVC fixture"
    );
}

#[test]
fn hevc_pps_extended_fields_parse() {
    // The Round 1 parser stopped after `entropy_coding_sync_enabled_flag`.
    // Round 5 extends it through the deblocking-filter, lists-modification,
    // parallel-merge and slice-segment-header-extension fields. Verify the
    // extended fields parse on the existing x265 fixture without rejecting
    // the input.
    let parsed = parse_idr_only(HEVC_MAIN).expect("parse_idr_only HEVC");

    // Concrete numeric assertions for the new PPS fields. The x265
    // ultrafast preset enables loop_filter_across_slices but does NOT
    // emit the deblocking-filter control block, so all of the
    // deblocking-related fields stay at their defaults.
    assert!(parsed.pps.pps_loop_filter_across_slices_enabled_flag);
    assert!(!parsed.pps.deblocking_filter_control_present_flag);
    assert!(!parsed.pps.deblocking_filter_override_enabled_flag);
    assert!(!parsed.pps.pps_deblocking_filter_disabled_flag);
    assert_eq!(parsed.pps.pps_beta_offset_div2, 0);
    assert_eq!(parsed.pps.pps_tc_offset_div2, 0);
    // lists_modification + parallel_merge + extension flag.
    assert!(!parsed.pps.lists_modification_present_flag);
    assert_eq!(parsed.pps.log2_parallel_merge_level_minus2, 0);
    assert!(!parsed.pps.slice_segment_header_extension_present_flag);
    // SPS num_long_term_ref_pics_sps default — fixture has
    // long_term_ref_pics_present_flag=0 so this is 0.
    assert_eq!(parsed.sps.num_long_term_ref_pics_sps, 0);
}

#[test]
fn hevc_individual_parsers_succeed() {
    let vps_nal = find_nal_of_type(HEVC_MAIN, NAL_TYPE_VPS).expect("HEVC has VPS");
    let sps_nal = find_nal_of_type(HEVC_MAIN, NAL_TYPE_SPS).expect("HEVC has SPS");
    let pps_nal = find_nal_of_type(HEVC_MAIN, NAL_TYPE_PPS).expect("HEVC has PPS");

    let vps = parse_vps_nal(vps_nal).expect("parse_vps_nal");
    let sps = parse_sps_nal(sps_nal).expect("parse_sps_nal");
    let pps = parse_pps_nal(pps_nal).expect("parse_pps_nal");
    assert_eq!(vps.vps_video_parameter_set_id, 0);
    assert_eq!(sps.sps_video_parameter_set_id, vps.vps_video_parameter_set_id);
    assert_eq!(sps.pic_width_in_luma_samples, 320);
    assert_eq!(sps.pic_height_in_luma_samples, 240);
    assert_eq!(pps.pps_seq_parameter_set_id, sps.sps_seq_parameter_set_id);
}
