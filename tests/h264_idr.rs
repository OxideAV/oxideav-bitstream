//! H.264 minimal-IDR parser end-to-end tests against ffmpeg/x264-encoded
//! 320×240 single-frame fixtures.

use oxideav_bitstream::h264::{
    parse_idr_only, parse_pps_nal, parse_slice_header_minimal, parse_sps_nal, split_annex_b,
    NAL_TYPE_IDR, NAL_TYPE_PPS, NAL_TYPE_SPS,
};

const BASELINE: &[u8] = include_bytes!("fixtures/h264_baseline_320x240_1frame.h264");
const HIGH: &[u8] = include_bytes!("fixtures/h264_high_320x240_1frame.h264");

fn find_nal_of_type(stream: &[u8], t: u8) -> Option<&[u8]> {
    split_annex_b(stream)
        .into_iter()
        .find(|n| !n.is_empty() && (n[0] & 0x1f) == t)
}

#[test]
fn baseline_parses_via_idr_only_and_dimensions_match() {
    let parsed = parse_idr_only(BASELINE).expect("parse_idr_only(baseline)");

    // x264 baseline emits profile_idc = 66.
    assert_eq!(parsed.sps.profile_idc, 66, "baseline profile_idc");
    // Level depends on bitrate and resolution; for 320×240 ultrafast
    // x264 picks level 1.1 → 11.
    assert_eq!(parsed.sps.level_idc, 11, "baseline level_idc");
    assert_eq!(parsed.sps.chroma_format_idc, 1, "baseline chroma 4:2:0");
    assert_eq!(parsed.sps.bit_depth_luma_minus8, 0, "8-bit luma");
    assert_eq!(parsed.sps.bit_depth_chroma_minus8, 0, "8-bit chroma");

    assert_eq!(parsed.sps.coded_width(), 320);
    assert_eq!(parsed.sps.coded_height(), 240);
    // Display equals coded for 320×240 — there's no crop offset needed.
    assert_eq!(parsed.sps.display_width(), 320);
    assert_eq!(parsed.sps.display_height(), 240);

    // Slice header.
    assert_eq!(parsed.slice_header.first_mb_in_slice, 0);
    assert!(
        parsed.slice_header.is_i_slice(),
        "first slice must be I (slice_type%5==2), got {}",
        parsed.slice_header.slice_type
    );
    assert_eq!(parsed.slice_header.idr_pic_id, Some(0));
    assert_eq!(parsed.slice_header.pic_order_cnt_lsb, 0);
    assert_eq!(parsed.slice_header.frame_num, 0);

    // PPS.
    assert_eq!(parsed.pps.num_slice_groups_minus1, 0);
}

#[test]
fn high_profile_parses_via_idr_only() {
    let parsed = parse_idr_only(HIGH).expect("parse_idr_only(high)");
    // x264 high → profile_idc 100.
    assert_eq!(parsed.sps.profile_idc, 100, "high profile_idc");
    assert_eq!(parsed.sps.chroma_format_idc, 1);
    assert_eq!(parsed.sps.bit_depth_luma_minus8, 0);
    assert_eq!(parsed.sps.coded_width(), 320);
    assert_eq!(parsed.sps.coded_height(), 240);
    assert_eq!(parsed.slice_header.idr_pic_id, Some(0));
    assert!(parsed.slice_header.is_i_slice());
}

#[test]
fn split_annex_b_finds_at_least_three_nals_in_baseline() {
    let nals = split_annex_b(BASELINE);
    assert!(
        nals.len() >= 3,
        "expected at least SPS+PPS+IDR (>= 3) NALs, got {}",
        nals.len()
    );
    // First should be SPS, somewhere there's PPS, and an IDR.
    let types: Vec<u8> = nals.iter().map(|n| n[0] & 0x1f).collect();
    assert!(types.contains(&NAL_TYPE_SPS), "no SPS NAL in baseline");
    assert!(types.contains(&NAL_TYPE_PPS), "no PPS NAL in baseline");
    assert!(types.contains(&NAL_TYPE_IDR), "no IDR NAL in baseline");
}

#[test]
fn parse_sps_pps_individually_via_split() {
    let sps_nal = find_nal_of_type(HIGH, NAL_TYPE_SPS).expect("HIGH has SPS");
    let pps_nal = find_nal_of_type(HIGH, NAL_TYPE_PPS).expect("HIGH has PPS");
    let idr_nal = find_nal_of_type(HIGH, NAL_TYPE_IDR).expect("HIGH has IDR");

    let sps = parse_sps_nal(sps_nal).expect("parse_sps_nal");
    let pps = parse_pps_nal(pps_nal).expect("parse_pps_nal");
    assert_eq!(sps.profile_idc, 100);
    assert_eq!(sps.coded_width(), 320);
    assert_eq!(sps.coded_height(), 240);
    assert_eq!(pps.num_slice_groups_minus1, 0);

    // Use parse_slice_header_minimal directly.
    let rbsp = oxideav_bitstream::h264::ebsp_to_rbsp(&idr_nal[1..]);
    let sh =
        parse_slice_header_minimal(&rbsp, NAL_TYPE_IDR, &sps, &pps).expect("parse_slice_header");
    assert_eq!(sh.first_mb_in_slice, 0);
    assert!(sh.is_i_slice());
    assert_eq!(sh.idr_pic_id, Some(0));
}
