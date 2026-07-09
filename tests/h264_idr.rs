//! H.264 minimal-IDR parser end-to-end tests against reference-encoder-produced
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

    // Baseline-profile reference encoding emits profile_idc = 66.
    assert_eq!(parsed.sps.profile_idc, 66, "baseline profile_idc");
    // Level depends on bitrate and resolution; for 320×240 ultrafast
    // The fixture encodes level 1.1 → 11.
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

    // VUI (Annex E) — the fixture signals square samples, 1 fps
    // timing (a single-frame encode) and a bitstream-restriction
    // block.
    let vui = parsed.sps.vui.as_ref().expect("baseline fixture has VUI");
    assert_eq!(vui.aspect_ratio_idc, 1, "square SAR (Table E-1 idc 1)");
    assert_eq!(vui.sample_aspect_ratio(), Some((1, 1)));
    assert!(vui.timing_info_present_flag);
    assert_eq!(vui.num_units_in_tick, 1);
    assert_eq!(vui.time_scale, 2);
    // frame rate = time_scale / (2 * num_units_in_tick) = 1 fps.
    assert_eq!(vui.frame_rate(), Some((2, 2)));
    assert!(vui.nal_hrd_parameters.is_none());
    assert!(vui.vcl_hrd_parameters.is_none());
    assert!(vui.bitstream_restriction_flag);
    assert!(vui.motion_vectors_over_pic_boundaries_flag);
    assert_eq!(vui.log2_max_mv_length_horizontal, 9);
    assert_eq!(vui.log2_max_mv_length_vertical, 9);
    assert_eq!(vui.max_num_reorder_frames, 0);
    assert_eq!(vui.max_dec_frame_buffering, 1);

    // No scaling matrix on the baseline fixture.
    assert!(parsed.sps.seq_scaling_lists.is_none());
}

#[test]
fn high_profile_parses_via_idr_only() {
    let parsed = parse_idr_only(HIGH).expect("parse_idr_only(high)");
    // High-profile fixture → profile_idc 100.
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

#[test]
fn sei_nal_parses_on_both_fixtures() {
    use oxideav_bitstream::h264::sei::{
        decode_sei_message, parse_sei_nal, H264Sei, NAL_TYPE_SEI, SEI_TYPE_USER_DATA_UNREGISTERED,
    };
    for (name, stream) in [("baseline", BASELINE), ("high", HIGH)] {
        let sei_nal = find_nal_of_type(stream, NAL_TYPE_SEI)
            .unwrap_or_else(|| panic!("{name} fixture has an SEI NAL"));
        let msgs = parse_sei_nal(sei_nal).expect("SEI NAL parses");
        assert_eq!(msgs.len(), 1, "{name}: one sei_message()");
        assert_eq!(
            msgs[0].payload_type, SEI_TYPE_USER_DATA_UNREGISTERED,
            "{name}: encoder-settings user data"
        );
        let H264Sei::UserDataUnregistered(u) = decode_sei_message(&msgs[0], None).expect("decodes")
        else {
            panic!("{name}: expected UserDataUnregistered");
        };
        // 16-byte UUID followed by a non-empty settings string.
        assert!(!u.payload.is_empty(), "{name}: non-empty user data body");
        assert_ne!(u.uuid, [0u8; 16], "{name}: non-zero UUID");
    }
}

#[test]
fn sps_pps_fixture_roundtrip_is_byte_exact() {
    use oxideav_bitstream::h264::{ebsp_to_rbsp, parse_pps, parse_sps, write_pps, write_sps};
    for (name, stream) in [("baseline", BASELINE), ("high", HIGH)] {
        let sps_nal = find_nal_of_type(stream, NAL_TYPE_SPS).expect("SPS NAL");
        let sps_rbsp = ebsp_to_rbsp(&sps_nal[1..]);
        let sps = parse_sps(&sps_rbsp).expect("SPS parses");
        assert_eq!(
            write_sps(&sps).expect("SPS writes"),
            sps_rbsp,
            "{name}: SPS parse→write must reproduce the fixture bytes"
        );

        let pps_nal = find_nal_of_type(stream, NAL_TYPE_PPS).expect("PPS NAL");
        let pps_rbsp = ebsp_to_rbsp(&pps_nal[1..]);
        let pps = parse_pps(&pps_rbsp).expect("PPS parses");
        assert_eq!(
            write_pps(&pps).expect("PPS writes"),
            pps_rbsp,
            "{name}: PPS parse→write must reproduce the fixture bytes"
        );
    }
}
