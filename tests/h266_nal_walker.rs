//! H.266 / VVC NAL-walker integration test.
//!
//! No bitstream fixture is required at this level: the walker is
//! purely structural (Annex-B framing + 2-byte NAL header decode +
//! VCL / IRAP / parameter-set classifiers). We synthesise a minimal
//! stream covering one VPS, one SPS, one PPS, one picture header,
//! and one IDR_W_RADL VCL NAL — exactly what a future
//! `parse_irap_only` would need to locate to begin VVC decode.
//!
//! All field encodings follow ITU-T H.266 7.3.1.2 (NAL unit header
//! syntax) and 7.4.2.2 Table 5 (NAL unit type codes). Each NAL body
//! is prefixed with the two-byte header and then padded with one
//! filler byte so `split_annex_b` actually has a body to slice.

use oxideav_bitstream::bit_writer::BitWriter;
use oxideav_bitstream::h266::{
    is_irap, is_parameter_set, is_vcl, parse_nal_header, parse_picture_header,
    parse_picture_header_with_sps, parse_pps, parse_sps, parse_vps, split_annex_b, write_pps,
    write_sps, VvcChromaQpTable, VvcPps, VvcSps, NAL_TYPE_IDR_W_RADL, NAL_TYPE_PH, NAL_TYPE_PPS,
    NAL_TYPE_SPS, NAL_TYPE_VPS,
};

/// A complete 1920x1080 10-bit 4:2:0 no-PTL SPS RBSP with the given
/// POC-LSB width, produced through the crate's own byte-exact writer
/// (§7.3.2.4 full walk).
fn full_sps_rbsp(log2_max_poc_lsb_minus4: u8) -> Vec<u8> {
    write_sps(&VvcSps {
        sps_chroma_format_idc: 1,
        sps_log2_ctu_size_minus5: 2,
        sps_pic_width_max_in_luma_samples: 1920,
        sps_pic_height_max_in_luma_samples: 1080,
        sps_bitdepth_minus8: 2,
        sps_log2_max_pic_order_cnt_lsb_minus4: log2_max_poc_lsb_minus4,
        sps_same_qp_table_for_chroma_flag: 1,
        chroma_qp_tables: vec![VvcChromaQpTable {
            sps_qp_table_start_minus26: 0,
            points: vec![(0, 0)],
        }],
        sps_chroma_horizontal_collocated_flag: 1,
        sps_chroma_vertical_collocated_flag: 1,
        ..Default::default()
    })
    .expect("SPS writes")
}

/// Build a 2-byte VVC NAL header for `(nal_unit_type, nuh_layer_id,
/// nuh_temporal_id_plus1)`. Forbidden + reserved zero bits are
/// always 0.
fn vvc_hdr(nal_unit_type: u8, layer_id: u8, tid_plus1: u8) -> [u8; 2] {
    assert!(nal_unit_type < 32, "nal_unit_type is u(5)");
    assert!(layer_id < 64, "nuh_layer_id is u(6)");
    assert!(tid_plus1 < 8, "nuh_temporal_id_plus1 is u(3)");
    let b0 = layer_id & 0x3f;
    let b1 = ((nal_unit_type & 0x1f) << 3) | (tid_plus1 & 0x7);
    [b0, b1]
}

fn push_nal(stream: &mut Vec<u8>, hdr: [u8; 2], filler: u8) {
    // Four-byte start code followed by header + one filler byte body.
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    stream.extend_from_slice(&hdr);
    stream.push(filler);
}

#[test]
fn walks_synthetic_au_with_vps_sps_pps_ph_idr() {
    let mut stream = Vec::new();
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_VPS, 0, 1), 0xa1);
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_SPS, 0, 1), 0xa2);
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_PPS, 0, 1), 0xa3);
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_PH, 0, 1), 0xa4);
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_IDR_W_RADL, 0, 1), 0xa5);

    let nals = split_annex_b(&stream);
    assert_eq!(nals.len(), 5, "expected five NALs in the synthetic AU");

    let parsed: Vec<_> = nals
        .iter()
        .map(|n| parse_nal_header(n).expect("two-byte NAL header"))
        .collect();

    // Order matches the order we pushed.
    assert_eq!(parsed[0].nal_unit_type, NAL_TYPE_VPS);
    assert_eq!(parsed[1].nal_unit_type, NAL_TYPE_SPS);
    assert_eq!(parsed[2].nal_unit_type, NAL_TYPE_PPS);
    assert_eq!(parsed[3].nal_unit_type, NAL_TYPE_PH);
    assert_eq!(parsed[4].nal_unit_type, NAL_TYPE_IDR_W_RADL);

    // Every header decoded to layer 0, temporal_id 0.
    for h in &parsed {
        assert_eq!(h.forbidden_zero_bit, 0);
        assert_eq!(h.nuh_reserved_zero_bit, 0);
        assert_eq!(h.nuh_layer_id, 0);
        assert_eq!(h.temporal_id(), 0);
    }

    // VPS/SPS/PPS classify as parameter sets, the IDR classifies as
    // both VCL and IRAP, the PH is neither VCL nor a parameter set.
    assert!(is_parameter_set(parsed[0].nal_unit_type));
    assert!(is_parameter_set(parsed[1].nal_unit_type));
    assert!(is_parameter_set(parsed[2].nal_unit_type));
    assert!(!is_parameter_set(parsed[3].nal_unit_type));
    assert!(!is_vcl(parsed[3].nal_unit_type));
    assert!(is_vcl(parsed[4].nal_unit_type));
    assert!(is_irap(parsed[4].nal_unit_type));
}

#[test]
fn walks_au_and_parses_sps_structural_fields() {
    // VPS + SPS + IDR_W_RADL with a complete 1920×1080 10-bit
    // 4:2:0 / no-PTL SPS body. Demonstrates that a HW bridge can
    // run `split_annex_b` → `parse_nal_header` → `parse_sps` to
    // recover the geometry fields it needs.
    let sps_rbsp = full_sps_rbsp(0);
    let mut sps_nal = Vec::new();
    sps_nal.extend_from_slice(&vvc_hdr(NAL_TYPE_SPS, 0, 1));
    sps_nal.extend_from_slice(&sps_rbsp);

    let mut stream = Vec::new();
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_VPS, 0, 1), 0xa1);
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    stream.extend_from_slice(&sps_nal);
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_IDR_W_RADL, 0, 1), 0xa5);

    let nals = split_annex_b(&stream);
    assert_eq!(nals.len(), 3);

    let sps_body = nals
        .iter()
        .find(|n| parse_nal_header(n).map(|h| h.nal_unit_type) == Ok(NAL_TYPE_SPS))
        .expect("SPS NAL present");

    let sps = parse_sps(sps_body).expect("SPS parses");
    assert_eq!(sps.sps_pic_width_max_in_luma_samples, 1920);
    assert_eq!(sps.sps_pic_height_max_in_luma_samples, 1080);
    assert_eq!(sps.sps_chroma_format_idc, 1);
    assert_eq!(sps.bit_depth(), 10);
    assert_eq!(sps.ctb_size_y(), 128);
}

#[test]
fn walks_au_and_parses_pps_structural_fields() {
    // VPS + SPS + PPS + IDR_W_RADL with a complete PPS body
    // (64×32, no conformance/scaling windows, output_flag_present = 1,
    // no_pic_partition = 1, no subpic id mapping), built through the
    // crate's own byte-exact writer. Demonstrates that a HW bridge can
    // run `split_annex_b` → `parse_nal_header` → `parse_pps` to
    // recover the per-picture geometry fields.
    let pps_rbsp = write_pps(&VvcPps {
        pps_pic_width_in_luma_samples: 64,
        pps_pic_height_in_luma_samples: 32,
        pps_output_flag_present_flag: 1,
        pps_no_pic_partition_flag: 1,
        ..Default::default()
    })
    .expect("PPS writes");
    let mut pps_nal = Vec::new();
    pps_nal.extend_from_slice(&vvc_hdr(NAL_TYPE_PPS, 0, 1));
    pps_nal.extend_from_slice(&pps_rbsp);

    let mut stream = Vec::new();
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_VPS, 0, 1), 0xa1);
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_SPS, 0, 1), 0xa2);
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    stream.extend_from_slice(&pps_nal);
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_IDR_W_RADL, 0, 1), 0xa5);

    let nals = split_annex_b(&stream);
    assert_eq!(nals.len(), 4);

    let pps_body = nals
        .iter()
        .find(|n| parse_nal_header(n).map(|h| h.nal_unit_type) == Ok(NAL_TYPE_PPS))
        .expect("PPS NAL present");

    let pps = parse_pps(pps_body).expect("PPS parses");
    assert_eq!(pps.pps_pic_parameter_set_id, 0);
    assert_eq!(pps.pps_seq_parameter_set_id, 0);
    assert_eq!(pps.pps_pic_width_in_luma_samples, 64);
    assert_eq!(pps.pps_pic_height_in_luma_samples, 32);
    assert!(pps.pps_conf_win_offsets.is_none());
    assert!(pps.pps_scaling_win_offsets.is_none());
    assert_eq!(pps.pps_output_flag_present_flag, 1);
    assert_eq!(pps.pps_no_pic_partition_flag, 1);
    assert!(pps.subpic_id_mapping.is_none());
}

#[test]
fn walks_au_and_parses_vps_structural_fields() {
    // VPS + SPS + IDR_W_RADL where the VPS body carries the minimal
    // single-layer structural prefix (vps_id = 1, max_layers_minus1 =
    // 0, max_sublayers_minus1 = 0, vps_layer_id[0] = 0). Demonstrates
    // that a HW bridge can run split_annex_b -> parse_nal_header ->
    // parse_vps to recover the layer / sublayer count it needs.
    let vps_rbsp: [u8; 3] = [0x10, 0x00, 0x00];
    let mut vps_nal = Vec::new();
    vps_nal.extend_from_slice(&vvc_hdr(NAL_TYPE_VPS, 0, 1));
    vps_nal.extend_from_slice(&vps_rbsp);

    let mut stream = Vec::new();
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    stream.extend_from_slice(&vps_nal);
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_SPS, 0, 1), 0xa2);
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_IDR_W_RADL, 0, 1), 0xa5);

    let nals = split_annex_b(&stream);
    assert_eq!(nals.len(), 3);

    let vps_body = nals
        .iter()
        .find(|n| parse_nal_header(n).map(|h| h.nal_unit_type) == Ok(NAL_TYPE_VPS))
        .expect("VPS NAL present");

    let vps = parse_vps(vps_body).expect("VPS parses");
    assert_eq!(vps.vps_video_parameter_set_id, 1);
    assert_eq!(vps.vps_max_layers_minus1, 0);
    assert_eq!(vps.vps_max_sublayers_minus1, 0);
    assert_eq!(vps.vps_layer_id, vec![0]);
}

#[test]
fn walks_au_and_parses_picture_header_structural_prefix() {
    // VPS + SPS + PPS + PH + IDR_W_RADL where the PH body carries the
    // structural prefix (gdr_or_irap=1, non_ref=0, gdr_pic=0 — i.e.
    // an IRAP picture — inter_allowed=1, intra_allowed=1, pps_id=0).
    // Demonstrates that a HW bridge can run split_annex_b ->
    // parse_nal_header -> parse_picture_header to classify the picture
    // for random-access entry-point detection.
    //
    // PH structural-prefix RBSP bit layout (MSB-first):
    //   gdr_or_irap = 1   (1b)
    //   non_ref     = 0   (1b)
    //   gdr_pic     = 0   (1b, present because gdr_or_irap=1)
    //   inter       = 1   (1b)
    //   intra       = 1   (1b, present because inter=1)
    //   ue(0)       = 1   (1b)
    // 6 bits packed: 1 0 0 1 1 1 = 0b100111_xx → 0x9c.
    let ph_rbsp: [u8; 1] = [0x9c];
    let mut ph_nal = Vec::new();
    ph_nal.extend_from_slice(&vvc_hdr(NAL_TYPE_PH, 0, 1));
    ph_nal.extend_from_slice(&ph_rbsp);

    let mut stream = Vec::new();
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_VPS, 0, 1), 0xa1);
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_SPS, 0, 1), 0xa2);
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_PPS, 0, 1), 0xa3);
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    stream.extend_from_slice(&ph_nal);
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_IDR_W_RADL, 0, 1), 0xa5);

    let nals = split_annex_b(&stream);
    assert_eq!(nals.len(), 5);

    let ph_body = nals
        .iter()
        .find(|n| parse_nal_header(n).map(|h| h.nal_unit_type) == Ok(NAL_TYPE_PH))
        .expect("PH NAL present");

    let ph = parse_picture_header(ph_body).expect("PH parses");
    assert_eq!(ph.ph_gdr_or_irap_pic_flag, 1);
    assert_eq!(ph.ph_non_ref_pic_flag, 0);
    assert_eq!(ph.ph_gdr_pic_flag, Some(0));
    assert_eq!(ph.ph_inter_slice_allowed_flag, 1);
    assert_eq!(ph.ph_intra_slice_allowed_flag, Some(1));
    assert_eq!(ph.ph_pic_parameter_set_id, 0);
    assert!(ph.is_irap());
    assert!(!ph.is_gdr());
}

#[test]
fn walks_au_and_parses_picture_header_with_sps_context() {
    // End-to-end SPS-→-PH context-routing walk. Build a synthetic AU
    // whose SPS carries `sps_log2_max_pic_order_cnt_lsb_minus4 = 4`
    // (POC LSB u(8)) and whose PH packs a non-zero
    // `ph_pic_order_cnt_lsb = 0xa5`. Confirms a HW bridge can run
    //   split_annex_b -> parse_nal_header -> parse_sps -> parse_picture_header_with_sps
    // and recover the POC LSB the GPU needs for reference-picture-list
    // management, not just the prefix flags.
    //
    // Build the SPS RBSP via the crate's own writer (the canonical
    // inverse path), with sps_log2_max_pic_order_cnt_lsb_minus4 = 4.
    let sps_rbsp = full_sps_rbsp(4);

    let mut sps_nal_body = Vec::new();
    sps_nal_body.extend_from_slice(&vvc_hdr(NAL_TYPE_SPS, 0, 1));
    sps_nal_body.extend_from_slice(&sps_rbsp);

    // Build the PH RBSP: IRAP picture, no GDR → no recovery_poc_cnt.
    // Carry a deliberately non-canonical POC LSB so a wrong width would
    // truncate the field and miss it in the assertion.
    let mut w = BitWriter::new();
    w.write_bits(1, 1); // gdr_or_irap
    w.write_bits(0, 1); // non_ref
    w.write_bits(0, 1); // gdr_pic = 0 → IRAP
    w.write_bits(1, 1); // inter_allowed
    w.write_bits(1, 1); // intra_allowed
    w.write_ue(0).expect("pps_id ue");
    w.write_bits(0xa5, 8); // ph_pic_order_cnt_lsb
    let ph_rbsp = w.finish();

    let mut ph_nal_body = Vec::new();
    ph_nal_body.extend_from_slice(&vvc_hdr(NAL_TYPE_PH, 0, 1));
    ph_nal_body.extend_from_slice(&ph_rbsp);

    let mut stream = Vec::new();
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_VPS, 0, 1), 0xa1);
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    stream.extend_from_slice(&sps_nal_body);
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_PPS, 0, 1), 0xa3);
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    stream.extend_from_slice(&ph_nal_body);
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_IDR_W_RADL, 0, 1), 0xa5);

    let nals = split_annex_b(&stream);
    assert_eq!(nals.len(), 5);

    let sps_body = nals
        .iter()
        .find(|n| parse_nal_header(n).map(|h| h.nal_unit_type) == Ok(NAL_TYPE_SPS))
        .expect("SPS NAL present");
    let sps = parse_sps(sps_body).expect("SPS parses");
    assert_eq!(sps.sps_log2_max_pic_order_cnt_lsb_minus4, 4);
    assert_eq!(sps.poc_lsb_width(), 8);

    let ph_body = nals
        .iter()
        .find(|n| parse_nal_header(n).map(|h| h.nal_unit_type) == Ok(NAL_TYPE_PH))
        .expect("PH NAL present");
    let ph = parse_picture_header_with_sps(ph_body, &sps).expect("PH parses with SPS ctx");
    assert_eq!(ph.ph_pic_order_cnt_lsb, Some(0xa5));
    assert_eq!(ph.ph_recovery_poc_cnt, None);
    assert!(ph.is_irap());
}

#[test]
fn walker_first_irap_helper_pattern() {
    // Demonstrate the canonical "find first IRAP NAL" pattern a
    // downstream HW bridge would write against this module.
    let mut stream = Vec::new();
    // A leading TRAIL (decoded VCL, not IRAP).
    push_nal(&mut stream, vvc_hdr(0, 0, 1), 0x10); // TRAIL
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_VPS, 0, 1), 0x20);
    push_nal(&mut stream, vvc_hdr(NAL_TYPE_IDR_W_RADL, 0, 1), 0x30);

    let first_irap = split_annex_b(&stream)
        .into_iter()
        .filter_map(|n| parse_nal_header(n).ok())
        .find(|h| is_irap(h.nal_unit_type));
    assert!(first_irap.is_some(), "should locate IDR_W_RADL");
    assert_eq!(first_irap.unwrap().nal_unit_type, NAL_TYPE_IDR_W_RADL);
}
