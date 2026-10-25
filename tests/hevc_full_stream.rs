//! HEVC full-stream front end: complete slice segment headers checked
//! field by field against `ffmpeg -bsf:v trace_headers` goldens, POC
//! against container presentation order, RPS / reference list
//! invariants over B-pyramid, open-GOP (CRA + RASL), weighted, WPP,
//! tiles, multi-slice and Main 10 streams.
//!
//! `tests/fixtures/hevc/*.slices`: one line per slice segment, syntax
//! elements in bitstream order as `trace_headers` names them, then
//! `bytes=` (NAL unit header + header RBSP bytes through
//! `byte_alignment()`). `*.order`: each picture's presentation index in
//! decode order, from the MP4 the stream was cut from.

use oxideav_bitstream::hevc::dpb::HevcDpb;
use oxideav_bitstream::hevc::slice::{HevcSliceType, SliceSegmentHeader};
use oxideav_bitstream::hevc::stream::{HevcEvent, HevcParser, nal_units};
use oxideav_bitstream::hevc::{HevcPps, HevcSps, HevcStRpsCoding};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/hevc/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn text(name: &str) -> String {
    String::from_utf8(fixture(name)).unwrap()
}

fn ceil_log2(v: u64) -> u32 {
    if v <= 1 {
        0
    } else {
        64 - (v - 1).leading_zeros()
    }
}

fn trace(h: &SliceSegmentHeader, sps: &HevcSps, pps: &HevcPps) -> String {
    let mut v: Vec<String> = Vec::new();
    let mut p = |k: &str, x: i64| v.push(format!("{k}={x}"));
    p("forbidden_zero_bit", 0);
    p("nal_unit_type", h.nal_unit_type.into());
    p("nuh_layer_id", h.nuh_layer_id.into());
    p("nuh_temporal_id_plus1", (h.temporal_id + 1).into());
    p(
        "first_slice_segment_in_pic_flag",
        h.first_slice_segment_in_pic_flag.into(),
    );
    if h.is_irap() {
        p(
            "no_output_of_prior_pics_flag",
            h.no_output_of_prior_pics_flag.into(),
        );
    }
    p(
        "slice_pic_parameter_set_id",
        h.slice_pic_parameter_set_id.into(),
    );
    if !h.first_slice_segment_in_pic_flag {
        if pps.dependent_slice_segments_enabled_flag {
            p(
                "dependent_slice_segment_flag",
                h.dependent_slice_segment_flag.into(),
            );
        }
        p("slice_segment_address", h.slice_segment_address.into());
    }
    if !h.dependent_slice_segment_flag {
        for i in 0..pps.num_extra_slice_header_bits {
            p(
                &format!("slice_reserved_flag[{i}]"),
                ((h.slice_reserved_flags >> i) & 1).into(),
            );
        }
        p("slice_type", h.slice_type.code().into());
        if pps.output_flag_present_flag {
            p("pic_output_flag", h.pic_output_flag.into());
        }
        if !h.is_idr() {
            p("slice_pic_order_cnt_lsb", h.slice_pic_order_cnt_lsb.into());
            p(
                "short_term_ref_pic_set_sps_flag",
                h.short_term_ref_pic_set_sps_flag.into(),
            );
            let n = sps.short_term_rps.len();
            if !h.short_term_ref_pic_set_sps_flag {
                let rps = &h.short_term_rps;
                match &rps.coding {
                    HevcStRpsCoding::InterPredicted {
                        delta_rps_sign,
                        abs_delta_rps_minus1,
                        used_by_curr_pic_flag,
                        use_delta_flag,
                    } => {
                        p("inter_ref_pic_set_prediction_flag", 1);
                        p("delta_idx_minus1", h.delta_idx_minus1.into());
                        p("delta_rps_sign", (*delta_rps_sign).into());
                        p("abs_delta_rps_minus1", (*abs_delta_rps_minus1).into());
                        for (j, &u) in used_by_curr_pic_flag.iter().enumerate() {
                            p(&format!("used_by_curr_pic_flag[{j}]"), u.into());
                            if !u {
                                p(&format!("use_delta_flag[{j}]"), use_delta_flag[j].into());
                            }
                        }
                    }
                    _ => {
                        if n != 0 {
                            p("inter_ref_pic_set_prediction_flag", 0);
                        }
                        p("num_negative_pics", rps.delta_poc_s0.len() as i64);
                        p("num_positive_pics", rps.delta_poc_s1.len() as i64);
                        let mut prev = 0;
                        for (i, (&d, &u)) in rps
                            .delta_poc_s0
                            .iter()
                            .zip(&rps.used_by_curr_pic_s0)
                            .enumerate()
                        {
                            p(&format!("delta_poc_s0_minus1[{i}]"), (prev - d - 1).into());
                            p(&format!("used_by_curr_pic_s0_flag[{i}]"), u.into());
                            prev = d;
                        }
                        let mut prev = 0;
                        for (i, (&d, &u)) in rps
                            .delta_poc_s1
                            .iter()
                            .zip(&rps.used_by_curr_pic_s1)
                            .enumerate()
                        {
                            p(&format!("delta_poc_s1_minus1[{i}]"), (d - prev - 1).into());
                            p(&format!("used_by_curr_pic_s1_flag[{i}]"), u.into());
                            prev = d;
                        }
                    }
                }
            } else if n > 1 {
                p(
                    "short_term_ref_pic_set_idx",
                    h.short_term_ref_pic_set_idx.into(),
                );
            }
            if sps.long_term_ref_pics_present_flag {
                if !sps.long_term_ref_pics.is_empty() {
                    p("num_long_term_sps", h.num_long_term_sps.into());
                }
                p("num_long_term_pics", h.num_long_term_pics.into());
                for (i, lt) in h.long_term_refs.iter().enumerate() {
                    match lt.lt_idx_sps {
                        Some(idx) if sps.long_term_ref_pics.len() > 1 => {
                            p(&format!("lt_idx_sps[{i}]"), idx.into())
                        }
                        Some(_) => {}
                        None => {
                            p(&format!("poc_lsb_lt[{i}]"), lt.poc_lsb_lt.into());
                            p(
                                &format!("used_by_curr_pic_lt_flag[{i}]"),
                                lt.used_by_curr_pic_lt.into(),
                            );
                        }
                    }
                    p(
                        &format!("delta_poc_msb_present_flag[{i}]"),
                        lt.delta_poc_msb_present_flag.into(),
                    );
                    if lt.delta_poc_msb_present_flag {
                        p(
                            &format!("delta_poc_msb_cycle_lt[{i}]"),
                            lt.delta_poc_msb_cycle_lt.into(),
                        );
                    }
                }
            }
            if sps.sps_temporal_mvp_enabled_flag {
                p(
                    "slice_temporal_mvp_enabled_flag",
                    h.slice_temporal_mvp_enabled_flag.into(),
                );
            }
        }
        if sps.sample_adaptive_offset_enabled_flag {
            p("slice_sao_luma_flag", h.slice_sao_luma_flag.into());
            if sps.chroma_format_idc != 0 {
                p("slice_sao_chroma_flag", h.slice_sao_chroma_flag.into());
            }
        }
        let b = h.slice_type == HevcSliceType::B;
        if h.slice_type.is_inter() {
            p(
                "num_ref_idx_active_override_flag",
                h.num_ref_idx_active_override_flag.into(),
            );
            if h.num_ref_idx_active_override_flag {
                p(
                    "num_ref_idx_l0_active_minus1",
                    h.num_ref_idx_l0_active_minus1.into(),
                );
                if b {
                    p(
                        "num_ref_idx_l1_active_minus1",
                        h.num_ref_idx_l1_active_minus1.into(),
                    );
                }
            }
            let total = h.num_pic_total_curr();
            if pps.lists_modification_present_flag && total > 1 {
                let m = &h.ref_pic_lists_modification;
                p(
                    "ref_pic_list_modification_flag_l0",
                    m.ref_pic_list_modification_flag_l0.into(),
                );
                for (i, e) in m.list_entry_l0.iter().enumerate() {
                    p(&format!("list_entry_l0[{i}]"), (*e).into());
                }
                if b {
                    p(
                        "ref_pic_list_modification_flag_l1",
                        m.ref_pic_list_modification_flag_l1.into(),
                    );
                    for (i, e) in m.list_entry_l1.iter().enumerate() {
                        p(&format!("list_entry_l1[{i}]"), (*e).into());
                    }
                }
                let _ = ceil_log2(u64::from(total));
            }
            if b {
                p("mvd_l1_zero_flag", h.mvd_l1_zero_flag.into());
            }
            if pps.cabac_init_present_flag {
                p("cabac_init_flag", h.cabac_init_flag.into());
            }
            if h.slice_temporal_mvp_enabled_flag {
                if b {
                    p("collocated_from_l0_flag", h.collocated_from_l0_flag.into());
                }
                if (h.collocated_from_l0_flag && h.num_ref_idx_l0_active_minus1 > 0)
                    || (!h.collocated_from_l0_flag && h.num_ref_idx_l1_active_minus1 > 0)
                {
                    p("collocated_ref_idx", h.collocated_ref_idx.into());
                }
            }
            if let Some(w) = &h.pred_weight_table {
                p("luma_log2_weight_denom", w.luma_log2_weight_denom.into());
                if sps.chroma_format_idc != 0 {
                    p(
                        "delta_chroma_log2_weight_denom",
                        w.delta_chroma_log2_weight_denom.into(),
                    );
                }
                for (x, l) in [(0, &w.l0), (1, &w.l1)] {
                    for (i, e) in l.iter().enumerate() {
                        p(
                            &format!("luma_weight_l{x}_flag[{i}]"),
                            e.luma_weight_flag.into(),
                        );
                    }
                    if sps.chroma_format_idc != 0 {
                        for (i, e) in l.iter().enumerate() {
                            p(
                                &format!("chroma_weight_l{x}_flag[{i}]"),
                                e.chroma_weight_flag.into(),
                            );
                        }
                    }
                    for (i, e) in l.iter().enumerate() {
                        if e.luma_weight_flag {
                            p(
                                &format!("delta_luma_weight_l{x}[{i}]"),
                                e.delta_luma_weight.into(),
                            );
                            p(&format!("luma_offset_l{x}[{i}]"), e.luma_offset.into());
                        }
                        if e.chroma_weight_flag {
                            for j in 0..2 {
                                p(
                                    &format!("delta_chroma_weight_l{x}[{i}][{j}]"),
                                    e.delta_chroma_weight[j].into(),
                                );
                                p(
                                    &format!("chroma_offset_l{x}[{i}][{j}]"),
                                    e.delta_chroma_offset[j].into(),
                                );
                            }
                        }
                    }
                }
            }
            p(
                "five_minus_max_num_merge_cand",
                h.five_minus_max_num_merge_cand.into(),
            );
        }
        p("slice_qp_delta", h.slice_qp_delta.into());
        if pps.pps_slice_chroma_qp_offsets_present_flag {
            p("slice_cb_qp_offset", h.slice_cb_qp_offset.into());
            p("slice_cr_qp_offset", h.slice_cr_qp_offset.into());
        }
        if pps
            .range_extension
            .as_ref()
            .is_some_and(|e| e.chroma_qp_offset_list_enabled_flag)
        {
            p(
                "cu_chroma_qp_offset_enabled_flag",
                h.cu_chroma_qp_offset_enabled_flag.into(),
            );
        }
        if pps.deblocking_filter_override_enabled_flag {
            p(
                "deblocking_filter_override_flag",
                h.deblocking_filter_override_flag.into(),
            );
        }
        if h.deblocking_filter_override_flag {
            p(
                "slice_deblocking_filter_disabled_flag",
                h.slice_deblocking_filter_disabled_flag.into(),
            );
            if !h.slice_deblocking_filter_disabled_flag {
                p("slice_beta_offset_div2", h.slice_beta_offset_div2.into());
                p("slice_tc_offset_div2", h.slice_tc_offset_div2.into());
            }
        }
        if pps.pps_loop_filter_across_slices_enabled_flag
            && (h.slice_sao_luma_flag
                || h.slice_sao_chroma_flag
                || !h.slice_deblocking_filter_disabled_flag)
        {
            p(
                "slice_loop_filter_across_slices_enabled_flag",
                h.slice_loop_filter_across_slices_enabled_flag.into(),
            );
        }
    }
    if pps.tiles.is_some() || pps.entropy_coding_sync_enabled_flag {
        p("num_entry_point_offsets", h.num_entry_point_offsets.into());
        if h.num_entry_point_offsets > 0 {
            p("offset_len_minus1", h.offset_len_minus1.into());
            for (i, o) in h.entry_point_offset_minus1.iter().enumerate() {
                p(&format!("entry_point_offset_minus1[{i}]"), (*o).into());
            }
        }
    }
    if pps.slice_segment_header_extension_present_flag {
        p(
            "slice_segment_header_extension_length",
            h.slice_segment_header_extension_length.into(),
        );
    }
    p("alignment_bit_equal_to_one", 1);
    p("bytes", (2 + h.header_bytes) as i64);
    v.join(" ")
}

struct Run {
    traces: Vec<String>,
    pocs: Vec<(usize, i32)>,
    skipped: usize,
}

fn run(name: &str) -> Run {
    let data = fixture(&format!("{name}.h265"));
    let mut parser = HevcParser::new();
    let mut dpb = HevcDpb::new();
    let mut traces = Vec::new();
    let mut pocs = Vec::new();
    let mut period = 0usize;
    let mut skipped = 0usize;
    let mut skipping = false;
    for nal in nal_units(&data) {
        let ev = parser
            .process_nal(nal)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let slice = match ev {
            HevcEvent::Slice(s) => s,
            HevcEvent::EndOfSequence => {
                dpb.end_of_sequence();
                continue;
            }
            _ => continue,
        };
        let (sps, pps) = parser.active(&slice).unwrap();
        traces.push(trace(&slice.header, sps, pps));
        let h = &slice.header;
        // The escaped offset lands on the slice data.
        assert!(h.slice_data_byte_offset() <= nal.len());
        if slice.first_of_picture {
            if dpb.current().is_some() && !skipping {
                dpb.finish_picture().unwrap();
            }
            if h.is_idr() {
                period += 1;
            }
            let cur = dpb.begin_picture(sps, h).unwrap();
            skipping = cur.skip;
            if cur.skip {
                skipped += 1;
                continue;
            }
            for k in cur
                .rps
                .st_curr_before
                .iter()
                .chain(&cur.rps.st_curr_after)
                .chain(&cur.rps.lt_curr)
            {
                assert!(k.is_some(), "{name}: missing reference {:?}", cur.rps);
            }
            pocs.push((period, cur.poc));
        }
        if skipping {
            continue;
        }
        let lists = dpb.ref_pic_lists(h).unwrap();
        if h.slice_type.is_inter() {
            assert_eq!(
                lists.list0.len(),
                h.num_ref_idx_l0_active_minus1 as usize + 1
            );
            assert!(lists.list0.iter().all(Option::is_some), "{name}: {lists:?}");
            if h.slice_type == HevcSliceType::B {
                assert_eq!(
                    lists.list1.len(),
                    h.num_ref_idx_l1_active_minus1 as usize + 1
                );
                assert!(lists.list1.iter().all(Option::is_some));
            }
            // B lists are ordered: list 0 starts before, list 1 after.
            let cur_poc = dpb.current().unwrap().poc;
            if let (Some(Some(a)), true) = (
                lists.list0.first(),
                !dpb.current().unwrap().rps.st_curr_before.is_empty(),
            ) {
                assert!(a.poc < cur_poc);
            }
        }
    }
    if dpb.current().is_some() && !skipping {
        dpb.finish_picture().unwrap();
    }
    Run {
        traces,
        pocs,
        skipped,
    }
}

fn check(name: &str) -> Run {
    let r = run(name);
    let golden = text(&format!("{name}.slices"));
    let golden: Vec<&str> = golden.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(r.traces.len(), golden.len(), "{name}: slice count");
    for (i, (ours, theirs)) in r.traces.iter().zip(&golden).enumerate() {
        assert_eq!(ours, theirs, "{name}: slice {i}");
    }
    r
}

fn check_order(name: &str, r: &Run) {
    let order: Vec<usize> = text(&format!("{name}.order"))
        .split_whitespace()
        .map(|t| t.parse().unwrap())
        .collect();
    assert_eq!(order.len(), r.pocs.len(), "{name}: picture count");
    let mut keyed: Vec<(usize, i32, usize)> = r
        .pocs
        .iter()
        .enumerate()
        .map(|(i, &(p, poc))| (p, poc, i))
        .collect();
    keyed.sort();
    for (rank, &(_, _, i)) in keyed.iter().enumerate() {
        assert_eq!(order[i], rank, "{name}: picture {i}");
    }
}

#[test]
fn open_gop_pyramid_with_wpp_and_slices() {
    let r = check("pyramid");
    // The MP4 starts at the first IDR, so no RASL picture is skipped.
    assert_eq!(r.skipped, 0);
    // POC continues across CRA pictures (one period), so presentation
    // order follows the counts across the whole stream.
    check_order("pyramid", &r);
}

#[test]
fn weighted_fade_with_scaling_lists() {
    let r = check("fade");
    check_order("fade", &r);
}

#[test]
fn main10() {
    let r = check("main10");
    check_order("main10", &r);
}

#[test]
fn tiles_slices_wpp_and_b_frames() {
    check("true_tiles_2x2");
    check("multi_slice_per_frame");
    check("bipred_b_frames_main");
    check("wpp_on");
}

#[test]
fn rasl_after_a_leading_cra_is_skipped() {
    // Cut the pyramid stream at its second CRA: the RASL pictures that
    // follow reference pictures before it and must be skipped.
    let data = fixture("pyramid.h265");
    let nals = nal_units(&data);
    let cra = nals
        .iter()
        .enumerate()
        .filter(|(_, n)| (n[0] >> 1) & 0x3f == 21)
        .map(|(i, _)| i)
        .next()
        .expect("a CRA picture");
    let mut parser = HevcParser::new();
    for n in nals[..cra]
        .iter()
        .filter(|n| (32..=34).contains(&((n[0] >> 1) & 0x3f)))
    {
        parser.process_nal(n).unwrap();
    }
    let mut dpb = HevcDpb::new();
    let mut skipped = 0;
    let mut decoded = 0;
    for n in &nals[cra..] {
        let Ok(HevcEvent::Slice(s)) = parser.process_nal(n) else {
            continue;
        };
        if !s.first_of_picture {
            continue;
        }
        if dpb.current().is_some_and(|c| !c.skip) {
            dpb.finish_picture().unwrap();
        }
        let (sps, _) = parser.active(&s).unwrap();
        let cur = dpb.begin_picture(sps, &s.header).unwrap();
        if cur.skip {
            skipped += 1;
        } else {
            decoded += 1;
            assert!(
                cur.rps
                    .st_curr_before
                    .iter()
                    .chain(&cur.rps.st_curr_after)
                    .all(Option::is_some),
                "non-RASL pictures only reference decoded pictures"
            );
        }
    }
    assert!(skipped > 0, "RASL pictures of the leading CRA are skipped");
    assert!(decoded > 0);
}
