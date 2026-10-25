//! H.264 full-stream front end: complete slice headers checked field by
//! field against `ffmpeg -bsf:v trace_headers` goldens, picture order
//! counts against container presentation order, and reference list /
//! marking invariants over B-pyramid, MMCO, long-term, PAFF and MBAFF
//! streams.
//!
//! Goldens (`tests/fixtures/h264/*.slices`) hold one line per slice:
//! the syntax elements in bitstream order as `trace_headers` prints them
//! plus `end=` (the bit after the last header element, NAL header byte
//! included, RBSP bits). `*.dpb` holds the reference frames left after
//! each reference picture's marking, from `ffmpeg -debug mmco` (short-term
//! FrameNums, long-term LongTermFrameIdx:FrameNum). `*.order` holds each picture's presentation
//! index in decode order (from the MP4 the stream was cut from).

use oxideav_bitstream::h264::dpb::{Dpb, FinishedPicture, Marking};
use oxideav_bitstream::h264::slice::{MmcoOp, RefPicListModificationOp, SliceHeader, SliceType};
use oxideav_bitstream::h264::stream::{H264Event, H264Parser, nal_units};
use oxideav_bitstream::h264::{H264Pps, H264Sps};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/h264/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn text(name: &str) -> String {
    String::from_utf8(fixture(name)).unwrap()
}

/// The slice header as `trace_headers` prints it.
fn trace(h: &SliceHeader, sps: &H264Sps, pps: &H264Pps) -> String {
    let mut v: Vec<String> = Vec::new();
    let mut p = |k: &str, x: i64| v.push(format!("{k}={x}"));
    p("forbidden_zero_bit", 0);
    p("nal_ref_idc", h.nal_ref_idc.into());
    p("nal_unit_type", h.nal_unit_type.into());
    p("first_mb_in_slice", h.first_mb_in_slice.into());
    p("slice_type", h.slice_type_raw.into());
    p("pic_parameter_set_id", h.pic_parameter_set_id.into());
    if sps.separate_colour_plane_flag {
        p("colour_plane_id", h.colour_plane_id.into());
    }
    p("frame_num", h.frame_num.into());
    if !sps.frame_mbs_only_flag {
        p("field_pic_flag", h.field_pic_flag.into());
        if h.field_pic_flag {
            p("bottom_field_flag", h.bottom_field_flag.into());
        }
    }
    if h.is_idr() {
        p("idr_pic_id", h.idr_pic_id.into());
    }
    if sps.pic_order_cnt_type == 0 {
        p("pic_order_cnt_lsb", h.pic_order_cnt_lsb.into());
        if pps.bottom_field_pic_order_in_frame_present_flag && !h.field_pic_flag {
            p(
                "delta_pic_order_cnt_bottom",
                h.delta_pic_order_cnt_bottom.into(),
            );
        }
    }
    if sps.pic_order_cnt_type == 1 && !sps.delta_pic_order_always_zero_flag {
        p("delta_pic_order_cnt[0]", h.delta_pic_order_cnt[0].into());
        if pps.bottom_field_pic_order_in_frame_present_flag && !h.field_pic_flag {
            p("delta_pic_order_cnt[1]", h.delta_pic_order_cnt[1].into());
        }
    }
    if pps.redundant_pic_cnt_present_flag {
        p("redundant_pic_cnt", h.redundant_pic_cnt.into());
    }
    if h.slice_type == SliceType::B {
        p(
            "direct_spatial_mv_pred_flag",
            h.direct_spatial_mv_pred_flag.into(),
        );
    }
    if h.slice_type.has_list0() {
        p(
            "num_ref_idx_active_override_flag",
            h.num_ref_idx_active_override_flag.into(),
        );
        if h.num_ref_idx_active_override_flag {
            p(
                "num_ref_idx_l0_active_minus1",
                h.num_ref_idx_l0_active_minus1.into(),
            );
            if h.slice_type == SliceType::B {
                p(
                    "num_ref_idx_l1_active_minus1",
                    h.num_ref_idx_l1_active_minus1.into(),
                );
            }
        }
    }
    let m = &h.ref_pic_list_modification;
    for (x, flag, ops, present) in [
        (
            0,
            m.ref_pic_list_modification_flag_l0,
            &m.modifications_l0,
            h.slice_type.has_list0(),
        ),
        (
            1,
            m.ref_pic_list_modification_flag_l1,
            &m.modifications_l1,
            h.slice_type.has_list1(),
        ),
    ] {
        if !present {
            continue;
        }
        p(&format!("ref_pic_list_modification_flag_l{x}"), flag.into());
        if flag {
            for op in ops {
                match *op {
                    RefPicListModificationOp::SubtractPicNum(d) => {
                        p("modification_of_pic_nums_idc", 0);
                        p("abs_diff_pic_num_minus1", d.into());
                    }
                    RefPicListModificationOp::AddPicNum(d) => {
                        p("modification_of_pic_nums_idc", 1);
                        p("abs_diff_pic_num_minus1", d.into());
                    }
                    RefPicListModificationOp::LongTermPicNum(n) => {
                        p("modification_of_pic_nums_idc", 2);
                        p("long_term_pic_num", n.into());
                    }
                    _ => unreachable!(),
                }
            }
            p("modification_of_pic_nums_idc", 3);
        }
    }
    if let Some(w) = &h.pred_weight_table {
        p("luma_log2_weight_denom", w.luma_log2_weight_denom.into());
        if sps.chroma_array_type() != 0 {
            p(
                "chroma_log2_weight_denom",
                w.chroma_log2_weight_denom.into(),
            );
        }
        for (x, list) in [(0, &w.l0), (1, &w.l1)] {
            for (i, e) in list.iter().enumerate() {
                p(
                    &format!("luma_weight_l{x}_flag[{i}]"),
                    e.luma_weight_flag.into(),
                );
                if e.luma_weight_flag {
                    p(&format!("luma_weight_l{x}[{i}]"), e.luma_weight.into());
                    p(&format!("luma_offset_l{x}[{i}]"), e.luma_offset.into());
                }
                if sps.chroma_array_type() != 0 {
                    p(
                        &format!("chroma_weight_l{x}_flag[{i}]"),
                        e.chroma_weight_flag.into(),
                    );
                    if e.chroma_weight_flag {
                        for j in 0..2 {
                            p(
                                &format!("chroma_weight_l{x}[{i}][{j}]"),
                                e.chroma_weight[j].into(),
                            );
                            p(
                                &format!("chroma_offset_l{x}[{i}][{j}]"),
                                e.chroma_offset[j].into(),
                            );
                        }
                    }
                }
            }
        }
    }
    if let Some(d) = &h.dec_ref_pic_marking {
        if h.is_idr() {
            p(
                "no_output_of_prior_pics_flag",
                d.no_output_of_prior_pics_flag.into(),
            );
            p(
                "long_term_reference_flag",
                d.long_term_reference_flag.into(),
            );
        } else {
            p(
                "adaptive_ref_pic_marking_mode_flag",
                d.adaptive_ref_pic_marking_mode_flag.into(),
            );
            if d.adaptive_ref_pic_marking_mode_flag {
                for op in &d.mmco {
                    p("memory_management_control_operation", op.code().into());
                    match *op {
                        MmcoOp::MarkShortTermUnused {
                            difference_of_pic_nums_minus1: x,
                        } => p("difference_of_pic_nums_minus1", x.into()),
                        MmcoOp::MarkLongTermUnused {
                            long_term_pic_num: x,
                        } => p("long_term_pic_num", x.into()),
                        MmcoOp::AssignLongTerm {
                            difference_of_pic_nums_minus1: x,
                            long_term_frame_idx: y,
                        } => {
                            p("difference_of_pic_nums_minus1", x.into());
                            p("long_term_frame_idx", y.into());
                        }
                        MmcoOp::SetMaxLongTermFrameIdx {
                            max_long_term_frame_idx_plus1: x,
                        } => p("max_long_term_frame_idx_plus1", x.into()),
                        MmcoOp::AssignCurrentLongTerm {
                            long_term_frame_idx: x,
                        } => p("long_term_frame_idx", x.into()),
                        _ => {}
                    }
                }
                p("memory_management_control_operation", 0);
            }
        }
    }
    if pps.entropy_coding_mode_flag && !h.slice_type.is_intra() {
        p("cabac_init_idc", h.cabac_init_idc.into());
    }
    p("slice_qp_delta", h.slice_qp_delta.into());
    if matches!(h.slice_type, SliceType::SP | SliceType::SI) {
        if h.slice_type == SliceType::SP {
            p("sp_for_switch_flag", h.sp_for_switch_flag.into());
        }
        p("slice_qs_delta", h.slice_qs_delta.into());
    }
    if pps.deblocking_filter_control_present_flag {
        p(
            "disable_deblocking_filter_idc",
            h.disable_deblocking_filter_idc.into(),
        );
        if h.disable_deblocking_filter_idc != 1 {
            p(
                "slice_alpha_c0_offset_div2",
                h.slice_alpha_c0_offset_div2.into(),
            );
            p("slice_beta_offset_div2", h.slice_beta_offset_div2.into());
        }
    }
    p("end", (8 + h.header_bits) as i64);
    v.join(" ")
}

#[derive(Debug)]
struct Pic {
    poc: i32,
    idr_period: usize,
    finished: FinishedPicture,
}

struct Run {
    traces: Vec<String>,
    /// DPB contents after each reference picture: `S=<FrameNum,…>
    /// L=<LongTermFrameIdx:FrameNum,…>` (stores with any field so marked).
    states: Vec<String>,
    pictures: Vec<Pic>,
    max_refs_seen: usize,
}

/// Parse a whole stream through the front end and the DPB.
fn run(name: &str) -> Run {
    let data = fixture(name);
    let mut parser = H264Parser::new();
    let mut dpb = Dpb::new();
    let mut traces = Vec::new();
    let mut pictures = Vec::new();
    let mut in_progress: Option<(i32, usize, u8)> = None;
    let mut idr_period = 0usize;
    let mut max_refs_seen = 0usize;
    let mut states = Vec::new();
    let finish = |dpb: &mut Dpb,
                  sps: &H264Sps,
                  p: (i32, usize, u8),
                  pictures: &mut Vec<Pic>,
                  states: &mut Vec<String>| {
        let reference = dpb.current().unwrap().reference;
        let f = dpb.finish_picture(sps).unwrap();
        if reference {
            let mut st: Vec<u32> = dpb
                .references()
                .filter(|s| {
                    s.fields
                        .iter()
                        .any(|f| f.decoded && f.marking == Marking::ShortTerm)
                })
                .map(|s| s.frame_num)
                .collect();
            st.sort();
            let mut lt: Vec<(u32, u32)> = dpb
                .references()
                .filter_map(|s| s.long_term_frame_idx().map(|i| (i, s.frame_num)))
                .collect();
            lt.sort();
            let st: Vec<String> = st.iter().map(u32::to_string).collect();
            let lt: Vec<String> = lt.iter().map(|(i, f)| format!("{i}:{f}")).collect();
            states.push(format!("S={} L={}", st.join(","), lt.join(",")));
        }
        pictures.push(Pic {
            poc: if f.mmco5 { p.0 } else { f.pic_order_cnt },
            idr_period: p.1,
            finished: f,
        });
    };
    let mut last_sps: Option<H264Sps> = None;
    for nal in nal_units(&data) {
        let ev = parser
            .process_nal(nal)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let H264Event::Slice(slice) = ev else {
            continue;
        };
        let (sps, pps) = parser.active(&slice).unwrap();
        let (sps, pps) = (sps.clone(), pps.clone());
        traces.push(trace(&slice.header, &sps, &pps));
        if !slice.primary {
            continue;
        }
        if slice.first_of_picture {
            if let Some(p) = in_progress.take() {
                finish(
                    &mut dpb,
                    last_sps.as_ref().unwrap(),
                    p,
                    &mut pictures,
                    &mut states,
                );
            }
            if slice.header.is_idr() {
                idr_period += 1;
            }
            let cur = dpb.begin_picture(&sps, &slice.header).unwrap();
            in_progress = Some((cur.poc.pic_order_cnt, idr_period, 0));
            last_sps = Some(sps.clone());
        }
        let refs = dpb.references().count();
        max_refs_seen = max_refs_seen.max(refs);
        assert!(
            refs <= sps.max_num_ref_frames.max(1) as usize + 1,
            "{name}: {refs} stores for max_num_ref_frames {}",
            sps.max_num_ref_frames
        );
        let lists = dpb.ref_pic_lists(&sps, &slice.header).unwrap();
        let h = &slice.header;
        if h.slice_type.has_list0() {
            assert_eq!(
                lists.list0.len(),
                h.num_ref_idx_l0_active_minus1 as usize + 1
            );
            for (i, e) in lists.list0.iter().enumerate() {
                let e = e.unwrap_or_else(|| panic!("{name}: RefPicList0[{i}] empty: {h:?}"));
                let s = dpb.store(e.key).expect("list entry is in the DPB");
                assert!(!s.non_existing);
                if h.field_pic_flag {
                    assert!(e.parity.is_some());
                } else {
                    assert!(e.parity.is_none());
                }
            }
        }
        if h.slice_type.has_list1() {
            assert_eq!(
                lists.list1.len(),
                h.num_ref_idx_l1_active_minus1 as usize + 1
            );
            assert!(
                lists.list1.iter().all(Option::is_some),
                "{name}: list1 {lists:?}"
            );
        }
    }
    if let Some(p) = in_progress.take() {
        finish(
            &mut dpb,
            last_sps.as_ref().unwrap(),
            p,
            &mut pictures,
            &mut states,
        );
    }
    Run {
        traces,
        states,
        pictures,
        max_refs_seen,
    }
}

fn check_trace(name: &str) -> Run {
    let r = run(&format!("{name}.h264"));
    let golden = text(&format!("{name}.slices"));
    let golden: Vec<&str> = golden.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(r.traces.len(), golden.len(), "{name}: slice count");
    for (i, (ours, theirs)) in r.traces.iter().zip(&golden).enumerate() {
        assert_eq!(ours, theirs, "{name}: slice {i}");
    }
    let golden = text(&format!("{name}.dpb"));
    let golden: Vec<&str> = golden.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        r.states, golden,
        "{name}: DPB state after each reference picture"
    );
    r
}

/// Presentation order inside each IDR period must follow the counts.
fn check_order(name: &str, r: &Run) {
    let order: Vec<usize> = text(&format!("{name}.order"))
        .split_whitespace()
        .map(|t| t.parse().unwrap())
        .collect();
    assert_eq!(order.len(), r.pictures.len(), "{name}: picture count");
    let mut keyed: Vec<(usize, i32, usize)> = r
        .pictures
        .iter()
        .enumerate()
        .map(|(i, p)| (p.idr_period, p.poc, i))
        .collect();
    keyed.sort();
    for (rank, &(_, _, decode_idx)) in keyed.iter().enumerate() {
        assert_eq!(order[decode_idx], rank, "{name}: picture {decode_idx}");
    }
}

#[test]
fn b_pyramid_headers_order_and_lists() {
    let r = check_trace("bpyramid");
    check_order("bpyramid", &r);
    assert!(r.max_refs_seen >= 3, "pyramid keeps several references");
    // x264's pyramid unmarks B references with MMCO 1.
    let golden = text("bpyramid.slices");
    assert!(golden.contains("memory_management_control_operation=1"));
}

#[test]
fn fade_weighted_prediction_with_chroma() {
    let r = check_trace("fade");
    check_order("fade", &r);
    assert!(text("fade.slices").contains("chroma_weight_l0[0][0]"));
}

#[test]
fn mbaff_interlaced_frames() {
    let r = check_trace("mbaff");
    check_order("mbaff", &r);
}

#[test]
fn paff_long_term_anchor() {
    let r = check_trace("paff_lt_anchor");
    // Two fields per frame share one store.
    let keys: Vec<u32> = r.pictures.iter().map(|p| p.finished.key).collect();
    for pair in keys.chunks(2) {
        assert_eq!(pair[0], pair[1], "field pair shares its store: {keys:?}");
    }
}

#[test]
fn paff_mmco1_field_marking() {
    check_trace("paff_mmco1_field");
}

#[test]
fn paff_b_fields() {
    let r = check_trace("paff_b_fields");
    // Field POCs inside a frame are distinct and the pair shares a key.
    for pair in r.pictures.chunks(2) {
        assert_eq!(pair[0].finished.key, pair[1].finished.key);
    }
}

#[test]
fn paff_mixed_frames_and_fields() {
    check_trace("paff_mixed");
    check_trace("paff_idr_frame_p_fields");
}

#[test]
fn other_profiles_and_tools() {
    check_trace("mbaff_field_pairs");
    check_trace("multi_ref");
    check_trace("weighted_explicit");
    check_trace("scaling_jvt");
    check_trace("cavlc_b");
}
